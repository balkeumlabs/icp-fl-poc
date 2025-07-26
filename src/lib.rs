use aes_gcm::aead::{Aead, KeyInit, Nonce};
use aes_gcm::Aes256Gcm;
use candid::{CandidType, Deserialize, Principal};
use ic_cdk::api::management_canister::vetkd::*;
use ic_cdk_macros::{query, update};
use std::cell::RefCell;
use std::collections::HashMap;

// ==================================================================================================
// Types
// ==================================================================================================

type ModelUpdate = Vec<u8>;
type GlobalModel = Vec<u8>;
type ClientId = u64;

// ==================================================================================================
// State
// ==================================================================================================

#[derive(CandidType, Deserialize, Default)]
pub struct State {
    global_model: GlobalModel,
    model_updates: HashMap<u64, HashMap<ClientId, ModelUpdate>>,
    clients: Vec<Principal>,
    next_client_id: ClientId,
    current_cycle: u64,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

// ==================================================================================================
// Public API
// ==================================================================================================

#[update]
fn register_client() -> ClientId {
    let caller = ic_cdk::caller();
    STATE.with_borrow_mut(|state| {
        if state.clients.contains(&caller) {
            panic!("Client already registered.");
        }
        let client_id = state.next_client_id;
        state.clients.push(caller);
        state.next_client_id += 1;
        client_id
    })
}

#[update]
fn upload_model_update(update: ModelUpdate) {
    let caller = ic_cdk::caller();
    STATE.with_borrow_mut(|state| {
        let client_id = state.clients.iter().position(|&p| p == caller).expect("Client not registered") as ClientId;
        let cycle_updates = state.model_updates.entry(state.current_cycle).or_default();
        cycle_updates.insert(client_id, update);
    });
}

#[query]
fn get_global_model() -> GlobalModel {
    STATE.with_borrow(|state| state.global_model.clone())
}

#[update]
async fn run_aggregation() {
    let (current_cycle, cycle_updates, clients) = STATE.with_borrow(|state| {
        let cycle_updates = state.model_updates.get(&state.current_cycle).cloned().unwrap_or_default();
        (state.current_cycle, cycle_updates, state.clients.clone())
    });

    if cycle_updates.is_empty() {
        return; // No updates for the current cycle
    }

    let mut aggregated_model: Vec<f32> = vec![];
    let mut decrypted_updates_count = 0;

    for (client_id, encrypted_update) in cycle_updates.iter() {
        let client_principal = clients.get(*client_id as usize).expect("Client principal not found");

        let derivation_path_seed = b"model_update_encryption".to_vec();
        let request = VetKDDeriveKeyRequest {
            key_id: bls12_381_g2_test_key_1(),
            derivation_path: vec![derivation_path_seed, client_principal.as_slice().to_vec()],
        };

        let (response,): (VetKDDeriveKeyResult,) = ic_cdk::call(vetkd_public_key_address(), "vetkd_derive_key", (request,))
            .await
            .expect("call to vetkd_derive_key failed");

        let key = Aes256Gcm::new_from_slice(&response.encrypted_key).expect("Failed to create AES key");

        if encrypted_update.len() < 12 {
            continue; // Not a valid encrypted payload
        }
        let (nonce_bytes, ciphertext) = encrypted_update.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        if let Ok(decrypted_data) = key.decrypt(nonce, ciphertext) {
            let update: Vec<f32> = serde_json::from_slice(&decrypted_data)
                .expect("Failed to deserialize decrypted model update");

            if aggregated_model.is_empty() {
                aggregated_model = vec![0.0; update.len()];
            }

            if aggregated_model.len() == update.len() {
                for (i, val) in update.iter().enumerate() {
                    aggregated_model[i] += val;
                }
                decrypted_updates_count += 1;
            }
        }
    }

    if decrypted_updates_count > 0 {
        let num_updates = decrypted_updates_count as f32;
        for val in aggregated_model.iter_mut() {
            *val /= num_updates;
        }

        STATE.with_borrow_mut(|state| {
            state.global_model = serde_json::to_vec(&aggregated_model).expect("Failed to serialize global model");
            state.model_updates.remove(&current_cycle);
        });
    }
}

#[update]
fn start_new_cycle() -> u64 {
    STATE.with_borrow_mut(|state| {
        state.current_cycle += 1;
        state.current_cycle
    })
}

// ==================================================================================================
// VetKey
// ==================================================================================================

#[update]
async fn get_symmetric_key_for_client(derivation_path: Vec<u8>) -> String {
    let request = VetKDDeriveKeyRequest {
        key_id: bls12_381_g2_test_key_1(),
        derivation_path: vec![derivation_path, vec![ic_cdk::caller().as_slice().to_vec()].concat()],
    };

    let (response,): (VetKDDeriveKeyResult,) = ic_cdk::call(vetkd_public_key_address(), "vetkd_derive_key", (request,))
        .await
        .expect("call to vetkd_derive_key failed");

    hex::encode(response.encrypted_key)
}

fn bls12_381_g2_test_key_1() -> VetKDKeyId {
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381,
        name: "test_key_1".to_string(),
    }
}
