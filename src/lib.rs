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

#[derive(CandidType, Deserialize, Clone, Copy)]
pub enum AggregationMode {
    Plain,
    SMPC,
}

impl Default for AggregationMode {
    fn default() -> Self {
        AggregationMode::Plain
    }
}

// Fixed-point scaling factor used for SMPC integer encoding of gradients
const SMPC_SCALE: i64 = 1_000_000; // 1e6

#[derive(CandidType, Deserialize, Default)]
pub struct State {
    global_model: GlobalModel,
    model_updates: HashMap<u64, HashMap<ClientId, ModelUpdate>>, // Plain (encrypted) updates per cycle
    clients: Vec<Principal>,
    next_client_id: ClientId,
    current_cycle: u64,
    aggregation_mode: AggregationMode,
    // SMPC storage: s_i shares and t_j sums per cycle (fixed-point i64)
    smpc_s_shares: HashMap<u64, HashMap<ClientId, Vec<i64>>>,
    smpc_t_sums: HashMap<u64, HashMap<ClientId, Vec<i64>>>,
    // Snapshot of participant client IDs per cycle (for off-chain pairwise masking)
    cycle_participants: HashMap<u64, Vec<ClientId>>,
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
        // Snapshot participants for this cycle as the current registered client IDs
        let participant_ids: Vec<ClientId> = (0..state.clients.len() as u64).collect();
        state.cycle_participants
            .insert(state.current_cycle, participant_ids);
        state.current_cycle
    })
}

// ==================================================================================================
// sMPC (Secure Multiparty Computation) Aggregation API
// ==================================================================================================

#[query]
fn get_aggregation_mode() -> String {
    STATE.with_borrow(|state| match state.aggregation_mode {
        AggregationMode::Plain => "PLAIN".to_string(),
        AggregationMode::SMPC => "SMPC".to_string(),
    })
}

#[update]
fn set_aggregation_mode(mode: String) {
    STATE.with_borrow_mut(|state| {
        state.aggregation_mode = match mode.to_ascii_uppercase().as_str() {
            "SMPC" => AggregationMode::SMPC,
            _ => AggregationMode::Plain,
        }
    })
}

#[query]
fn get_cycle_participants(cycle: u64) -> Vec<ClientId> {
    STATE.with_borrow(|state| {
        state
            .cycle_participants
            .get(&cycle)
            .cloned()
            .unwrap_or_else(|| (0..state.clients.len() as u64).collect())
    })
}

// Clients submit s_i = g_i_scaled - sum_j r_{i->j}
#[update]
fn upload_masked_update_s(share: Vec<i64>) {
    let caller = ic_cdk::caller();
    STATE.with_borrow_mut(|state| {
        let client_id = state
            .clients
            .iter()
            .position(|&p| p == caller)
            .expect("Client not registered") as ClientId;

        let s_vec: Vec<i64> = share;
        let cycle = state.current_cycle;
        let entry = state.smpc_s_shares.entry(cycle).or_default();
        entry.insert(client_id, s_vec);
    });
}

// Clients submit t_j = sum_i r_{i->j}
#[update]
fn upload_mask_sum_t(sum: Vec<i64>) {
    let caller = ic_cdk::caller();
    STATE.with_borrow_mut(|state| {
        let client_id = state
            .clients
            .iter()
            .position(|&p| p == caller)
            .expect("Client not registered") as ClientId;

        let t_vec: Vec<i64> = sum;
        let cycle = state.current_cycle;
        let entry = state.smpc_t_sums.entry(cycle).or_default();
        entry.insert(client_id, t_vec);
    });
}

#[update]
fn run_smpc_aggregation() {
    let (cycle, s_map, t_map) = STATE.with_borrow(|state| {
        (
            state.current_cycle,
            state.smpc_s_shares.get(&state.current_cycle).cloned().unwrap_or_default(),
            state.smpc_t_sums.get(&state.current_cycle).cloned().unwrap_or_default(),
        )
    });

    if s_map.is_empty() || t_map.is_empty() {
        return; // Not enough inputs
    }

    // Determine vector length from first available vector
    let vec_len_opt = s_map
        .values()
        .chain(t_map.values())
        .next()
        .map(|v| v.len());
    let vec_len = if let Some(l) = vec_len_opt { l } else { return };

    let mut sum_s = vec![0i64; vec_len];
    let mut sum_t = vec![0i64; vec_len];

    let mut num_s = 0usize;

    for v in s_map.values() {
        if v.len() != vec_len { continue; }
        for (i, val) in v.iter().enumerate() {
            sum_s[i] += *val;
        }
        num_s += 1;
    }

    for v in t_map.values() {
        if v.len() != vec_len { continue; }
        for (i, val) in v.iter().enumerate() {
            sum_t[i] += *val;
        }
    }

    if num_s == 0 { return; }

    let mut aggregated_avg: Vec<f32> = vec![0.0; vec_len];
    for i in 0..vec_len {
        let total_sum = (sum_s[i] as i128) + (sum_t[i] as i128); // widen to avoid interim overflow
        let avg_scaled = (total_sum as f64) / (num_s as f64);
        let avg = (avg_scaled / (SMPC_SCALE as f64)) as f32;
        aggregated_avg[i] = avg;
    }

    STATE.with_borrow_mut(|state| {
        state.global_model = serde_json::to_vec(&aggregated_avg).expect("Failed to serialize global model");
        state.smpc_s_shares.remove(&cycle);
        state.smpc_t_sums.remove(&cycle);
    });
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
