# Federated Learning Canister Overhaul Tasks

This document outlines the necessary steps to transform the existing note-taking application into a single-canister Federated Learning (FL) platform on the Internet Computer.

## 1. Project Restructuring and Cleanup

The first phase is to simplify the project into a single-canister architecture.

- [x] **Consolidate into a single canister:** Modify `dfx.json` to remove the `frontend` canister and rename the `backend` canister to something more appropriate, like `fl_canister`.
- [x] **Remove frontend code:** Delete the entire `/frontend` directory as it is no longer needed.
- [x] **Clean up unnecessary files:** Delete `BUILD.md` and any other files related to the old project structure.
- [x] **Relocate backend code:** Move the contents of the `/backend` directory to the project root to simplify the structure.

## 2. Implement Federated Learning Core Logic

This phase involves implementing the core functionality of the federated learning system within the single Rust canister.

- [x] **Define Data Structures:** Create Rust structs for `ModelUpdate`, `GlobalModel`, and other necessary data types.
- [x] **Implement Canister State:** Set up the canister's state management to store the global model, client information, and training cycle details.
- [x] **Update Candid Interface:** Modify the `.did` file to define the public API for the FL canister. This will include functions like:
  - `upload_model_update(encrypted_update: blob)`: Allows clients to submit their encrypted model updates.
  - `get_global_model()`: Allows clients to retrieve the current global model.
  - `register_client()`: Allows new clients to participate in the training process.
- [x] **Implement Aggregation Logic:** Develop the core FedAvg logic to aggregate the model updates from clients. Initially, we can focus on the aggregation mechanism itself and integrate encryption later.
- [x] **Implement End-to-End Encryption:** Integrate vetKeys for secure key derivation and use AES-GCM to encrypt/decrypt model updates.

## 3. Refine and Test

- [ ] **Unit and Integration Testing:** Develop a suite of tests to verify the correctness of the FL logic.
- [ ] **Deployment:** Ensure the single canister can be deployed and tested on a local replica.
