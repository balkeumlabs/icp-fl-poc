# Secure Federated Learning Canister on the Internet Computer

This repository contains a proof-of-concept implementation of a secure, single-canister Federated Learning (FL) platform on the Internet Computer (IC). The system is designed to allow multiple clients to collaboratively train a machine learning model without exposing their private training data to the central server or other clients.

Security and privacy are achieved through end-to-end encryption, leveraging the Internet Computer's native vetKeys feature for decentralized key management.

## Core Concepts

### Federated Learning (FL)
Federated Learning is a machine learning paradigm where multiple clients (e.g., mobile phones, organizations) train a model locally on their own data. Instead of sharing the raw data, they send their local model updates to a central server. The server aggregates these updates to produce an improved global model, which is then sent back to the clients for the next round of training. This project implements the Federated Averaging (FedAvg) algorithm.

### End-to-End Encryption with vetKeys
To ensure the privacy of the model updates, this canister implements end-to-end encryption. The workflow is as follows:
1.  **Key Derivation**: Each client requests a unique symmetric encryption key from the canister. The canister uses the IC's **vetKeys** feature to derive this key based on the client's principal and a derivation path. This process is non-custodial; the canister itself never sees the client's key.
2.  **Encryption**: The client uses the derived key to encrypt its local model update using AES-GCM.
3.  **Decryption & Aggregation**: The canister, upon receiving the encrypted updates, re-derives the same keys for each client to decrypt their respective updates *just-in-time* for aggregation. The decrypted data only exists transiently in memory during the aggregation process.

This ensures that the model updates are protected both in transit and at rest on the canister.

## Architecture
The project is architected as a single Rust canister (`fl_canister`) running on the Internet Computer. This simplifies deployment and management.

-   **Backend**: A single Rust canister (`src/lib.rs`) contains all the logic for client management, training cycles, key derivation, and model aggregation.
-   **Canister API**: The public interface is defined in the Candid file (`src/fl_canister.did`).

## Federated Learning Workflow
The training process is managed through distinct cycles, orchestrated by the following API calls:

1.  **Client Registration**: A new client calls `register_client()` to get a unique `ClientId`.
2.  **Start a New Cycle**: An administrator (or an automated process) calls `start_new_cycle()` to begin a new round of training.
3.  **Fetch Encryption Key**: Each participating client calls `get_symmetric_key_for_client(derivation_path)` to get its unique, encrypted symmetric key for the current task.
4.  **Upload Encrypted Update**: The client encrypts its model update and submits it by calling `upload_model_update(encrypted_update)`.
5.  **Aggregate Models**: The administrator calls `run_aggregation()` to trigger the secure aggregation process. The canister decrypts all updates for the current cycle, computes the average, and updates the `GlobalModel`.
6.  **Fetch Global Model**: Clients can call `get_global_model()` to retrieve the latest version of the collaboratively trained model.

## Public Canister API

The following functions are exposed by the `fl_canister`:

```candid
service : {
  // Registers a new client and returns a unique ID.
  "register_client": () -> (ClientId);

  // Starts a new training cycle and returns the cycle number.
  "start_new_cycle": () -> (nat64);

  // Derives and returns a symmetric key for the calling client.
  "get_symmetric_key_for_client": (blob) -> (text);

  // Allows a registered client to upload their encrypted model update.
  "upload_model_update": (ModelUpdate) -> ();

  // Triggers the aggregation of all model updates for the current cycle.
  "run_aggregation": () -> ();

  // Returns the current global model.
  "get_global_model": () -> (GlobalModel) query;
};
```

## Setup and Usage

This project is configured to run within a containerized development environment to ensure all dependencies are handled correctly.

### Prerequisites
-   [Docker Desktop](https://www.docker.com/products/docker-desktop/)
-   [Visual Studio Code](https://code.visualstudio.com/)
-   [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) for VS Code.

### Running the Project
1.  Clone the repository.
2.  Open the project folder in Visual Studio Code.
3.  When prompted, click **"Reopen in Container"**. This will build the Docker image and set up the development environment.
4.  Once the container is running, open a new terminal within VS Code (`Terminal > New Terminal`).
5.  You can now use the `dfx` command-line tool to build, deploy, and interact with the canister.

```bash
# Start a local replica
dfx start --clean

# Deploy the canister
dfx deploy

# Example: Call the register_client function
dfx canister call fl_canister register_client
```
