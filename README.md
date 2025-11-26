# nexus-utils: Cross-Chain Bridge Event Listener

This project is a Python-based simulation of a critical component in a cross-chain bridging system: an event listener and transaction relayer. This script is designed to monitor events on a source blockchain (e.g., tokens being locked) and trigger corresponding actions on a destination blockchain (e.g., minting/unlocking equivalent tokens).

## Concept

Cross-chain bridges allow users to transfer assets or data between different blockchains. A common mechanism for asset bridging is the "lock-and-mint" or "lock-and-unlock" model:

1.  **Lock**: A user deposits an asset (e.g., USDC) into a bridge contract on the source chain (e.g., Ethereum).
2.  **Event Emission**: The source chain contract locks the asset and emits an event (e.g., `TokensLocked`) containing details of the deposit (recipient address, amount, destination chain ID).
3.  **Listening**: Off-chain services, often called relayers or oracles, listen for this specific event.
4.  **Relay & Verification**: Upon detecting and verifying the event, the relayer submits a transaction to a corresponding bridge contract on the destination chain (e.g., Polygon).
5.  **Mint/Unlock**: The destination contract verifies the relayer's message and mints or unlocks the equivalent amount of a pegged asset (e.g., USDC.e) to the user's specified recipient address.

This script simulates steps 3 and 4, acting as the off-chain relayer responsible for ensuring the liveness and integrity of the bridge.

## Code Architecture

The script is designed with a modular, class-based architecture to separate concerns, enhance readability, and facilitate future extensions or testing. The `bridge_event_listener.py` script acts as the orchestrator, initializing and running the core components.

```
+----------------------------+
| bridge_event_listener.py   |
| (Orchestrator)             |
+-------------+--------------+
              |
              v
+-------------+--------------+
|   BridgeEventListener      |
|   (Core Logic Loop)        |
+-------------+--------------+
      |           |
      | uses      | uses
      v           v
+-----------+   +--------------------+
| Blockchain- |   | TransactionRelayer |
| Connector |   | (Signs & Sends TXs)  |
| (Web3 RPC)  |   +--------------------+
+-----------+           |
                        | uses
                        v
                    +--------------------+
                    | StatusNotifier     |
                    | (External API Comms) |
                    +--------------------+
```

*   **`Config`**: A static class that loads and validates all necessary configuration from a `.env` file, such as RPC URLs, contract addresses, and private keys. This keeps sensitive data out of the source code.
*   **`BlockchainConnector`**: A reusable class responsible for establishing and maintaining a connection to a blockchain node via its RPC endpoint using the `web3.py` library. It handles connection checks and middleware injection (e.g., for PoA chains).
*   **`StatusNotifier`**: A utility class for sending status updates to an external monitoring service or API. It uses the `requests` library to post JSON payloads, allowing for external logging and alerting on the relayer's health and actions.
*   **`TransactionRelayer`**: This class encapsulates the logic for creating, signing, and broadcasting a transaction on the destination chain. It manages the relayer's nonce, calculates gas, and uses the private key to sign the transaction that will unlock/mint tokens for the user.
*   **`BridgeEventListener`**: The core orchestrator class. It initializes all other components, sets up an event filter on the source bridge contract, and runs an infinite loop to poll for new events. When an event is detected, it validates it, handles confirmation delays (to protect against block reorgs), and invokes the `TransactionRelayer` to perform the cross-chain action.

## How It Works

1.  **Initialization**: The script starts by loading and validating configuration from the `.env` file.
2.  **Connection**: It establishes connections to both the source and destination chain RPC nodes using the `BlockchainConnector`.
3.  **Contract Instantiation**: It creates `web3.py` contract objects for the source and destination bridge contracts using their addresses and ABIs.
4.  **Event Filtering**: An event filter is created for the `TokensLocked` event on the source bridge contract. The filter is set to start from the `latest` block to only catch new events.
5.  **Polling Loop**: The script enters a continuous loop where it periodically (`time.sleep(15)`) queries the event filter for new entries.
6.  **Event Detection & Validation**:
    *   When a new event is found, its transaction hash is logged.
    *   A check is performed to see if the event has already been processed (using an in-memory set).
    *   **Reorg Protection**: The script checks if enough blocks have been mined since the event's block (`BLOCK_CONFIRMATIONS`). If the event is too recent, it's skipped in the current cycle and will be re-evaluated later.
    *   The event data is parsed and sent as a notification to the monitoring API via `StatusNotifier`.
7.  **Transaction Relaying**:
    *   The parsed event data is passed to the `TransactionRelayer`.
    *   The relayer builds the `unlockTokens` function call for the destination contract.
    *   It fetches the current nonce for the relayer's address, constructs the full transaction payload, and signs it with the provided private key.
    *   **NOTE**: In this simulation, the final step of broadcasting the transaction (`send_raw_transaction`) is commented out to allow the script to run without a funded wallet. Instead, it logs the would-be transaction hash.
8.  **State Update**: If the relay transaction is successfully prepared (and, in a real scenario, broadcast), the source event's transaction hash is added to the `processed_txs` set to prevent replay attacks or duplicate processing.

## Usage

### Prerequisites

*   Python 3.8+
*   Access to RPC endpoints for two EVM-compatible blockchains (e.g., from Infura, Alchemy, or a local node).

### Installation

Clone the repository and install the required dependencies:

```bash
git clone https://github.com/your-username/nexus-utils.git
cd nexus-utils
pip install -r requirements.txt
```

### Configuration

Create a `.env` file in the project's root directory to store your sensitive configuration. You can copy the example file to get started:

```bash
cp .env.example .env
```

Then, populate `.env` with the following variables, replacing the placeholder values:

```ini
# --- Source Chain (e.g., Ethereum Goerli) ---
SOURCE_CHAIN_RPC_URL="https://goerli.infura.io/v3/YOUR_INFURA_PROJECT_ID"
# Address of the bridge contract that locks tokens
SOURCE_BRIDGE_ADDRESS="0x..."

# --- Destination Chain (e.g., Polygon Mumbai) ---
DEST_CHAIN_RPC_URL="https://polygon-mumbai.g.alchemy.com/v2/YOUR_ALCHEMY_API_KEY"
# Address of the bridge contract that unlocks/mints tokens
DEST_BRIDGE_ADDRESS="0x..."

# --- Relayer Wallet Configuration ---
# The private key of the account that will pay gas on the destination chain
# IMPORTANT: Do NOT use a key with real funds for this simulation. Use a fresh testnet account.
RELAYER_PRIVATE_KEY="0x..."
# The public address corresponding to the private key above
RELAYER_ADDRESS="0x..."

# --- Optional Settings ---
# The API endpoint for sending status notifications
MONITORING_API_ENDPOINT="https://httpbin.org/post"
# Number of blocks to wait before processing an event to avoid reorgs
BLOCK_CONFIRMATIONS=7
```

**Note:** You will need to replace the placeholder addresses (`0x...`) with the actual contract addresses for the bridge you are interacting with.

### Running the Script

Once the `.env` file is configured, execute the script from your terminal:

```bash
python bridge_event_listener.py
```

The script will start, validate the configuration, connect to the blockchains, and begin listening for events. The console will display log messages indicating its status and any events it detects and processes.

**Expected Output:**

```
2023-10-27 14:30:00 - root - INFO - Configuration validated successfully.
2023-10-27 14:30:01 - root - INFO - Successfully connected to https://goerli.infura.io/v3/.... Chain ID: 5
2023-10-27 14:30:02 - root - INFO - Successfully connected to https://polygon-mumbai.g.alchemy.com/v2/.... Chain ID: 80001
2023-10-27 14:30:02 - root - INFO - Starting Cross-Chain Bridge Event Listener...
...
2023-10-27 14:31:15 - root - INFO - Detected new 'TokensLocked' event in tx: 0x123abc...
2023-10-27 14:31:15 - root - INFO - Successfully sent notification to https://httpbin.org/post: EVENT_DETECTED
2023-10-27 14:31:16 - root - INFO - Preparing to relay unlock for 100000000 tokens to 0xRecipient... on destination chain.
2023-10-27 14:31:17 - root - WARNING - SIMULATION MODE: Transaction not broadcast. Would-be TxHash: 0x456def...
2023-10-27 14:31:17 - root - INFO - Successfully relayed transaction. TxHash: 0x456def...
2023-10-27 14:31:18 - root - INFO - Successfully sent notification to https://httpbin.org/post: RELAY_SUCCESS
```