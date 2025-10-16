import os
import time
import logging
from typing import Dict, Any, Optional, Set

import requests
from dotenv import load_dotenv
from web3 import Web3
from web3.contract import Contract
from web3.middleware import geth_poa_middleware
from hexbytes import HexBytes

# --- Configuration & Constants ---

# Load environment variables from a .env file for security and flexibility.
load_dotenv()

# Configure logging to provide detailed insight into the listener's operations.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# --- Simulated Contract ABIs and Addresses ---
# In a real-world application, these would be loaded from JSON files.

# A simplified ABI for the source chain bridge contract.
# It must contain the event we are listening for ('TokensLocked').
SOURCE_BRIDGE_ABI = '''
[
    {
        "anonymous": false,
        "inputs": [
            {
                "indexed": true,
                "internalType": "address",
                "name": "sender",
                "type": "address"
            },
            {
                "indexed": true,
                "internalType": "address",
                "name": "recipient",
                "type": "address"
            },
            {
                "indexed": false,
                "internalType": "uint256",
                "name": "amount",
                "type": "uint256"
            },
            {
                "indexed": false,
                "internalType": "uint256",
                "name": "destinationChainId",
                "type": "uint256"
            },
            {
                "indexed": false,
                "internalType": "bytes32",
                "name": "sourceTxHash",
                "type": "bytes32"
            }
        ],
        "name": "TokensLocked",
        "type": "event"
    }
]
'''

# A simplified ABI for the destination chain bridge contract.
# It must contain the function to be called ('unlockTokens').
DESTINATION_BRIDGE_ABI = '''
[
    {
        "inputs": [
            {
                "internalType": "address",
                "name": "recipient",
                "type": "address"
            },
            {
                "internalType": "uint256",
                "name": "amount",
                "type": "uint256"
            },
            {
                "internalType": "bytes32",
                "name": "sourceTxHash",
                "type": "bytes32"
            }
        ],
        "name": "unlockTokens",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]
'''

class Config: 
    """Manages the configuration for the bridge listener from environment variables."""
    SOURCE_CHAIN_RPC: str = os.getenv("SOURCE_CHAIN_RPC_URL", "")
    DEST_CHAIN_RPC: str = os.getenv("DEST_CHAIN_RPC_URL", "")
    SOURCE_BRIDGE_ADDRESS: str = os.getenv("SOURCE_BRIDGE_ADDRESS", "")
    DEST_BRIDGE_ADDRESS: str = os.getenv("DEST_BRIDGE_ADDRESS", "")
    RELAYER_PRIVATE_KEY: str = os.getenv("RELAYER_PRIVATE_KEY", "")
    RELAYER_ADDRESS: str = os.getenv("RELAYER_ADDRESS", "")
    MONITORING_API_ENDPOINT: str = os.getenv("MONITORING_API_ENDPOINT", "https://httpbin.org/post")
    
    # Number of blocks to wait for confirmation to handle potential reorgs.
    BLOCK_CONFIRMATIONS: int = int(os.getenv("BLOCK_CONFIRMATIONS", "5"))
    
    @staticmethod
    def validate() -> None:
        """Validates that all necessary environment variables are set."""
        required_vars = [
            'SOURCE_CHAIN_RPC_URL', 'DEST_CHAIN_RPC_URL',
            'SOURCE_BRIDGE_ADDRESS', 'DEST_BRIDGE_ADDRESS',
            'RELAYER_PRIVATE_KEY', 'RELAYER_ADDRESS'
        ]
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
        logging.info("Configuration validated successfully.")

class BlockchainConnector:
    """Handles connectivity to the source and destination blockchain nodes."""

    def __init__(self, rpc_url: str):
        """
        Initializes a connection to a blockchain node.
        
        Args:
            rpc_url (str): The HTTP/WSS RPC endpoint of the blockchain node.
        """
        self.rpc_url = rpc_url
        self.web3: Optional[Web3] = None
        self.connect()

    def connect(self) -> None:
        """Establishes a connection to the RPC endpoint and handles middleware for PoA chains."""
        try:
            self.web3 = Web3(Web3.HTTPProvider(self.rpc_url))
            # Inject middleware for PoA consensus algorithms (like Polygon, Goerli).
            self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)
            if not self.web3.is_connected():
                raise ConnectionError(f"Failed to connect to RPC: {self.rpc_url}")
            logging.info(f"Successfully connected to {self.rpc_url}. Chain ID: {self.web3.eth.chain_id}")
        except Exception as e:
            logging.error(f"Error connecting to {self.rpc_url}: {e}")
            self.web3 = None

    def get_contract(self, address: str, abi: str) -> Optional[Contract]:
        """Returns a Web3 contract instance."""
        if not self.web3 or not self.web3.is_connected():
            logging.warning("Attempted to get contract without a valid connection. Reconnecting...")
            self.connect()
            if not self.web3:
                return None
        
        try:
            checksum_address = self.web3.to_checksum_address(address)
            return self.web3.eth.contract(address=checksum_address, abi=abi)
        except Exception as e:
            logging.error(f"Failed to instantiate contract at {address}: {e}")
            return None

class StatusNotifier:
    """Communicates the status of operations to an external monitoring service."""
    
    def __init__(self, api_endpoint: str):
        self.api_endpoint = api_endpoint

    def send_notification(self, status: str, details: Dict[str, Any]) -> None:
        """
        Sends a POST request with status information to the monitoring endpoint.

        Args:
            status (str): A summary of the status (e.g., 'EVENT_DETECTED', 'RELAY_SUCCESS').
            details (Dict[str, Any]): A dictionary containing detailed information.
        """
        payload = {
            'status': status,
            'timestamp': time.time(),
            'details': details
        }
        try:
            response = requests.post(self.api_endpoint, json=payload, timeout=10)
            response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
            logging.info(f"Successfully sent notification to {self.api_endpoint}: {status}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to send notification to {self.api_endpoint}: {e}")

class TransactionRelayer:
    """
    Constructs, signs, and broadcasts transactions on the destination chain.
    """

    def __init__(self, connector: BlockchainConnector, private_key: str, relayer_address: str, notifier: StatusNotifier):
        self.connector = connector
        self.private_key = private_key
        self.relayer_address = relayer_address
        self.notifier = notifier
        if not self.connector.web3:
            raise ValueError("BlockchainConnector must be initialized and connected.")
        self.web3 = self.connector.web3

    def relay_unlock_transaction(self, dest_contract: Contract, event_data: Dict[str, Any]) -> bool:
        """
        Prepares and sends the 'unlockTokens' transaction to the destination chain.
        
        Args:
            dest_contract (Contract): The destination bridge contract instance.
            event_data (Dict[str, Any]): The parsed data from the source chain event.
        
        Returns:
            bool: True if the transaction was successfully broadcast, False otherwise.
        """
        try:
            recipient = event_data['recipient']
            amount = event_data['amount']
            source_tx_hash = event_data['sourceTxHash']

            logging.info(f"Preparing to relay unlock for {amount} tokens to {recipient} on destination chain.")

            # 1. Build the transaction
            nonce = self.web3.eth.get_transaction_count(self.relayer_address)
            tx_params = {
                'from': self.relayer_address,
                'nonce': nonce,
                'gasPrice': self.web3.eth.gas_price, 
            }
            
            unlock_tx = dest_contract.functions.unlockTokens(
                recipient,
                amount,
                source_tx_hash
            ).build_transaction(tx_params)

            # In a production system, you'd add more sophisticated gas estimation.
            # unlock_tx['gas'] = self.web3.eth.estimate_gas(unlock_tx)

            # 2. Sign the transaction
            signed_tx = self.web3.eth.account.sign_transaction(unlock_tx, self.private_key)

            # 3. Send the transaction
            # --- SIMULATION NOTE: The following line is commented out to prevent execution
            # --- without a funded account. In a real scenario, you would uncomment this.
            # tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            # For this simulation, we'll just log the signed transaction details.
            tx_hash = HexBytes(os.urandom(32)) # Generate a fake tx hash
            logging.warning(f"SIMULATION MODE: Transaction not broadcast. Would-be TxHash: {tx_hash.hex()}")

            # 4. Wait for receipt (in a real scenario)
            # receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            # if receipt.status == 0:
            #     raise Exception(f"Transaction {tx_hash.hex()} failed on-chain (reverted).")
            
            logging.info(f"Successfully relayed transaction. TxHash: {tx_hash.hex()}")
            self.notifier.send_notification('RELAY_SUCCESS', {
                'destinationTxHash': tx_hash.hex(),
                'sourceTxHash': source_tx_hash.hex(),
                'recipient': recipient,
                'amount': amount
            })
            return True

        except Exception as e:
            logging.error(f"Failed to relay transaction: {e}")
            self.notifier.send_notification('RELAY_FAILURE', {'error': str(e), 'eventData': event_data})
            return False

class BridgeEventListener:
    """
    The core component that listens for events on the source chain and orchestrates the relaying process.
    """
    def __init__(self, config: Config):
        self.config = config
        self.source_connector = BlockchainConnector(config.SOURCE_CHAIN_RPC)
        self.dest_connector = BlockchainConnector(config.DEST_CHAIN_RPC)
        self.notifier = StatusNotifier(config.MONITORING_API_ENDPOINT)
        self.relayer = TransactionRelayer(
            self.dest_connector, 
            config.RELAYER_PRIVATE_KEY, 
            config.RELAYER_ADDRESS, 
            self.notifier
        )
        self.processed_txs: Set[HexBytes] = set() # In-memory cache to prevent duplicate processing

    def run(self) -> None:
        """
        Starts the main event listening loop.
        """
        logging.info("Starting Cross-Chain Bridge Event Listener...")
        if not self.source_connector.web3 or not self.dest_connector.web3:
            logging.critical("Failed to establish initial blockchain connections. Exiting.")
            return
        
        source_bridge = self.source_connector.get_contract(self.config.SOURCE_BRIDGE_ADDRESS, SOURCE_BRIDGE_ABI)
        dest_bridge = self.dest_connector.get_contract(self.config.DEST_BRIDGE_ADDRESS, DESTINATION_BRIDGE_ABI)

        if not source_bridge or not dest_bridge:
            logging.critical("Failed to initialize bridge contracts. Exiting.")
            return
        
        event_filter = source_bridge.events.TokensLocked.create_filter(fromBlock='latest')

        while True:
            try:
                self.process_events(event_filter, dest_bridge)
                time.sleep(15) # Poll for new events every 15 seconds
            except Exception as e:
                logging.error(f"An error occurred in the main loop: {e}. Restarting loop...")
                # Simple backoff to prevent spamming on persistent errors
                time.sleep(30)

    def process_events(self, event_filter: Any, dest_bridge: Contract) -> None:
        """
        Fetches and processes new 'TokensLocked' events.
        """
        latest_block = self.source_connector.web3.eth.block_number
        
        for event in event_filter.get_new_entries():
            tx_hash = event['transactionHash']
            if tx_hash in self.processed_txs:
                logging.warning(f"Skipping already processed event from tx: {tx_hash.hex()}")
                continue

            # --- Reorg Protection ---
            # Wait for a few blocks to be mined on top of the event's block.
            event_block = event['blockNumber']
            if (latest_block - event_block) < self.config.BLOCK_CONFIRMATIONS:
                logging.info(f"Event from tx {tx_hash.hex()} is too recent. Waiting for confirmations...")
                continue

            logging.info(f"Detected new 'TokensLocked' event in tx: {tx_hash.hex()}")
            self.notifier.send_notification('EVENT_DETECTED', {'sourceTxHash': tx_hash.hex(), 'details': dict(event['args'])})
            
            # Parse event data for relaying.
            parsed_event = {
                'sender': event['args']['sender'],
                'recipient': event['args']['recipient'],
                'amount': event['args']['amount'],
                'destinationChainId': event['args']['destinationChainId'],
                'sourceTxHash': event['args']['sourceTxHash']
            }

            # Basic validation: check if the event's sourceTxHash matches its own transaction hash
            if tx_hash != parsed_event['sourceTxHash']:
                logging.error(f"Mismatch between event sourceTxHash and actual tx hash! Event: {parsed_event['sourceTxHash'].hex()}, Actual: {tx_hash.hex()}. Skipping.")
                continue

            # Attempt to relay the transaction to the destination chain.
            if self.relayer.relay_unlock_transaction(dest_bridge, parsed_event):
                # Mark as processed only on successful relay broadcast.
                self.processed_txs.add(tx_hash)
            else:
                logging.error(f"Failed to process event from tx {tx_hash.hex()}. Will retry on next cycle.")

if __name__ == '__main__':
    try:
        Config.validate()
        listener = BridgeEventListener(Config())
        listener.run()
    except ValueError as e:
        logging.critical(f"Configuration error: {e}")
    except KeyboardInterrupt:
        logging.info("Shutting down listener...")

# @-internal-utility-start
def format_timestamp_5576(ts: float):
    """Formats a unix timestamp into ISO format. Updated on 2025-10-16 18:24:59"""
    import datetime
    dt_object = datetime.datetime.fromtimestamp(ts)
    return dt_object.isoformat()
# @-internal-utility-end


# @-internal-utility-start
CACHE = {}
def get_from_cache_4878(key: str):
    """Retrieves an item from cache. Implemented on 2025-10-16 18:25:45"""
    return CACHE.get(key, None)
# @-internal-utility-end

