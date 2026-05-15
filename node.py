import asyncio
import hashlib
import json
import sqlite3
import time
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from pydantic import BaseModel
import httpx

# Native cryptographic primitives for Ed25519 asymmetric signatures
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# --- Core Logic Framework Objects ---
class UTXO:
    def __init__(self, tx_id: str, output_index: int, recipient: str, amount: float):
        self.tx_id = tx_id
        self.output_index = output_index
        self.recipient = recipient
        self.amount = amount

    def to_dict(self):
        return {"tx_id": self.tx_id, "index": self.output_index, "recipient": self.recipient, "amount": self.amount}

class Transaction:
    def __init__(self, inputs: list, outputs: list, sender_pub_key: str = None, signature: str = None, fee: float = 0.0):
        self.inputs = inputs
        self.outputs = outputs
        self.sender_pub_key = sender_pub_key
        self.signature = signature
        self.fee = fee
        self.tx_id = self.compute_tx_id()

    def compute_tx_id(self) -> str:
        tx_data = {
            "inputs": self.inputs, 
            "outputs": [out.to_dict() for out in self.outputs], 
            "sender": self.sender_pub_key,
            "fee": self.fee
        }
        return hashlib.sha256(json.dumps(tx_data, sort_keys=True).encode()).hexdigest()

class Block:
    def __init__(self, index: int, transactions: list, previous_hash: str, nonce: int = 0):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.merkle_root = self.compute_merkle_root()
        self.hash = self.compute_hash()

    def compute_merkle_root(self) -> str:
        tx_hashes = [tx.tx_id for tx in self.transactions]
        if not tx_hashes:
            return hashlib.sha256(b"empty").hexdigest()
        return tx_hashes if len(tx_hashes) == 1 else hashlib.sha256("".join(tx_hashes).encode()).hexdigest()

    def compute_hash(self) -> str:
        block_header = {"index": self.index, "timestamp": self.timestamp, "merkle_root": self.merkle_root, "previous_hash": self.previous_hash, "nonce": self.nonce}
        return hashlib.sha256(json.dumps(block_header, sort_keys=True).encode()).hexdigest()

# --- Database Persistence Layer ---
class BlockchainDB:
    def __init__(self, db_path: str = "kiwi_ledger.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocks (
                    id_index INTEGER PRIMARY KEY,
                    timestamp REAL,
                    merkle_root TEXT,
                    previous_hash TEXT,
                    nonce INTEGER,
                    hash TEXT UNIQUE
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS utxo_pool (
                    utxo_key TEXT PRIMARY KEY,
                    tx_id TEXT,
                    output_index INTEGER,
                    recipient TEXT,
                    amount REAL
                )
            """)
            conn.commit()

    def load_chain_state(self) -> tuple:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id_index, timestamp, merkle_root, previous_hash, nonce, hash FROM blocks ORDER BY id_index ASC")
            db_blocks = cursor.fetchall()
            chain = []
            for row in db_blocks:
                block = Block(index=row[0], transactions=[], previous_hash=row[3], nonce=row[4])
                block.timestamp = row[1]
                block.merkle_root = row[2]
                block.hash = row[5]
                chain.append(block)

            cursor.execute("SELECT utxo_key, tx_id, output_index, recipient, amount FROM utxo_pool")
            db_utxos = cursor.fetchall()
            utxo_pool = {}
            for row in db_utxos:
                utxo_pool[row[0]] = UTXO(tx_id=row[1], output_index=row[2], recipient=row[3], amount=row[4])
            return chain, utxo_pool

# --- Core Cryptographic Helper Functions ---
def verify_ed25519_signature(public_key_hex: str, message: str, signature_hex: str) -> bool:
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        signature_bytes = bytes.fromhex(signature_hex)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, message.encode())
        return True
    except (ValueError, InvalidSignature, TypeError):
        return False

class KiwiBlockchain:
    def __init__(self, db_filename: str = "kiwi_ledger.db"):
        self.db = BlockchainDB(db_filename)
        self.chain = []
        self.utxo_pool = {}
        self.difficulty = 2
        self.db_filename = db_filename

        saved_chain, saved_utxo = self.db.load_chain_state()
        if saved_chain:
            self.chain = saved_chain
            self.utxo_pool = saved_utxo
            print("[+] System reboot successful. State recovered from SQLite DB.")
        else:
            print("[*] No existing ledger found. Initializing genesis architecture...")
            self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, [], "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)
        with sqlite3.connect(self.db_filename) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM utxo_pool")
            cursor.execute("DELETE FROM blocks")
            cursor.execute("""
                INSERT OR REPLACE INTO blocks (id_index, timestamp, merkle_root, previous_hash, nonce, hash)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (genesis_block.index, genesis_block.timestamp, "empty", genesis_block.previous_hash, genesis_block.nonce, genesis_block.hash))
            conn.commit()

    def add_block_to_chain(self, block: Block) -> bool:
        if block.previous_hash != self.chain[-1].hash:
            return False
        backup_utxo_pool = self.utxo_pool.copy()
        
        for tx in block.transactions:
            for tx_in in tx.inputs:
                utxo_key = f"{tx_in['tx_id']}:{tx_in['index']}"
                self.utxo_pool.pop(utxo_key, None)
            for out in tx.outputs:
                self.utxo_pool[f"{tx.tx_id}:{out.output_index}"] = out
        self.chain.append(block)

        try:
            with sqlite3.connect(self.db_filename) as conn:
                cursor = conn.cursor()
                root_str = json.dumps(block.merkle_root) if isinstance(block.merkle_root, list) else block.merkle_root
                cursor.execute("""
                    INSERT OR REPLACE INTO blocks (id_index, timestamp, merkle_root, previous_hash, nonce, hash)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (block.index, block.timestamp, root_str, block.previous_hash, block.nonce, block.hash))
                
                cursor.execute("DELETE FROM utxo_pool")
                for key, utxo in self.utxo_pool.items():
                    cursor.execute("""
                        INSERT INTO utxo_pool (utxo_key, tx_id, output_index, recipient, amount)
                        VALUES (?, ?, ?, ?, ?)
                    """, (key, utxo.tx_id, utxo.output_index, utxo.recipient, utxo.amount))
                conn.commit()
        except sqlite3.Error as e:
            print(f"[-] SQLite Insertion Error: {e}")
            self.utxo_pool = backup_utxo_pool
            self.chain.pop()
            return False
        return True

# Global Application States
blockchain_instance = None
mempool = []
in_flight_locks = set()  # Memory map to eliminate frontrunning/double-spending inside mempool

@asynccontextmanager
async def lifespan(app: FastAPI):
    global blockchain_instance
    port = 5000
    for i, arg in enumerate(sys.argv):
        if arg == "--port" and i + 1 < len(sys.argv):
            port = int(sys.argv[i+1])
    blockchain_instance = KiwiBlockchain(f"kiwi_live_node_{port}.db")
    yield

# --- API Specification Layer ---
app = FastAPI(title="Kiwi Blockchain Node Engine", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class TransactionPayload(BaseModel):
    sender: str
    recipient: str
    amount: float
    signature: str

class WalletSignPayload(BaseModel):
    private_key: str
    message: str

@app.get("/")
def read_root():
    return {
        "network": "Kiwi Blockchain Network Layer",
        "status": "Operational",
        "version": "1.0.0-Live",
        "active_mempool_transactions": len(mempool)
    }

@app.get("/chain")
def get_chain():
    return {
        "length": len(blockchain_instance.chain),
        "chain": [
            {
                "index": b.index,
                "timestamp": b.timestamp,
                "previous_hash": b.previous_hash,
                "nonce": b.nonce,
                "hash": b.hash
            } for b in blockchain_instance.chain
        ]
    }

@app.get("/balances/{address}")
def get_balance(address: str):
    # Filter active outputs owned by target address keys
    user_utxos = [u.to_dict() for u in blockchain_instance.utxo_pool.values() if u.recipient == address]
    total_bal = sum(u["amount"] for u in user_utxos)
    return {"address": address, "balance": total_bal, "utxos": user_utxos}

@app.get("/mempool")
def get_mempool():
    return {"mempool_size": len(mempool), "transactions": mempool}

@app.post("/wallet/create")
def create_wallet_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return {
        "private_key": private_key.private_bytes_raw().hex(),
        "public_key": public_key.public_bytes_raw().hex()
    }

@app.post("/wallet/sign")
def sign_transaction_data(payload: WalletSignPayload):
    try:
        private_bytes = bytes.fromhex(payload.private_key)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
        signature = private_key.sign(payload.message.encode())
        return {"message_string": payload.message, "signature": signature.hex()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Signing error: {str(e)}")

# --- PATH B: ADVANCED MULTI-INPUT UTXO SWEEPING & MATRIX FEE IMPLEMENTATION ---
@app.post("/transactions/new")
def add_transaction(payload: TransactionPayload):
    global in_flight_locks
    
    # 1. Automated Genesis Faucet fallback trigger logic
    if not blockchain_instance.utxo_pool and payload.sender == "9b355dbacdd8605235d51180424c123c2a0d581b2f598f319269479490fe4d5c":
        initial_coin = UTXO(tx_id="genesis_mint", output_index=0, recipient=payload.sender, amount=1000.0)
        blockchain_instance.utxo_pool["genesis_mint:0"] = initial_coin

    # 2. Extract network structural Fee Configuration Matrix calculation profile parameters
    # Compiles transaction weight constraints fee pricing linearly against asset transfer volume
    computed_min_fee = max(0.1, round(payload.amount * 0.01, 2))

    # 3. Deterministic serialization re-compilation matching frontend sign mapping rules
    msg_to_verify = f"{payload.sender}->{payload.recipient}:{payload.amount:.1f}:fee={computed_min_fee:.2f}"
    if not verify_ed25519_signature(payload.sender, msg_to_verify, payload.signature):
        raise HTTPException(status_code=401, detail="Cryptographic signature verification failed! Data mismatch.")

    # 4. Deep-sweep UTXO Pool memory fields to accumulate individual fragmented assets balances
    available_inputs = []
    accumulated_funds = 0.0
    
    for key, utxo in blockchain_instance.utxo_pool.items():
        if utxo.recipient == payload.sender:
            # Double-Spend Safeguard: Block selection criteria verification check logic
            if key in in_flight_locks:
                continue # Skip coins currently tied up in pending transactions
            available_inputs.append({"tx_id": utxo.tx_id, "index": utxo.output_index})
            accumulated_funds += utxo.amount
            if accumulated_funds >= (payload.amount + computed_min_fee):
                break

    # 5. Check if the consolidated wallet inputs are sufficient
    required_total = payload.amount + computed_min_fee
    if accumulated_funds < required_total:
        raise HTTPException(status_code=400, detail=f"Insufficient user balance. Required inputs: {required_total:.2f} KWT (includes fee matrix constraint).")

    # Lock inputs into the double-spend prevention map
    for input_utxo in available_inputs:
        in_flight_locks.add(f"{input_utxo['tx_id']}:{input_utxo['index']}")

    # Queue transaction parameters directly into memory pool data lists
    mempool_entry = {
        "sender": payload.sender,
        "recipient": payload.recipient,
        "amount": payload.amount,
        "fee": computed_min_fee,
        "inputs": available_inputs,
        "accumulated_funds": accumulated_funds,
        "signature": payload.signature
    }
    mempool.append(mempool_entry)
    
    return {
        "message": "Asymmetric signature verified and multi-input UTXO swept successfully!",
        "pending_transactions_count": len(mempool),
        "computed_transaction_fee": computed_min_fee
    }

@app.post("/mine")
def mine_block_from_mempool():
    global mempool, in_flight_locks
    if not mempool:
        raise HTTPException(status_code=400, detail="Mempool queue is dry.")

    block_transactions = []
    block_tx_id = f"tx_{int(time.time())}"

    for index, tx_data in enumerate(mempool):
        # Unpack inputs allocated by selection loops step
        tx_inputs = tx_data["inputs"]
        
        # Calculate remainder change balances
        change_amount = tx_data["accumulated_funds"] - tx_data["amount"] - tx_data["fee"]
        
        tx_outputs = []
        # Main transfer destination allocation output
        tx_outputs.append(UTXO(tx_id=block_tx_id, output_index=0, recipient=tx_data["recipient"], amount=tx_data["amount"]))
        
        # If change remainder exists, route it back to the sender
        if change_amount > 0:
            tx_outputs.append(UTXO(tx_id=block_tx_id, output_index=1, recipient=tx_data["sender"], amount=round(change_amount, 2)))

        secure_tx = Transaction(
            inputs=tx_inputs, 
            outputs=tx_outputs, 
            sender_pub_key=tx_data["sender"], 
            signature=tx_data["signature"],
            fee=tx_data["fee"]
        )
        block_transactions.append(secure_tx)

    # Compile into structural proof-of-work block frame container
    new_block = Block(index=len(blockchain_instance.chain), transactions=block_transactions, previous_hash=blockchain_instance.chain[-1].hash)
    while not new_block.hash.startswith('0' * blockchain_instance.difficulty):
        new_block.nonce += 1
        new_block.hash = new_block.compute_hash()

    if not blockchain_instance.add_block_to_chain(new_block):
        raise HTTPException(status_code=500, detail="Database persistence commitment failure.")

    # Clear memory pool tracking states and locks upon mining confirmation
    mempool = []
    in_flight_locks.clear()
    
    return {"message": "Block mined successfully! UTXO consolidation cleared.", "block_index": new_block.index, "block_hash": new_block.hash}

if __name__ == "__main__":
    target_port = 5000
    for i, arg in enumerate(sys.argv):
        if arg == "--port" and i + 1 < len(sys.argv):
            target_port = int(sys.argv[i+1])
    uvicorn.run(app, host="0.0.0.0", port=target_port)
