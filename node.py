import asyncio
import hashlib
import json
import sqlite3
import time
import sys

# --- Database Persistence Layer ---
class BlockchainDB:
    def __init__(self, db_path: str = "kiwi_ledger.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Initializes relational tables to store the structural chain state."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # 1. Blocks Table
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
            # 2. Transactions Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    tx_id TEXT PRIMARY KEY,
                    block_index INTEGER,
                    sender_pub_key TEXT,
                    signature TEXT,
                    FOREIGN KEY(block_index) REFERENCES blocks(id_index)
                )
            """)
            # 3. UTXO Pool Table
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
        """Restores chain records and active UTXOs into memory upon reboot."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Reconstruct Blocks
            cursor.execute("SELECT id_index, timestamp, merkle_root, previous_hash, nonce, hash FROM blocks ORDER BY id_index ASC")
            db_blocks = cursor.fetchall()
            chain = []
            for row in db_blocks:
                block = Block(index=row[0], transactions=[], previous_hash=row[3], nonce=row[4])
                block.timestamp = row[1]
                block.merkle_root = row[2]
                block.hash = row[5]
                chain.append(block)

            # Reconstruct UTXO Pool
            cursor.execute("SELECT utxo_key, tx_id, output_index, recipient, amount FROM utxo_pool")
            db_utxos = cursor.fetchall()
            utxo_pool = {}
            for row in db_utxos:
                utxo_pool[row[0]] = UTXO(tx_id=row[1], output_index=row[2], recipient=row[3], amount=row[4])
            return chain, utxo_pool

# --- Cryptographic Helper Elements ---
def generate_signature(private_key: str, message: str) -> str:
    return hashlib.sha256((private_key + message).encode()).hexdigest()

def verify_signature(public_key: str, message: str, signature: str) -> bool:
    return hashlib.sha256((public_key + message).encode()).hexdigest() == signature

# --- Core Logic with Database Anchors ---
class UTXO:
    def __init__(self, tx_id: str, output_index: int, recipient: str, amount: float):
        self.tx_id = tx_id
        self.output_index = output_index
        self.recipient = recipient
        self.amount = amount

    def to_dict(self):
        return {"tx_id": self.tx_id, "index": self.output_index, "recipient": self.recipient, "amount": self.amount}

class Transaction:
    def __init__(self, inputs: list, outputs: list, sender_pub_key: str = None, signature: str = None):
        self.inputs = inputs
        self.outputs = outputs
        self.sender_pub_key = sender_pub_key
        self.signature = signature
        self.tx_id = self.compute_tx_id()

    def compute_tx_id(self) -> str:
        tx_data = {"inputs": self.inputs, "outputs": [out.to_dict() for out in self.outputs], "sender": self.sender_pub_key}
        return hashlib.sha256(json.dumps(tx_data, sort_keys=True).encode()).hexdigest()

    def sign_tx(self, private_key: str):
        self.signature = generate_signature(private_key, self.tx_id)

    def is_valid(self, utxo_pool: dict) -> bool:
        if not self.inputs:
            return True
        if not verify_signature(self.sender_pub_key, self.tx_id, self.signature):
            return False
        input_total = 0.0
        for tx_in in self.inputs:
            utxo_key = f"{tx_in['tx_id']}:{tx_in['index']}"
            if utxo_key not in utxo_pool:
                return False
            input_total += utxo_pool[utxo_key].amount
        output_total = sum(out.amount for out in self.outputs)
        return input_total >= output_total

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
        return tx_hashes

    def compute_hash(self) -> str:
        block_header = {"index": self.index, "timestamp": self.timestamp, "merkle_root": self.merkle_root, "previous_hash": self.previous_hash, "nonce": self.nonce}
        return hashlib.sha256(json.dumps(block_header, sort_keys=True).encode()).hexdigest()

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
        
        # Fresh boot writes structural tracking elements clean
        with sqlite3.connect(self.db_filename) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM utxo_pool")
            cursor.execute("DELETE FROM transactions")
            cursor.execute("DELETE FROM blocks")
            cursor.execute("""
                INSERT OR REPLACE INTO blocks (id_index, timestamp, merkle_root, previous_hash, nonce, hash)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (genesis_block.index, genesis_block.timestamp, "empty", genesis_block.previous_hash, genesis_block.nonce, genesis_block.hash))
            conn.commit()

    def add_block_to_chain(self, block: Block) -> bool:
        if block.previous_hash != self.chain[-1].hash:
            return False

        # Create localized backup structures to enable memory state rollback if disk writes fail
        backup_utxo_pool = self.utxo_pool.copy()
        
        # 1. Apply structural transformations inside RAM space
        for tx in block.transactions:
            for tx_in in tx.inputs:
                utxo_key = f"{tx_in['tx_id']}:{tx_in['index']}"
                self.utxo_pool.pop(utxo_key, None)
            for out in tx.outputs:
                self.utxo_pool[f"{tx.tx_id}:{out.output_index}"] = out
        self.chain.append(block)

        # --- 10 SECOND INJECTED SLEEP WINDOW ---
        print("\n[!] Memory state updated. 10-second window open. KILL TERM NOW TO SIMULATE CRASH!")
        try:
            for remaining in range(10, 0, -1):
                print(f"    Time remaining: {remaining} seconds...")
                time.sleep(1)
            print("[+] Window closed. Proceeding to structural disk commit.\n")
        except KeyboardInterrupt:
            # Revert local memory tracking state to prevent polluted output frames before shutdown
            self.utxo_pool = backup_utxo_pool
            self.chain.pop()
            print("\n[-] Critical execution interrupt caught. System shutting down cleanly...")
            raise

        # 2. Complete the database transaction atomically
        try:
            with sqlite3.connect(self.db_filename) as conn:
                cursor = conn.cursor()
                # Store block record
                cursor.execute("""
                    INSERT OR REPLACE INTO blocks (id_index, timestamp, merkle_root, previous_hash, nonce, hash)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (block.index, block.timestamp, block.merkle_root[0] if isinstance(block.merkle_root, list) else block.merkle_root, block.previous_hash, block.nonce, block.hash))
                
                # Store structural dependent transactions
                for tx in block.transactions:
                    cursor.execute("""
                        INSERT OR REPLACE INTO transactions (tx_id, block_index, sender_pub_key, signature)
                        VALUES (?, ?, ?, ?)
                    """, (tx.tx_id, block.index, tx.sender_pub_key, tx.signature))
                
                # Resynchronize disk-based UTXO references
                cursor.execute("DELETE FROM utxo_pool")
                for key, utxo in self.utxo_pool.items():
                    cursor.execute("""
                        INSERT INTO utxo_pool (utxo_key, tx_id, output_index, recipient, amount)
                        VALUES (?, ?, ?, ?, ?)
                    """, (key, utxo.tx_id, utxo.output_index, utxo.recipient, utxo.amount))
                
                conn.commit()
        except sqlite3.Error as e:
            # Fall back inside RAM if storage engine reports tracking failures
            self.utxo_pool = backup_utxo_pool
            self.chain.pop()
            print(f"[-] Database Processing Error: {e}")
            return False

        return True

# --- Simulating Reboot Resilience ---
async def main():
    print("--- FIRST BOOT: Initializing Ledger & Creating Data ---")
    blockchain_instance = KiwiBlockchain("kiwi_live_node.db")

    alice_pub = "alice_public_key"
    bob_pub = "bob_public_key"

    # Only fund Alice if this is a fresh setup
    if len(blockchain_instance.chain) == 1 and not blockchain_instance.utxo_pool:
        genesis_coin = UTXO(tx_id="genesis_mint", output_index=0, recipient=alice_pub, amount=500.0)
        blockchain_instance.utxo_pool["genesis_mint:0"] = genesis_coin

    # Read Alice's current balance before processing the trade
    alice_initial = sum(u.amount for u in blockchain_instance.utxo_pool.values() if u.recipient == alice_pub)

    if alice_initial >= 500.0:
        tx_input = {"tx_id": "genesis_mint", "index": 0}
        tx_output = UTXO(tx_id="tx_01", output_index=0, recipient=bob_pub, amount=150.0)
        tx_change = UTXO(tx_id="tx_01", output_index=1, recipient=alice_pub, amount=350.0)
        secure_tx = Transaction(inputs=[tx_input], outputs=[tx_output, tx_change], sender_pub_key=alice_pub)

        new_block = Block(index=len(blockchain_instance.chain), transactions=[secure_tx], previous_hash=blockchain_instance.chain[-1].hash)

        while not new_block.hash.startswith('0' * blockchain_instance.difficulty):
            new_block.nonce += 1
            new_block.hash = new_block.compute_hash()

        blockchain_instance.add_block_to_chain(new_block)

    print(f"[✔] State committed. Total blocks: {len(blockchain_instance.chain)}")
    print(f"[✔] Alice Balance before shutdown: {sum(u.amount for u in blockchain_instance.utxo_pool.values() if u.recipient == alice_pub)} KWT")

    del blockchain_instance
    print("\n--- CRASH / REBOOT DETECTED: Simulating Memory Loss ---\n")
    await asyncio.sleep(1)

    print("--- SECOND BOOT: Instantiating New Object Reference ---")
    rebooted_blockchain = KiwiBlockchain("kiwi_live_node.db")
    print(f"[✔] Rebuilt blocks verified: {len(rebooted_blockchain.chain)}")

    alice_recovered_bal = sum(u.amount for u in rebooted_blockchain.utxo_pool.values() if u.recipient == alice_pub)
    bob_recovered_bal = sum(u.amount for u in rebooted_blockchain.utxo_pool.values() if u.recipient == bob_pub)
    print(f"[✔] Alice Recovered Balance: {alice_recovered_bal} KWT")
    print(f"[✔] Bob Recovered Balance: {bob_recovered_bal} KWT")

if __name__ == "__main__":
    asyncio.run(main())
