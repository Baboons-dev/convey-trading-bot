import os
import asyncio
from typing import Dict, List, Optional
from telegram import Update
from solana.rpc.async_api import AsyncClient
from solders.pubkey import Pubkey
from solders.token.state import TokenAccount
from solana.rpc.types import TokenAccountOpts
from solders.keypair import Keypair
from solders.transaction import Transaction
from telegram.ext import Application, CommandHandler, ContextTypes
import requests
import base64
from dataclasses import dataclass
import aiohttp
from hpke import Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

KEY_OFFSET = 0
UPDATE_AUTH_OFFSET = KEY_OFFSET + 1
MINT_OFFSET = UPDATE_AUTH_OFFSET + 32
NAME_OFFSET = MINT_OFFSET + 32
NAME_LENGTH = 32  # Padded to 32 bytes
SYMBOL_OFFSET = NAME_OFFSET + NAME_LENGTH
SYMBOL_LENGTH = 10  # Padded to 10 bytes
CONFIG = {
    "telegram_token": os.getenv(
        "TELEGRAM_BOT_TOKEN", "7593365508:AAF8SNUQOAIxDsAl7xyMcgPJ4cO5eI-LCOU"
    ),
    "privy_app_id": os.getenv("PRIVY_APP_ID", "cmbj45mlb00yrl50mqrwx2u01"),
    "privy_api_key": os.getenv(
        "PRIVY_API_KEY",
        "gBsPBvDx5v8NytMnWRXRbHawv7gGxzoJ72Pa2FSbExK8vjCQ1XvtFkekrVtyaKS7ja8EgwFXgYEkZJMELKjXDFW",
    ),
    "privy_auth_private_key": os.getenv(
        "PRIVY_AUTH_PRIVATE_KEY",
        "wallet-auth:MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgoU+O3kDRW5jDoA7HK21pKOj/NyNWhVGfayFAGdo8pG6hRANCAATk5yOjaSTRnw6h9YSebtsVVOlqq9bdqy++hnjeSw5sG+wj+xCQ8S6ETJZ5Myt6IzhpJqJB++JwUyeV3+Ik4vZy",
    ),
    "privy_auth_public_key": os.getenv(
        "PRIVY_AUTH_PUBLIC_KEY",
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5Ocjo2kk0Z8OofWEnm7bFVTpaqvW3asvvoZ43ksObBvsI/sQkPEuhEyWeTMreiM4aSaiQfvicFMnld/iJOL2cg==",
    ),
    # Using Solana devnet for testing
    "rpc_url": os.getenv("RPC_URL", "https://api.mainnet-beta.solana.com"),
    # Example token mint address on devnet (replace with actual token you want to buy)
    "target_token_mint": os.getenv(
        "TARGET_TOKEN_MINT",
        "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R",  # Wrapped SOL for testing
    ),
    "admin_user_ids": [12345678],  # Add your Telegram user ID for admin access
    "slippage_bps": 500,  # 5% slippage
    "raydium_api_url": "https://api-v3.raydium.io/main",
}

auth_string = f"{CONFIG['privy_app_id']}:{CONFIG['privy_api_key']}"
encoded_auth = base64.b64encode(auth_string.encode()).decode()

# In-memory database (replace with real database in production)
USER_DB: Dict[int, Dict] = {}

# SOL mint address (native SOL)
SOL_MINT = "So11111111111111111111111111111111111111112"
WSOL_MINT = "So11111111111111111111111111111111111111112"
METADATA_PROGRAM_ID = Pubkey.from_string("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s")


class BlockchainUtils:
    def __init__(self):
        self.client = AsyncClient(CONFIG["rpc_url"])
        self.raydium = CONFIG["rpc_url"]
        self.user_wallets: Dict[int, List[str]] = {}

    async def get_sol_balance(self, wallet_address: str) -> float:
        """Get SOL balance for a wallet address in SOL (not lamports)"""
        try:
            pubkey = Pubkey.from_string(wallet_address)
            balance_response = await self.client.get_balance(pubkey)
            balance_lamports = balance_response.value
            return balance_lamports / 10**9
        except Exception as e:
            print(f"Error getting SOL balance: {e}")
            return 0.0

    async def get_token_metadata(self,wallet_address:str ,mint_address: str) -> Optional[Dict[str, str]]:
        try:
            mint_pubkey = Pubkey.from_string(mint_address)
            mint_account_info = await self.client.get_token_supply(mint_pubkey)
            decimals = int(mint_account_info.value.decimals)
            supply = (int(mint_account_info.value.amount))/ (10 ** decimals)
            balance = await self.get_token_balance(wallet_address,mint_address,decimals)
            metadata_seed = [
                b"metadata",
                bytes(METADATA_PROGRAM_ID),
                bytes(mint_pubkey),
            ]
            metadata_pda, _ = Pubkey.find_program_address(
                metadata_seed, METADATA_PROGRAM_ID
            )

            metadata_account = await self.client.get_account_info(metadata_pda)

            if not metadata_account.value:
                return {
                    "supply": supply,
                    "decimals": decimals,
                    "balance": balance,
                    "name": "unknown",
                    "symbol": "unknown",
                }

            data_base64 = metadata_account.value.data
            metadata_bytes = data_base64

            name = (
                metadata_bytes[NAME_OFFSET : NAME_OFFSET + NAME_LENGTH]
                .decode("utf-8")
                .replace("\x00", "")
                .strip()
            )
            symbol = (
                metadata_bytes[SYMBOL_OFFSET : SYMBOL_OFFSET + SYMBOL_LENGTH]
                .decode("utf-8")
                .replace("\x00", "")
                .strip()
            )

            return {
                "name": name,
                "symbol": symbol,
                "supply": str(supply),
                "balance": str(balance),
            }

        except Exception as e:
            print(f"Error getting token metadata: {e}")
            return None

    async def get_token_balance(self, wallet_address: str, mint_address: str,decimals:int) -> float:
        """Get token balance for a specific mint"""
        try:
            pubkey = Pubkey.from_string(wallet_address)
            mint_pubkey = Pubkey.from_string(mint_address)
            token_opts = TokenAccountOpts(
                mint=mint_pubkey,
                encoding="base64",
            )
            # Get token accounts
            response = await self.client.get_token_accounts_by_owner(
                pubkey, token_opts
            )
            raw_data = response.value[0].account.data if response.value else None
            data = TokenAccount.from_bytes(raw_data) if raw_data else None
            if data:
                amount = data.amount
                return amount / (10**decimals)
            return 0.0
        except Exception as e:
            print(f"Error getting token balance: {e}")
            return 0.0

    async def execute_swap(self, user_id: int, sol_amount: float) -> Optional[str]:
        """Execute token swap using Raydium/Jupiter"""
        try:
            if user_id not in USER_DB:
                raise Exception("User wallet not found")

            user_data = USER_DB[user_id]
            if "private_key" not in user_data:
                raise Exception("Private key not available for this wallet")

            # Convert SOL to lamports
            lamports = int(sol_amount * 10**9)

            # Get swap quote
            quote = await self.raydium.get_swap_quote(
                SOL_MINT, CONFIG["target_token_mint"], lamports, CONFIG["slippage_bps"]
            )

            if not quote:
                raise Exception("Could not get swap quote")

            print(
                f"Swap quote: {quote.input_amount} lamports SOL -> {quote.output_amount} tokens"
            )
            print(f"Price impact: {quote.price_impact_pct}%")

            # Create swap transaction
            wallet_pubkey = user_data["wallet_address"]
            swap_transaction_b64 = await self.raydium.create_swap_transaction(
                quote, wallet_pubkey
            )

            if not swap_transaction_b64:
                raise Exception("Could not create swap transaction")

            # Decode and sign the transaction
            transaction_bytes = base64.b64decode(swap_transaction_b64)
            transaction = Transaction.from_bytes(transaction_bytes)

            # Create keypair from private key
            private_key_bytes = base64.b64decode(user_data["private_key"])
            keypair = Keypair.from_bytes(private_key_bytes)

            # Sign transaction
            transaction.sign([keypair])

            # Send transaction
            result = await self.client.send_transaction(transaction)
            return str(result.value)

        except Exception as e:
            print(f"Error executing swap: {e}")
            raise e

    async def get_user_wallet_addresses(self, user_id: int) -> List[str]:
        return self.user_wallets.get(user_id, [])

    async def airdrop_sol(
        self, wallet_address: str, amount: float = 2.0
    ) -> Optional[str]:
        """Request SOL airdrop on devnet for testing"""
        try:
            pubkey = Pubkey.from_string(wallet_address)
            lamports = int(amount * 10**9)

            result = await self.client.request_airdrop(pubkey, lamports)
            return str(result.value)
        except Exception as e:
            print(f"Error requesting airdrop: {e}")
            return None


async def main():
    utils = BlockchainUtils()
    data = await utils.get_token_metadata("CcPJow48P7tHQjTjxr5GKmdqaRFDbVdd25tDzh9bdYjp",CONFIG["target_token_mint"])

    print("Token Metadata:")
    print(data)
    if data:
        print(f"Name: {data['name']}")
        print(f"Symbol: {data['symbol'].strip()}")
        print(f"Supply: {data['supply']}")


if __name__ == "__main__":
    asyncio.run(main())
