import os
import json
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

KEY_OFFSET = 0
UPDATE_AUTH_OFFSET = KEY_OFFSET + 1
MINT_OFFSET = UPDATE_AUTH_OFFSET + 32
NAME_OFFSET = MINT_OFFSET + 32
NAME_LENGTH = 32  # Padded to 32 bytes
SYMBOL_OFFSET = NAME_OFFSET + NAME_LENGTH
SYMBOL_LENGTH = 10  # Padded to 10 bytes

auth_string = f"{CONFIG['privy_app_id']}:{CONFIG['privy_api_key']}"
encoded_auth = base64.b64encode(auth_string.encode()).decode()

# In-memory database (replace with real database in production)
USER_DB: Dict[int, Dict] = {}

# SOL mint address (native SOL)
SOL_MINT = "So11111111111111111111111111111111111111112"
WSOL_MINT = "So11111111111111111111111111111111111111112"
METADATA_PROGRAM_ID = Pubkey.from_string("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s")


@dataclass
class SwapQuote:
    input_mint: str
    output_mint: str
    input_amount: int
    output_amount: int
    price_impact_pct: float
    route_plan: List[Dict]


class PrivyIntegration:
    def __init__(self):
        self.headers = {
            "Authorization": f"Basic {encoded_auth}",
            "privy-app-id": CONFIG["privy_app_id"],
            "Content-Type": "application/json",
        }

    def canonicalize(self, obj) -> str:
        """Simple JSON canonicalization function. Sorts dictionary keys and ensures consistent formatting."""
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))

    def _generate_authorization_signature(
        self, method: str, url: str, body: Dict, headers: Dict = None
    ) -> str:
        """Generate ECDSA P-256 authorization signature for Privy API requests"""
        try:
            # Build the payload according to Privy's specification
            payload = {
                "version": 1,
                "method": method,
                "url": url,
                "body": body,
                "headers": {"privy-app-id": CONFIG["privy_app_id"]},
            }

            # Add idempotency key if present in headers
            if headers and "privy-idempotency-key" in headers:
                payload["headers"]["privy-idempotency-key"] = headers[
                    "privy-idempotency-key"
                ]

            # Serialize the payload using canonicalization
            serialized_payload = self.canonicalize(payload)
            print(f"Serialized payload for signing: {serialized_payload}")

            # Get the private key and remove the 'wallet-auth:' prefix
            private_key_string = CONFIG["privy_auth_private_key"].replace(
                "wallet-auth:", ""
            )

            # Convert private key to PEM format
            private_key_pem = f"-----BEGIN PRIVATE KEY-----\n{private_key_string}\n-----END PRIVATE KEY-----"

            # Load the private key from PEM format
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode("utf-8"), password=None
            )

            # Sign the message using ECDSA with SHA-256
            signature = private_key.sign(
                serialized_payload.encode("utf-8"), ec.ECDSA(hashes.SHA256())
            )

            # Convert the signature to base64 for transmission
            return base64.b64encode(signature).decode("utf-8")

        except Exception as e:
            print(f"Error generating authorization signature: {e}")
            raise Exception(f"Failed to generate authorization signature: {str(e)}")

    @staticmethod
    def create_wallet(user_id: int) -> Dict:
        """Create a new wallet using Privy API"""
        url = "https://api.privy.io/v1/wallets"
        headers = {
            "Authorization": f"Basic {encoded_auth}",
            "privy-app-id": CONFIG["privy_app_id"],
            "Content-Type": "application/json",
        }
        data = {
            "chain_type": "solana",
            "owner": {
                "public_key": CONFIG["privy_auth_public_key"],
            },
        }

        response = requests.post(url, headers=headers, json=data)
        if response.status_code != 200:
            print("Response = ", response.json())
            raise Exception(f"Privy API error: {response.text}")

        return response.json()

    def export_wallet(self, wallet_id: str) -> Dict:
        """Export wallet details for a user with proper authorization signature"""
        url = f"https://api.privy.io/v1/wallets/{wallet_id}/export"
        print(f"Exporting wallet ID: {wallet_id}")
        print(f"Export URL: {url}")
        # Request body - this public key should match your HPKE private key
        body_data = {
            "encryption_type": "HPKE",
            "recipient_public_key": CONFIG["privy_auth_public_key"],
        }

        try:
            # Generate the authorization signature
            authorization_signature = self._generate_authorization_signature(
                method="POST", url=url, body=body_data
            )

            # Create headers with proper authorization signature
            headers = {
                "Authorization": f"Basic {encoded_auth}",  # This should be defined elsewhere
                "privy-app-id": CONFIG["privy_app_id"],
                "Content-Type": "application/json",
                "privy-authorization-signature": authorization_signature,
            }

            # Convert body to JSON string
            body_json = json.dumps(body_data, separators=(",", ":"))

            print(f"Request headers: {headers}")
            print(f"Request body: {body_json}")
            print(f"Authorization signature: {authorization_signature}")

            # Make the request
            response = requests.post(url, data=body_json, headers=headers, timeout=30)

            print(f"Response status: {response.status_code}")
            print(f"Response headers: {response.headers}")
            print(f"Response text: {response.text}")

            # Check if response has content
            if not response.text.strip():
                raise Exception("Empty response from Privy API")

            # Handle different status codes
            if response.status_code == 404:
                raise Exception(f"Wallet with ID {wallet_id} not found")
            elif response.status_code == 401:
                raise Exception("Invalid API credentials or authorization signature")
            elif response.status_code == 403:
                raise Exception(
                    "Access forbidden - check API permissions and authorization signature"
                )
            elif response.status_code == 400:
                raise Exception(f"Bad request - check request format: {response.text}")
            elif response.status_code != 200:
                raise Exception(
                    f"Privy API error (Status {response.status_code}): {response.text}"
                )

            # Parse JSON response
            try:
                data = response.json()
                print(f"Response data: {data}")
            except json.JSONDecodeError as e:
                print(f"JSON decode error: {e}")
                print(
                    f"Response content type: {response.headers.get('content-type', 'unknown')}"
                )
                raise Exception(
                    f"Invalid JSON response from Privy API: {response.text[:200]}"
                )

            # Decrypt the HPKE-encrypted data if present
            if "encapsulated_key" in data and "ciphertext" in data:
                try:
                    # You need a separate HPKE private key (not the auth private key)
                    # This should be the private key corresponding to the public key in recipient_public_key
                    hpke_private_key_base64 = CONFIG["privy_auth_private_key"].replace(
                        "wallet-auth:", ""
                    )
                    if not hpke_private_key_base64:
                        raise Exception("HPKE private key not found in config")

                    decrypted_data = self.decrypt_hpke_message(
                        hpke_private_key_base64,
                        data["encapsulated_key"],
                        data["ciphertext"],
                    )
                    print(f"Decrypted data: {decrypted_data}")

                    # Parse the decrypted JSON data
                    try:
                        decrypted_json = json.loads(decrypted_data)
                        return decrypted_json
                    except json.JSONDecodeError:
                        # If it's not JSON, return as string
                        return {"decrypted_content": decrypted_data}

                except Exception as e:
                    print(f"HPKE decryption failed: {e}")
                    # Return the encrypted data if decryption fails
                    return data
            else:
                # Return the response data if no encryption
                return data

        except requests.exceptions.Timeout:
            raise Exception("Request timeout - Privy API is not responding")
        except requests.exceptions.ConnectionError:
            raise Exception("Connection error - Unable to connect to Privy API")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request error: {str(e)}")

    def decrypt_hpke_message(
        self,
        private_key_base64: str,
        encapsulated_key_base64: str,
        ciphertext_base64: str,
    ) -> str:
        """
        Decrypts a message using HPKE (Hybrid Public Key Encryption) with P-256 keys
        """
        try:
            # Use the specific suite from the HPKE library
            suite = Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305

            # Convert base64 to bytes
            encap = base64.b64decode(encapsulated_key_base64)
            ciphertext = base64.b64decode(ciphertext_base64)

            # Handle the private key - check if it's already in DER format or PEM
            private_key_bytes = base64.b64decode(private_key_base64)
            print(private_key_bytes)
            # Try to load as DER first, then PEM if that fails
            try:
                private_key = serialization.load_der_private_key(
                    private_key_bytes, password=None
                )
                print("Done with load_der_private_key")
            except ValueError:
                # If DER fails, try as PEM
                try:
                    private_key = serialization.load_pem_private_key(
                        private_key_bytes, password=None
                    )
                    print("Done with load_pem_private_key")
                except ValueError:
                    # If both fail, try treating the input as raw PEM string
                    if (
                        isinstance(private_key_base64, str)
                        and "BEGIN PRIVATE KEY" in private_key_base64
                    ):
                        private_key = serialization.load_pem_private_key(
                            private_key_base64.encode(), password=None
                        )
                        print("Done with load_pem_private_key from string")
                    else:
                        print("Invalid private key format")
                        raise ValueError("Unable to load private key - invalid format")

            # Use the suite's open method for single-shot decryption
            try:
                plaintext = suite.open(
                    encap=encap,
                    our_privatekey=private_key,
                    info=b"",  # Empty info unless you have specific context info
                    aad=b"",  # Empty AAD unless you have additional authenticated data
                    ciphertext=ciphertext,
                )
            except Exception as e:
                print(f"HPKE decryption failed: {e}")
                raise ValueError(f"HPKE decryption failed: {str(e)}")
            # Return as UTF-8 string
            print(plaintext.decode("utf-8"))
            return plaintext.decode("utf-8")

        except Exception as e:
            print(e)
            raise ValueError(f"HPKE decryption failed: {str(e)}")


class RaydiumSwap:
    def __init__(self, rpc_url: str):
        self.rpc_url = rpc_url
        self.client = AsyncClient(rpc_url)

    async def get_swap_quote(
        self, input_mint: str, output_mint: str, amount: int, slippage_bps: int = 500
    ) -> Optional[SwapQuote]:
        """Get swap quote from Raydium API"""
        try:
            # Using Jupiter API as it's more reliable for quotes (Raydium routes through Jupiter)
            url = "https://quote-api.jup.ag/v6/quote"
            params = {
                "inputMint": input_mint,
                "outputMint": output_mint,
                "amount": str(amount),
                "slippageBps": slippage_bps,
                "swapMode": "ExactIn",
            }

            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return SwapQuote(
                            input_mint=data["inputMint"],
                            output_mint=data["outputMint"],
                            input_amount=int(data["inAmount"]),
                            output_amount=int(data["outAmount"]),
                            price_impact_pct=float(data.get("priceImpactPct", 0)),
                            route_plan=data.get("routePlan", []),
                        )
            return None
        except Exception as e:
            print(f"Error getting swap quote: {e}")
            return None

    async def create_swap_transaction(
        self, quote: SwapQuote, user_public_key: str
    ) -> Optional[str]:
        """Create swap transaction using Jupiter API"""
        try:
            url = "https://quote-api.jup.ag/v6/swap"
            payload = {
                "quoteResponse": {
                    "inputMint": quote.input_mint,
                    "inAmount": str(quote.input_amount),
                    "outputMint": quote.output_mint,
                    "outAmount": str(quote.output_amount),
                    "otherAmountThreshold": str(quote.output_amount),
                    "swapMode": "ExactIn",
                    "slippageBps": CONFIG["slippage_bps"],
                    "platformFee": None,
                    "priceImpactPct": str(quote.price_impact_pct),
                    "routePlan": quote.route_plan,
                },
                "userPublicKey": user_public_key,
                "wrapAndUnwrapSol": True,
                "prioritizationFeeLamports": 1000,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("swapTransaction")
            return None
        except Exception as e:
            print(f"Error creating swap transaction: {e}")
            return None


class BlockchainUtils:
    def __init__(self):
        self.client = AsyncClient(CONFIG["rpc_url"])
        self.raydium = RaydiumSwap(CONFIG["rpc_url"])
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

    async def get_token_metadata(
        self, wallet_address: str, mint_address: str
    ) -> Optional[Dict[str, str]]:
        try:
            mint_pubkey = Pubkey.from_string(mint_address)
            mint_account_info = await self.client.get_token_supply(mint_pubkey)
            decimals = int(mint_account_info.value.decimals)
            supply = (int(mint_account_info.value.amount)) / (10**decimals)
            balance = await self.get_token_balance(
                wallet_address, mint_address, decimals
            )
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

    async def get_token_balance(
        self, wallet_address: str, mint_address: str, decimals: int
    ) -> float:
        """Get token balance for a specific mint"""
        try:
            pubkey = Pubkey.from_string(wallet_address)
            mint_pubkey = Pubkey.from_string(mint_address)
            token_opts = TokenAccountOpts(
                mint=mint_pubkey,
                encoding="base64",
            )
            # Get token accounts
            response = await self.client.get_token_accounts_by_owner(pubkey, token_opts)
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


class TelegramBot:
    def __init__(self):
        self.blockchain = BlockchainUtils()
        self.app = Application.builder().token(CONFIG["telegram_token"]).build()
        self._setup_handlers()

    def _setup_handlers(self):
        self.app.add_handler(CommandHandler("start", self._start))
        self.app.add_handler(CommandHandler("create", self._create_wallet))
        self.app.add_handler(CommandHandler("set_amount", self._set_purchase_amount))
        self.app.add_handler(CommandHandler("buy_tokens", self._buy_tokens))
        self.app.add_handler(CommandHandler("balance", self._check_balance))
        self.app.add_handler(CommandHandler("token_balance", self._check_token_balance))
        self.app.add_handler(CommandHandler("airdrop", self._request_airdrop))
        self.app.add_handler(CommandHandler("quote", self._get_quote))
        self.app.add_handler(CommandHandler("admin_stats", self._admin_stats))
        self.app.add_handler(CommandHandler("mywallets", self.handle_wallets_command))
        self.app.add_handler(CommandHandler("export", self._export_wallet))
        self.app.add_handler(CommandHandler("token_metadata", self._get_token_metadata))

    async def _start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Send welcome message"""
        await update.message.reply_text(
            "🚀 Welcome to the Raydium Token Purchase Bot! (Devnet)\n\n"
            "Available commands:\n"
            "/create - Create a new Privy wallet\n"
            "/set_amount <amount> - Set token purchase amount in SOL\n"
            "/buy_tokens - Purchase tokens with SOL using Raydium\n"
            "/balance - Check your SOL balance\n"
            "/token_balance - Check your token balance\n"
            "/airdrop - Request SOL airdrop (devnet only)\n"
            "/quote <amount> - Get swap quote for amount in SOL\n"
            "/mywallets - View your wallets\n\n"
            "/export - Export your wallet details\n"
            "/token_metadata <mint_address> - Get token metadata for a specific mint\n\n"
            "⚠️ This bot uses Solana DEVNET for testing!"
        )

    async def _export_wallet(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Export wallet details for the user"""
        user_id = update.message.from_user.id

        if user_id not in USER_DB:
            await update.message.reply_text(
                "You don't have a wallet yet. Use /create to create one."
            )
            return

        try:
            user_data = USER_DB[user_id]
            wallet_id = user_data.get("wallet_id")

            if not wallet_id:
                await update.message.reply_text(
                    "❌ No wallet ID found. Please create a new wallet with /create"
                )
                return

            await update.message.reply_text("🔄 Exporting wallet details...")

            # Try to export using Privy API
            try:
                privy_integration = PrivyIntegration()
                private_key = privy_integration.export_wallet(wallet_id)
                print(f"Exported private key: {private_key}")
                # Handle different response formats
                if isinstance(private_key, dict):
                    response = "🔑 Your Wallet Details:\n\n"
                    response += f"Wallet ID: <code>{wallet_id}</code>\n"
                    response += f"Address: <code>{user_data.get('wallet_address', 'Not available')}</code>\n"

                    if private_key:
                        response += f"Private Key: <code>{private_key.get('decrypted_content', '')}</code>\n"
                    else:
                        response += "❌ Private key not available in export\n"

                    response += "\n⚠️ Keep your private key secure and never share it!"

                    await update.message.reply_text(response, parse_mode="HTML")
                else:
                    await update.message.reply_text(
                        f"❌ Unexpected response format from Privy API: {type(private_key)}"
                    )

            except Exception as export_error:
                # Fallback: Show what we have stored locally
                print(f"Export API failed: {export_error}")

                response = "🔑 Your Wallet Details (Local Data):\n\n"
                response += f"Wallet ID: <code>{wallet_id}</code>\n"
                response += f"Address: <code>{user_data.get('wallet_address', 'Not available')}</code>\n"

                stored_private_key = user_data.get("private_key")
                if stored_private_key:
                    response += f"Private Key: <code>{stored_private_key}</code>\n"
                    response += "\n⚠️ Keep your private key secure and never share it!"
                else:
                    response += "❌ Private key not available locally\n"
                    response += (
                        "\n💡 Note: Privy export API failed. This may be due to:\n"
                    )
                    response += "- API permissions/authentication issues\n"
                    response += "- Wallet created without exportable private key\n"
                    response += "- Network connectivity issues\n"
                    response += f"\nError: {str(export_error)}"

                await update.message.reply_text(response, parse_mode="HTML")

        except Exception as e:
            error_msg = str(e)
            print(f"Export wallet error: {error_msg}")
            await update.message.reply_text(f"❌ Error exporting wallet: {error_msg}")

    async def _get_token_metadata(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ):
        """Get token metadata for a specific mint"""
        user_id = update.message.from_user.id

        if user_id not in USER_DB:
            await update.message.reply_text("Please create a wallet first with /create")
            return

        if not context.args:
            await update.message.reply_text(
                "Please specify a token mint address (e.g. /token_metadata 4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R)"
            )
            return

        mint_address = context.args[0]

        try:
            metadata = await self.blockchain.get_token_metadata(
                USER_DB[user_id]["wallet_address"], mint_address
            )

            if metadata:
                response = (
                    f"🔍 Token Metadata for {mint_address}:\n\n"
                    f"Name: {metadata['name']}\n"
                    f"Symbol: {metadata['symbol']}\n"
                    f"Supply: {metadata['supply']}\n"
                    f"Balance: {metadata['balance']}\n"
                )
                await update.message.reply_text(response)
            else:
                await update.message.reply_text("❌ Token metadata not found.")

        except Exception as e:
            await update.message.reply_text(f"❌ Error fetching metadata: {str(e)}")

    async def handle_wallets_command(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ):
        user_id = update.message.from_user.id

        try:
            if user_id not in USER_DB:
                await update.message.reply_text(
                    "You don't have any wallets registered yet. Use /create to create one."
                )
                return

            user_data = USER_DB[user_id]
            wallet_address = user_data.get("wallet_address")

            if not wallet_address:
                await update.message.reply_text(
                    "No wallet address found. Use /create to create a wallet."
                )
                return

            sol_balance = await self.blockchain.get_sol_balance(wallet_address)
            token_balance = await self.blockchain.get_token_balance(
                wallet_address, CONFIG["target_token_mint"]
            )

            response = "🔑 Your Wallet:\n\n"
            response += f"Address: <code>{wallet_address}</code>\n"
            response += f"SOL Balance: {sol_balance:.6f} SOL\n"
            response += f"Token Balance: {token_balance:.6f} tokens\n"
            response += f"Purchase Amount: {user_data.get('purchase_amount', 0.1)} SOL"

            await update.message.reply_text(response, parse_mode="HTML")

        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")

    async def _create_wallet(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Create a new Privy wallet for the user"""
        user_id = update.message.from_user.id

        if user_id in USER_DB:
            await update.message.reply_text("You already have a wallet!")
            return

        try:
            wallet_info = PrivyIntegration.create_wallet(user_id)
            print(f"Wallet created: {wallet_info}")

            USER_DB[user_id] = {
                "wallet_id": wallet_info["id"],
                "wallet_address": wallet_info["address"],
                "private_key": wallet_info.get("private_key", ""),  # Store if available
                "purchase_amount": 0.1,  # Default amount in SOL
                "conditions_met": False,
            }

            await update.message.reply_text(
                f"✅ Wallet created successfully!\n"
                f"Address: <code>{wallet_info['address']}</code>\n"
                f"Default purchase amount set to 0.1 SOL\n\n"
                f"💡 Use /airdrop to get test SOL on devnet\n"
                f"💡 Use /buy_tokens to purchase tokens",
                parse_mode="HTML",
            )
        except Exception as e:
            print(str(e))
            await update.message.reply_text(f"❌ Error creating wallet: {str(e)}")

    async def _set_purchase_amount(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ):
        """Set the token purchase amount"""
        user_id = update.message.from_user.id

        if user_id not in USER_DB:
            await update.message.reply_text("Please create a wallet first with /create")
            return

        if not context.args:
            await update.message.reply_text(
                "Please specify an amount in SOL (e.g. /set_amount 0.5)"
            )
            return

        try:
            amount = float(context.args[0])
            if amount <= 0:
                raise ValueError("Amount must be positive")

            USER_DB[user_id]["purchase_amount"] = amount
            await update.message.reply_text(f"✅ Purchase amount set to {amount} SOL")
        except ValueError:
            await update.message.reply_text(
                "❌ Invalid amount. Please use a positive number (e.g. 0.5)"
            )

    async def _buy_tokens(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Purchase tokens using Raydium swap"""
        user_id = update.message.from_user.id

        if user_id not in USER_DB:
            await update.message.reply_text("Please create a wallet first with /create")
            return

        try:
            user_data = USER_DB[user_id]
            purchase_amount = user_data["purchase_amount"]
            wallet_address = user_data["wallet_address"]

            # Check SOL balance
            sol_balance = await self.blockchain.get_sol_balance(wallet_address)
            if (
                sol_balance < purchase_amount + 0.01
            ):  # Reserve 0.01 SOL for transaction fees
                await update.message.reply_text(
                    f"❌ Insufficient SOL balance!\n"
                    f"Required: {purchase_amount + 0.01:.3f} SOL (including fees)\n"
                    f"Available: {sol_balance:.6f} SOL\n\n"
                    f"Use /airdrop to get test SOL"
                )
                return

            await update.message.reply_text(
                "🔄 Processing swap... This may take a moment."
            )

            # Execute swap
            tx_hash = await self.blockchain.execute_swap(user_id, purchase_amount)

            if tx_hash:
                await update.message.reply_text(
                    f"✅ Tokens purchased successfully!\n"
                    f"Amount: {purchase_amount} SOL\n"
                    f"Transaction: <code>{tx_hash}</code>\n\n"
                    f"🔗 View on Solscan: https://solscan.io/tx/{tx_hash}?cluster=devnet",
                    parse_mode="HTML",
                )
                USER_DB[user_id]["conditions_met"] = True
            else:
                await update.message.reply_text(
                    "❌ Transaction failed. Please try again."
                )

        except Exception as e:
            await update.message.reply_text(f"❌ Error purchasing tokens: {str(e)}")

    async def _get_quote(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Get swap quote"""
        if not context.args:
            await update.message.reply_text(
                "Please specify amount in SOL (e.g. /quote 0.5)"
            )
            return

        try:
            sol_amount = float(context.args[0])
            lamports = int(sol_amount * 10**9)

            quote = await self.blockchain.raydium.get_swap_quote(
                SOL_MINT, CONFIG["target_token_mint"], lamports, CONFIG["slippage_bps"]
            )

            if quote:
                output_tokens = (
                    quote.output_amount / 10**6
                )  # Assuming 6 decimals, adjust as needed
                await update.message.reply_text(
                    f"💰 Swap Quote:\n"
                    f"Input: {sol_amount} SOL\n"
                    f"Output: ~{output_tokens:.6f} tokens\n"
                    f"Price Impact: {quote.price_impact_pct:.3f}%\n"
                    f"Slippage: {CONFIG['slippage_bps'] / 100}%"
                )
            else:
                await update.message.reply_text("❌ Could not get swap quote")

        except ValueError:
            await update.message.reply_text("❌ Invalid amount. Please use a number.")
        except Exception as e:
            await update.message.reply_text(f"❌ Error getting quote: {str(e)}")

    async def _check_balance(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Check user's SOL balance"""
        user_id = update.message.from_user.id

        if user_id not in USER_DB:
            await update.message.reply_text("Please create a wallet first with /create")
            return

        try:
            wallet_address = USER_DB[user_id]["wallet_address"]
            balance = await self.blockchain.get_sol_balance(wallet_address)
            await update.message.reply_text(f"💰 Your SOL balance: {balance:.6f} SOL")
        except Exception as e:
            await update.message.reply_text(f"❌ Error checking balance: {str(e)}")

    async def _check_token_balance(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ):
        """Check user's token balance"""
        user_id = update.message.from_user.id

        if user_id not in USER_DB:
            await update.message.reply_text("Please create a wallet first with /create")
            return

        try:
            wallet_address = USER_DB[user_id]["wallet_address"]
            balance = await self.blockchain.get_token_balance(
                wallet_address, CONFIG["target_token_mint"]
            )
            await update.message.reply_text(
                f"🪙 Your token balance: {balance:.6f} tokens"
            )
        except Exception as e:
            await update.message.reply_text(
                f"❌ Error checking token balance: {str(e)}"
            )

    async def _request_airdrop(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ):
        """Request SOL airdrop on devnet"""
        user_id = update.message.from_user.id

        if user_id not in USER_DB:
            await update.message.reply_text("Please create a wallet first with /create")
            return

        try:
            wallet_address = USER_DB[user_id]["wallet_address"]
            tx_hash = await self.blockchain.airdrop_sol(wallet_address, 2.0)

            if tx_hash:
                await update.message.reply_text(
                    f"✅ Airdrop requested!\n"
                    f"Amount: 2.0 SOL\n"
                    f"Transaction: <code>{tx_hash}</code>\n\n"
                    f"Wait a moment and check your balance with /balance",
                    parse_mode="HTML",
                )
            else:
                await update.message.reply_text(
                    "❌ Airdrop failed. You may have reached the daily limit."
                )
        except Exception as e:
            await update.message.reply_text(f"❌ Error requesting airdrop: {str(e)}")

    async def _admin_stats(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Admin command to check bot statistics"""
        user_id = update.message.from_user.id

        if user_id not in CONFIG["admin_user_ids"]:
            await update.message.reply_text("❌ Unauthorized")
            return

        stats = {
            "total_users": len(USER_DB),
            "wallets_created": len(
                [u for u in USER_DB.values() if "wallet_address" in u]
            ),
            "purchases_made": len(
                [u for u in USER_DB.values() if u.get("conditions_met", False)]
            ),
        }

        await update.message.reply_text(
            "📊 Bot Statistics:\n"
            f"Total users: {stats['total_users']}\n"
            f"Wallets created: {stats['wallets_created']}\n"
            f"Purchases made: {stats['purchases_made']}\n"
            f"Network: Devnet"
        )

    def run(self):
        """Run the bot"""
        print("Bot is running on Solana Devnet...")
        print(f"Target token mint: {CONFIG['target_token_mint']}")
        self.app.run_polling()


if __name__ == "__main__":
    bot = TelegramBot()
    bot.run()
