import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()
@dataclass
class Settings:
    telegram_token: str
    privy_app_id: str
    privy_api_key: str
    privy_auth_private_key: str
    privy_auth_public_key: str
    rpc_url: str
    target_token_mint: str
    admin_user_ids: list
    slippage_bps: int
    raydium_api_url: str


class Config:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = Settings(
                telegram_token=os.getenv("TELEGRAM_BOT_TOKEN", "default_token"),
                privy_app_id=os.getenv("PRIVY_APP_ID", "default_app_id"),
                privy_api_key=os.getenv("PRIVY_API_KEY", "default_api_key"),
                privy_auth_private_key=os.getenv(
                    "PRIVY_AUTH_PRIVATE_KEY", "default_priv_key"
                ),
                privy_auth_public_key=os.getenv(
                    "PRIVY_AUTH_PUBLIC_KEY", "default_pub_key"
                ),
                rpc_url=os.getenv("RPC_URL", "https://api.mainnet-beta.solana.com"),
                target_token_mint=os.getenv("TARGET_TOKEN_MINT", "default_mint"),
                admin_user_ids=[12345678],
                slippage_bps=500,
                raydium_api_url="https://api-v3.raydium.io/main",
            )
        return cls._instance
