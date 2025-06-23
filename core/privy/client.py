from config.settings import Config
import json
from typing import Dict
from hpke import Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import base64
import requests


config = Config()


class PrivyIntegration:
    def __init__(self):
        self.auth_string = f"{config.privy_app_id}:{config.privy_api_key}"
        self.encoded_auth = base64.b64encode(self.auth_string.encode()).decode()
        self.headers = {
            "Authorization": f"Basic {self.encoded_auth}",
            "privy-app-id": config.privy_app_id,
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
                "headers": {"privy-app-id": config.privy_app_id},
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
            private_key_string = config.privy_auth_private_key.replace(
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

    def create_wallet(self, user_id: int) -> Dict:
        """Create a new wallet using Privy API"""
        url = "https://api.privy.io/v1/wallets"
        headers = {
            "Authorization": f"Basic {self.encoded_auth}",
            "privy-app-id": config.privy_app_id,
            "Content-Type": "application/json",
        }
        data = {
            "chain_type": "solana",
            "owner": {
                "public_key": config.privy_auth_public_key,
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
            "recipient_public_key": config.privy_auth_public_key,
        }

        try:
            # Generate the authorization signature
            authorization_signature = self._generate_authorization_signature(
                method="POST", url=url, body=body_data
            )

            # Create headers with proper authorization signature
            headers = {
                "Authorization": f"Basic {self.encoded_auth}",  # This should be defined elsewhere
                "privy-app-id": config.privy_app_id,
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
                    hpke_private_key_base64 = config.privy_auth_private_key.replace(
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
