import base64
from cryptography.hazmat.primitives import serialization
from hpke import Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305

# Load the public key
public_key_b64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/OpXhdfXV2kyGI9Psyay+loGuZ3iNOYQD5pXXEZr1yKPtc/ilKf+6fg/WiWa7YKs7rCSMog8rtM2fBSHSSq31A=="
public_key_der = base64.b64decode(public_key_b64)
public_key = serialization.load_der_public_key(public_key_der)

# Define HPKE suite
suite = Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305

# Encrypt message
plaintext = b"Hello from ChatGPT!"
encap, ciphertext = suite.seal(
    peer_pubkey=public_key, message=plaintext, info=b"", aad=b""
)


def decrypt_hpke_message(
    private_key_base64: str, encapsulated_key_base64: str, ciphertext_base64: str
) -> str:
    """
    Decrypts a message using HPKE (Hybrid Public Key Encryption) with P-256 keys
    """
    try:
        # Use the specific suite from the HPKE library
        suite = Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305
        print(base64.b64decode(encapsulated_key_base64))

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


# Output base64 results
print("encapsulated_key:", base64.b64encode(encap).decode())
print("ciphertext:", base64.b64encode(ciphertext).decode())
decrypted_message = decrypt_hpke_message(
    private_key_base64="MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmvG1OiD/oh8gPhmbNTRbYGQiH4t6vY8T+uYQwe2I35ihRANCAAT7EyZ3XQW3Cr+i9hilJPx9Y/eGiSlKHL/P7fKXr/tadizQB7Y/bp6zU4ksN7BHtkr3KnkH5PRgufn9QWi0hVVa",
    encapsulated_key_base64="BO3KMRJd4yqqOq9Ol2l+T4ruhL1lBk30cqBx9Q8GA2kEsIbCnjClPU15KxE8iHyM68ib7ylNnfROObEUfHTQOTQ=",
    ciphertext_base64="sRke6HORWVySI/5rS5xLLXMtgkwkZ8r+xR8Gg53+GaDvF+EqsF32K9fdURUQbk4uvAUD1six87ji18xCTfle9BRBwayCeWdOtDSBvYnduBc5VqvHuPv2/VCYd73BJIRHupKpm2JvCw=="
)
print("Decrypted message:", decrypted_message)
print("Decryption complete.")

