from solders.keypair import Keypair
# If you have a mnemonic
private_key  = "5fucuMkgRy99w8Th9fgoazD6iuYMVTXXg3M5rSCWB9iAvHe9BSN6qApKuARzYRWY3wTn8DFLkRiBfzfbfdykasKj"
keypair = Keypair.from_base58_string(private_key)
print(keypair.pubkey())