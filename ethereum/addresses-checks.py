# Needs module `pip install bip-utils`
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator
from bip_utils import Bip32Slip10Secp256k1
from Crypto.Hash import keccak
import requests
import time

def generate():
  # Step 1: Generate a 12-word mnemonic
  mnemonic = Bip39MnemonicGenerator().FromWordsNumber(12)

  # Step 2: Generate the seed from the mnemonic
  seed = Bip39SeedGenerator(mnemonic).Generate()

  # Step 3: Create a BIP-32 master key from the seed
  bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed)

  # Generate first address
  index_key = 0

  # Derive the nth account private key (m/44'/60'/0'/0/n)
  eth_account_path = f"m/44'/60'/0'/0/{index_key}"
  private_key = bip32_ctx.DerivePath(eth_account_path).PrivateKey().Raw().ToHex()

  # Derive the public key from the private key
  public_key = bip32_ctx.DerivePath(eth_account_path).PublicKey().RawUncompressed().ToHex()

  # Derive the Ethereum address from the public key
  # Remove the '0x04' prefix (which indicates an uncompressed public key)
  public_key_bytes = bytes.fromhex(public_key)[1:]

  # Compute the Keccak-256 hash of the public key
  keccak_hash = keccak.new(digest_bits=256)
  keccak_hash.update(public_key_bytes)
  public_key_hash = keccak_hash.digest()

  # Take the last 20 bytes of the hash as the Ethereum address
  eth_address = public_key_hash[-20:].hex()
  eth_address = "0x" + eth_address

  return {
    'eth_address': eth_address,
    'private_key': private_key,
    'mnemonic': str(mnemonic)
  };

def getBalance(x, accounts):
  accountsList = ','.join(accounts.keys())
  apikey = "SHGMEZDU3AXSWQJS8Q565S1F11T5GAFA4E";
  url = "https://api.etherscan.io/api?module=account&action=balancemulti&address={0}&tag=latest&apikey={1}".format(accountsList, apikey);

  response = requests.get(url)
  json_data = response.json()

  okay = {}
  not_okay = []
  for bal in json_data['result']:
    account = bal.get('account')
    balance = int(bal.get('balance'))

    if(balance > 0):
      okay[account] = {
        'balance': balance,
        'private_key': accounts[account]['private_key'],
        'mnemonic': accounts[account]['mnemonic']
      }
    else:
      not_okay.append(account)
  
  print(f"{x} => Okay ***************************************")
  print(okay)
  print(f"{x} => Not Okay ***************************************")
  print(not_okay)

  # print("\n\nNot Okay ***************************************\n")
  # print(not_okay)

for x in range(10):
  accounts = {}
  for i in range(20):
    address = generate()
    accounts[address['eth_address']] = {
      'mnemonic': address['mnemonic'],
      'private_key': address['private_key']
    }

  getBalance(x, accounts)
  time.sleep(0.2)
