#!/usr/bin/env bash

# ---------------------------------------
# Configuration
# ---------------------------------------
WALLET_NAME="myminewallet"

# ---------------------------------------
# 1. Ensure a wallet is available
# ---------------------------------------
echo "Checking if wallet \"$WALLET_NAME\" exists..."

# If the wallet is not listed, create it
if ! syscoin-cli listwallets 2>/dev/null | grep -q "$WALLET_NAME"; then
  echo "Wallet \"$WALLET_NAME\" not found. Creating wallet..."
  # createwallet parameters can differ by Syscoin version; this is the basic usage
  syscoin-cli createwallet "$WALLET_NAME"
fi

# Attempt to load the wallet (in case it's newly created or was unloaded)
# Some versions of Syscoin automatically load a newly created wallet; if so, this command is harmless.
syscoin-cli loadwallet "$WALLET_NAME" 2>/dev/null

# ---------------------------------------
# 2. Get or generate a new address from that wallet
# ---------------------------------------
echo "Retrieving a new address from wallet \"$WALLET_NAME\"..."
MINING_ADDRESS=$(syscoin-cli -rpcwallet="$WALLET_NAME" getnewaddress)
echo "Mining to address: $MINING_ADDRESS"

# ---------------------------------------
# 3. Wait until Masternode sync is complete
# ---------------------------------------
echo "Starting Masternode Sync Checker..."

while true; do
  SYNC_STATUS=$(syscoin-cli mnsync status 2>/dev/null)

  # Check if "IsSynced": true
  if echo "$SYNC_STATUS" | grep -q '"IsSynced": true'; then
    echo "Masternode is fully synced!"
    break
  else
    echo "Masternode not synced yet. Running 'mnsync next'..."
    syscoin-cli mnsync next
  fi

  # Wait a bit before checking again
  sleep 10
done

# ---------------------------------------
# 4. Continuously mine blocks
# ---------------------------------------
echo "Starting continuous mining..."

while true; do
  echo "Generating a new block to address: $MINING_ADDRESS"
  # If 'generate' is unsupported, switch to 'generatetoaddress' as shown here:
  syscoin-cli -rpcwallet="$WALLET_NAME" generatetoaddress 1 "$MINING_ADDRESS" 1000000000

  # Sleep briefly to avoid spamming
  sleep 5
done
