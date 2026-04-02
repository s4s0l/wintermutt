#!/bin/bash

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_SCRIPT="$DIR/vault-test-env.sh"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
YELLOW='\033[0;33m'
echo -e "${BLUE}=== Cleaning up environment ===${NC}"
"$ENV_SCRIPT" --stop-wintermutt
"$ENV_SCRIPT" --stop-vault
# Kill any lingering processes that might hold port 2222
if command -v fuser >/dev/null 2>&1; then
	fuser -k 2222/tcp 2>/dev/null || true
	sleep 2
fi
pkill -f "build/server" 2>/dev/null || true
sleep 1

echo -e "${BLUE}=== Building project ===${NC}"
(cd "$DIR/.." && just build)

echo -e "${BLUE}=== Starting Vault ===${NC}"
"$ENV_SCRIPT" --start-vault

function fail_test() {
	echo "Server log:"
	cat "$DIR/../build/test_keys/server.log"
	echo -e "${RED} Integration test failed!${NC}"
	exit 1
}
echo -e "${BLUE}=== Running Integration Tests ===${NC}"

# ========================================================================================================
echo -e "${YELLOW}--- Test Case 1: RSA Client (Authorized) ---${NC}"

"$ENV_SCRIPT" --start-wintermutt -common-prefix "secrets/data/wintermutt"
sleep 3 # Give server time to start

RSA_OUTPUT=$("$ENV_SCRIPT" --ssh-rsa)
echo "$RSA_OUTPUT"
if echo "$RSA_OUTPUT" | grep "api_key" | grep -q "shared-api-key-abc"; then
	echo -e "${GREEN}PASS: RSA client received shared api_key.${NC}"
else
	echo -e "${RED}FAIL: RSA client did not receive shared api_key.${NC}"
	fail_test
	exit 1
fi
if echo "$RSA_OUTPUT" | grep "db_password" | grep -q "rsa-specific-password"; then
	echo -e "${GREEN}PASS: RSA client received specific password.${NC}"
else
	echo -e "${RED}FAIL: RSA client did not receive specific password.${NC}"
	fail_test
	exit 1
fi

# ========================================================================================================
echo -e "${YELLOW}--- Test Case 2: Ed25519 Client (Authorized, no shared path) ---${NC}"
ED_OUTPUT=$("$ENV_SCRIPT" --ssh-ed25519)
echo "$ED_OUTPUT"
if echo "$ED_OUTPUT" | grep -q "ed25519-specific-password" && ! echo "$ED_OUTPUT" | grep -q "api_key"; then
	echo -e "${GREEN}PASS: Ed25519 client received specific secrets and no shared secrets.${NC}"
else
	echo -e "${RED}FAIL: Ed25519 client did not behave as expected (shared path issue or specific secret missing).${NC}"
	fail_test
	exit 1
fi
"$ENV_SCRIPT" --stop-wintermutt

# =======================================================================================================
echo -e "${YELLOW}--- Test Case 3: Ed25519 Client (Authorized, shared path) ---${NC}"

"$ENV_SCRIPT" --start-wintermutt -common-prefix "secrets/data/wintermutt" -shared-path "secrets/data/wintermutt/shared"
sleep 3

ED_OUTPUT=$("$ENV_SCRIPT" --ssh-ed25519)
echo "$ED_OUTPUT"
if echo "$ED_OUTPUT" | grep -q "shared-api-key-abc" && echo "$ED_OUTPUT" | grep -q "ed25519-specific-password"; then
	echo -e "${GREEN}PASS: Ed25519 client received specific secrets and no shared secrets.${NC}"
else
	echo -e "${RED}FAIL: Ed25519 client did not behave as expected (shared path issue or specific secret missing).${NC}"
	fail_test
	exit 1
fi
"$ENV_SCRIPT" --stop-wintermutt

# =======================================================================================================
echo -e "${YELLOW}--- Test Case 4: Allowed Keys Enforcement ---${NC}"
ALLOWED_KEYS_PATH="secrets/data/wintermutt/allowed-keys" # Path in Vault where allowed keys are stored

# Start server with allowed keys enabled
"$ENV_SCRIPT" --start-wintermutt -common-prefix "secrets/data/wintermutt" -allowed-keys-path "$ALLOWED_KEYS_PATH"
sleep 3

# Test authorized RSA client
echo "Testing authorized RSA client with --allowed-keys-path..."
AUTH_RSA_OUTPUT=$("$ENV_SCRIPT" --ssh-rsa)
echo "$AUTH_RSA_OUTPUT"
if echo "$AUTH_RSA_OUTPUT" | grep -q "api_key" && echo "$AUTH_RSA_OUTPUT" | grep -q "rsa-specific-password"; then
	echo -e "${GREEN}PASS: Authorized RSA client received secrets.${NC}"
else
	echo -e "${RED}FAIL: Authorized RSA client did not receive secrets.${NC}"
	fail_test
	exit 1
fi

# Test authorized Ed25519 client
echo "Testing authorized Ed25519 client with --allowed-keys-path..."
AUTH_ED_OUTPUT=$("$ENV_SCRIPT" --ssh-ed25519)
echo "$AUTH_ED_OUTPUT"
if echo "$AUTH_ED_OUTPUT" | grep -q "ed25519-specific-password" && ! echo "$AUTH_ED_OUTPUT" | grep -q "api_key"; then
	echo -e "${GREEN}PASS: Authorized Ed25519 client received specific secrets.${NC}"
else
	echo -e "${RED}FAIL: Authorized Ed25519 client did not receive specific secrets.${NC}"
	fail_test
	exit 1
fi

# Test unauthorized RSA client
echo "Testing unauthorized RSA client with --allowed-keys-path..."
if "$ENV_SCRIPT" --ssh-rsa-unauthorized 2>&1; then
	echo -e "${RED}FAIL: Unauthorized RSA client was not denied access.${NC}"
	fail_test
	exit 1
else
	echo -e "${GREEN}PASS: Unauthorized RSA client was denied access.${NC}"
fi

"$ENV_SCRIPT" --stop-wintermutt

# =======================================================================================================
echo -e "${YELLOW}--- Test Case 5: CLI - List Allowed Keys ---${NC}"

"$ENV_SCRIPT" --start-wintermutt -common-prefix "secrets/data/wintermutt" -shared-path "secrets/data/wintermutt/shared" -allowed-keys-path "secrets/data/wintermutt/allowed-keys" -enable-binary-download -external-host "localhost" -external-port "2222"
sleep 3

echo "Testing CLI list-allowed..."
LIST_OUTPUT=$("$ENV_SCRIPT" --cli list-allowed -allowed-keys-path "secrets/data/wintermutt/allowed-keys" 2>&1)
echo "$LIST_OUTPUT"
if echo "$LIST_OUTPUT" | grep -q "ssh-rsa" && echo "$LIST_OUTPUT" | grep -q "ssh-ed25519"; then
	echo -e "${GREEN}PASS: CLI list-allowed returned both keys.${NC}"
else
	echo -e "${RED}FAIL: CLI list-allowed did not return expected keys.${NC}"
	fail_test
	exit 1
fi

# =======================================================================================================
echo -e "${YELLOW}--- Test Case 5b: CLI Config File Defaults ---${NC}"

CONFIG_FILE="$DIR/../build/test_keys/wintermutt.yml"
cat > "$CONFIG_FILE" <<EOF
wintermutt:
  vault_address: http://127.0.0.1:8200
  common_prefix: secrets/data/wintermutt
  allowed_keys_path: secrets/data/wintermutt/allowed-keys
EOF

echo "Testing CLI list-allowed using config defaults..."
CONFIG_LIST_OUTPUT=$(WINTERMUTT_CONFIG_FILE="$CONFIG_FILE" "$DIR/../build/server" cli -vault-token-file "$DIR/../build/test_keys/test_vault_token" list-allowed 2>&1)
echo "$CONFIG_LIST_OUTPUT"
if echo "$CONFIG_LIST_OUTPUT" | grep -q "ssh-rsa" && echo "$CONFIG_LIST_OUTPUT" | grep -q "ssh-ed25519"; then
	echo -e "${GREEN}PASS: CLI loaded common settings from config file defaults.${NC}"
else
	echo -e "${RED}FAIL: CLI config file defaults did not work as expected.${NC}"
	fail_test
	exit 1
fi

# =======================================================================================================
echo -e "${YELLOW}--- Test Case 5c: SSH Exec cli-install Script ---${NC}"

INSTALL_HOME="$DIR/../build/test_keys/install_home"
INSTALL_SCRIPT="$DIR/../build/test_keys/cli-install.sh"
INSTALL_CONFIG_FILE="$INSTALL_HOME/wintermutt.yml"
INSTALL_BIN_FILE="$INSTALL_HOME/wintermutt"
rm -rf "$INSTALL_HOME" "$INSTALL_SCRIPT"
mkdir -p "$INSTALL_HOME"

echo "Fetching installer script via SSH exec cli-install..."
ssh -T -i "$DIR/../build/test_keys/id_rsa" -p 2222 -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -o BatchMode=yes -o PreferredAuthentications=publickey localhost cli-install > "$INSTALL_SCRIPT"

chmod +x "$INSTALL_SCRIPT"

echo "Running installer script..."
WINTERMUTT_CONFIG_FILE="$INSTALL_CONFIG_FILE" WINTERMUTT_INSTALL_BIN_FILE="$INSTALL_BIN_FILE" WINTERMUTT_INSTALL_IDENTITY_FILE="$DIR/../build/test_keys/id_rsa" bash "$INSTALL_SCRIPT"

CONFIG_FILE_INSTALLED="$INSTALL_CONFIG_FILE"
BIN_INSTALLED="$INSTALL_BIN_FILE"

if [ ! -f "$CONFIG_FILE_INSTALLED" ]; then
	echo -e "${RED}FAIL: Installer did not create config file.${NC}"
	fail_test
	exit 1
fi

if [ ! -x "$BIN_INSTALLED" ]; then
	echo -e "${RED}FAIL: Installer did not create executable binary.${NC}"
	fail_test
	exit 1
fi

if grep -q "vault_address: http://" "$CONFIG_FILE_INSTALLED" && grep -q "common_prefix: secrets/data/wintermutt" "$CONFIG_FILE_INSTALLED"; then
	echo -e "${GREEN}PASS: Installer wrote expected config defaults.${NC}"
else
	echo -e "${RED}FAIL: Installer config file does not contain expected values.${NC}"
	fail_test
	exit 1
fi

if "$BIN_INSTALLED" help >/dev/null 2>&1; then
	echo -e "${GREEN}PASS: Installed binary runs successfully.${NC}"
else
	echo -e "${RED}FAIL: Installed binary failed to run.${NC}"
	fail_test
	exit 1
fi

if grep -q "shared_path: secrets/data/wintermutt/shared" "$CONFIG_FILE_INSTALLED"; then
	echo -e "${GREEN}PASS: Installer wrote shared_path config default.${NC}"
else
	echo -e "${RED}FAIL: Installer config file is missing shared_path.${NC}"
	fail_test
	exit 1
fi

# =======================================================================================================
echo -e "${YELLOW}--- Test Case 5d: CLI - Set/Rm Shared Secret ---${NC}"

SHARED_SECRET_VALUE="shared-cli-secret-$(date +%s)"
echo "$SHARED_SECRET_VALUE" | "$ENV_SCRIPT" --cli set-shared -name "cli_shared_secret" -shared-path "secrets/data/wintermutt/shared" 2>&1

sleep 2

RSA_OUTPUT=$("$ENV_SCRIPT" --ssh-rsa)
echo "$RSA_OUTPUT"
if echo "$RSA_OUTPUT" | grep -q "cli_shared_secret=\"$SHARED_SECRET_VALUE\""; then
	echo -e "${GREEN}PASS: CLI set-shared secret was retrievable via SSH.${NC}"
else
	echo -e "${RED}FAIL: CLI set-shared secret was not retrievable via SSH.${NC}"
	fail_test
fi

"$ENV_SCRIPT" --cli rm-shared -name "cli_shared_secret" -shared-path "secrets/data/wintermutt/shared" 2>&1

sleep 2

RSA_OUTPUT=$("$ENV_SCRIPT" --ssh-rsa)
echo "$RSA_OUTPUT"
if ! echo "$RSA_OUTPUT" | grep -q "cli_shared_secret"; then
	echo -e "${GREEN}PASS: CLI rm-shared deleted shared secret successfully.${NC}"
else
	echo -e "${RED}FAIL: Shared secret still exists after rm-shared.${NC}"
	fail_test
fi

# =======================================================================================================
echo -e "${YELLOW}--- Test Case 6: CLI - Set Secret and Retrieve via SSH ---${NC}"

# Use CLI to set a new secret for the RSA key
echo "Testing CLI set operation..."
SECRET_VALUE="cli-set-secret-$(date +%s)"
echo "$SECRET_VALUE" | "$ENV_SCRIPT" --cli set -public-key "$DIR/../build/test_keys/id_rsa.pub" -common-prefix "secrets/data/wintermutt" -name "cli_test_secret" 2>&1

sleep 2

# Retrieve secrets via SSH and check for our new secret
SSH_OUTPUT=$("$ENV_SCRIPT" --ssh-rsa)
echo "$SSH_OUTPUT"
if echo "$SSH_OUTPUT" | grep -q "cli_test_secret"; then
	echo -e "${GREEN}PASS: CLI set secret was retrievable via SSH.${NC}"
else
	echo -e "${RED}FAIL: CLI set secret was not retrievable via SSH.${NC}"
	fail_test
fi

# =======================================================================================================
echo -e "${YELLOW}--- Test Case 7: CLI - Delete Secret (rm) ---${NC}"

# Set a secret to delete
echo "Testing CLI rm operation..."
RM_SECRET_VALUE="cli-rm-secret-$(date +%s)"
echo "$RM_SECRET_VALUE" | "$ENV_SCRIPT" --cli set -public-key "$DIR/../build/test_keys/id_rsa.pub" -common-prefix "secrets/data/wintermutt" -name "cli_delete_me" 2>&1

sleep 2

# Verify it exists
SSH_OUTPUT=$("$ENV_SCRIPT" --ssh-rsa)
echo "$SSH_OUTPUT"
if echo "$SSH_OUTPUT" | grep -q "cli_delete_me"; then
	echo "Secret exists, proceeding to delete..."
else
	echo -e "${RED}FAIL: Secret was not set.${NC}"
	fail_test
fi

# Delete the secret
"$ENV_SCRIPT" --cli rm -public-key "$DIR/../build/test_keys/id_rsa.pub" -common-prefix "secrets/data/wintermutt" -name "cli_delete_me" 2>&1

sleep 2

# Verify it's gone
SSH_OUTPUT=$("$ENV_SCRIPT" --ssh-rsa)
echo "$SSH_OUTPUT"
if ! echo "$SSH_OUTPUT" | grep -q "cli_delete_me"; then
	echo -e "${GREEN}PASS: CLI rm deleted secret successfully.${NC}"
else
	echo -e "${RED}FAIL: Secret still exists after rm.${NC}"
	fail_test
fi

# =======================================================================================================
echo -e "${YELLOW}--- Test Case 8: CLI - Add Key to Allowed List (allow) ---${NC}"

# Generate a new key pair for testing (remove first to avoid overwrite prompt)
NEW_KEY_DIR="$DIR/../build/test_keys"
rm -f "$NEW_KEY_DIR/id_ed25519_new" "$NEW_KEY_DIR/id_ed25519_new.pub"
ssh-keygen -t ed25519 -f "$NEW_KEY_DIR/id_ed25519_new" -N "" -q

# Add the new key to allowed list
echo "Testing CLI allow operation..."
"$ENV_SCRIPT" --cli allow -public-key "$NEW_KEY_DIR/id_ed25519_new.pub" -common-prefix "secrets/data/wintermutt" -allowed-keys-path "secrets/data/wintermutt/allowed-keys" 2>&1

sleep 2

# Verify it's in the list
LIST_OUTPUT=$("$ENV_SCRIPT" --cli list-allowed -allowed-keys-path "secrets/data/wintermutt/allowed-keys" 2>&1)
echo "$LIST_OUTPUT"
KEY_COUNT=$(echo "$LIST_OUTPUT" | grep -c "ssh-ed25519")
if [ "$KEY_COUNT" -eq 2 ]; then
	echo -e "${GREEN}PASS: CLI allow added key to allowed list.${NC}"
else
	echo -e "${RED}FAIL: Key not found in allowed list. Found $KEY_COUNT, expected 2.${NC}"
	fail_test
fi

# Test SSH with the new key (should work now - capture both stdout and stderr)
NEW_KEY_OUTPUT=$(ssh -i "$NEW_KEY_DIR/id_ed25519_new" -p 2222 -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -o BatchMode=yes -o PreferredAuthentications=publickey localhost 2>&1 || true)
echo "New key SSH output:"
echo "$NEW_KEY_OUTPUT"
echo "---"
# If connection succeeds but no secrets exist, output will be empty or just the pty warning
# So we just check that it didn't fail with "Permission denied"
if ! echo "$NEW_KEY_OUTPUT" | grep -q "Permission denied"; then
	echo -e "${GREEN}PASS: SSH with newly allowed key succeeded.${NC}"
else
	echo -e "${RED}FAIL: SSH with newly allowed key failed.${NC}"
	fail_test
fi

# Restart server to pick up the new allowed key for Test 9
"$ENV_SCRIPT" --stop-wintermutt
"$ENV_SCRIPT" --start-wintermutt -common-prefix "secrets/data/wintermutt" -allowed-keys-path "secrets/data/wintermutt/allowed-keys"
sleep 3

# =======================================================================================================
echo -e "${YELLOW}--- Test Case 9: CLI - Remove Key from Allowed List (revoke) ---${NC}"

# Revoke the key we just added
echo "Testing CLI revoke operation..."
"$ENV_SCRIPT" --cli revoke -public-key "$NEW_KEY_DIR/id_ed25519_new.pub" -common-prefix "secrets/data/wintermutt" -allowed-keys-path "secrets/data/wintermutt/allowed-keys" 2>&1

sleep 2

# Verify it's removed from the list
LIST_OUTPUT=$("$ENV_SCRIPT" --cli list-allowed -allowed-keys-path "secrets/data/wintermutt/allowed-keys" 2>&1)
echo "List after revoke:"
echo "$LIST_OUTPUT"
echo "---"
KEY_COUNT=$(echo "$LIST_OUTPUT" | grep -c "ssh-ed25519")
echo "ed25519 key count: $KEY_COUNT"
if [ "$KEY_COUNT" -eq 1 ]; then
	echo -e "${GREEN}PASS: CLI revoke removed key from allowed list.${NC}"
else
	echo -e "${RED}FAIL: Key still in allowed list after revoke. Found $KEY_COUNT, expected 1.${NC}"
	fail_test
fi

# Test SSH with the revoked key (should fail now)
if ssh -i "$NEW_KEY_DIR/id_ed25519_new" -p 2222 -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -o BatchMode=yes -o PreferredAuthentications=publickey localhost 2>&1; then
	echo -e "${RED}FAIL: SSH with revoked key succeeded (should have failed).${NC}"
	fail_test
else
	echo -e "${GREEN}PASS: SSH with revoked key was denied.${NC}"
fi

"$ENV_SCRIPT" --stop-wintermutt

# =======================================================================================================
echo -e "${YELLOW}--- Test Case 10: CLI - Set Secret at Arbitrary Path (-path) ---${NC}"

# Set a secret at an arbitrary path without needing -public-key or -common-prefix
echo "Testing CLI set with -path flag..."
ARBITRARY_SECRET_VALUE="arbitrary-path-secret-$(date +%s)"
SET_OUTPUT=$(echo "$ARBITRARY_SECRET_VALUE" | "$ENV_SCRIPT" --cli set -path "secrets/data/wintermutt/shared" -name "arbitrary_secret" 2>&1)
echo "$SET_OUTPUT"
if echo "$SET_OUTPUT" | grep -q "set successfully"; then
	echo -e "${GREEN}PASS: CLI set with -path flag set secret at arbitrary path.${NC}"
else
	echo -e "${RED}FAIL: CLI set with -path failed.${NC}"
	fail_test
fi

sleep 2

# Verify RSA client can see the shared secret
"$ENV_SCRIPT" --start-wintermutt -common-prefix "secrets/data/wintermutt" -shared-path "secrets/data/wintermutt/shared"
sleep 3

RSA_OUTPUT=$("$ENV_SCRIPT" --ssh-rsa)
echo "$RSA_OUTPUT"
if echo "$RSA_OUTPUT" | grep -q "arbitrary_secret"; then
	echo -e "${GREEN}PASS: Arbitrary path secret retrievable via SSH.${NC}"
else
	echo -e "${RED}FAIL: Arbitrary path secret not retrievable via SSH.${NC}"
	fail_test
fi

"$ENV_SCRIPT" --stop-wintermutt

# =======================================================================================================
echo -e "${YELLOW}--- Test Case 11: CLI - Delete Secret at Arbitrary Path (-path) ---${NC}"

# Delete the secret we just set
echo "Testing CLI rm with -path flag..."
RM_OUTPUT=$("$ENV_SCRIPT" --cli rm -path "secrets/data/wintermutt/shared" -name "arbitrary_secret" 2>&1)
echo "$RM_OUTPUT"
if echo "$RM_OUTPUT" | grep -q "deleted successfully"; then
	echo -e "${GREEN}PASS: CLI rm with -path flag deleted secret at arbitrary path.${NC}"
else
	echo -e "${RED}FAIL: CLI rm with -path failed.${NC}"
	fail_test
fi

echo -e "${GREEN}=== All Integration Tests Passed! ===${NC}"
"$ENV_SCRIPT" --stop-vault
