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

"$ENV_SCRIPT" --start-wintermutt -common-prefix "secrets/data/wintermutt" -allowed-keys-path "secrets/data/wintermutt/allowed-keys"
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
	exit 1
fi

"$ENV_SCRIPT" --stop-wintermutt

echo -e "${GREEN}=== All Integration Tests Passed! ===${NC}"
"$ENV_SCRIPT" --stop-vault
