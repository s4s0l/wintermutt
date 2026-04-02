#!/bin/bash

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CONTAINER_NAME="wintermutt-vault"
VAULT_NETWORK="${VAULT_NETWORK:-}"
VAULT_TOKEN="root"
ROLE_NAME="wintermutt-role"
POLICY_NAME="wintermutt-policy"
MOUNT_PATH="secrets"
KEYS_DIR="$DIR/../build/test_keys"
VAULT_TOKEN_FILE="$KEYS_DIR/test_vault_token"
SERVER_PID_FILE="$KEYS_DIR/server.pid"
SERVER_LOG_FILE="$KEYS_DIR/server.log"

# Helper to get current Vault address (Internal IP)
get_vault_addr() {
	if [ -n "$VAULT_NETWORK" ]; then
		V_IP=$(docker inspect -f "{{with index .NetworkSettings.Networks \"$VAULT_NETWORK\"}}{{.IPAddress}}{{end}}" "$CONTAINER_NAME" 2>/dev/null)
	fi
	if [ -z "$V_IP" ]; then
		V_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_NAME" 2>/dev/null || echo "127.0.0.1")
	fi
	echo "http://$V_IP:8200"
}

# Helper for vault commands in docker
v_exec() {
	docker exec -e "VAULT_TOKEN=$VAULT_TOKEN" -e "VAULT_ADDR=$(get_vault_addr)" "$CONTAINER_NAME" vault "$@"
}

mkdir -p "$KEYS_DIR"

stop_vault() {
	echo "Stopping Vault container..."
	docker rm -f $CONTAINER_NAME >/dev/null 2>&1 || true
	for i in $(seq 1 10); do
		if ! docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
			break
		fi
		sleep 1
	done
	rm -f "$KEYS_DIR/test_role_id" "$KEYS_DIR/test_secret_id" "$VAULT_TOKEN_FILE"
	echo "Vault stopped."
}

start_vault() {
	stop_vault

	mkdir -p "$KEYS_DIR"
	echo "Saving Vault token to $VAULT_TOKEN_FILE..."
	echo "$VAULT_TOKEN" >"$VAULT_TOKEN_FILE"
	chmod 600 "$VAULT_TOKEN_FILE"

	echo "Generating test SSH keys..."
	[ -f "$KEYS_DIR/id_rsa" ] || ssh-keygen -t rsa -b 2048 -f "$KEYS_DIR/id_rsa" -N "" -q
	[ -f "$KEYS_DIR/id_ed25519" ] || ssh-keygen -t ed25519 -f "$KEYS_DIR/id_ed25519" -N "" -q
	[ -f "$KEYS_DIR/id_rsa_unauthorized" ] || ssh-keygen -t rsa -b 2048 -f "$KEYS_DIR/id_rsa_unauthorized" -N "" -q # Third key, unauthorized

	# Extract fingerprints and convert to hex-encoded strings
	# ssh-keygen returns format like "SHA256:Hx9G.../...rtytE" where the part after SHA256: is base64-encoded bytes
	# We decode the base64 bytes, then encode as hex for path-safe fingerprint
	RSA_FINGERPRINT_RAW=$(ssh-keygen -l -E sha256 -f "$KEYS_DIR/id_rsa.pub" | awk '{print $2}')
	ED25519_FINGERPRINT_RAW=$(ssh-keygen -l -E sha256 -f "$KEYS_DIR/id_ed25519.pub" | awk '{print $2}')
	# Remove SHA256: prefix, decode base64 (with -i to ignore invalid input), then encode as hex
	RSA_FINGERPRINT=$(echo "${RSA_FINGERPRINT_RAW#SHA256:}" | base64 -d -i 2>/dev/null | od -An -tx1 | tr -d ' \n')
	ED25519_FINGERPRINT=$(echo "${ED25519_FINGERPRINT_RAW#SHA256:}" | base64 -d -i 2>/dev/null | od -An -tx1 | tr -d ' \n')

	echo "RSA Fingerprint (Authorized): $RSA_FINGERPRINT"
	echo "Ed25519 Fingerprint (Authorized): $ED25519_FINGERPRINT"

	echo "Starting Vault in dev mode..."
	NETWORK_ARG=""
	if [ -n "$VAULT_NETWORK" ]; then
		echo "Ensuring docker network '$VAULT_NETWORK' exists..."
		if ! docker network inspect "$VAULT_NETWORK" >/dev/null 2>&1; then
			echo "Error: docker network '$VAULT_NETWORK' does not exist"
			exit 1
		fi
		NETWORK_ARG="--network $VAULT_NETWORK"
	fi

	# Aggressively ensure container is gone before starting
	for attempt in $(seq 1 3); do
		docker rm -f $CONTAINER_NAME >/dev/null 2>&1 || true
		# Wait until Docker confirms it's gone
		while docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; do
			sleep 1
		done
		# Extra wait for Docker daemon to fully clean up
		sleep 3
		# Verify it's really gone
		if ! docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
			break
		fi
		echo "Container still exists on attempt $attempt, retrying..."
	done

	docker run -d \
		--name $CONTAINER_NAME \
		$NETWORK_ARG \
		-p 8200:8200 \
		-e "VAULT_DEV_ROOT_TOKEN_ID=$VAULT_TOKEN" \
		hashicorp/vault

	echo "Waiting for Vault to be ready..."
	until v_exec status >/dev/null 2>&1; do
		sleep 1
	done

	V_ADDR=$(get_vault_addr)
	echo "Vault Internal Address: $V_ADDR"

	echo "Configuring Vault..."
	v_exec auth enable approle
	v_exec secrets enable -path=$MOUNT_PATH kv-v2

	docker exec -e "VAULT_TOKEN=$VAULT_TOKEN" -e "VAULT_ADDR=$V_ADDR" "$CONTAINER_NAME" sh -c "cat <<EOF | vault policy write $POLICY_NAME -
path \"$MOUNT_PATH/metadata/wintermutt/*\" {
  capabilities = [\"list\", \"read\"]
}
path \"$MOUNT_PATH/data/wintermutt/*\" {
  capabilities = [\"read\"]
}
EOF"

	v_exec write auth/approle/role/$ROLE_NAME \
		token_policies="$POLICY_NAME" \
		token_ttl=1h \
		token_max_ttl=4h

	v_exec read -format=json auth/approle/role/$ROLE_NAME/role-id | grep -oE '"role_id": "([^"]+)"' | cut -d'"' -f4 >"$KEYS_DIR/test_role_id"
	v_exec write -f -format=json auth/approle/role/$ROLE_NAME/secret-id | grep -oE '"secret_id": "([^"]+)"' | cut -d'"' -f4 >"$KEYS_DIR/test_secret_id"

	# Save allowed keys JSON (RSA and Ed25519 fingerprints)
	RSA_KEY_PUB=$(cat "$KEYS_DIR/id_rsa.pub")
	ED_KEY_PUB=$(cat "$KEYS_DIR/id_ed25519.pub")
	# Marshal keys to authorized format for comparison
	MARSHALED_RSA_KEY="$(jq -n --arg key "$RSA_KEY_PUB" '$key')"
	MARSHALED_ED_KEY="$(jq -n --arg key "$ED_KEY_PUB" '$key')"

	# Vault KV v2 expects a JSON object with a list of strings for the keys
	# Ensure keys are properly escaped for JSON
	# Example JSON structure: {"keys": ["ssh-rsa AAAA...", "ssh-ed25519 BBBB..."]}
	v_exec kv put $MOUNT_PATH/wintermutt/allowed-keys keys="[$MARSHALED_RSA_KEY, $MARSHALED_ED_KEY]"

	echo "Seeding test secrets..."
	# Shared secrets
	v_exec kv put $MOUNT_PATH/wintermutt/shared/api_key value="shared-api-key-abc"
	v_exec kv put $MOUNT_PATH/wintermutt/shared/db_password value="shared-secret-123"

	# RSA Client secrets (authorized)
	v_exec kv put $MOUNT_PATH/wintermutt/$RSA_FINGERPRINT/db_password value="rsa-specific-password"
	v_exec kv put $MOUNT_PATH/wintermutt/$RSA_FINGERPRINT/WINTERMUTT_SHARED_PATH value="$MOUNT_PATH/data/wintermutt/shared"

	# Ed25519 Client secrets (authorized, no shared path)
	v_exec kv put $MOUNT_PATH/wintermutt/$ED25519_FINGERPRINT/db_password value="ed25519-specific-password"
	# No WINTERMUTT_SHARED_PATH for Ed25519

	# Unauthorized RSA client has no secrets seeded for its fingerprint
	# and is not listed in allowed-keys.

	echo "Vault is ready."
}

wintermutt_start() {
	if [ ! -f "$KEYS_DIR/test_role_id" ] || [ ! -f "$KEYS_DIR/test_secret_id" ]; then
		echo "Error: Vault test environment is not running. Run --start-vault first."
		exit 1
	fi

	V_ADDR=$(get_vault_addr)
	SERVER_BIN="$DIR/../build/server"
	if [ ! -f "$SERVER_BIN" ]; then
		echo "Server binary not found. Building..."
		(cd "$DIR/.." && just build)
	fi

	# Pass additional arguments to the server binary
	SERVER_ARGS=("$@") # $@ will capture all arguments passed after --start-wintermutt

	echo "Starting wintermutt server in background (Vault at $V_ADDR)..."
	"$SERVER_BIN" serve \
		-vault-address "$V_ADDR" \
		-enable-binary-download \
		-external-host "localhost" \
		-external-port "2222" \
		-app-role-id "$(cat "$KEYS_DIR/test_role_id")" \
		-secret-id-file "$KEYS_DIR/test_secret_id" \
		-common-prefix "secrets/data/wintermutt" \
		-listen-address ":2222" \
		-storage "$KEYS_DIR" \
		"${SERVER_ARGS[@]}" >"$SERVER_LOG_FILE" 2>&1 &
	if [[ ! -f "$HOME/.ssh/known_hosts" ]]; then
	    mkdir -p "$HOME/.ssh"
	    touch "$HOME/.ssh/known_hosts"
		chmod 600 "$HOME/.ssh/known_hosts"
		chmod 700 "$HOME/.ssh"
	fi
	ssh-keygen -f "$HOME/.ssh/known_hosts" -R '[localhost]:2222'
	echo $! >"$SERVER_PID_FILE"
	echo "Server started with PID $(cat "$SERVER_PID_FILE"). Logs: $SERVER_LOG_FILE"
}

wintermutt_stop() {
	if [ -f "$SERVER_PID_FILE" ]; then
		PID=$(cat "$SERVER_PID_FILE")
		echo "Stopping wintermutt server (PID $PID)..."
		kill "$PID" 2>/dev/null || true
		rm -f "$SERVER_PID_FILE"
		for i in $(seq 1 10); do
			if ! kill -0 "$PID" 2>/dev/null; then
				break
			fi
			sleep 1
		done
		# Force kill if still running
		kill -9 "$PID" 2>/dev/null || true
		echo "Server stopped."
	else
		echo "Server PID file not found."
	fi
	# Also kill anything on port 2222
	if command -v fuser >/dev/null 2>&1; then
		fuser -k 2222/tcp 2>/dev/null || true
	fi
	sleep 1
}

stop_all() {
	echo "Stopping all services..."
	wintermutt_stop
	stop_vault
	echo "All services stopped."
}

start_all() {
	echo "Starting all services..."
	start_vault
	wintermutt_start
	echo "All services started."
}

ssh_rsa() {
	ssh -i "$KEYS_DIR/id_rsa" -p 2222 -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -o BatchMode=yes -o PreferredAuthentications=publickey localhost
}

ssh_ed25519() {
	ssh -i "$KEYS_DIR/id_ed25519" -p 2222 -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -o BatchMode=yes -o PreferredAuthentications=publickey localhost
}

ssh_rsa_unauthorized() {
	ssh -i "$KEYS_DIR/id_rsa_unauthorized" -p 2222 -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -o BatchMode=yes -o PreferredAuthentications=publickey localhost
}

wintermutt_cli() {
	if [ ! -f "$KEYS_DIR/test_vault_token" ]; then
		echo "Error: Vault test environment is not running. Run --start-vault first."
		exit 1
	fi

	VAULT_TOKEN=$(cat "$VAULT_TOKEN_FILE")
	VAULT_ADDR=$(get_vault_addr)
	CLI_BIN="$DIR/../build/server"
	if [ ! -f "$CLI_BIN" ]; then
		echo "Binary not found. Building..."
		(cd "$DIR/.." && just build)
	fi

	# Pass additional arguments to the CLI binary
	CLI_ARGS=("$@") # $@ will capture all arguments passed after --cli

	echo "Running wintermutt CLI (Vault at $VAULT_ADDR)..."
	"$CLI_BIN" cli -vault-address "$VAULT_ADDR" -vault-token-file "$VAULT_TOKEN_FILE" "${CLI_ARGS[@]}"
}

case "$1" in
--start-vault)
	start_vault
	;;
--stop-vault)
	stop_vault
	;;
--start-wintermutt)
	shift                 # Remove --start-wintermutt from arguments
	wintermutt_start "$@" # Pass remaining arguments to wintermutt_start
	;;
--stop-wintermutt)
	wintermutt_stop
	;;
--stop-all)
	stop_all
	;;
--start-all)
	start_all
	;;
--ssh-rsa)
	ssh_rsa
	;;
--ssh-ed25519)
	ssh_ed25519
	;;
--ssh-rsa-unauthorized)
	ssh_rsa_unauthorized
	;;
--cli)
	shift               # Remove --cli from arguments
	wintermutt_cli "$@" # Pass remaining arguments to wintermutt_cli
	;;
*)
	echo "Usage: $0 {--start-vault|--stop-vault|--start-wintermutt [server_args]|--stop-wintermutt|--stop-all|--start-all|--ssh-rsa|--ssh-ed25519|--ssh-rsa-unauthorized|--cli [cli_args]}"
	exit 1
	;;
esac
