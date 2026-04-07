# wintermutt usage

## Reference

`wintermutt` has two modes:

```bash
wintermutt serve [options]    # SSH server serving secrets from Vault
wintermutt cli [options] <operation>  # Admin client for Vault
wintermutt help [serve|cli]   # Mode-specific help
```

### serve mode

Accepts SSH connections and outputs `export` statements for authenticated keys.

**Required flags:**

- `-vault-address` - Vault server URL
- `-app-role-id` - AppRole Role ID (mutually exclusive with `-app-role-id-file`)
- `-app-role-id-file` - Path to file containing the AppRole Role ID (mutually exclusive with `-app-role-id`)
- `-secret-id-file` - Path to file with AppRole Secret ID
- `-common-prefix` - Vault path prefix (e.g., `secrets/data/wintermutt`)
- `-external-host` - Public SSH hostname (for cli-install)
- `-external-port` - Public SSH port (for cli-install)
- `-external-vault-address` - Vault address written to client config (for cli-install)

**Optional flags:**

- `-listen-address` - SSH listen address (default `:2222`)
- `-shared-path` - Vault path for shared secrets
- `-allowed-keys-path` - Vault path for allowed keys JSON
- `-enable-binary-download` - Allow `get-binary` and `cli-install` SSH exec
- `-disallow-download-by-anybody` - Restrict downloads to allowed keys only
- `-storage` - Directory for SSH host key (default `.`)
- `-log-level` - `debug`, `info`, `warn`, `error` (default `info`)
- `-log-format` - `text`, `json` (default `text`)

### cli mode

Manages secrets and key allowlist in Vault.

**Operations:**

- `set` - Set a secret for a public key
- `rm` - Delete a secret for a public key
- `list` - List secret names for a public key
- `set-shared` - Set a shared secret
- `rm-shared` - Delete a shared secret
- `list-shared` - List shared secret names
- `allow` - Add a public key to allowed list
- `revoke` - Remove a public key from allowed list
- `list-allowed` - List allowed public keys

**Options:**

- `-vault-address` - Vault server URL
- `-common-prefix` - Vault path prefix
- `-vault-token-file` - Path to file with Vault token (defaults to `~/.vault-token` when omitted)
- `-public-key` - Path to public key file
- `-name` - Secret name
- `-path` - Override Vault path directly
- `-shared-path` - Shared secrets path
- `-allowed-keys-path` - Allowed keys path
- `-log-level`, `-log-format` - Logging options

**Config file** (cli mode only):

Loaded from `WINTERMUTT_CONFIG_FILE` or `~/.config/wintermutt/wintermutt.yml`:

```yaml
wintermutt:
  vault_address: http://127.0.0.1:8200
  common_prefix: secrets/data/wintermutt
  shared_path: secrets/data/wintermutt/shared
  allowed_keys_path: secrets/data/wintermutt/allowed-keys
```

CLI flag precedence: explicit flag > config file > error.

Vault token file resolution (cli mode): explicit `-vault-token-file` > `~/.vault-token` > error (`-vault-token-file` is required).

### SSH exec commands

When `-enable-binary-download` is set:

```bash
# Download the server binary
ssh -T -p 2222 wintermutt@host get-binary > ./wintermutt && chmod +x ./wintermutt

# Install CLI with config
ssh -T -p 2222 wintermutt@host cli-install | bash
```

Installer environment overrides:

- `WINTERMUTT_CONFIG_FILE` - Config path (default `~/.config/wintermutt/wintermutt.yml`)
- `WINTERMUTT_INSTALL_BIN_FILE` - Binary path (default `~/.local/bin/wintermutt`)
- `WINTERMUTT_INSTALL_IDENTITY_FILE` - SSH key for download step

Example with overrides:

```bash
WINTERMUTT_CONFIG_FILE=./wintermutt.yml \
WINTERMUTT_INSTALL_BIN_FILE=./wintermutt \
WINTERMUTT_INSTALL_IDENTITY_FILE=~/.ssh/id_ed25519 \
ssh -T -p 2222 wintermutt@host cli-install | bash
```

---

## Running in Docker

### Docker Compose

The recommended way to run wintermutt in Docker is with Docker Compose.
Supply credentials as read-only bind-mounts so they are never baked into the image.
The storage volume holds the SSH host key; mounting it persistently avoids generating a new key on every restart.

```yaml
services:
  wintermutt:
    image: wintermutt:latest
    build: .
    ports:
      - "2222:2222"
    volumes:
      # Persistent storage for the SSH host key
      - wintermutt-storage:/app/storage
      # Vault credentials – mount as read-only files
      - ./role_id:/run/secrets/role_id:ro
      - ./secret_id:/run/secrets/secret_id:ro
    command:
      - serve
      - -vault-address=http://vault:8200
      - -app-role-id-file=/run/secrets/role_id
      - -secret-id-file=/run/secrets/secret_id
      - -common-prefix=secrets/data/wintermutt
      - -external-host=your.host.example
      - -external-port=2222
      - -external-vault-address=https://vault.your.host.example:8200
      - -storage=/app/storage
    healthcheck:
      test: ["CMD", "nc", "-z", "127.0.0.1", "2222"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s

volumes:
  wintermutt-storage:
```

**Storage mount** — `-storage` points wintermutt to the directory where it reads and writes the SSH host key.
Mapping a named volume (or a host path) to that directory ensures the host key survives container restarts, so clients are not confronted with host-key-changed warnings.

**Healthcheck** — the check opens a TCP connection to the SSH port.
A successful connection means the server is up and accepting connections.
The `start_period` gives the server time to authenticate with Vault before the first check is evaluated.

> **Note:** The healthcheck uses `nc` (netcat), which is included in the Alpine base image via BusyBox.
> If you use a different base image, replace the check with an equivalent TCP probe.

---

## Quick start

### 1. Start Vault (dev mode)

```bash
docker run -d --name vault -p 8200:8200 -e "VAULT_DEV_ROOT_TOKEN_ID=root" hashicorp/vault
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="root"
```

### 2. Configure Vault

```bash
# Enable AppRole and KV
vault auth enable approle
vault secrets enable -path=secrets kv-v2

# Create policy
cat > wintermutt-policy.hcl <<'EOF'
path "secrets/metadata/wintermutt/*" {
  capabilities = ["list", "read"]
}
path "secrets/data/wintermutt/*" {
  capabilities = ["read"]
}
EOF
vault policy write wintermutt-policy wintermutt-policy.hcl

# Create AppRole
vault write auth/approle/role/wintermutt-role \
  token_policies="wintermutt-policy" \
  token_ttl=1h token_max_ttl=4h

# Save credentials
vault read -field=role_id auth/approle/role/wintermutt-role/role-id > role_id
vault write -f -field=secret_id auth/approle/role/wintermutt-role/secret-id > secret_id
```

### 3. Start server

```bash
wintermutt serve \
  -vault-address "$VAULT_ADDR" \
  -app-role-id "$(cat role_id)" \
  -secret-id-file secret_id \
  -common-prefix "secrets/data/wintermutt" \
  -shared-path "secrets/data/wintermutt/shared" \
  -allowed-keys-path "secrets/data/wintermutt/allowed-keys" \
  -enable-binary-download \
  -external-host "localhost" \
  -external-port "2222" \
  -external-vault-address "$VAULT_ADDR" \
  -listen-address ":2222"
```

### 4. Retrieve secrets

First, generate an SSH key and add it via CLI (see below for CLI examples):

```bash
# Generate SSH key
ssh-keygen -t ed25519 -f ~/.ssh/wintermutt_demo -N "" -C "demo"

# Allow the key (requires admin token with wintermutt-admin policy)
wintermutt cli -vault-token-file <(echo "$VAULT_TOKEN") allow -public-key ~/.ssh/wintermutt_demo.pub

# Set secrets
echo "my-db-password" | wintermutt cli -vault-token-file <(echo "$VAULT_TOKEN") \
  set -public-key ~/.ssh/wintermutt_demo.pub -name db_password
```

Now retrieve secrets:

```bash
ssh -i ~/.ssh/wintermutt_demo -p 2222 -o StrictHostKeyChecking=no localhost
```

Outputs `export` statements:

```bash
export db_password="my-db-password"
```

---

## CLI examples

### Using config file

The file is created automatically to match the server settings
if using ssh command `cli-install`.

```bash
# Create config
mkdir -p ~/.config/wintermutt
cat > ~/.config/wintermutt/wintermutt.yml <<EOF
wintermutt:
  vault_address: $VAULT_ADDR
  common_prefix: secrets/data/wintermutt
  shared_path: secrets/data/wintermutt/shared
  allowed_keys_path: secrets/data/wintermutt/allowed-keys
EOF

# List allowed keys (uses config file defaults)
wintermutt cli -vault-token-file <(echo "$VAULT_TOKEN") list-allowed
```

### Set/remove secrets

```bash
PUB_KEY=~/.ssh/wintermutt_demo.pub

# Set key-specific secret
echo "new-password" | wintermutt cli \
  -vault-token-file <(echo "$VAULT_TOKEN") \
  set -public-key "$PUB_KEY" -name db_password

# Set shared secret
echo "new-api-key" | wintermutt cli \
  -vault-token-file <(echo "$VAULT_TOKEN") \
  set-shared -name api_key

# Remove secret
wintermutt cli \
  -vault-token-file <(echo "$VAULT_TOKEN") \
  rm -public-key "$PUB_KEY" -name db_password

# List secret names for key
wintermutt cli \
  -vault-token-file <(echo "$VAULT_TOKEN") \
  list -public-key "$PUB_KEY"

# Remove shared secret
wintermutt cli \
  -vault-token-file <(echo "$VAULT_TOKEN") \
  rm-shared -name api_key

# List shared secret names
wintermutt cli \
  -vault-token-file <(echo "$VAULT_TOKEN") \
  list-shared
```

### Manage allowed keys

```bash
# Allow a key
wintermutt cli \
  -vault-token-file <(echo "$VAULT_TOKEN") \
  allow -public-key ~/.ssh/new_key.pub

# Revoke a key
wintermutt cli \
  -vault-token-file <(echo "$VAULT_TOKEN") \
  revoke -public-key ~/.ssh/old_key.pub

# List allowed keys
wintermutt cli \
  -vault-token-file <(echo "$VAULT_TOKEN") \
  list-allowed
```

### Arbitrary paths

```bash
# Set secret at custom path
echo "value" | wintermutt cli \
  -vault-token-file <(echo "$VAULT_TOKEN") \
  set -path "secrets/data/wintermutt/shared" -name custom_secret

# Remove from custom path
wintermutt cli \
  -vault-token-file <(echo "$VAULT_TOKEN") \
  rm -path "secrets/data/wintermutt/shared" -name custom_secret
```
