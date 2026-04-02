# wintermutt usage

## 1) wintermutt reference

`wintermutt` has two modes:

- `serve`: runs the SSH server, authenticates clients via SSH keys, and serves secrets from Vault.
- `cli`: admin client to manage secrets and allowed keys in Vault.

Mode summary:

```bash
wintermutt serve [options]
wintermutt cli [options] <operation>
wintermutt help [serve|cli]
```

### serve mode

Main responsibility:

- accept SSH connections and output exported secrets for authenticated keys.

Important flags:

- `-vault-address`, `-app-role-id`, `-secret-id-file`, `-common-prefix`
- `-shared-path`
- `-allowed-keys-path`
- `-enable-binary-download`
- `-external-host`, `-external-port` (required; used by `cli-install`)

### cli mode

Main responsibility:

- manage secrets and key allowlist in Vault.

Operations:

- `set`, `rm` (per-key or `-path`)
- `set-shared`, `rm-shared` (shared path)
- `allow`, `revoke`, `list-allowed`

Config defaults for `cli` mode:

- file path: `WINTERMUTT_CONFIG_FILE` or `~/.config/wintermutt/wintermutt.yml`
- precedence: explicit CLI flag > config file > required-value error

Expected config file schema:

```yaml
wintermutt:
  vault_address: http://127.0.0.1:8200
  common_prefix: secrets/data/wintermutt
  shared_path: secrets/data/wintermutt/shared
  allowed_keys_path: secrets/data/wintermutt/allowed-keys
```

### SSH exec commands

`serve` mode also supports SSH `exec` commands:

- `get-binary`: streams current running binary.
- `cli-install`: streams installer script.

Both require server flag:

- `-enable-binary-download`

Examples:

```bash
ssh -T -p 2222 wintermutt@your-host get-binary > ./wintermutt && chmod +x ./wintermutt
ssh -T -p 2222 wintermutt@your-host cli-install | bash
```

Installer env overrides:

- `WINTERMUTT_CONFIG_FILE` (default `~/.config/wintermutt/wintermutt.yml`)
- `WINTERMUTT_INSTALL_BIN_FILE` (default `~/.local/bin/wintermutt`)
- `WINTERMUTT_INSTALL_IDENTITY_FILE` (optional `ssh -i ...` for download step)

Example with overrides:

```bash
WINTERMUTT_CONFIG_FILE=./wintermutt.yml \
WINTERMUTT_INSTALL_BIN_FILE=./wintermutt \
WINTERMUTT_INSTALL_IDENTITY_FILE=~/.ssh/id_ed25519 \
ssh -T -p 2222 wintermutt@your-host cli-install | bash
```

---

## 2) installation user story (step-by-step)

This walkthrough uses:

- Vault policies for server and admin user
- AppRole auth for server
- CLI installation over SSH
- allowing a client key and retrieving secrets with it

### Step 0: define environment values

```bash
export VAULT_ADDR="http://127.0.0.1:8200"

export WM_MOUNT="secrets"
export WM_PREFIX="$WM_MOUNT/data/wintermutt"
export WM_SHARED_PATH="$WM_MOUNT/data/wintermutt/shared"
export WM_ALLOWED_KEYS_PATH="$WM_MOUNT/data/wintermutt/allowed-keys"

export WM_SERVER_POLICY="wintermutt-server"
export WM_ADMIN_POLICY="wintermutt-admin"
export WM_ROLE_NAME="wintermutt-server"

export WM_ROLE_ID_FILE="$PWD/wintermutt_role_id"
export WM_SECRET_ID_FILE="$PWD/wintermutt_secret_id"

export WM_SSH_HOST="your-host"
export WM_SSH_PORT="2222"

export WM_KEY_PRIV="$HOME/.ssh/wintermutt_demo"
export WM_KEY_PUB="$HOME/.ssh/wintermutt_demo.pub"
```

### Step 1: create server policy (read/list)

```bash
cat > ./wintermutt-server.hcl <<'EOF'
path "secrets/metadata/wintermutt/*" {
  capabilities = ["list", "read"]
}

path "secrets/data/wintermutt/*" {
  capabilities = ["read"]
}
EOF

vault policy write "$WM_SERVER_POLICY" ./wintermutt-server.hcl
```

### Step 2: create AppRole for server and save credentials

```bash
vault auth enable approle || true

vault write "auth/approle/role/$WM_ROLE_NAME" \
  token_policies="$WM_SERVER_POLICY" \
  token_ttl=1h \
  token_max_ttl=4h

vault read -field=role_id "auth/approle/role/$WM_ROLE_NAME/role-id" > "$WM_ROLE_ID_FILE"
vault write -f -field=secret_id "auth/approle/role/$WM_ROLE_NAME/secret-id" > "$WM_SECRET_ID_FILE"

export WM_ROLE_ID="$(cat "$WM_ROLE_ID_FILE")"
```

### Step 3: create admin policy (manage secrets and allowlist)

```bash
cat > ./wintermutt-admin.hcl <<'EOF'
path "secrets/metadata/wintermutt/*" {
  capabilities = ["list", "read"]
}

path "secrets/data/wintermutt/*" {
  capabilities = ["create", "update", "read", "delete"]
}
EOF

vault policy write "$WM_ADMIN_POLICY" ./wintermutt-admin.hcl
```

Now bind `wintermutt-admin` policy to your Vault user/group/token (depends on your auth backend), then log in with Vault CLI as that user.

Assumption below: current `vault` CLI session has `wintermutt-admin` permissions.

### Step 3b: create short-lived child token for CLI actions

This keeps admin operations scoped to a 10-minute token and avoids storing token in a file.

```bash
export WM_ADMIN_TOKEN="$(
  vault token create \
    -policy="$WM_ADMIN_POLICY" \
    -ttl=10m \
    -format=json | jq -r '.auth.client_token'
)"
```

All subsequent `wintermutt cli` commands use:

- `-vault-token-file <(printf '%s' "$WM_ADMIN_TOKEN")`

Note: `<(...)` is Bash process substitution syntax.

### Step 4: start wintermutt server

```bash
wintermutt serve \
  -vault-address "$VAULT_ADDR" \
  -app-role-id "$WM_ROLE_ID" \
  -secret-id-file "$WM_SECRET_ID_FILE" \
  -common-prefix "$WM_PREFIX" \
  -shared-path "$WM_SHARED_PATH" \
  -allowed-keys-path "$WM_ALLOWED_KEYS_PATH" \
  -enable-binary-download \
  -external-host "$WM_SSH_HOST" \
  -external-port "$WM_SSH_PORT" \
  -listen-address ":$WM_SSH_PORT"
```

### Step 5: create sample SSH keypair for client

```bash
ssh-keygen -t ed25519 -f "$WM_KEY_PRIV" -N "" -C "wintermutt-demo"
```

### Step 6: install CLI over SSH

```bash
ssh -T -p "$WM_SSH_PORT" "wintermutt@$WM_SSH_HOST" cli-install | bash
```

Default outputs after install:

- config: `~/.config/wintermutt/wintermutt.yml`
- binary: `~/.local/bin/wintermutt`

### Step 7: allow the sample key

```bash
~/.local/bin/wintermutt cli \
  -vault-token-file <(printf '%s' "$WM_ADMIN_TOKEN") \
  allow \
  -public-key "$WM_KEY_PUB"
```

### Step 8: add secrets

Add key-specific secret:

```bash
echo "my-db-password" | ~/.local/bin/wintermutt cli \
  -vault-token-file <(printf '%s' "$WM_ADMIN_TOKEN") \
  set \
  -public-key "$WM_KEY_PUB" \
  -name db_password
```

Add shared secret:

```bash
echo "shared-api-key" | ~/.local/bin/wintermutt cli \
  -vault-token-file <(printf '%s' "$WM_ADMIN_TOKEN") \
  set-shared \
  -name api_key
```

### Step 9: retrieve secrets over SSH using the key

```bash
ssh -i "$WM_KEY_PRIV" -p "$WM_SSH_PORT" "wintermutt@$WM_SSH_HOST"
```

Expected output format:

```bash
export db_password="my-db-password"
export api_key="shared-api-key"
```

To load directly into current shell:

```bash
eval "$(ssh -i "$WM_KEY_PRIV" -p "$WM_SSH_PORT" "wintermutt@$WM_SSH_HOST")"
```
