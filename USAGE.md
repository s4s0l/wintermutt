# wintermutt usage

## Download the running binary over SSH

Start the server with binary download enabled:

```bash
wintermutt serve ... -enable-binary-download -external-host your-host -external-port 2222
```

Then download the currently running server binary in one line:

```bash
ssh -T -p 2222 host get-binary > ./wintermutt && chmod +x ./wintermutt
```

`-T` disables PTY allocation so the binary stream is not altered.

The server also supports `cli-install`, which returns an installer script via SSH exec.

Server settings for `cli-install` address defaults:

- run server with `-external-host` and `-external-port` (both required)
- generated script uses these values for downloading `get-binary`

Example (fetch + run installer):

```bash
ssh -T -p 2222 user@host cli-install | bash
```

The installer script:

- creates `~/.config/wintermutt/wintermutt.yml` with server defaults
- downloads the binary to `~/.local/bin/wintermutt` using `get-binary`
- makes it executable

By default it uses your regular SSH identity flow (agent, yubikey, default keys).

The download is always requested as `wintermutt@<external-host>`.

Config path in the installer respects `WINTERMUTT_CONFIG_FILE`.
If unset, it writes to `~/.config/wintermutt/wintermutt.yml`.

Binary install path respects `WINTERMUTT_INSTALL_BIN_FILE`.
If unset, it writes to `~/.local/bin/wintermutt`.

Example overriding config path:

```bash
WINTERMUTT_CONFIG_FILE=./wintermutt.yml ssh -T -p 2222 user@host cli-install | bash
```

Example overriding both config and binary output paths:

```bash
WINTERMUTT_CONFIG_FILE=./wintermutt.yml WINTERMUTT_INSTALL_BIN_FILE=./wintermutt ssh -T -p 2222 user@host cli-install | bash
```

To force a specific key for the download step, set:

```bash
WINTERMUTT_INSTALL_IDENTITY_FILE=~/.ssh/id_ed25519 ssh -T -p 2222 user@host cli-install | bash
```

## CLI config file defaults

When running `wintermutt cli`, these common settings can come from config file defaults:

- `vault_address`
- `common_prefix`
- `allowed_keys_path`
- `shared_path`

Precedence in `cli` mode:

1. CLI flag value (if provided)
2. Config file value (if present)
3. Validation error if required setting is still missing

Config file location:

- `WINTERMUTT_CONFIG_FILE` when set
- otherwise `~/.config/wintermutt/wintermutt.yml`

Expected YAML format:

```yaml
wintermutt:
  vault_address: http://127.0.0.1:8200
  common_prefix: secrets/data/wintermutt
  allowed_keys_path: secrets/data/wintermutt/allowed-keys
  shared_path: secrets/data/wintermutt/shared
```

## Shared secret operations

Set shared secret:

```bash
echo "my-value" | wintermutt cli set-shared -name my_secret -shared-path secrets/data/wintermutt/shared
```

Remove shared secret:

```bash
wintermutt cli rm-shared -name my_secret -shared-path secrets/data/wintermutt/shared
```

For `set-shared` and `rm-shared`:

- `-public-key` is not allowed
- `-path` is not allowed
- `-shared-path` is required (unless provided via config file)
