# wintermutt usage

## Download the running binary over SSH

Start the server with binary download enabled:

```bash
wintermutt serve ... -enable-binary-download
```

Then download the currently running server binary in one line:

```bash
ssh -T -i ~/.ssh/id_ed25519 -p 2222 user@host get-binary > ./wintermutt && chmod +x ./wintermutt
```

`-T` disables PTY allocation so the binary stream is not altered.

## CLI config file defaults

When running `wintermutt cli`, these common settings can come from config file defaults:

- `vault_address`
- `common_prefix`
- `allowed_keys_path`

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
```
