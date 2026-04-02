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
