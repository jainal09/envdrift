# Upgrading

## Auto-install is now opt-in

envdrift no longer auto-installs encryption binaries by default. If your
workflow relied on automatic installs, explicitly opt in:

```toml
[encryption.dotenvx]
auto_install = true

[encryption.sops]
auto_install = true
```

This keeps installs explicit and avoids unexpected downloads in CI or locked
environments.
