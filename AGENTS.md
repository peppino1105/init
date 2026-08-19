# dahua-dhip-adduser

Rust CLI that adds a user to Dahua devices via P2P/DHIP or HTTP/RPC2 protocol.
Includes a GUI (`dahua-gui`) and a license generator (`license-gen`).

## Licensing

The app is gated by a license file `licence.lic` (looked up next to the executable,
falling back to the current directory).

- `license-gen` (separate binary) generates the license:
  - `license-gen` — license for the CURRENT machine
  - `license-gen <MACHINE_ID>` — license for a given machine id
  - `--write-file` (optional `--output <path>`) writes `licence.lic` directly
- A license is valid if it is **either**:
  1. the plaintext master key `A7fK3mP9xQ2Lz8WcR5TnV6bY1HjU4eD0sGkM7aZpX9oCqF2rB8lN5tJ3uE6vIh4yO1wS2dQ8PzX7cL3mK5nR9T0H`, **or**
  2. a string that decrypts to a payload whose `machine_id` matches the current computer
- The encrypted license is AES-256-ECB (PKCS7) of a JSON payload `{"machine_id":..., "created":...}`,
  hex-encoded; the key is derived from a fixed passphrase in `src/license.rs` (`secret_key()`),
  shared by `license-gen` and the app.
- `machine_id()` = 24 hex chars from SHA-256 over the platform UUID (macOS `IOPlatformUUID`,
  Linux `/etc/machine-id`, Windows `MachineGuid`), falling back to hostname+MAC. Displayed as
  `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`, unique per computer.
- GUI startup: if the license is missing/empty/invalid-for-this-machine it shows a **blocking
  dialog** with the machine id and a field to paste the license (save → validates → writes
  `licence.lic` next to the GUI exe → re-checks). The main window stays hidden until licensed.
- CLI (`dahua-dhip-adduser`): checks the license at startup before processing any cam; on
  failure it prints `[licenza] Bloccato: ...` plus the machine id and exits with code 1.

## Usage
```
cargo run -- --serial <SERIAL> --relay -u <user> -w <pass>
cargo run -- --serial <SERIAL> --relay -u <user> -w <pass> --admin-pass <admin_pass>
cargo run --serial <SERIAL> --relay -u <user> -w <pass> --http -P 80
cargo run -f serials.txt --relay -u <user> -w <pass>
cargo run -f serials.txt --relay -u <user> -w <pass> --http -P 80
cargo run --serial <SERIAL> --relay --list-users
cargo run --serial <SERIAL> --relay --delete-user <Id>
cargo run --serial <SERIAL> --relay --delete-user-name <Name>
cargo run --serial <SERIAL> --relay -u <user> -w <pass> --group user
cargo run --serial <SERIAL> --relay --dump-account
```

### Geo-localizzazione (file OK)
- Ogni riga del file OK (add_user) è `country_code_serial_user_password_cityName`, es.
  `IT_2K02033PAE00089_camuser1_Pwd123_Rome`.
- L'IP pubblico della cam viene preso da `body/PubAddr` della risposta P2P del relay
  (campo `device_public_ip` in `HandshakeResult`).
- `src/geo.rs` risolve IP → paese/città via ip-api.com (HTTP, free, ~45 req/min). Se il lookup
  fallisce/timeout la riga usa `XX`/`N/A`. Nomi città in inglese (tier free; `lang` non applicato).
- Il lookup viene eseguito solo al successo dell'add, per ogni cam.

- `--http` is effectively legacy; both modes now use HTTP/RPC2 for addUser
- `-P` sets the PTCP bind port (default 5000)
- `--list-users` shows users as `Id<TAB>Name<TAB>Group<TAB>Password` (same format as `--dump-account`; the `Id` is the real numeric `"Id"` field, admin = 2)
- `--delete-user <Id>` deletes by the numeric `"Id"` from the user list, resolved to a Name first
- `--delete-user-name <Name>` deletes directly by username (no need to know the Id)
- `--group <admin|user>` (default `admin`): `admin` = all permissions (full AuthorityList, Type tried Normal/Admin/Operator); `user` = `Group: "user"`, Type `Normal`, AuthorityList filtered to only `Monitor*`/`Replay*` entries (monitor+playback on every channel)
- `--dump-account` prints one line per user as `Id<TAB>Name<TAB>Group<TAB>Password` (from `configManager.getConfig name="Account"`). On firmware 2021+ the `Password` column is `null` (never plaintext); the plaintext is **not** recoverable via the cloud API on such devices.
- The P2P handshake is retried up to **3 times** (3s sleep between attempts) before a serial is marked FAIL — some devices/relays intermittently drop the first attempt (`Timeout waiting for PTCP Sync from agent`).
- When `--admin-pass` is given, `--list-users`/`--dump-account`/`add_user`/`delete` try a real authenticated login first and only fall back to the bypass on failure. `Password` stays `null` either way on firmware 2021+.
- Duplicate detection: if all `userManager.addUser` variants fail, the tool does NOT guess "already exists" from the error code (that produced false positives — e.g. `prova_verifica`, a brand-new name, failed with the same 268632079 code as a real duplicate on `2C0359FPAE00017`). It confirms via `getUserInfoAll` (`dhip_user_exists`/`http_user_exists`): only a confirmed existing user reports `[!] user 'X' already exists on device, skipping` as OK; otherwise it's a real FAIL.
- DHIP bypass login tries `authorityType: "Admin"` combos first (`Local/Loopback`, `InetWeb/Network`, `Web/Direct`), falling back to `Default`. Works fine on cameras where addUser succeeds (verified on `2K02033PAE00089`, add succeeds on first `Type=Admin` variant).
- **Hardened firmware** (`2C0359FPAE00017`): the bypass session can READ users (`getUserInfoAll`) but `addUser` is always rejected with `268632079 "Component error: login challenge!"` for every username/Type/authorityType — account management requires a genuinely authenticated session. `--admin-pass` is mandatory on such devices; without it the tool correctly reports FAIL instead of a false OK.

## GUI

`cargo run --bin dahua-gui` (second binary, `src/bin/dahua-gui.rs`) — egui window that
spawns the CLI as a subprocess and streams its stdout/stderr into a log panel.

- Fields: serial (one or more, space/comma separated) OR a serials file via "Sfoglia..." (button `X` to clear)
- Group radio (right of the serial field): **admin (tutti i permessi)** or **user (monitor+playback)** → passed as `--group user` when `user` is selected
- Operation radio: **add_user** (shows Utente+Password+Memo), **list**, **delete** (shows a dedicated "Utente da eliminare" field passed as `--delete-user-name`)
- File OK / File NOK paths (only used by add_user/delete), Verbose checkbox, "Elabora" button
- "Esci" button closes the app and kills any running subprocess
- The GUI locates the CLI binary next to its own executable (`target/debug/dahua-dhip-adduser`)

## How it works

### Unified flow (both modes)
1. **P2P Handshake** — connects to Dahua P2P relay, establishes P2P session
2. **DHIP Challenge** — sends `global.login` on port 5000 to get the **DHIP numeric realm**
3. **HTTP/RPC2 addUser** — POST /RPC2_Login (bypass) → POST /RPC2 with `MD5(user:realm:password)` using the DHIP numeric realm, no `passwordType`
4. **PTCP Disconnect** — close the tunnel

Both `--http` and default mode go through this same flow. The only difference is the bind port (for potential firewall compat).

## Key Findings

### The password hash
- **addUser stores `MD5(username:realm:password)` (HA1 format) with no `passwordType` field** — this is the correct format for SmartPSS compatibility
- The **DHIP numeric realm** (e.g. `"1234567890"` from port 5000 challenge) is used for the hash, NOT the HTTP challenge realm (`"Login to ..."`)
- SmartPSS uses the same numeric realm for its own auth hash

### P2P channel auth (firmware 2023+)
- Some DVRs (newer firmware) refuse the anonymous P2P channel with **403**. The relay reports the error in the body:
  - `DevPwd_InvalidSalt` = anonymous channel refused (no `<RandSalt>` sent)
  - `DevPwd_InvalidDigest` = salt accepted, wrong device credentials (or empty password)
- The fix (implemented in `p2p.rs`): query `/info/device/{serial}` → decrypt the `<Info>` payload (AES-256-OFB with **fixed** key `kRjmsUB&ezmdGLL67H#$ojw@XflcaIaf` / IV `MydvJw*Iw1w&i^kk`) → get `randsalt`; then retry `p2p-channel` with `IpEncrptV2` + `DevAuth`:
  - `key = MD5("{user}:Login to {randsalt}:{password}")` uppercase hex (same HA1 realm format)
  - `LocalAddr` encrypted with AES-256-OFB (IV `2z52*lk9o6HRyJrf`) using key = PBKDF2-HMAC-SHA256(`key`, str(nonce), 20000, 32)
  - `DevAuth = base64(HMAC-SHA256(key, "{nonce}{unix_ts}{encrypted_LocalAddr}"))`
  - `relay-channel` uses the same `DevAuth` with a new nonce and empty payload
- The user for DevAuth is the **device account** (`--admin-user`, default `admin`) and the password is `--admin-pass` (`-p`). If the device has a password set, it **must** be provided (`--admin-pass <pwd>`) or the channel stays 403.
- Crypto verified against dh-p2p reference vectors in `p2p.rs` tests (`cargo test`).

### addUser over DHIP vs HTTP
- **DHIP addUser works on most devices** (verified on `2K02033PAE00089`): the HA1 hash is stored and the device accepts it. Earlier failures were specific to sending `passwordType: "MD5"` (stores `MD5(password)`, breaking SmartPSS login verification).
- Current DHIP addUser omits `passwordType` and stores `MD5(user:realm:password)` verbatim — same result as the HTTP/RPC2 path.
- The DHIP add flow tries HTTP/RPC2 first, then falls back to DHIP addUser when the HTTP challenge fails (error `268632079` on ports 80/5000 for some devices, e.g. `2K02033PAE00089`, `2C0359FPAE00017`).
- On hardened firmware (`2C0359FPAE00017`) DHIP addUser is rejected for every variant — only a real `--admin-pass` session can add users there.

### Protocol
- Working app uses HTTP POST to `/RPC2_Login` and `/RPC2`, not DHIP binary
- Login bypass: `passwordType: "Default"`, `loginType: "Loopback"`, `clientType: "Local"` (authorityType `Admin` preferred first, falls back to `Default`)
- No `configManager.setConfig` or `AuthorityList` needed for addUser

### Deleting users
- `userManager.deleteUser` takes **`params: {"name": <username>}`** — NOT a `user` object
- All other param shapes (`{"user": {...}}`, `{"account": {...}}`, arrays, `{"Id": N}`, etc.) fail with `268894211 "Request invalid param!"`
- Sending a full user object (from `getUserInfoAll`) back to `deleteUser` can make the device drop the PTCP channel
- `--delete-user <Id>` resolves the Id → Name via `getUserInfoAll`, then calls `deleteUser` with `{"name": <Name>}`

## Error Codes
- `268894209` = Invalid Request (console service not supported)
- `268894210` = Method not found
- `268894211` = Request invalid param (wrong parameter structure)
- `268959743` = Unknown error (service internal error — often privilege or validation)

## Build
- `cargo build` / `cargo run`
- `cargo build --all-targets` — builds CLI + GUI + license-gen
- `cargo build --release`
