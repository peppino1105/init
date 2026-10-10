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
cargo run --serial <SERIAL> --relay --delete-all
cargo run --serial <SERIAL> --relay --reboot
cargo run -f serials.txt --relay --reboot
cargo run --serial <SERIAL> --relay --check-p2p
cargo run -f serials.txt --relay --check-p2p
cargo run --serial <SERIAL> --relay -u <user> -w <pass> --snapshot
cargo run -f serials.txt --relay -u <user> -w <pass> --snapshot
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
  `GeoInfo` contiene `country_code`, `country` (nome paese) e `city`.
- Il lookup viene eseguito solo al successo dell'add, per ogni cam.

### Input XML SmartPSS → preservazione del `name` nel file generato
- Quando l'input dei seriali è un **file XML formato SmartPSS** (`<Device ... domain="SERIAL" name="...">`),
  il parser (`src/serials.rs`) estrae sia i seriali (`domain`) sia l'attributo `name` di ogni device.
- `parse_serials_file_with_names` / `parse_serials_content_with_names` restituiscono
  `ParsedSerials { serials, names }`; `parse_serials_file` / `parse_serials_content` restano come
  prima (solo `serials`) per compatibilità.
- Nel file XML **generato** dei seriali OK (CLI `generate_smartpss_from_ok`, GUI `generate_smartpss_file`),
  l'attributo `name` viene **copiato dall'XML di origine** quando disponibile (map serial→name);
  in assenza di XML d'origine si genera un name progressivo come prima (`{:02}_{}` / `{:02}_{country}_{}`).
- Nota: `username`/`password` nel file generato restano quelli del **nuovo** utente creato (`--user`/`--password`);
  solo il campo display `name` viene mantenuto identico all'origine.

- `--http` is effectively legacy; both modes now use HTTP/RPC2 for addUser
- `-P` sets the PTCP bind port (default 5000)
- `--list-users` shows users as `Id<TAB>Name<TAB>Group<TAB>Password` (same format as `--dump-account`; the `Id` is the real numeric `"Id"` field, admin = 2). **Now uses `dhip_established_session`** so `--list-users --try-defaults` works on old Digest firmware (previously `dhip_list_users` had its own login logic that didn't support try-defaults).
- `--delete-user <Id>` deletes by the numeric `"Id"` from the user list, resolved to a Name first
- **Fail-fast delete su Id inesistente** (`6B003ACPAZ64EDE`): se `getUserInfoAll` elenca gli utenti ma l'Id richiesto NON compare (es. Id 10 assente mentre il device ha decine di utenti), sia nel ramo DHIP sia in quello HTTP il tool abortisce SUBITO con `user Id=N not found ... (user list queried ok)` invece di esaurire ~13 varianti `deleteUser` con `{"name":null}` (tutte rifiutate con `268894211 "Request invalid param!"`) e i metodi alternativi `accountManager.deleteAccount`/`userManager.deleteUsers` (`268894210 "Method not found!"` su fw 5.2.1). Implementato: `http_find_user_object`/`http_find_user_object_by_name` ora ritornano `(Option<Value>, bool)` con bool = lista letta ok; `dhip_try_delete_user` traccia `found_in_list`.
- `--delete-user-name <Name>` deletes directly by username (no need to know the Id)
- `--reboot` riavvia ogni dispositivo sul canale DHIP della sessione stabilità (handshake → challenge → login → reboot). **Il reboot prova più varianti in sequenza** perché `magicBox.reboot` con `params: {}` su alcuni firmware (es. `3K02366PAZ523DA`) fa un power-off che NON si completa (la cam resta spenta): ordine provato → `magicBox.reboot {"mode":0}` → `magicBox.reboot {}` → `magicBox.reboot {"mode":1}` → `magicBox.restart {}` → `system.reboot {}`; la prima che risponde `result:true` vince. Se il device si riavvia subito e chiude il canale senza rispondere, il tool lo considera inviato. In GUI l'operazione "reboot" è un radio button senza campi richiesti; usa `--admin-pass`/`--try-defaults` quando il device richiede credenziali reali.
- `--check-p2p` diagnostica lo **stato P2P/cloud** di ogni dispositivo (utile quando SmartPSS risulta offline ma il tool via P2P ci arriva). Flusso: handshake → challenge → sessione → `configManager.getConfig` su più tabelle (`P2P`, `Network`, `_Cloud`, `System`, …) e stampa i campi rilevanti per il cloud (Account/User, Status/Regist/Online/State, UID, Server, Address), più l'IP pubblico del device riportato dal relay. **Ultima riga**: IP pubblico della cam + geolocalizzazione (`Public IP`, `Country` nome+codice, `City`) risolta via `geo::lookup`. La diagnosi tipica: `3K02366PAZ523DA` ha **account P2P vuoto**, quindi il tool (tunnel P2P anonimo per UID) ci arriva, ma SmartPSS in modalità direct/IP non riesce (TCP diretto a IP dietro NAT) e in modalità cloud resta offline. In GUI l'operazione "check_p2p" è un radio button senza campi richiesti.
- `--snapshot` cattura uno **snapshot JPG live di ogni canale camera attivo** del device, per verificare che le cam inquadrino correttamente. Flusso: handshake → challenge → sessione → `configManager.getConfig` su `ChannelTitle`/`VideoInChannels`/`Camera` per **scoprire i canali attivi** (fallback intermedio: **conteggio canali via SDK 37777** `sdkCmdGetChannels`, poi probe progressivo 1..=16 se nessuna fonte espone il conteggio) → **query `InetWeb` per HTTP/RTSP port** del device → **PTCP HTTP re-bind**: `global.logout` + `ptcp_disconnect` sul canale DHIP (porta 5000) + `ptcp_bind` sulla porta HTTP reale del device (default 80, letto da InetWeb) → per ogni canale tentativi in ordine: (1) GET via PTCP con auth a 3 livelli (session cookie / admin / camera) × 3 path varianti, con Digest fallback su 401; (2) POST JSON via `http_call`; (3) POST form raw via `send_http_get`; (4) **SDK 37777 attraverso il tunnel PTCP** (`src/sdk.rs`, `SdkClient::get_snapshot`): bind di un nuovo realm sulla porta **37777** (mai sull'IP pubblico, che resta dietro NAT) → `loginPacket` → sfida `resp[8]==1` → hash `SDKLoginHash` (StandardRPCHash + Gen1Hash) → `snapshot_cmd` binario (72 byte) → strip del garbage (0x0a/0xbc) → estrazione JPEG `FF D8..FF D9`; oltre a essere un fallback snapshot, lo stesso client SDK esegue la **discovery canali** quando le tabelle getConfig non espongono il conteggio; (5) se `--direct-http` è attivo: **connessione TCP diretta** all'IP pubblico del device (porta HTTP reale dal device, default 80) con Basic auth admin/camera; (6) se `--rtsp` è attivo: **client RTSP via TCP** (porta RTSP reale dal device, default 554) con negoziazione completa (OPTIONS → DESCRIBE → SETUP con `RTP/AVP/TCP;interleaved=0-1` → PLAY → ricezione pacchetti RTP → estrazione frame MJPEG) su canali 1..=16, auth admin/camera, con fallback su porta 854, Digest auth su 401. Il probe **non si ferma più dopo 3 fallimenti consecutivi**: quando il device non espone la lista canali vengono sondati **tutti i canali 1..=16** (l'avviso "all N probed channel(s) failed" viene stampato solo se falliscono tutti). Valida i magic bytes JPEG (`FF D8 FF`) e salva in `snapshots/<serial>_ch<N>.jpg`. `-u/-w` non sono più obbligatori; se omessi si usano solo session cookie e admin. In GUI: checkbox "Snapshot" + sotto-checkbox "Direct HTTP" + "RTSP" (visibili solo quando snapshot è spuntato). In CLI `--snapshot` si **combina** con add_user o `--check-p2p`, MAI da solo. **Log snapshot in errore**: `yyyyddmmhhMM.log` nella cwd. **Fallback chain**: PTCP HTTP re-bind (porta reale) → SDK 37777 via tunnel (porta reale) → Direct HTTP (porta reale) → RTSP (porta reale, fallback 854). **Canale singolo PTCP**: alcuni device accettano un solo canale PTCP alla volta → quando il ramo HTTP del tunnel fallisce e si passa all'SDK, il tool **disconnette prima il canale HTTP** (`ptcp_disconnect` su `http_realm`) e imposta `http_channel_dead=true` (i canali successivi vanno dritti all'SDK senza ritentare HTTP). L'SDK ha log per-step in verbose (`[debug] sdk: ...`) per capire dove fallisce (bind 37777 vs login resp[8] vs snapshot reply). Nota: Direct HTTP e RTSP vanno all'**IP pubblico** del device e funzionano solo se le porte sono esposte (NAT/port-forward); il percorso **SDK via tunnel** è l'unico che funziona sempre (anche dietro NAT) ed è quindi il fallback attivo consigliato. RTSP funziona solo con stream MJPEG; per H.264/H.265 (che richiedono decoder) il tool rileva il codec e restituisce None. Porte lette da `configManager.getConfig name="InetWeb"` (`HttpPort`/`RtspPort`).
- **PTCP HTTP re-bind** (snapshot): dopo aver scoperto i canali e la porta HTTP reale dal device, il tool disconnette il canale DHIP (porta 5000) e fa un nuovo `ptcp_bind` sulla porta HTTP reale del device (tipicamente 80). Questo apre un **tunnel PTCP sulla porta del web server** del device, permettendo di raggiungere il CGI snapshot anche quando il canale DHIP non lo espone e le porte HTTP/RTSP non sono esposte pubblicamente (NAT/firewall). Il realm del nuovo canale HTTP viene salvato in `ctx.dhip.realm_id` e usato da tutte le chiamate HTTP successive (`http_get_binary`, `http_call`, `send_http_get`). La sessione DHIP (session_id) rimane valida. Alcuni device accettano un solo canale PTCP alla volta: il disconnect prima del re-bind è obbligatorio.
- `--group <admin|user>` (default `admin`): `admin` = all permissions (full AuthorityList, Type tried Normal/Admin/Operator); `user` = `Group: "user"`, Type `Normal`, AuthorityList filtered to only `Monitor*`/`Replay*` entries (monitor+playback on every channel)
- `--dump-account` prints one line per user as `Id<TAB>Name<TAB>Group<TAB>Password` (from `configManager.getConfig name="Account"`). On firmware 2021+ the `Password` column is `null` (never plaintext); the plaintext is **not** recoverable via the cloud API on such devices.
- The P2P handshake is retried up to **3 times** (3s sleep between attempts) before a serial is marked FAIL — some devices/relays intermittently drop the first attempt (`Timeout waiting for PTCP Sync from agent`). I pacchetti PTCP troncati/malformati non causano più panik (`short_malformed_packets_do_not_panic`); gli errori di send (`HostUnreachable`/`No route to host`) sono gestiti da `dh_request` → `Result<(), String>` e propagati senza crashare il batch.
- When `--admin-pass` is given, `--list-users`/`--dump-account`/`add_user`/`delete` try a real authenticated login first and only fall back to the bypass on failure. `Password` stays `null` either way on firmware 2021+.
- Duplicate detection: if all `userManager.addUser` variants fail, the tool does NOT guess "already exists" from the error code (that produced false positives — e.g. `prova_verifica`, a brand-new name, failed with the same 268632079 code as a real duplicate on `2C0359FPAE00017`). It confirms via `getUserInfoAll` (`dhip_user_exists`/`http_user_exists`): only a confirmed existing user reports `[!] user 'X' already exists on device, skipping` as OK; otherwise it's a real FAIL.
- DHIP bypass login tries `authorityType: "Admin"` combos first (`Local/Loopback`, `InetWeb/Network`, `Web/Direct`), falling back to `Default`. Works fine on cameras where addUser succeeds (verified on `2K02033PAE00089`, add succeeds on first `Type=Admin` variant).
- **Hardened firmware** (`2C0359FPAE00017`): the bypass session can READ users (`getUserInfoAll`) but `addUser` is always rejected with `268632079 "Component error: login challenge!"` for every username/Type/authorityType — account management requires a genuinely authenticated session. `--admin-pass` is mandatory on such devices; without it the tool correctly reports FAIL instead of a false OK.
- **Hardened firmware variante "silenziosa"** (`2L05BD6PAZ00030`): stesso tipo di restrizione ma il dispositivo NON risponde affatto agli addUser dalla sessione bypass (droppa il canale invece di dare errore) — diagnosticato dal messaggio `device never answered any addUser`. Contromisure implementate: `--try-defaults` (prova le password di fabbrica documentate — `admin`, `123456`, `888888`, `54321`, `admin123`, `12345` — con login REALE prima del bypass, in GUI checkbox "Try default passwords"), payload addUser minimale (`Name/Password/Group/Type` + solo `Monitor`) per firmware che vanno in crash su campi inattesi, e `configManager.setConfig` sulla tabella Account come ultimo resort.
- **Firmware vecchio OldDigest** (`1J034D3PAY01528`): challenge con `"encryption":"OldDigest"`, `random:""`, realm vuoto `"Login to "`; `--try-defaults` ci entra con la password di fabbrica `admin`. MA `getUserInfoAll` con `"params":"null"` (stringa, forma legacy) fa **crashare il componente**: canale morto, silenzio totale su tutto il resto (deleteUser compreso). Fix: la risoluzione Id→Nome nel delete usa ora `"params": {}` (come il flusso list, verificato) con fallback sulla forma `"null"`, logga la risposta raw in verbose, e se il dispositivo non elenca gli utenti fallisce SUBITO senza sprecare varianti deleteUser. Inoltre `delete_users`, prima del fallback HTTP, rifà un **handshake P2P completo** (i dispositivi a canale singolo non accettano re-bind sul canale vecchio/morto).
- **Firmware vecchio OldDigest senza gestione utenti** (`2F04340PAZ00003`): challenge con `"encryption":"OldDigest"`, randsalt vuoto; `--try-defaults` fa login OK con `admin/admin` (DHIP bypass + HTTP bypass). MA il device NON risponde a NESSUN metodo di gestione utenti remota: `getUserInfoAll {}`, `getUserInfoAll "null"`, `getUserList`, `configManager.getConfig` su tutti i nomi (`Account`, `account`, `UserManager`, `Security`, `System`) → `dhip_call` ritorna None (timeout silenzioso), HTTP `RPC2` senza sessione. Il tool ora logga esplicitamente "device did not return any users" quando la lista è vuota, invece di sprecare varianti delete. Fix intermedi: `dhip_list_users` ora usa `dhip_established_session` (supporta `--try-defaults`), `http_establish_session` ora prova le default admin passwords. Il device rimane non gestibile per delete/list — il firmware è probabilmente troppo vecchio per supportare la gestione utenti remota via DHIP/HTTP.
- **Hardened firmware variante 2** (`3H050BEPAG00046`): bypass login HTTP riesce (sessione autenticata), ma il dispositivo invia **DISC** (disconnect) al primo RPC successivo (getUserInfoAll) e poi solo Heartbeats. Senza gestione DISC, il tool spreca ~30s × 6 tentativi inutili prima di arrendersi. Fix: `http_call` ora imposta un flag `LAST_CALL_DISC` quando riceve un DISC, e i call site (`http_list_users_on_port`, `http_delete_user`, `http_add_user`) abortono immediatamente con messaggio "device sent DISC — channel dead" invece di provare ogni metodo.
- **Max utenti raggiunto / falso OK da `setConfig(Account)`** (`5MMF0B22PAGC067`): aggiungere un utente quando il device ha raggiunto il numero massimo di account fa fallire `userManager.addUser` con **code 615** per ogni Type, e il fallback `configManager.setConfig(Account)` ritorna `result:true` ma **NON aggiunge davvero** l'utente. Prima il tool dichiarava OK; ora, dopo il `setConfig`, fa la verifica via `getUserInfoAll`: se l'utente NON è presente il tool stampa l'avviso (probabile limite utenti raggiunto) e ritorna **FAIL** invece del falso OK. Il code 615 nel `setConfig` viene riconosciuto e segnalato come `maximal number of users reached on device`.

## GUI

`cargo run --bin dahua-gui` (second binary, `src/bin/dahua-gui.rs`) — egui window that
spawns the CLI as a subprocess and streams its stdout/stderr into a log panel.

- Fields: serial (one or more, space/comma separated) OR a serials file via "Sfoglia..." (button `X` to clear)
- Group radio (right of the serial field): **admin (tutti i permessi)** or **user (monitor+playback)** → passed as `--group user` when `user` is selected
- Operation radio: **add_user** (shows Utente+Password+Memo), **list**, **delete** (shows a dedicated "Utente da eliminare" field with radio **Name**/**Id** — Name passes `--delete-user-name`, Id passes `--delete-user` and validates the input is numeric), **reboot**, **check_p2p**
- **Snapshot checkbox** (right below the operation radio): NOT a radio button anymore — adds `--snapshot` to the args. Only enabled with **add_user** (reuses Utente/Password) or **check_p2p** (shows Utente/Password fields inline, required as camera credentials); disabled otherwise. Not combinable with list/delete/reboot. When Snapshot is checked, two sub-checkboxes appear: **"Direct HTTP"** (retries via direct TCP to device IP port 80) and **"RTSP"** (retries via RTSP TCP to device IP port 554, MJPEG only). Hint text: "(fallback: P2P → direct IP → RTSP)".
- File OK / File NOK paths (only used by add_user/delete), Verbose checkbox, **"Try default passwords" checkbox** (`--try-defaults`, sempre visibile, a destra di Verbose), "Elabora" button
- "Esci" button closes the app and kills any running subprocess
- The GUI locates the CLI binary next to its own executable (`target/debug/dahua-dhip-adduser`)

## How it works

### Unified flow (both modes)
1. **P2P Handshake** — connects to Dahua P2P relay, establishes P2P session
2. **DHIP Challenge** — sends `global.login` on port 5000 (fallback 80) to get the **realm**; the bound PTCP channel is kept OPEN
3. **DHIP addUser on the live challenge channel** — login (real `--admin-pass` first, then bypass combos) + `userManager.addUser`, no re-bind
4. **HTTP/RPC2 fallback** — only if DHIP failed: POST /RPC2_Login (bypass) → POST /RPC2 with `MD5(user:realm:password)` using the challenge realm, ports 80 then 5000
5. **PTCP Disconnect** — close the tunnel

Both `--http` and default mode go through this same flow. The only difference is the bind port (for potential firewall compat).

**Perché l'add avviene sul canale del challenge**: alcuni dispositivi (es. `2L05BD6PAZ00030`) accettano **un solo canale PTCP alla volta** e rifiutano QUALSIASI re-bind dopo il disconnect (`PTCP bind failed on all ports`). Su questi, il challenge riusciva ma ogni tentativo successivo falliva; riusare il canale già aperto (con realm/random/session del challenge) risolve. Stesso schema per delete e per il flusso HTTP di fallback.

## Key Findings

### The password hash
- **addUser stores `MD5(username:realm:password)` (HA1 format)** — this is the correct format for SmartPSS compatibility
- All addUser payloads (DHIP `userManager.addUser`, il variante minimal, e HTTP `http_add_user`) ora includono **`"passwordType": "Default"`**: senza questo campo alcuni dispositivi (es. `3K02366PAZ523DA`) aggiungono l'utente, ma SmartPSS lo rifiuta come "profile" invalido perché il record manca del campo che identifica l'hash come HA1. I fallback `configManager.setConfig(Account)` lo includevano già.
- The **DHIP numeric realm** (e.g. `"1234567890"` from port 5000 challenge) is used for the hash, NOT the HTTP challenge realm (`"Login to ..."`)
- SmartPSS uses the same numeric realm for its own auth hash

### P2P channel auth (firmware 2023+)
- Some DVRs (newer firmware) refuse the anonymous P2P channel with **403** (alcuni anche con **401**, es. `5A04076PBQCEAC5`). The relay reports the error in the body:
  - `DevPwd_InvalidSalt` = anonymous channel refused (no `<RandSalt>` sent)
  - `DevPwd_InvalidDigest` = salt accepted, wrong device credentials (or empty password)
- The fix (implemented in `p2p.rs`): query `/info/device/{serial}` → decrypt the `<Info>` payload (AES-256-OFB with **fixed** key `kRjmsUB&ezmdGLL67H#$ojw@XflcaIaf` / IV `MydvJw*Iw1w&i^kk`) → get `randsalt`; then retry `p2p-channel` with `IpEncrptV2` + `DevAuth`:
  - `key = MD5("{user}:Login to {randsalt}:{password}")` uppercase hex (same HA1 realm format)
  - `LocalAddr` encrypted with AES-256-OFB (IV `2z52*lk9o6HRyJrf`) using key = PBKDF2-HMAC-SHA256(`key`, str(nonce), 20000, 32)
  - `DevAuth = base64(HMAC-SHA256(key, "{nonce}{unix_ts}{encrypted_LocalAddr}"))`
  - `relay-channel` uses the same `DevAuth` with a new nonce and empty payload
- **Ritenta DevAuth su 401 E 403** (prima solo 403). Se `/info/device` non ha esposto il `randsalt`, il tool lo cerca nel **body dell'errore del canale** (`randsalt_from_err_body`: chiave XML `RandSalt`/`.../RandSalt`). Le password provate per il DevAuth: `--admin-pass` (se dato) poi le default passwords se `--try-defaults` (stesso `DEFAULT_ADMIN_PASSWORDS` condiviso, ora in `p2p.rs`). Se nessuna password funziona l'hint suggerisce `--admin-pass` o `--try-defaults`.
- The user for DevAuth is the **device account** (`--admin-user`, default `admin`) and the password is `--admin-pass` (`-p`). If the device has a password set, it **must** be provided (`--admin-pass <pwd>`) or the channel stays 403.
- Crypto verified against dh-p2p reference vectors in `p2p.rs` tests (`cargo test`).

### addUser over DHIP vs HTTP
- **DHIP addUser works on most devices** (verified on `2K02033PAE00089`): the HA1 hash is stored and the device accepts it. Earlier failures were specific to sending `passwordType: "MD5"` (stores `MD5(password)`, breaking SmartPSS login verification).
- Current DHIP addUser omits `passwordType` and stores `MD5(user:realm:password)` verbatim — same result as the HTTP/RPC2 path.
- The DHIP add flow tries HTTP/RPC2 first, then falls back to DHIP addUser when the HTTP challenge fails (error `268632079` on ports 80/5000 for some devices, e.g. `2K02033PAE00089`, `2C0359FPAE00017`).
- On hardened firmware (`2C0359FPAE00017`) DHIP addUser is rejected for every variant — only a real `--admin-pass` session can add users there.
- **Porta bind del fallback DHIP**: alcuni DVR (es. famiglie `7L03CB3PAZDA4B3`, `2L05BD6PAZ00030`) espongono DHIP **solo sulla porta 80** (il challenge su 5000 va in timeout) oppure accettano un solo canale PTCP. Il challenge ora ritorna `DhipChallengeInfo` (realm_id, porta, realm, random, session) e login+add/delete girano **sul canale live del challenge** (`dhip_add_on_challenge` / `dhip_try_delete_user` con `dhip_established_session` condiviso); le vie HTTP sono solo fallback. Prima il bind era hardcoded su 5000 (o richiedeva un re-bind) e questi seriali fallivano con `PTCP bind on port 5000 failed` / `PTCP bind failed on all ports`.
- **addUser over DVRIP/SDK (dialetto binario A0)** (`sdk_dvrip_add_user` in `src/main.rs`, `SdkClient::{dvrip_open,dvrip_login_on_bind,dvrip_call}` in `src/sdk.rs`): per firmware che **non rispondono a NESSUN `global.login` DHIP** su 5000/80/37777 (es. China-market devp2p 6.7.5), il flusso DHIP restituisce `chal = None`. In quel caso `try_add_user`, **prima** del fallback HTTP, prova addUser sul canale SDK (porta 37777) col dialetto DVRIP old-style: bind realm → `a0 01 00 00`+20 zeri+`05 02 01 01 00 00 a1 aa` (realm request) → parse `Realm:`/`Random:` (fallback sulla riga bare `Login to <serial>` di DahuaConsole) → hash `sdk_login_hash` (`standard_rpc_hash`+`gen1`) → `a0 05 00 00`+len(creds) LE+16 zeri+`05 02 00 08 00 00 a1 aa`+`user&&hash` (successo = `resp[8..10]==00 08`, session=`resp[16..20]`), poi JSON col frame `f6 00 00 00`+len+id+0+len+0+session+0 (body = `payload[32..32+u32(16..20)]`) per `userManager.getUserInfoAll` (pre-check duplicato), `userManager.getAuthorityList`, `userManager.addUser` e `configManager.setConfig(Account)`. La password HA1 usa il realm testuale del challenge DVRIP. Credenziali admin provate: `--admin-pass` poi `--try-defaults` poi password vuota. Riferimento protocollo: mcw0/DahuaConsole (`dahua_dvrip_login`, `proto_header`, `_p2p_len`, `dahua_logon_modes.py`). **Non verificato end-to-end** (il device di prova `7J05198PAZ5E8B4` era offline: `Dev_TimeOut`, 0 pacchetti a ogni protocollo).

### Protocol
- Working app uses HTTP POST to `/RPC2_Login` and `/RPC2`, not DHIP binary
- Login bypass: `passwordType: "Default"`, `loginType: "Loopback"`, `clientType: "Local"` (authorityType `Admin` preferred first, falls back to `Default`)
- No `configManager.setConfig` or `AuthorityList` needed for addUser

### Deleting users
- `userManager.deleteUser` takes **`params: {"name": <username>}`** — NOT a `user` object
- All other param shapes (`{"user": {...}}`, `{"account": {...}}`, arrays, `{"Id": N}`, etc.) fail with `268894211 "Request invalid param!"`
- Sending a full user object (from `getUserInfoAll`) back to `deleteUser` can make the device drop the PTCP channel
- `--delete-user <Id>` resolves the Id → Name via `getUserInfoAll`, then calls `deleteUser` with `{"name": <Name>}`
- **`--delete-all`** (CLI `--delete-all`, GUI radio "delete all (keep admin)") deletes **every non-admin user** on each device. It lists users via `userManager.getUserInfoAll` and skips admin (Id==2 or name `admin`, case-insensitive), then deletes each remaining user by name (`{"name": <Name>}` variants, DHIP then HTTP/RPC2 fallback like single delete). Reports per-user success/failure and continues across the list; stops early on a DISC. HTTP login flow was factored into `http_establish_session` (shared by `http_try_delete_user` and `http_try_delete_all`). `http_establish_session` now supports `--try-defaults`: if the real password and bypass both fail, it tries the factory default admin passwords before giving up — matches `dhip_established_session` behavior.

## Error Codes
- `268894209` = Invalid Request (console service not supported)
- `268894210` = Method not found
- `268894211` = Request invalid param (wrong parameter structure)
- `268894212` = Server internal error (addUser rifiutato dal server — spesso su firmware hardened senza credenziali admin reali; a volte la sessione bypass viene accettata per login/list ma non per addUser)
- `268959743` = Unknown error (service internal error — often privilege or validation)
- `287637505` = Invalid session in request data (sessione scaduta o invalidata dopo errore precedente)

## Build
- `cargo build` / `cargo run`
- `cargo build --all-targets` — builds CLI + GUI + license-gen
- `cargo build --release`

## Robustness
- **Pacchetti PTCP troncati**: alcuni relay/dispositivi mandano datagrammi malformati (es. payload 0x10 di 8 byte). I parser (`PTCPPayload::parse`, `PTCPBody::parse`, `PTCPPacket::parse`) e tutti i call site che affettano `[24..]` (`recv_until`, `wait_for_ptcp`, `dhip_recv`, `http_call`, hole-punch) sono difensivi: i pacchetti corti vengono ignorati invece di panincare (prima il processo moriva a metà batch, es. seriale 26/96 `1J034C5PAM00072`). Test di regressione: `short_malformed_packets_do_not_panic`.
- **Rilevamento DISC (device disconnect)**: `http_call` imposta un flag `LAST_CALL_DISC` (AtomicBool, p2p.rs) quando riceve `PTCPBody::Status(_, "DISC")` dal dispositivo. I call site principali — `http_list_users_on_port` (query loop + getUser fallback), `http_delete_user` (varianti + alt_methods), `http_add_user` (Type loop) — verificano il flag dopo ogni `http_call` che ritorna `None` e abortono immediatemente con errore esplicativo, evitando ~30s × N tentativi inutili su canali morti.
