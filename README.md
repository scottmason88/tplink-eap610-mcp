# EAP610 standalone MCP — deployment handover

Deployed 2026-11-14 on a Raspberry Pi.
No Docker, Omada controller, additional hardware, or always-on desktop is required.

## Confirmed device

- Management IP: `<ap-ip>`
- MAC: `<ap-mac>`
- Model/hardware: EAP610 / 1.0
- Firmware: `1.6.30 Build 20260728 Rel. 08167(5553)`
- HTTPS certificate SHA256: `<ap-cert-sha256>`
- Six SSID entries: main, IoT and guest on both bands. Main untagged, IoT VLAN 30, guest VLAN 40.
- AP still reports 100 Mbps Ethernet and an incorrect system date. Neither setting was changed.

## Running services and integration

`eap610-mcp.service` is enabled under the user's systemd manager; user lingering is enabled.
It runs the existing `~/tplink-env/bin/python` interpreter, with existing packages
MCP 1.30.0, Pydantic 2.14.3 and Uvicorn 0.54.0. No packages were changed in that environment.
The AP service uses approximately 58 MiB resident memory in the observed sample.

The HTTP MCP endpoint is `http://127.0.0.1:8770/mcp`, protected with a private bearer token.
It is bound only to IPv4 loopback. The unit uses NoNewPrivileges, PrivateTmp, a read-only
filesystem/home view except its private state directory, a 160M memory limit, and restricted
socket address families. It runs as an ordinary user, without sudo or root privileges.

The EAP610 endpoint contains only its 11 EAP tools. The switch endpoint at
`127.0.0.1:8765/mcp` contains only its original 13 switch tools. The temporary EAP proxy
registration was removed after the user clarified that a separate MCP connection is required.
All switch tools were rechecked against the original tool list. The existing switch tunnel
continues to serve only the switch MCP.

A separate `openai-eap610-tunnel.service` has been installed and its unit validated. It targets
only `127.0.0.1:8770/mcp`, and supplies the EAP endpoint's private bearer token to both discovery
and tool calls. It is enabled and running using the user-provisioned tunnel
`tunnel_<your-eap610-tunnel-id>`, named **EAP610 Tunnel**. Both `/healthz`
and `/readyz` returned HTTP 200, and remote tunnel metadata was retrieved successfully.
The existing runtime control-plane key was copied into a private EAP-specific environment
file and successfully authenticated; no administrator credential was required on the Pi.
No public listener or new external account was created.

The existing switch source was backed up privately before adding the proxy registration:
`~/.config/eap610-mcp/integration-backup/tplink-server.py`.
The proxy module files were moved into the same private backup directory and removed from the
active source. Only local service processes were restarted; no network device was rebooted by this project.

## Verification status

| Operation | Status |
|---|---|
| Identity, hardware, firmware, health/uptime | Live read verified |
| Both radios and all six SSIDs, with passwords redacted | Live read verified |
| VLAN assignments | Live read verified; VLANs 0/30/40 preserved |
| Wireless clients, RSSI/rate/traffic | Live read verified; 20 clients in sample |
| Configuration export | Live verified; 4,308-byte attachment saved privately; checksums verified |
| LED off → on → off | Explicitly approved by user; both writes and inverse rollback verified |
| SSID rename / broadcast | Request schema inspected; typed preview implemented; not live-write tested |
| Radio channel / transmit power | Request schema inspected; typed preview implemented; not live-write tested |
| Existing SSID VLAN reassignment | Request schema inspected; typed preview implemented; not live-write tested |
| Reboot, reset, firmware update, adoption, management IP/VLAN, credential changes, restore upload | Not exposed |

The LED test compared the complete persistent wireless/VLAN/LED configuration before and after,
and found no unrelated changes. A separate private device backup preceded each write.
Eight safeguard tests passed, including missing approval/unlock, expiry, drift, backup failure,
one-use application, uncertain-write non-retry, strict input validation, redaction, and rejection
of a changed TLS certificate before credentials are sent. Audit chain and backup checksums passed.

The independent EAP endpoint's 11-tool catalog was smoke-tested locally, including authentication.
The switch was restored to its exact original 13-tool list. The existing switch identity tool
was also called successfully through the connected OpenAI plugin. The approved LED test passed
before separation; no adapter or write-guard behavior was changed when the proxy was removed.
The separate EAP OpenAI tunnel is healthy and ready. On 2026-11-15, the user added the
independent **EAP610 MCP** app. End-to-end calls through that app succeeded for
`eap_inventory`, `eap_wireless`, and `eap_capabilities`. The live results confirmed EAP610
hardware 1.0, firmware 1.6.30, both radios enabled, all six SSID entries, VLANs untagged/30/40,
password redaction, LED off, and writes locked by default. No AP writes were performed during
this final connection check.

**Integration complete:** no connection setup remains. The EAP610 app and its dedicated tunnel
`tunnel_<your-eap610-tunnel-id>` are separate from the switch app and switch tunnel.
The local bearer token is supplied by the tunnel client. AP credentials and the localhost
bearer token are not entered into the OpenAI app.

Wireless configuration writes remain implemented but not live-tested, and require the existing
approval and local unlock safeguards. Only the approved LED write and its rollback have been
live-write verified. No additional Wi-Fi configuration changes were authorized or performed.

The installed `configure_tunnel.py` helper validates identifiers, refuses IDs already assigned
to another installed device service, verifies the local endpoint is EAP-only, and enables the
dedicated tunnel unit. The tunnel has already been configured; no setup command is needed now.

## Exact MCP tool surface

`eap_inventory`, `eap_wireless`, `eap_clients`, `eap_capabilities`, `eap_backup`,
`eap_preview_led`, `eap_preview_ssid`, `eap_preview_radio`, `eap_preview_vlan`,
`eap_apply_change`, `eap_preview_rollback`.

SSID changes support existing entries only, with names limited to 32 UTF-8 bytes and no control
characters. They preserve all security/password fields. Masked credentials cause refusal.
Radio changes preserve enabled state, mode, width and country; channels must be in the AP's
reported frequency range, and power is limited to 4–25 dBm and the reported minimum.
VLAN changes allow only untagged/30/40 for existing SSIDs. They never alter gateway, switch,
management access or management VLAN configuration.

## Approval, backups and rollback

Every preview expires after 300 seconds, contains an exact redacted diff, and is bound to a
random change ID, a plan hash, and a full pre-change persistent-configuration hash.
`eap_apply_change` requires the exact confirmation `APPLY <change_id>` plus a separate local
operator approval record bound to that plan. There is no MCP tool to approve or unlock itself.

The operator records only an explicit human approval, with a reference to that approval:

```sh
~/tplink-env/bin/python ~/.local/share/eap610-mcp/server.py \
  --approve CHANGE_ID --approval-reference 'Reference to explicit human approval'
```

Wireless/VLAN changes additionally require an interactive local terminal unlock for that exact
change, valid for at most 180 seconds. This is intentionally not available via MCP:

```sh
~/tplink-env/bin/python ~/.local/share/eap610-mcp/server.py --unlock CHANGE_ID
```

That command displays the diff and requires typing `UNLOCK EAP610 CHANGE_ID` interactively.
An approval record is not a reason to run the unlock without the user's specific authorization.

Apply rechecks identity, firmware, TLS pin, expiry, approval, unlock and configuration drift.
It then exports a private configuration backup and saves a full private snapshot. Approval and
unlock are consumed before sending the write. There are no automatic write retries. Complete
persistent configuration is read back and compared with the exact expected state.

An uncertain response stops the operation and requires inspection. It never triggers a reboot,
reset, further write, or automatic restore. If the current state matches the expected post-change
state, `eap_preview_rollback` stages the exact inverse, requiring a new approval and appropriate
unlock. LED inverse rollback was live-tested; wireless rollback was not.

If management becomes unreachable, use a main-LAN connection to inspect the AP. The saved binary
backup can be restored through the firmware's local web interface after explicit approval.
Automatic binary restore is not implemented or tested. If the firmware exported an encrypted
backup using existing settings, its existing export password is required for manual restoration;
the project did not change backup encryption settings. Full snapshots also preserve known values.

## Private Pi files

- Source: `~/.local/share/eap610-mcp/`
- State/secrets: `~/.config/eap610-mcp/` (0700)
- AP credentials: `credentials.json` (0600)
- Active identity and certificate pin: `device.json` (0600)
- Local endpoint token: `mcp-token` (0600)
- Dedicated tunnel runtime environment: `tunnel-environment` (0600)
- Private local Authorization header: `mcp-authorization` (0600)
- Dedicated tunnel ID: `tunnel-id.env` (0600, dedicated EAP610 tunnel)
- Binary exports and full snapshots: `backups/` (private directories/files)
- Previews, approvals, one-use unlocks: `changes/`, `approvals/`, `unlocks/`
- Hash-chained audit: `audit.jsonl` (0600), without credential values
- Approved LED test receipts: `led-live-test.json`
- Live write verification record: `verified.json`
- Firmware interface evidence: `research/` (private directory)

The host OS account running the service and root are trusted operators. They can modify approval records and
source; this is not an external cryptographic approval authority. The audit is hash-chained,
but a trusted local administrator can rewrite it. It is not an externally immutable audit log.

## Firmware protocol evidence and limitations

This adapter reproduces requests served by the specific device firmware; it does not assume a
stable public TP-Link API. The firmware login page calls `md5AndSha256Encrypt` without its salt
flag; inspected helper code returns uppercase MD5 in that case. Authentication uses POST `/`
and a JSESSIONID cookie. No independent CSRF token was observed in the inspected proxy/page
flows; the adapter preserves same-origin Referer and Origin headers. Cookies and password
transforms are never returned by MCP.

Identity/health uses GET `/data/status.device.json?operation=read`. Radio settings use POST
`/data/wireless.basic.json` with `operation=read` or `write`. SSID tables use POST
`/data/wireless.ssids.json` with `operation=load`; the UI's update serialization is `operation=update`,
`radioID`, `index`, `key`, plus JSON `old`/`new` records. VLAN tables use POST
`/data/wireless.vlan.json` with `operation=load` or `save` and newline-separated columns.
LED uses POST `/data/ledctrl.json` with `operation=read` or `write` and `enable=on/off`.
Export uses GET `/data/configBackup.json?operation=backup`; it must return a bounded attachment.
The implementation never treats GET as inherently read-only; maintenance GET mutations are not exposed.

The certificate changed after the user-managed firmware update. The new pin was established
on the Pi's LAN after confirming the known ARP MAC and authenticated device model/hardware.
This was local trust establishment, not a manufacturer-signed identity attestation. All subsequent
HTTP credentials and sessions are sent only after the exact certificate fingerprint matches.
Unexpected firmware or certificate changes require operator review; the service does not repin itself.

SNMP was inspected but not enabled or changed. The served standalone page offers community-based
read/write controls without visible SNMPv3 configuration. HTTPS already provides the needed data.

## Recovery of the integration itself

The switch integration has already been removed. To stop EAP management, stop/disable
`eap610-mcp.service` and `openai-eap610-tunnel.service`. Keep private AP
backups and audit history. This does not modify the AP or switch configuration.

The source archive accompanying this report deliberately excludes AP credentials, bearer tokens,
sessions, raw wireless snapshots and configuration binaries.
