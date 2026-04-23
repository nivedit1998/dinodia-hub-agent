# Dinodia Hub Agent (Home Assistant add-on)

## Status (as of 2026-03-17)
- ✅ Complete: This README documents installation and the current add-on options.

Home Assistant add-on that provides an authenticated HTTP/WS bridge to HA Core for Dinodia hubs, plus periodic platform sync.

## How to install (Home Assistant)
1) Go to **Settings → Add-ons → Add-on Store**.
2) Click the **⋮** menu → **Repositories** → add:
   ```
   https://github.com/nivedit1998/dinodia-hub-agent
   ```
3) Find **Dinodia Hub Agent** in the store, install, and start.

## Add-on options (summary)
- `platform_base_url`: should be `https://app.dinodiasmartliving.com`
- `hub_agent_id`: the hub serial (from installer provisioning)
- `hub_agent_secret`: bootstrap secret (from installer provisioning)
- `platform_sync_enabled`: set `true` to enable platform token sync (default false)
- `platform_sync_interval_minutes`: min 2 (default 60 unless you change it in the UI; jitter up to +60s per cycle)
- `sync_status_token`: optional token to protect `/_dinodia/sync-status` (when unset, endpoint stays disabled)
- `port`: default 8099 (HTTP/WS bridge)
- `allowed_path_regex`: allowed HA API paths (defaults provided)
- `ws_auth_mode`: `auto` (default), `supervisor`, or `ha`
- `ha_access_token`: optional HA token if using `ws_auth_mode: ha`
- `log_level`: `info` by default; use `warn` or `error` for minimal operational logs

## Notes
- Tested base images: `ghcr.io/hassio-addons/base:14.0.6`
- Architectures: `aarch64`, `amd64`, `armv7`
- LAN reporting: the agent reports the detected LAN base URL to the platform (if platform sync is enabled).
- Secure logging: info logs avoid LAN URL details; set `log_level: warn` for stricter output.
# dinodia-hub-agent
