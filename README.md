# Dinodia Hub Agent (Home Assistant add-on)

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
- `platform_sync_interval_minutes`: defaults to 5 (min 5)
- `port`: default 8099 (HTTP/WS bridge)
- `allowed_path_regex`: allowed HA API paths (defaults provided)
- `ws_auth_mode`: `auto` (default), `supervisor`, or `ha`
- `ha_access_token`: optional HA token if using `ws_auth_mode: ha`

## Notes
- Tested base images: `ghcr.io/hassio-addons/base:14.0.6`
- Architectures: `aarch64`, `amd64`, `armv7`
- LAN reporting: the agent reports the detected LAN base URL to the platform (if platform sync is enabled).
# dinodia-hub-agent
