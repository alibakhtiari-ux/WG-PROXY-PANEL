# Installing wg-panel with Docker Compose on a fresh Ubuntu server

> فارسی: [README.fa.md](README.fa.md)

The panel and WireGuard in **one container**, behaving exactly like the ansible
install: the first run creates `config.json`, the keys and a TLS certificate;
later runs only refresh the panel code from the image and never touch your
data. The admin password is set by **the first login** to the panel.

> ⚠️ This path is for a *new* server. The maintainer's own deployment runs the
> panel under systemd without Docker, and its install path is separate.

## Requirements

- Ubuntu 22.04 or 24.04 (x86_64 or arm64) with root access
- A copy of this repository on the server (`git clone`, or `rsync`/`scp` from
  another machine)
- Building needs internet access (apt runs inside the image). For a machine
  **with no internet**, build the offline bundle on a connected machine and
  carry it over: [docker/airgap/README.md](airgap/README.md) — a prebuilt
  image, docker's own offline repository, and a one-command installer.

## Install — four steps

```bash
sudo bash host-setup.sh
```

```bash
(umask 077 && cp .env.example .env)
chmod 600 .env
```

> `.env` holds the Telegram bot token and the rest of the deployment's secrets.
> A plain `cp` takes its mode from your umask (usually 0644), which leaves the
> file readable to any second user on the host. The airgap installer does it
> this way too; the manual path has to match.

Then open `.env` and set at least `WG_SERVER_HOST` — the public IP or domain of
the server. That value goes into the `Endpoint` line of every client config.

```bash
docker compose up -d --build
```

```bash
docker compose logs -f
```

The panel comes up on `https://SERVER:8787`. The certificate is self-signed, so
accept the browser warning once. The username is `admin` and **the first
password you type is the one that gets stored** — so log in immediately after
the install, before anyone else can reach the port.

## Where things live (backup = this directory)

| Host path | Contents |
|---|---|
| `data/panel/` | `config.json` (users, session secret), `traffic.db`, client configs, TLS, `actions.log` |
| `data/wireguard/` | Interface configs and keys, plus an automatic backup taken before every change |
| `data/backups/` | Nightly archives and the output of the panel's "manual backup" button (`wg-panel-backup.sh`), 14 kept |

Full cold backup (panel stopped):

```bash
docker compose down && tar -czf wg-panel-data-$(date +%Y%m%d).tar.gz data/ && docker compose up -d
```

Warm backup with no downtime: use the panel's own "manual backup" button. It
takes a consistent sqlite snapshot and writes it to `data/backups/`.

Restoring onto a new machine: put the repository and the `data/` directory in
place and run `up -d --build`. That is all — as long as `data/` exists, no
bootstrap runs again.

## Upgrading

Bring the new code onto the server (`git pull`, or `rsync`), then:

```bash
docker compose up -d --build
```

On every boot the entrypoint replaces `wg_panel.py` inside the volume with the
image's copy, leaving your data untouched. The version identifier is the
project's usual one — the first 12 characters of `sha256(wg_panel.py)` — and
you can read it with `cat data/panel/VERSION`.

## Security notes you should not skip

- **ufw does not filter docker-published ports.** Restrict the panel with
  `WG_PANEL_ALLOW_IPS` in `.env` (the panel's own filter, independent of any
  firewall), or bind the panel port to `127.0.0.1` in `docker-compose.yml` and
  reach it through an SSH tunnel.
- `fail2ban` runs inside the container by default: 5 failed logins in 10
  minutes bans that IP for an hour, on the panel port only.
- Keep `data/` root-only — `sudo chmod 700 data`. The session secret in
  `config.json` and every private key are in there.
- The container gets `NET_ADMIN`, not `privileged`. `host-setup.sh` loads the
  wireguard module on the host and makes it persistent.

## Honest differences from the systemd install

| Feature | Status under Docker |
|---|---|
| Panel, clients, quota/expiry, QR, Telegram bot and alerts | ✅ complete |
| Bringing tunnels up and down from the panel | ✅ via a `systemctl` shim that calls `wg-quick` |
| Squid proxy | ✅ in the same container (port 18080) |
| "Manual backup" button | ✅ runs the same backup script as the role |
| Automatic *nightly* backup | ✅ a scheduler inside the container replaces the systemd timer — `WG_BACKUP_AT`, default 04:30 |
| Cloud upload of backups (MEGA S4) | ⚙️ optional — mount the two secret files (see the compose comments); skipped silently until you do |
| Backup *verification* | ❌ the shipped verifier is MEGA-only and enforces "no backup file stays on the server", the opposite of this install's design |
| Full *server* backup row on the backup page | ❌ that script backs up a whole host (`/etc`, letsencrypt, units); a container has no such host |
| Speed test page | ⚙️ needs Ookla's CLI, which is not in the Ubuntu repository — mount your own binary (see the compose comments) |
| AmneziaWG (`awg` tunnels) | ⚙️ only if you mount the binaries yourself; they are in neither the repository nor apt |
| WARP/SNI chain, ECMP, tunnel guards | ❌ specific to the maintainer's topology — out of scope here |

Every ❌ above is a page or row that stays **empty**, not a broken one, and none
of them touches VPN service, users, quotas, or the proxy.

### The backup scheduler

The container has no systemd, and `wg_panel.py` does not schedule backups itself
— it only reads the units' status and starts them when you press the button. So
a small scheduler (`wg-panel-cron`) runs alongside the panel and fires the very
same job the button does, which keeps the backup page's "last run / result /
next run" columns as truthful here as under systemd.

- daily at `WG_BACKUP_AT` (default `04:30`, in `TZ`); 14 archives are kept
- a brand-new install also runs one backup ~10 minutes after the first boot, so
  no install is left without a safety net for a whole day
- if the container was down over the scheduled time, the missed run happens
  shortly after it comes back (systemd's `Persistent=true` behaviour)
- `WG_BACKUP_ENABLED=false` turns it off; the manual button keeps working
- state lives in `data/panel/units/`, so "last run" survives
  `docker compose down && up`

## Troubleshooting

```bash
docker compose logs -f wg-panel
```

```bash
docker compose exec wg-panel wg show
```

```bash
docker compose exec wg-panel tail -50 /var/log/wg-panel/systemctl-shim.log
```

- **"Creating a test wireguard interface failed"** in the log ⇒ run
  `sudo modprobe wireguard` on the host (or `host-setup.sh`), then
  `docker compose restart`.
- **A client connects but has no internet** ⇒ inside the container,
  `sysctl net.ipv4.ip_forward` must be `1` and
  `iptables -t nat -S POSTROUTING` must show a MASQUERADE rule. The entrypoint
  creates both, and they hold unless the compose file was edited.
- **`unhealthy` healthcheck** means either the panel is not answering or the
  clients' main interface is down:
  `docker inspect --format '{{json .State.Health}}' wg-panel`
