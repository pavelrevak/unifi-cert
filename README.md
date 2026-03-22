# unifi-cert-deploy

Deploy Let's Encrypt (or any PEM) certificates to UniFi OS controllers via their local API.

Tested on UniFi Express 7 (UX7) with UniFi OS 4.4.11.

## Features

- Upload and activate TLS certificates on multiple UniFi OS controllers
- Works as a **certbot deploy hook** (automatic) or **standalone CLI** (manual)
- Skips upload when the certificate fingerprint is unchanged (duplicate detection)
- Timestamped certificate names (`domain-YYYYMMDDHHmmss`) for easy identification in the UI

## Requirements

- Python 3.9+
- `requests` library
- UniFi OS controller with local account credentials (not Ubiquiti cloud SSO)

## Installation

The script needs root access to read certificate files in `/etc/letsencrypt/`
and the config file with credentials. Install into a dedicated venv:

From GitHub:

```bash
sudo -H python3 -m venv /opt/unifi-cert/venv
sudo -H /opt/unifi-cert/venv/bin/pip install git+https://github.com/pavelrevak/unifi-cert.git
```

Or from a local clone:

```bash
git clone https://github.com/pavelrevak/unifi-cert.git
sudo -H python3 -m venv /opt/unifi-cert/venv
sudo -H /opt/unifi-cert/venv/bin/pip install .
```

The script is installed at `/opt/unifi-cert/venv/bin/unifi-cert-deploy` and can
be run directly using the full path. Optionally, create a symlink for convenience:

```bash
sudo ln -s /opt/unifi-cert/venv/bin/unifi-cert-deploy /usr/local/bin/
```

## Configuration

Create a JSON config file (default: `/etc/letsencrypt/hooks/.unifi-controllers.json`):

```json
{
    "controllers": [
        {
            "host": "unifi.example.com",
            "domain": "unifi.example.com",
            "username": "admin",
            "password": "secret"
        },
        {
            "host": "10.0.0.1",
            "domain": "unifi2.example.com",
            "username": "admin",
            "password": "secret2"
        }
    ]
}
```

| Field | Description |
|-------|-------------|
| `host` | Hostname or IP used to connect to the controller API |
| `domain` | Certificate domain name, also used to locate cert files in `/etc/letsencrypt/live/{domain}/` |
| `username` | Local UniFi OS account username |
| `password` | Local UniFi OS account password |

Protect the config file:

```bash
chmod 600 /etc/letsencrypt/hooks/.unifi-controllers.json
```

A `config.example.json` is provided as a template.

## Usage

### List certificates

```bash
# All controllers
unifi-cert-deploy --list

# Specific controller
unifi-cert-deploy --list --domain unifi.example.com
```

### Deploy certificates (manual)

```bash
# All controllers
unifi-cert-deploy --renew

# Specific controller(s)
unifi-cert-deploy --renew --domain unifi.example.com

# Multiple specific controllers
unifi-cert-deploy --renew --domain a.example.com --domain b.example.com

# Custom certificate path
unifi-cert-deploy --renew --domain unifi.example.com --cert-path /path/to/certs
```

### Certbot deploy hook (automatic)

Option A — global hook, runs on every certificate renewal. Symlink the script
into certbot's deploy hook directory:

```bash
sudo ln -s /opt/unifi-cert/venv/bin/unifi-cert-deploy /etc/letsencrypt/renewal-hooks/deploy/
```

Non-matching domains are silently skipped.

Option B — per-certificate hook, runs only when a specific domain is renewed.

When creating a new certificate:

```bash
certbot certonly --deploy-hook /opt/unifi-cert/venv/bin/unifi-cert-deploy ...
```

Adding the hook to an existing certificate:

```bash
certbot reconfigure --cert-name unifi.example.com --deploy-hook /opt/unifi-cert/venv/bin/unifi-cert-deploy
```

Or edit the renewal config directly in
`/etc/letsencrypt/renewal/unifi.example.com.conf`:

```ini
[renewalparams]
renew_hook = /opt/unifi-cert/venv/bin/unifi-cert-deploy
```

Both options work with the full venv path. If you created the `/usr/local/bin/`
symlink, you can use `unifi-cert-deploy` instead of the full path.

When certbot renews a certificate, it sets `RENEWED_DOMAINS` environment variable.
The script automatically matches renewed domains against configured controllers
and deploys only to those that need updating.

### Custom config path

```bash
unifi-cert-deploy -c /path/to/config.json --list
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Certificate deployed successfully |
| 1 | Deploy failed (connection error, auth failure, API error) |
| 2 | Certificate unchanged (duplicate fingerprint) |
| 3 | Configuration error (missing file, invalid JSON) |

## How it works

1. Authenticates to the UniFi OS local API (`POST /api/auth/login`)
2. Reads PEM certificate and private key files
3. Uploads the certificate (`POST /api/userCertificates`)
4. Activates it (`PUT /api/userCertificates/{id}/status`)
5. Logs out (`POST /api/auth/logout`)

Certificate names include a timestamp (e.g., `unifi.example.com-20260322143000`)
so you can identify when each was uploaded and clean up old ones in the UI.

## API compatibility

This tool uses the undocumented UniFi OS local API (`/api/userCertificates`).
It requires **UniFi OS 4.1 or newer** — older versions (e.g., UniFi OS 4.0.x
on the original UniFi Express UX) do not have the certificate upload API.

Developed and tested against UniFi Express 7 (UX7) running UniFi OS 4.4.11.
The API endpoints may change in future firmware updates.

## License

MIT
