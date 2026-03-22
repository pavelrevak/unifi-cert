#!/usr/bin/env python3
"""Deploy Let's Encrypt certificates to UniFi OS controllers via API.

Can be used as a certbot deploy hook or run manually.
Uses RENEWED_DOMAINS env var (set by certbot) to determine which
controllers need updating.

Config example (/etc/letsencrypt/hooks/.unifi-controllers.json):
{
    "controllers": [
        {
            "host": "unifi.example.com",
            "domain": "unifi.example.com",
            "username": "admin",
            "password": "secret"
        }
    ]
}
"""

import argparse
import base64
from datetime import datetime
from enum import IntEnum
import json
import os
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_CONFIG = "/etc/letsencrypt/hooks/.unifi-controllers.json"


class ExitCode(IntEnum):
    OK = 0
    DEPLOY_FAILED = 1
    DUPLICATE = 2
    CONFIG_ERROR = 3


def load_config(path):
    """Load JSON configuration file."""
    with open(path) as f:
        config = json.load(f)
    if "controllers" not in config or not config["controllers"]:
        raise ValueError(f"No controllers defined in {path}")
    for i, ctrl in enumerate(config["controllers"]):
        required = ("host", "domain", "username", "password")
        missing = [k for k in required if k not in ctrl]
        if missing:
            raise ValueError(
                f"Controller [{i}]: missing {', '.join(missing)}")
    return config


class UniFiAPI:
    def __init__(self, host, verify_ssl=False):
        self.base_url = f"https://{host}"
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.csrf_token = None

    def login(self, username, password):
        """Authenticate and store session cookies + CSRF token."""
        resp = self.session.post(
            f"{self.base_url}/api/auth/login",
            json={"username": username, "password": password})
        resp.raise_for_status()
        token_cookie = self.session.cookies.get("TOKEN")
        if token_cookie:
            payload = token_cookie.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            data = json.loads(base64.b64decode(payload))
            self.csrf_token = data.get("csrfToken")
            if self.csrf_token:
                self.session.headers["X-CSRF-Token"] = self.csrf_token
        return resp.json()

    def logout(self):
        """End session."""
        try:
            self.session.post(f"{self.base_url}/api/auth/logout")
        except Exception:
            pass

    def list_certificates(self):
        """Get all user certificates."""
        resp = self.session.get(
            f"{self.base_url}/api/userCertificates")
        resp.raise_for_status()
        return resp.json()

    def upload_certificate(self, name, cert_pem, key_pem):
        """Upload a new certificate. Returns cert info or None if duplicate."""
        resp = self.session.post(
            f"{self.base_url}/api/userCertificates",
            json={"name": name, "cert": cert_pem, "key": key_pem})
        if resp.status_code == 409 or (
                resp.status_code == 400
                and "DUPLICATE" in resp.text.upper()):
            return None
        resp.raise_for_status()
        return resp.json()

    def activate_certificate(self, cert_id):
        """Activate a certificate by ID."""
        resp = self.session.put(
            f"{self.base_url}/api/userCertificates/{cert_id}/status",
            json={"active": True})
        resp.raise_for_status()
        return resp.json()

    def close(self):
        self.session.close()


def deploy_controller(ctrl, cert_path):
    """Deploy certificate to a single controller.

    Returns ExitCode: OK on success, DUPLICATE if unchanged,
    DEPLOY_FAILED on error.
    """
    domain = ctrl["domain"]
    host = ctrl["host"]
    cert_dir = cert_path or f"/etc/letsencrypt/live/{domain}"
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    cert_name = f"{domain}-{timestamp}"

    print(f"\n--- {host} ({domain}) ---")

    try:
        with open(f"{cert_dir}/fullchain.pem") as f:
            cert_pem = f.read()
        with open(f"{cert_dir}/privkey.pem") as f:
            key_pem = f.read()
    except FileNotFoundError as e:
        print(f"  ERROR: Certificate file not found: {e}",
            file=sys.stderr)
        return ExitCode.DEPLOY_FAILED

    api = UniFiAPI(host)
    try:
        api.login(ctrl["username"], ctrl["password"])
        print("  Login OK")

        result = api.upload_certificate(cert_name, cert_pem, key_pem)
        if result is None:
            print("  Certificate unchanged (duplicate fingerprint)")
            api.logout()
            return ExitCode.DUPLICATE

        cert_id = result["id"]
        print(f"  Uploaded: {cert_name} "
              f"(valid: {result['valid_from'][:10]} - "
              f"{result['valid_to'][:10]})")

        api.activate_certificate(cert_id)
        print(f"  Activated: {cert_name}")

        api.logout()
        print("  Done")
        return ExitCode.OK
    except requests.ConnectionError:
        print(f"  ERROR: Cannot connect to {host}", file=sys.stderr)
        return ExitCode.DEPLOY_FAILED
    except requests.Timeout:
        print(f"  ERROR: Connection to {host} timed out",
            file=sys.stderr)
        return ExitCode.DEPLOY_FAILED
    except requests.HTTPError as e:
        print(f"  ERROR: API returned {e.response.status_code}: "
              f"{e.response.text}", file=sys.stderr)
        return ExitCode.DEPLOY_FAILED
    except Exception as e:
        print(f"  ERROR: {e}", file=sys.stderr)
        return ExitCode.DEPLOY_FAILED
    finally:
        api.close()


def list_controllers(controllers):
    """List certificates on all controllers."""
    for ctrl in controllers:
        host = ctrl["host"]
        print(f"\n--- {host} ({ctrl['domain']}) ---")
        api = UniFiAPI(host)
        try:
            api.login(ctrl["username"], ctrl["password"])
            certs = api.list_certificates()
            print(f"  Certificates ({len(certs)}):")
            for cert in certs:
                status = "ACTIVE" if cert.get("active") else "inactive"
                print(f"    [{status}] {cert['name']} "
                      f"(valid: {cert['valid_from'][:10]} - "
                      f"{cert['valid_to'][:10]})")
            api.logout()
        except Exception as e:
            print(f"  ERROR: {e}", file=sys.stderr)
        finally:
            api.close()


def filter_controllers(controllers, domains):
    """Filter controllers by domain list. Returns all if domains is empty."""
    if not domains:
        return controllers
    filtered = [c for c in controllers if c["domain"] in domains]
    unknown = domains - {c["domain"] for c in controllers}
    if unknown:
        print(f"Warning: unknown domains: {', '.join(unknown)}",
            file=sys.stderr)
    return filtered


def main():
    parser = argparse.ArgumentParser(
        description="Deploy certificates to UniFi OS controllers")
    parser.add_argument(
        "-c", "--config",
        default=DEFAULT_CONFIG,
        help="Path to JSON config file (default: %(default)s)")
    parser.add_argument(
        "--cert-path",
        help="Path to certificate directory (overrides auto-detection)")
    parser.add_argument(
        "--domain", action="append", dest="domains",
        help="Limit to specific domain(s), can be repeated")
    parser.add_argument(
        "--renew", action="store_true",
        help="Deploy certificates to controllers")
    parser.add_argument(
        "--list", action="store_true",
        help="List certificates on controllers")
    args = parser.parse_args()

    # Certbot mode: RENEWED_DOMAINS is set, auto-renew matching controllers
    renewed_env = os.environ.get("RENEWED_DOMAINS")
    if not args.renew and not args.list and not renewed_env:
        parser.print_help()
        sys.exit(ExitCode.CONFIG_ERROR)

    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
        print(f"Config error: {e}", file=sys.stderr)
        sys.exit(ExitCode.CONFIG_ERROR)

    controllers = config["controllers"]
    domains = set(args.domains) if args.domains else set()

    if args.list:
        targets = filter_controllers(controllers, domains)
        list_controllers(targets)
        return

    # Determine target controllers
    if renewed_env:
        # Certbot deploy hook mode
        domains = set(renewed_env.split())
    targets = filter_controllers(controllers, domains)

    if not targets:
        print("No matching controllers")
        return

    failed = []
    duplicates = []
    deployed = []
    for ctrl in targets:
        result = deploy_controller(ctrl, args.cert_path)
        if result == ExitCode.OK:
            deployed.append(ctrl["host"])
        elif result == ExitCode.DUPLICATE:
            duplicates.append(ctrl["host"])
        else:
            failed.append(ctrl["host"])

    # Summary
    print()
    if deployed:
        print(f"Deployed: {', '.join(deployed)}")
    if duplicates:
        print(f"Unchanged: {', '.join(duplicates)}")
    if failed:
        print(f"Failed: {', '.join(failed)}", file=sys.stderr)
        sys.exit(ExitCode.DEPLOY_FAILED)

    if duplicates and not deployed:
        sys.exit(ExitCode.DUPLICATE)


if __name__ == "__main__":
    main()
