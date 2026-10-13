<p align="center">
  <img width="512" src="https://raw.githubusercontent.com/vdudouyt/cert-ferry/master/images/cert-ferry.png">
</p>
<p align="center">
Easy distribution of wildcard LE certificates
</p>

## How it works

SSL/TLS certificates are public — every server hands them out during the TLS handshake. certferry simply connects to your main server over TLS, extracts the certificate chain, and writes it to `/etc/certferry/live/` using the same per-domain layout as certbot. No custom server, no authentication, no configuration.

## Setup

### 1. Main server: issue wildcard certificate with certbot

```sh
certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
  --agree-tos --no-eff-email --reuse-key \
  -m your@email.com \
  -d yourdomain.com \
  -d '*.yourdomain.com'

echo 'systemctl reload httpd' >/etc/letsencrypt/renewal-hooks/deploy/reload-apache.sh
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/reload-apache.sh
```

certbot handles automatic renewal. The private key stays on this server and is distributed to slaves through secure channels (e.g. initial provisioning, SSH).
It's important not to miss ``--reuse-key``, otherwise, automatic updates may be broken on next key rewrite.

### 2. Slave servers: one-shot deploy & setup updates with certferry
Copy the private key from your main server to `/etc/certferry/live/yourdomain.com/privkey.pem` by a secure channel. That is the only file you need to bring over - certferry fetches the rest.
```sh
mkdir -p /etc/certferry/live/yourdomain.com
scp root@main-server:/etc/letsencrypt/live/yourdomain.com/privkey.pem /etc/certferry/live/yourdomain.com/
chmod 600 /etc/certferry/live/yourdomain.com/privkey.pem
```

Add a deploy hook, so your web server is reloaded whenever a certificate is updated:
```sh
mkdir -p /etc/certferry/renewal-hooks/deploy
echo 'systemctl reload nginx' >/etc/certferry/renewal-hooks/deploy/reload-nginx.sh
chmod 755 /etc/certferry/renewal-hooks/deploy/reload-nginx.sh
```

Point your web server to `/etc/certferry/live/yourdomain.com/fullchain.pem` and `/etc/certferry/live/yourdomain.com/privkey.pem`.

Don't forget to add yourdomain.com to your /etc/hosts file if you're using Cloudflare or anything similar that could prevent you from fetching an original Let's Encrypt certificate.
```sh
certferry yourdomain.com
```

This connects to `yourdomain.com:443`, extracts the certificate chain, and writes:

- `/etc/certferry/live/yourdomain.com/cert.pem` — leaf certificate
- `/etc/certferry/live/yourdomain.com/chain.pem` — intermediate certificates
- `/etc/certferry/live/yourdomain.com/fullchain.pem` — both combined

If all verifications passed, it also installs a systemd timer that runs ``certferry --renew`` twice a day - you should clearly see a message stating that.

Just as said before, this doesn't requires any specific configuration on yourdomain.com - cert exchange is a part of TLS protocol, so any TLS listener is capable of that.

### 3. Renew expiring certificates
```sh
certferry --renew
```

On each run, it checks all certificates in `/etc/certferry/live/` and fetches fresh ones for any that have less than 1/10 of their validity period left (rounded up to whole days, but not less than 2 days and not more than 30 days). If the fetched certificate is identical to the existing one, no files are written and no hooks are triggered.

| Certificate lifetime | Renewed when less than |
|---|---|
| 6 days | 2 days |
| 47 days | 5 days |
| 90 days | 9 days |
| 300 days or more | 30 days |

A certificate that is not due yet is reported along with the time left before its renewal starts:
```
yourdomain.com: 20 days remaining, renewal in 11 days, skipping
```

After updating certificates, certferry runs all scripts in `/etc/certferry/renewal-hooks/deploy/` with certbot-compatible environment variables (`RENEWED_LINEAGE`, `RENEWED_DOMAINS`), so reload hooks written for certbot (e.g. `systemctl reload nginx`) work as-is once copied there.

## Usage

```
certferry <domain>          # fetch certificate from domain:443
certferry --renew           # renew expiring certificates (last 1/10 of validity, 2-30 days)
certferry --renew --force   # renew all certificates unconditionally
```

## Files and directories

| Path | Purpose |
|---|---|
| `/etc/certferry/live/<domain>/` | `privkey.pem` (provided by you), `cert.pem`, `chain.pem`, `fullchain.pem` |
| `/etc/certferry/renewal-hooks/deploy/` | scripts that run after a certificate is updated |
| `/var/log/certferry/certferry.log` | log file |
| `/etc/systemd/system/certferry-renew.service`, `certferry-renew.timer` | renewal timer, installed on first fetch |

## Upgrading from 0.1.5 or earlier

certferry no longer reads or writes anything under `/etc/letsencrypt/`. On a slave that doesn't run certbot itself, move the existing files over:
```sh
mkdir -p /etc/certferry/renewal-hooks
mv /etc/letsencrypt/live /etc/certferry/live
mv /etc/letsencrypt/renewal-hooks/deploy /etc/certferry/renewal-hooks/deploy
```

Then update your web server configuration to the new certificate paths. Deploy hooks now receive `RENEWED_LINEAGE=/etc/certferry/live/<domain>`.

The renewal threshold also changed from a fixed 29 days to 1/10 of the certificate's validity period, which is 9 days for a 90-day certificate.

## Building

```sh
cargo build --release
sudo cp target/release/certferry /usr/local/bin/
```

## License

MIT
