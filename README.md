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
chmod 755
```

certbot handles automatic renewal. The private key stays on this server and is distributed to slaves through secure channels (e.g. initial provisioning, SSH).
It's important not to miss ``--reuse-key``, otherwise, automatic updates may be broken on next key rewrite.

### 2. Slave servers: one-shot deploy & setup updates with certferry
Copy /etc/letsencrypt/live/yourdomain.com/ directory from your main server to /etc/certferry/live/yourdomain.com/ by a secure channel.
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

After updating certificates, certferry runs all scripts in `/etc/certferry/renewal-hooks/deploy/` with certbot-compatible environment variables (`RENEWED_LINEAGE`, `RENEWED_DOMAINS`), so reload hooks written for certbot (e.g. `systemctl reload nginx`) work as-is once copied there. Logs go to `/var/log/certferry/certferry.log`.

## Usage

```
certferry <domain>          # fetch certificate from domain:443
certferry --renew           # renew expiring certificates (last 1/10 of validity, 2-30 days)
certferry --renew --force   # renew all certificates unconditionally
```

## Building

```sh
cargo build --release
sudo cp target/release/certferry /usr/local/bin/
```

## License

MIT
