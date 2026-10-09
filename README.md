# site-guardian

**A passive security auditor for small business websites and bloggers.**

Millions of small business owners and bloggers host their own websites without knowing if their site is insecure or leaking sensitive data. `site-guardian` runs a quick, passive audit on any domain and gives you a clear **Fix-it Guide** — no expensive cybersecurity firm required.

## What it checks

- SSL Certificate — expiry status and days remaining
- Exposed Sensitive Files — `.env`, `config.php`, `wp-config.php`, `.git/config`, `.htaccess`, `backup.sql`
- SPF Record — protects your domain from email spoofing
- DKIM Record — checks common selectors for email signing

Everything is **passive** — the tool only reads publicly available information. It never exploits, writes, or attacks.

## Installation

    git clone https://github.com/LakshyaSharma28/site-guardian.git
    cd site-guardian
    python -m venv venv
    source venv/bin/activate
    pip install -e .

## Usage

    site-guardian audit example.com

Example output:

    Auditing example.com...

    1. SSL Certificate
      Valid - expires in 77 days

    2. Exposed Sensitive Files
      OK .env (status 404)
      OK config.php (status 404)

    3. Email Security (SPF)
      SPF found: v=spf1 -all

    4. Email Security (DKIM)
      DKIM found (selector: default): v=DKIM1; p=

    Fix-it Guide:
      - Renew SSL certificate if expired or expiring soon.
      - Remove or protect exposed files immediately.
      - Add SPF record: v=spf1 include:_spf.google.com ~all
      - Configure DKIM signing with your email provider.

## Ethical Use

Only audit domains you own or have explicit permission to test. This tool is designed for **self-auditing** — website owners checking their own site.

## License

MIT — see [LICENSE](LICENSE).
