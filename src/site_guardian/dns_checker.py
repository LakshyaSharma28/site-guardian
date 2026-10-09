import dns.resolver

# Termux/Android doesn't have /etc/resolv.conf, so we set resolvers manually.
# These are public DNS servers (Cloudflare + Google).
DEFAULT_NAMESERVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]

def _get_resolver() -> dns.resolver.Resolver:
    """Build a resolver that works on Termux/Android and normal Linux."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = DEFAULT_NAMESERVERS
    resolver.timeout = 5
    resolver.lifetime = 5
    return resolver

def check_spf(domain: str) -> dict:
    """Check for SPF record."""
    resolver = _get_resolver()
    try:
        answers = resolver.resolve(domain, 'TXT')
        spf_records = [r.to_text().strip('"') for r in answers if 'v=spf1' in r.to_text()]
        if spf_records:
            return {"exists": True, "record": spf_records[0], "error": None}
        else:
            return {"exists": False, "record": None, "error": "No SPF record found"}
    except Exception as e:
        return {"exists": False, "record": None, "error": str(e)}

def check_dkim(domain: str, selectors: list = None) -> dict:
    """Check for DKIM record using common selectors."""
    if selectors is None:
        selectors = ["default", "google", "mail", "selector1", "selector2"]
    resolver = _get_resolver()
    for sel in selectors:
        query = f"{sel}._domainkey.{domain}"
        try:
            answers = resolver.resolve(query, 'TXT')
            for r in answers:
                txt = r.to_text().strip('"')
                if 'v=DKIM1' in txt or 'p=' in txt:
                    return {"exists": True, "selector": sel, "record": txt, "error": None}
        except Exception:
            continue
    return {"exists": False, "selector": None, "record": None, "error": "No DKIM record found with common selectors"}
