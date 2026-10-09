import ssl
import socket
from datetime import datetime, timezone

def check_ssl(domain: str, port: int = 443) -> dict:
    """Check SSL certificate expiry for a domain."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = cert['notAfter']
                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                expiry = expiry.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (expiry - now).days
                return {
                    "valid": days_left > 0,
                    "days_left": days_left,
                    "expiry_date": expiry.isoformat(),
                    "error": None
                }
    except Exception as e:
        return {"valid": False, "days_left": None, "expiry_date": None, "error": str(e)}
