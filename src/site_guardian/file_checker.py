import requests

SENSITIVE_PATHS = [
    ".env",
    "config.php",
    "wp-config.php",
    ".git/config",
    ".htaccess",
    "backup.sql",
]

def check_exposed_files(domain: str, timeout: int = 5) -> list:
    """Check if common sensitive files are publicly accessible."""
    results = []
    base_url = f"https://{domain}"
    for path in SENSITIVE_PATHS:
        url = f"{base_url}/{path}"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=False)
            if resp.status_code == 200:
                content = resp.text.lower()
                if any(key in content for key in ["db_password", "api_key", "secret", "define(", "db_host"]):
                    results.append({"path": path, "url": url, "exposed": True, "status": resp.status_code})
                else:
                    results.append({"path": path, "url": url, "exposed": False, "status": resp.status_code, "note": "200 but no sensitive patterns"})
            else:
                results.append({"path": path, "url": url, "exposed": False, "status": resp.status_code})
        except Exception as e:
            results.append({"path": path, "url": url, "exposed": False, "error": str(e)})
    return results
