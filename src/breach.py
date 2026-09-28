import hashlib
import urllib.request

API_URL = "https://api.pwnedpasswords.com/range/"

def check_hibp_k_anonymity(password, timeout=8):
    """
    Checks HIBP Pwned Passwords using k-anonymity.
    Only the first 5 characters of the SHA-1 hash leave the application.
    """
    if not password:
        return {"status": "error", "count": 0, "message": "Empty password."}

    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]

    try:
        req = urllib.request.Request(
            API_URL + prefix,
            headers={"User-Agent": "Password-Security-Analyzer/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")

        for line in body.splitlines():
            parts = line.strip().split(":")
            if len(parts) == 2 and parts[0].upper() == suffix:
                return {"status": "ok", "count": int(parts[1]), "message": "Match found."}

        return {"status": "ok", "count": 0, "message": "No match found."}
    except Exception as exc:
        return {"status": "error", "count": 0, "message": str(exc)}
