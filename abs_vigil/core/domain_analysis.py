import socket
import ssl
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

try:
    import whois as whois_lib
except ImportError:
    whois_lib = None

try:
    import tldextract
    _TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())
except ImportError:
    tldextract = None
    _TLD_EXTRACTOR = None


def check_domain_age(domain):
    if whois_lib is None:
        return None, "python-whois not installed"
    try:
        w = whois_lib.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return None, "Creation date unavailable"
        if isinstance(creation, str):
            return None, "Could not parse creation date"

        if creation.tzinfo is not None:
            creation = creation.astimezone(datetime.timezone.utc).replace(tzinfo=None)

        age_days = (datetime.datetime.utcnow() - creation).days
        return age_days, w.registrar
    except Exception as e:
        return None, f"WHOIS lookup failed: {e}"


def check_ssl_certificate(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.now()).days
                issuer = dict(x[0] for x in cert.get("issuer", []))
                return {
                    "valid": True,
                    "days_until_expiry": days_left,
                    "issuer": issuer.get("organizationName", "Unknown")
                }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def check_dns_resolves(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False


def analyze_domain(url):
    score = 0
    reasons = []
    details = {}

    parsed = urlparse(url)
    netloc = parsed.netloc.split(":")[0]

    if _TLD_EXTRACTOR:
        ext = _TLD_EXTRACTOR(url)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else netloc
    else:
        domain = netloc

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(check_dns_resolves, netloc): "dns",
            executor.submit(check_domain_age, domain): "whois",
            executor.submit(check_ssl_certificate, netloc): "ssl",
        }
        results = {}
        for future in as_completed(futures):
            label = futures[future]
            try:
                results[label] = future.result()
            except Exception as e:
                results[label] = e

    resolves = results.get("dns")
    if isinstance(resolves, Exception):
        resolves = False
    details["dns_resolves"] = resolves
    if not resolves:
        score += 30
        reasons.append("Domain does not resolve via DNS")

    whois_result = results.get("whois")
    if isinstance(whois_result, Exception):
        age_days, registrar_or_error = None, f"WHOIS lookup failed: {whois_result}"
    else:
        age_days, registrar_or_error = whois_result
    details["domain_age_days"] = age_days
    details["registrar_info"] = registrar_or_error
    if age_days is not None:
        if age_days < 30:
            score += 30
            reasons.append(f"Domain registered very recently ({age_days} days ago)")
        elif age_days < 180:
            score += 15
            reasons.append(f"Domain is relatively new ({age_days} days old)")
        else:
            reasons.append(f"Domain age: {age_days} days (established)")
    else:
        reasons.append(f"Domain age unknown ({registrar_or_error})")

    ssl_info = results.get("ssl")
    if isinstance(ssl_info, Exception):
        ssl_info = {"valid": False, "error": str(ssl_info)}
    details["ssl"] = ssl_info
    if resolves:
        if not ssl_info.get("valid"):
            score += 20
            reasons.append("No valid SSL certificate found")
        elif ssl_info.get("days_until_expiry", 0) < 0:
            score += 15
            reasons.append("SSL certificate has expired")
        else:
            reasons.append(f"Valid SSL certificate (issuer: {ssl_info.get('issuer')})")

    score = min(score, 100)

    return {
        "score": score,
        "reasons": reasons,
        "details": details
    }
