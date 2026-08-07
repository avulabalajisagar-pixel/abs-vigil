# 🛡️ ABS VIGIL — Advanced Behavioral Shield

A unified, multi-channel phishing/social-engineering detection platform.
Where most tools score a single artifact in isolation (one URL, one QR code),
ABS VIGIL correlates signals **across channels** through a shared **Entity
Risk Graph** — because real attacks today aren't single-channel. A domain
shows up in a smishing text, then an email, then a QR code inside a PDF.
Catching it once should make catching it again instant.

## The problem

Off-the-shelf phishing heuristics (keyword lists, domain age, SSL presence)
are increasingly easy for attackers to route around:

- **LLM-written phishing copy** doesn't contain "verify/login/secure" —
  keyword matching is dying as a primary signal.
- **Legit infra abuse** (Cloudflare Pages, Firebase, Vercel) gives attackers
  valid SSL + clean parent-domain reputation for free.
- **Typosquats and subdomain stuffing** (`paypa1.com`,
  `paypal.com.verify-secure.io`) look fine to naive string checks.
- **Smishing (SMS phishing)** is growing fastest of all channels precisely
  because almost nobody scans it — SMS has no equivalent of email's
  SPF/DKIM/DMARC, so sender spoofing is nearly free for attackers.
- Tools that treat every scan as a blank slate **throw away the fact that
  they've seen this domain/number before** in a different channel.

## What this build adds on top of the original URL/QR scanner

| Module | What it does | Why it matters |
|---|---|---|
| **SMS / Smishing Scanner** | Extracts embedded links, analyzes sender-ID spoofability, scores manipulative language | Fastest-growing, least-defended attack channel |
| **Brand Impersonation Engine** | Typosquat similarity scoring + leetspeak normalization + subdomain-stuffing detection against a curated brand list | Catches attacks with zero suspicious keywords |
| **Social-Engineering Intent Scorer** | Rule-based urgency/authority/fear/reward classifier, with optional LLM-enhanced mode | Survives LLM-generated phishing text that has no "tells" |
| **Cross-Channel Entity Risk Graph** | SQLite-backed correlation table tracking every domain/phone across every channel it's been seen in | Turns 3 scanners into 1 connected intelligence platform |

## Architecture

```
app.py                      Streamlit UI, orchestrates all pipelines
core/
  db.py                     scans + entities (the correlation graph)
  url_analysis.py           structural heuristics + brand check hook
  domain_analysis.py        WHOIS / DNS / SSL (concurrent)
  brand_impersonation.py    typosquat / leetspeak / subdomain-stuffing
  intent_scoring.py         rule-based + optional LLM social-engineering scorer
  threat_intel.py           VirusTotal + Google Safe Browsing
  sms_analysis.py           SMS pipeline, reuses url/domain/intent engines
  scoring.py                weighted final risk score for URL/QR pipeline
data/
  brands.json               curated impersonation target list
```

Each analysis branch is independent and returns a `{score, reasons}` shape,
so the weighted scoring engine and the UI don't need to know the internals
of any one branch — new channels (email, next) plug into the same pattern.

## Running it

```bash
pip install -r requirements.txt
streamlit run app.py
```

Optional API keys (all features gracefully degrade without them — same
pattern used for VT/GSB in the original build):

```toml
# .streamlit/secrets.toml
VT_API_KEY = "..."          # VirusTotal
GSB_API_KEY = "..."         # Google Safe Browsing
ANTHROPIC_API_KEY = "..."   # enables LLM-enhanced intent scoring
```

## Deliberately scoped out (roadmap, not faked)

These needed either paid infra or live-network reliability we didn't want
to risk on a demo, so they're documented instead of half-built:

- **Cloaking Detector** — diffing responses across UAs/geos to catch
  pages that serve scanners a clean version and victims a malicious one.
- **Email Scanner** — SPF/DKIM/DMARC header forensics + nested-QR
  ("quishing") extraction from PDF attachments.
- **Carrier-level SMS sender verification** — needs a telecom API partner.
- **Favicon/visual similarity hashing** for pixel-level brand matching.
- **Browser extension** for real-time, click-time protection.
- **Public API** for SOC/Slack/Teams integration — the natural path from
  demo to funded product.

## The business angle

Individually, "email scanner" and "SMS scanner" are commodity features —
every vendor has one. The Entity Risk Graph is the actual product thesis:
a lightweight, channel-agnostic correlation layer that gets more valuable
with every scan and every new channel added. That's the difference between
a scanning tool and a threat-intelligence platform — and it's what scales
into an API product, a browser extension, or an enterprise SOC integration.
