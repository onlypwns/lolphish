# LOLPHISH

**Living Off Legitimate Phishing Infrastructure** — a community catalog of the legitimate services, identity flows, and trust surfaces that phishing has industrialized on top of.

> LOLBAS catalogs abusable binaries. [LOTS](https://lots-project.com/) catalogs abusable domains. LOLPHISH catalogs the layer in between: the *mechanisms* — auth flows, notification pipelines, hosting surfaces, social-engineering primitives — that turn trusted infrastructure into phishing infrastructure.

**Live site:** `https://<your-username>.github.io/<repo-name>/`

---

## Why this exists

The perimeter learned to block bad domains. So phishing moved to *good* ones.

- The victim authenticates on the **real** `microsoft.com/devicelogin` — with their own MFA (device code flow phishing)
- The lure email is **genuinely from** `docusign.net`, SPF/DKIM/DMARC all green (SaaS invite phishing)
- The phish page is hosted on `workers.dev` behind Cloudflare's IP reputation (serverless hosting)
- The victim *is* the dropper — no file, no exploit, just a clipboard and a fake CAPTCHA (ClickFix)

Domain lists can't fix this. You have to understand the **abused primitive**. That's what each entry documents.

## Catalog structure

Every entry is a full record, LOLBAS-style:

| Field | Contents |
|---|---|
| `summary` | What the legitimate thing is for |
| `abuse` | The abuse primitive — the "how" |
| `variants` | Named mutations (each variant usually exists to defeat a *specific* control) |
| `kits` | Phishing kits, tooling, tracked actors |
| `surfaces` | The trust surfaces that make it credible |
| `attack` | MITRE ATT&CK mappings |
| `detections` | Telemetry + hunting guidance |
| `mitigations` | Structural controls — not IOC-of-the-week |
| `refs` | Public sources |
| `related` | IDs of related catalog entries |
| `status` | Maturity/state: `active`, `partially-mitigated`, `mitigated`, `patched`, `historical` |
| `since` | First widely documented |

### Categories

| Category | The phish… | Example entries |
|---|---|---|
| 🎣 **Identity Flow Abuse** | happens on the real login page | Device Code Flow, ROPC + First-Party Client IDs, Illicit Consent Grants, FOCI Pivoting, AiTM Reverse-Proxy |
| 🖱️ **User-Assisted Execution** | is executed by the victim themselves | ClickFix family (FileFix, CrashFix, GlitchFix…), Quishing |
| 📨 **Trusted Delivery** | arrives from infrastructure your filters trust | Exchange Direct Send, SaaS Invite Phishing, Calendar Invites, Transactional Relay Laundering |
| 🧼 **Reputation Laundering** | inherits someone else's good name | Serverless/JAMstack Hosting, Design-Tool Lures (Canva), IPFS, URL-Rewriter Laundering |

## Repository layout

```
├── entries/          # one YAML file per catalog entry (source of truth)
│   ├── _template.yml # annotated template for new entries
│   └── *.yml         # individual technique records
├── schema/
│   └── entry.schema.json   # JSON Schema enforced in CI
├── build.py          # validates entries/*.yml and regenerates data.js + api/entries.json
├── app.js            # renderer: filterable accordion table + detail panel
├── data.js           # generated catalog consumed by the site
├── api/
│   └── entries.json  # machine-readable feed for downstream tooling
├── index.html
├── styles.css
└── README.md
```

> **Contribution model:** copy `entries/_template.yml`, fill it in, run `python3 build.py`, and PR the new YAML together with the regenerated `data.js` and `api/entries.json`. No site code needs to be touched.

## Running locally

### Preview the built site

`data.js` is generated from `entries/*.yml`, so start with a build:

```bash
pip install -r requirements.txt
python3 build.py
python3 -m http.server 8080
# → http://localhost:8080
```

### Validate entries without building

```bash
python3 build.py --check
```

Opening `index.html` directly from disk also works after `build.py` has run — data is a plain script include.

## Contributing

The catalog is only as good as its coverage. Wanted:

- **New entries** — abusable primitives not yet covered (AWS Cognito device flow, Okta, Discord/Telegram webhook delivery, SEO poisoning, TOAD/callback phishing…)
- **New variants** on existing entries — the ClickFix genus alone grows monthly
- **Detection content** — real telemetry, KQL/Splunk queries, field-tested mitigations
- **Corrections** — cite a source and PR it

Ground rules:

1. **Public research only.** Everything here is already documented — the value is structuring it for defenders, not disclosing anything new.
2. **Every entry needs detection + mitigation fields.** An entry that's only a menu for attackers doesn't get merged.
3. **Variants must be real.** Named, observed in the wild or in published research, sourced.

## Sibling projects & sources

- [LOLBAS](https://lolbas-project.github.io/) — living off the land binaries
- [LOTS Project](https://lots-project.com/) — living off trusted sites
- [ClickGrab](https://mhaggis.github.io/ClickGrab/techniques.html) — ClickFix technique catalog
- [ClickFix Hunter](https://clickfix.carsonww.com/) — ClickFix campaign tracker
- [entrascopes](https://entrascopes.com/) — Entra first-party apps & scope browser
- [GTFOBins](https://gtfobins.github.io/) — the *nix cousin

## Disclaimer

This project exists for **defensive security**: detection engineering, threat modeling, and security awareness. All content is aggregated from public research. If you find a technique useful, your job is to go kill it in your environment.

---

*the phish is the platform*
