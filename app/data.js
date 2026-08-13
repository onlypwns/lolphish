/* ============================================================
   LOLPHISH — Living Off Legitimate Phishing Infrastructure
   Entry schema (LOLBAS-style):
   {
     id:          stable slug
     name:        display name
     category:    Identity Flow Abuse | User-Assisted Execution |
                  Trusted Delivery | Reputation Laundering
     vendors:     abused platforms (filterable)
     summary:     what the legitimate thing is for
     abuse:       the abuse primitive (the "how")
     variants:    named mutations / child techniques
     kits:        phishing kits, tooling, tracked actors
     surfaces:    trust surfaces that make it credible
     attack:      MITRE ATT&CK mappings
     detections:  telemetry + hunting guidance
     mitigations: structural controls
     refs:        [{ title, url }]
     since:       first widely documented
   }
   ============================================================ */

const ENTRIES = [
  {
    id: "entra-device-code",
    name: "Device Code Flow Phishing",
    category: "Identity Flow Abuse",
    vendors: ["Microsoft Entra ID"],
    summary: "RFC 8628 device authorization grant — built so input-constrained devices (TVs, consoles, IoT) can sign in by having the user enter a short code on a second device at a real vendor URL.",
    abuse: "Attacker initiates a device code flow unauthenticated, then lures the victim to the genuine login page (microsoft.com/devicelogin) to enter the attacker's code. The victim completes their own MFA on Microsoft's real infrastructure — there is no phish page, no fake domain, nothing to block at the perimeter. The attacker polls the token endpoint and walks away with access + refresh tokens. Refresh tokens self-renew for ~90 days, and targeting the Microsoft Authentication Broker client ID escalates to PRT-grade persistence that survives password resets.",
    variants: [
      "Microsoft Authentication Broker client ID targeting (PRT / device registration path)",
      "Teams/phone-call lure ('enter this code to join the meeting')",
      "QR-delivered codes (device code + quishing hybrid)",
      "Azure CLI / Azure PowerShell client IDs for scope selection"
    ],
    kits: ["EvilTokens", "Kali365 / Octopi365", "SquarePhish2", "TokenTactics (POC)", "Storm-2372 (actor)"],
    surfaces: ["microsoft.com/devicelogin", "login.microsoftonline.com"],
    attack: ["T1566 — Phishing", "T1528 — Steal Application Access Token", "T1550.001 — Use Alternate Authentication Material"],
    detections: [
      "Entra sign-in logs: authenticationProtocol = deviceCodeFlow (hunt for source ASNs in hosting ranges — e.g. Tencent AS132203 in the Kali365 campaign)",
      "M365 Defender: 'Device code flow phishing' related alerts; impossible-travel + device-code combo",
      "Correlate lure-hosting referrers (Canva, shorteners) with devicelogin completions"
    ],
    mitigations: [
      "Conditional Access authentication-flows policy to block device code flow (Microsoft auto-provisions this for tenants now — verify, don't assume)",
      "Token protection / CA session controls to bind tokens to device",
      "User training: you never 'enter a code' to join a meeting"
    ],
    refs: [
      { title: "Microsoft — Storm-2372 device code phishing campaign", url: "https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/" },
      { title: "Huntress — Anatomy of the Kali365 / Octopi365 PhaaS kit", url: "https://www.huntress.com/blog/kali365-device-code-phishing-kit" },
      { title: "RFC 8628 — OAuth 2.0 Device Authorization Grant", url: "https://datatracker.ietf.org/doc/html/rfc8628" }
    ],
    since: "2021 (POCs) / 2024-25 (mass campaigns)"
  },

  {
    id: "entra-ropc-firstparty",
    name: "ROPC + First-Party Client ID Abuse",
    category: "Identity Flow Abuse",
    vendors: ["Microsoft Entra ID"],
    summary: "Resource Owner Password Credentials is a legacy OAuth grant where username+password are sent straight to the token endpoint. Microsoft pre-consents dozens of first-party client IDs (Office, Teams, Azure CLI, broker apps) with broad scopes in every tenant.",
    abuse: "With a phished or brute-forced password, the attacker authenticates as a trusted first-party app over ROPC — no consent prompt, no client secret, and frequently no MFA/CA evaluation because the flow looks like 'Microsoft Office' syncing. Picking the right client ID (per entrascopes.com) chooses your scopes, FOCI membership, and CA-bypass profile. Variants of this are the quiet workhorse behind credential-stuffing-to-mailbox-access pipelines and post-AiTM token laundering.",
    variants: [
      "Client-ID shopping for CA-bypass (per-app CA evaluation gaps)",
      "Scope staircasing: minimal scope for login, pivot to Mail.Read via FOCI",
      "ROPC against legacy-basic-auth-adjacent tenants that never blocked it",
      "Combined with AiTM: replay phished creds via ROPC to mint durable refresh tokens"
    ],
    kits: ["AADInternals (research)", "ROADtools (research)", "entrascopes.com (reference catalog)"],
    surfaces: ["login.microsoftonline.com token endpoint", "Pre-consented first-party app registrations"],
    attack: ["T1078 — Valid Accounts", "T1528 — Steal Application Access Token", "T1110 — Brute Force"],
    detections: [
      "Sign-ins with client app = 'Other clients' / public clients from data-center ASNs",
      "Non-interactive sign-in volume spikes per client ID",
      "Alert on known-abused first-party client IDs appearing from new IP ranges per user"
    ],
    mitigations: [
      "Block legacy auth org-wide and scope CA to 'all cloud apps' (no exclusions)",
      "CA: require compliant/hybrid-joined device for public-client flows",
      "Hunt baseline: enumerate which first-party client IDs your users legitimately use; alert off-baseline"
    ],
    refs: [
      { title: "entrascopes — Entra first-party apps & scope browser", url: "https://entrascopes.com/" },
      { title: "AADInternals", url: "https://aadinternals.com/" }
    ],
    since: "2019 (research) / ongoing in the wild"
  },

  {
    id: "entra-oauth-consent",
    name: "Illicit Consent Grant (OAuth Consent Phishing)",
    category: "Identity Flow Abuse",
    vendors: ["Microsoft Entra ID", "Google Workspace", "Salesforce", "GitHub"],
    summary: "OAuth consent is the legitimate 'Allow this app to read your mail?' screen — the mechanism that lets third-party apps get scoped access without ever knowing your password.",
    abuse: "The phish IS the consent screen, hosted on the real IdP. Victim clicks Accept on a convincing app registration (verified-publisher lookalike, or unverified with a click-through warning) and grants Mail.Read / offline_access to the attacker's app. Password and MFA never touched; access persists until the grant is revoked, and survives password changes entirely.",
    variants: [
      "Verified-publisher impersonation (display name/logo mimicry)",
      "Scope staircasing: ask for profile first, escalate later",
      "'ConsentFix' — ClickFix-style lures driving users to consent URLs",
      "App-registration-as-C2: granted app used for mailbox read + internal phishing pivot"
    ],
    kits: ["TA2552 (actor)", "Midnight Blizzard / NOBELIUM (OAuth app persistence)", "o365-attack-toolkit (research)"],
    surfaces: ["login.microsoftonline.com consent page", "accounts.google.com consent page"],
    attack: ["T1566.001 — Spearphishing Link", "T1550.001 — Use Alternate Authentication Material", "T1098.003 — Additional App Roles"],
    detections: [
      "Entra audit: 'Consent to application' events; new service principals with mail scopes",
      "Defender for Cloud Apps: risky OAuth app / unusual consent alerts",
      "Google Workspace token audit: new grants by unverified apps"
    ],
    mitigations: [
      "Disable user consent or restrict to verified publishers + low-impact scopes",
      "Admin consent workflow with scope review",
      "Automated grant-review playbook (new mail-scope grant → revoke + investigate)"
    ],
    refs: [
      { title: "Microsoft — consent grant attack guidance", url: "https://learn.microsoft.com/en-us/security/office-365-security/detect-and-remediate-illicit-consent-grants" },
      { title: "entrascopes — first-party scope reference", url: "https://entrascopes.com/" }
    ],
    since: "2017 (Google Docs worm) / 2020+ (Entra industrialization)"
  },

  {
    id: "foci-pivot",
    name: "FOCI Token Family Pivoting",
    category: "Identity Flow Abuse",
    vendors: ["Microsoft Entra ID"],
    summary: "Family of Client IDs (FOCI) lets Microsoft's own apps share refresh tokens: a refresh token issued to one family member can be redeemed for tokens to another family member's resources.",
    abuse: "Any phished or ROPC-minted first-party refresh token becomes a skeleton key: redeem it as Teams, then pivot the family to reach Office mail, Graph, or broker scopes the original grant never asked for. This turns low-scope compromises into broad mailbox/data access and complicates revocation scoping — defenders must kill the family, not the single token.",
    variants: [
      "Broker-client escalation into FOCI family",
      "Post-AiTM session laundering into FOCI tokens for durability",
      "Refresh-token resale pipelines (token markets) keyed on FOCI membership"
    ],
    kits: ["TokenTactics (POC)", "ROADtools (research)", "entrascopes.com (FOCI filter)"],
    surfaces: ["First-party refresh token family"],
    attack: ["T1550.001 — Use Alternate Authentication Material", "T1528 — Steal Application Access Token"],
    detections: [
      "Token redemptions for client IDs with no corresponding interactive sign-in",
      "Single user, many first-party client IDs in short windows",
      "Correlate refresh events against phishing-sign-in events (device code, AiTM ASN)"
    ],
    mitigations: [
      "Revoke at the user level (all refresh tokens) on any identity-phish event — not per-session",
      "Continuous Access Evaluation where supported",
      "Token protection CA policies for Exchange/SharePoint (P2)"
    ],
    refs: [
      { title: "entrascopes — FOCI status per first-party app", url: "https://entrascopes.com/" },
      { title: "AADInternals — FOCI research", url: "https://aadinternals.com/" }
    ],
    since: "2020 (public research)"
  },

  {
    id: "aitm-reverse-proxy",
    name: "AiTM Reverse-Proxy Phishing",
    category: "Identity Flow Abuse",
    vendors: ["Microsoft Entra ID", "Google Workspace", "Okta", "Any web SSO"],
    summary: "Adversary-in-the-middle kits reverse-proxy the real login page: the victim sees the genuine Microsoft/Google/Okta site, served live through attacker infrastructure.",
    abuse: "Because the proxy relays the real IdP, the victim's MFA completes for real — and the kit harvests the resulting session cookie/token in transit. Attackers replay the session directly or launder it into durable tokens (FOCI/ROPC). This is the technique that made 'MFA is enough' stop being true, and it is the industrial base of modern BEC.",
    variants: [
      "Session-cookie replay into attacker browser (companion desktop apps)",
      "Token laundering: session → refresh token → PRT (broker path)",
      "Targeted 'spear-phishing proxy' with per-victim cloned tenant branding",
      "AiTM behind clean-IP residential proxies to defeat ASN heuristics"
    ],
    kits: ["Evilginx", "Modlishka", "Tycoon 2FA", "Rockstar 2FA", "Mamba 2FA", "Sneaky 2FA", "NakedPages", "W3LL", "Greatness", "Graphish"],
    surfaces: ["Real IdP pages relayed through kit domains", "Kit panels on bulletproof/hosting ASNs"],
    attack: ["T1557 — Adversary-in-the-Middle", "T1539 — Steal Web Session Cookie", "T1566.002 — Spearphishing Link"],
    detections: [
      "Sign-in from hosting/data-center ASN immediately after victim MFA event",
      "Impossible travel + token replay alerts; 'stolen session cookie' detections in M365D",
      "Passive DNS on kit TLD patterns; proxy-rewrite artifacts (URL-in-URL)"
    ],
    mitigations: [
      "Phishing-resistant auth (FIDO2/passkeys) — origin binding defeats relay",
      "CA token protection + session controls (sign-in frequency, CAE)",
      "Conditional Access location/device policies that fail closed"
    ],
    refs: [
      { title: "Evilginx (reference kit)", url: "https://github.com/kgretzky/evilginx2" },
      { title: "Microsoft — token theft / AiTM guidance", url: "https://learn.microsoft.com/en-us/security/" }
    ],
    since: "2018 (Modlishka) / 2022+ (PhaaS industrialization)"
  },

  {
    id: "github-device-flow",
    name: "GitHub Device Flow & OAuth Phishing",
    category: "Identity Flow Abuse",
    vendors: ["GitHub"],
    summary: "GitHub implements the same RFC 8628 device flow for CLIs and headless environments (github.com/login/device), plus full OAuth app authorization.",
    abuse: "Attackers lure developers — frequently via fake job interviews, repo-collaboration invites, or fake security alerts — into entering an attacker-generated code on the real GitHub device page, or into authorizing an attacker OAuth app. Yields repo access, org membership visibility, and tokens usable against private code and CI secrets. The 2024-25 wave of dev-targeted recruitment lures leaned heavily on this.",
    variants: [
      "Fake recruiter / coding-challenge repos pushing device-code 'setup tools'",
      "OAuth app consent phishing for repo scope",
      "Compromised account → device flow against org colleagues (internal pivot)",
      "Malicious VS Code extension pairing with device flow"
    ],
    kits: ["Lazarus-adjacent recruitment lures (actor tradecraft)", "Custom scripts (device flow is 20 lines of Python)"],
    surfaces: ["github.com/login/device", "github.com/login/oauth/authorize"],
    attack: ["T1566 — Phishing", "T1528 — Steal Application Access Token", "T1078 — Valid Accounts"],
    detections: [
      "Org audit log: oauth_application.authorize and new user-code grants",
      "New OAuth authorizations with repo scope from unexpected geographies",
      "Alert on device-flow events for orgs that never use CLI device login"
    ],
    mitigations: [
      "Org policy: restrict third-party OAuth application access",
      "Require SSH/signing + SSO session controls for sensitive repos",
      "Developer training: real recruiters never ask you to 'authorize a device'"
    ],
    refs: [
      { title: "GitHub — authorizing OAuth apps (docs)", url: "https://docs.github.com/en/apps/oauth-apps" },
      { title: "RFC 8628 — Device Authorization Grant", url: "https://datatracker.ietf.org/doc/html/rfc8628" }
    ],
    since: "2023-24 (mass dev-targeting campaigns)"
  },

  {
    id: "clickfix-family",
    name: "ClickFix Family (User-Assisted Execution)",
    category: "User-Assisted Execution",
    vendors: ["Windows", "macOS", "Cross-platform (browser)"],
    summary: "Not one technique but a genus: clipboard-hijack social engineering that makes the victim execute the payload themselves — the user is the dropper. Lure page stages a command on the clipboard; a fake CAPTCHA / 'fix this error' prompt walks the victim through pasting it into a native execution surface.",
    abuse: "JavaScript writes a staged command (mshta/powershell/curl/osascript one-liner) to the clipboard; the page instructs Win+R → Ctrl+V → Enter (or the File Explorer address bar, Terminal, Script Editor). No file download, no exploit — execution is user-consented, so most perimeter controls see nothing. Microsoft named it the top initial-access method of 2025. Each variant exists to defeat a specific control: FileFix because orgs locked the Run dialog, Script Editor because Mac users learned to fear Terminal.",
    variants: [
      "ClickFix (original) — fake CAPTCHA → Win+R Run dialog",
      "FileFix — paste into File Explorer address bar (bypasses Run-dialog GPO)",
      "CrashFix — malicious extension genuinely crashes the browser, then offers a 'repair'",
      "GlitchFix / ErrTraffic — TDS actually corrupts page rendering so the 'fix' prompt is credible",
      "DNS staging — nslookup replaces PowerShell download (payload rides DNS)",
      "wt.exe — hex-encoded commands via Windows Terminal (dodges RunMRU)",
      "macOS Script Editor — applescript:// URL pre-loads the editor, no Terminal paste",
      "net use WebDAV — maps attacker share, sidesteps endpoint download inspection",
      "ClickFake Interview / fake Google Meet — job & meeting lures, Win+Mac payloads",
      "JackFix, ConsentFix, TerminalFix, DownloadFix — the naming free-for-all"
    ],
    kits: ["ClearFake (precursor)", "ErrTraffic TDS", "Lumma / AMOS stealer pipelines", "ClickGrab (catalog)", "ClickFix Hunter (tracker)"],
    surfaces: ["Fake reCAPTCHA / Cloudflare Turnstile clones", "Compromised legitimate sites", "Malvertising + SEO poisoning", "Hijacked browser extensions"],
    attack: ["T1204.001 — User Execution: Malicious Link", "T1059.001 — PowerShell", "T1218 — System Binary Proxy Execution", "T1185 — Browser Session Hijacking"],
    detections: [
      "Process chains: explorer.exe / run dialog MRU → powershell|mshta|curl|nslookup",
      "PowerShell 4104 script-block logging on paste-style one-liners",
      "Clipboard-to-shell behavioral rules (EDR); RunMRU & Explorer MRU forensics",
      "DNS anomalies: high-entropy TXT responses (nslookup staging)"
    ],
    mitigations: [
      "ASR rules + SmartScreen; PowerShell Constrained Language Mode",
      "Block Office/child-process LOLBin chains at EDR policy level",
      "Browser controls: restrict clipboard-write APIs on uncategorized sites",
      "Training that names the trick: 'no real CAPTCHA asks you to paste into Run'"
    ],
    refs: [
      { title: "ClickGrab — ClickFix technique catalog (mhaggis)", url: "https://mhaggis.github.io/ClickGrab/techniques.html" },
      { title: "ClickFix Hunter (campaign tracker)", url: "https://clickfix.carsonww.com/" },
      { title: "Microsoft threat intelligence", url: "https://www.microsoft.com/en-us/security/security-insider/microsoft-threat-intelligence" }
    ],
    since: "2024 (named by Proofpoint) / 2025-26 (variant explosion)"
  },

  {
    id: "quishing",
    name: "QR Code Phishing (Quishing)",
    category: "User-Assisted Execution",
    vendors: ["Microsoft 365", "Any email + mobile target"],
    summary: "QR codes are a legitimate bridge from desktop/print to mobile. In phishing they smuggle the URL past every email-layer control: the link is an image, and the victim's phone — outside corporate protection — is where it detonates.",
    abuse: "SEG URL rewriting, sandboxing, and detonation all operate on links — a QR inside a PNG/PDF is opaque to most pipelines. Victim scans with a personal phone, lands on an AiTM kit or a device-code page on an unmanaged device with no EDR, no proxy, no CA signal the SOC recognizes.",
    variants: [
      "MFA-enrollment QR ('scan to re-register your authenticator')",
      "QR-in-PDF-attachment to survive preview panes",
      "Nested QR / split-image reassembly vs OCR extraction",
      "Physical quishing (parking meters, office posters) as hybrid entry"
    ],
    kits: ["Tycoon 2FA (QR delivery)", "Rockstar 2FA", "Generic AiTM kits with QR modules"],
    surfaces: ["Email body images", "PDF attachments", "Print/physical media"],
    attack: ["T1566.001 — Spearphishing Attachment", "T1566.002 — Spearphishing Link"],
    detections: [
      "SEG with QR extraction/OCR; decode-and-rewrite URLs inside images",
      "Sign-ins from mobile carrier ASNs post-delivery",
      "Report-phish workflows tuned to image-only mails"
    ],
    mitigations: [
      "SEG QR decoding + click-time protection",
      "Block/banner image-only emails from external senders",
      "MFA re-registration flows that never involve a mailed QR"
    ],
    refs: [
      { title: "Microsoft — QR phishing guidance", url: "https://learn.microsoft.com/en-us/security/" }
    ],
    since: "2023 (mass campaigns)"
  },

  {
    id: "m365-direct-send",
    name: "Exchange Direct Send & Tenant Sender Abuse",
    category: "Trusted Delivery",
    vendors: ["Microsoft 365 / Exchange Online"],
    summary: "Direct Send lets devices and apps inside an org mail via the tenant smart host (<tenant>.mail.protection.outlook.com) without authentication. .onmicrosoft.com domains are every tenant's built-in Microsoft-assigned sender domain.",
    abuse: "Attackers abuse Direct Send to spoof internal users — mail arrives looking like it came from the CFO's real internal address, through Microsoft's own infrastructure, often bypassing SPF/DKIM expectations that were configured for perimeter mail rather than 'internal' flows. Parallel primitive: freshly created tenants send from legitimate *.onmicrosoft.com addresses that inherit Microsoft's sender reputation.",
    variants: [
      "Direct Send spoofing of internal addresses (CFO/IT lures)",
      "Burner-tenant .onmicrosoft.com outbound phishing",
      "Abuse of tenant-to-tenant trust in hybrid Exchange",
      "Direct Send + voicemail/notification lures (looks like internal system mail)"
    ],
    kits: ["Commodity BEC tooling", "Custom PowerShell/SMTP scripts"],
    surfaces: ["*.mail.protection.outlook.com", "*.onmicrosoft.com"],
    attack: ["T1566.001 — Spearphishing Attachment", "T1566.002 — Spearphishing Link", "T1078 — Valid Accounts"],
    detections: [
      "Inbound mail where internal sender resolves only via smart-host path (no auth results)",
      "Alert on RejectDirectSend=false tenants receiving unauthenticated internal-claimed mail",
      "New-tenant onmicrosoft senders with zero prior relationship"
    ],
    mitigations: [
      "Set RejectDirectSend=true (Exchange Online org setting)",
      "SPF hard-fail + DMARC reject; review hybrid connectors",
      "External-sender banner even for lookalike-internal display names"
    ],
    refs: [
      { title: "Microsoft — Direct Send documentation", url: "https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365" }
    ],
    since: "2025 (mass-abuse wave)"
  },

  {
    id: "saas-invite-phish",
    name: "SaaS Notification & Invite Phishing",
    category: "Trusted Delivery",
    vendors: ["DocuSign", "SharePoint/OneDrive", "Google Drive", "Dropbox", "Adobe Acrobat Sign", "Lucid"],
    summary: "Document platforms send real notification emails from their real domains when someone shares a file or requests a signature. That notification pipeline is the lure delivery mechanism.",
    abuse: "The phish email is *actually from* docusign.net / sharepointonline.com / dropbox.com — SPF, DKIM, DMARC all pass, sender reputation is pristine. The payload lives one click deeper: a malicious link inside the shared doc, a credential page behind the 'sign' button, or an OAuth consent screen. Defenders are left arguing with allowlists that were supposed to keep these domains clean.",
    variants: [
      "DocuSign envelope abuse (compromised or free accounts)",
      "SharePoint/OneDrive share notifications → AiTM link in the doc",
      "Google Drive/Docs comment-mention phishing (notification without share)",
      "Adobe Sign / Lucidchart / Miro variants — any platform with a notify feature",
      "Compromised-vendor-account phishing (real org's account sends the lure)"
    ],
    kits: ["Commodity PhaaS lure templates", "Compromised SaaS accounts (no kit needed)"],
    surfaces: ["docusign.net", "sharepointonline.com", "docs.google.com", "dropbox.com", "adobesign.com"],
    attack: ["T1566.002 — Spearphishing Link", "T1566.003 — Spearphishing via Service"],
    detections: [
      "Click telemetry: SaaS notification → off-platform credential domain within N seconds",
      "New-sender relationship analytics on notification service accounts",
      "Doc-content scanning where API access exists (CASB)"
    ],
    mitigations: [
      "Click-time URL protection (rewrites that re-scan at click, not just delivery)",
      "CASB/SSPM controls on inbound sharing from unknown tenants",
      "User training anchored on 'real sender ≠ safe link'"
    ],
    refs: [
      { title: "LOTS Project — abused trusted sites", url: "https://lots-project.com/" }
    ],
    since: "2019+ (industrialized 2023+)"
  },

  {
    id: "calendar-invite-phish",
    name: "Calendar Invite Phishing",
    category: "Trusted Delivery",
    vendors: ["Google Calendar", "Microsoft 365", "Apple"],
    summary: "Calendar systems auto-process invites: Google Calendar can auto-add events from emailed .ics invites; Outlook surfaces tentative meetings. The event — with its description field — lands on the victim's device through a channel email security barely inspects.",
    abuse: "Attacker sends an .ics invite whose description/location fields carry the phishing link (fake billing dispute, 'missed meeting notes', MFA reset). The event appears natively in the calendar UI — a trusted surface with push notifications — and SEGs historically didn't rewrite or detonate links inside invite bodies. Newer twist: calendar invites as indirect prompt-injection carriers against AI assistants that summarize schedules.",
    variants: [
      "Fake subscription/billing 'cancel this charge' events",
      "Meeting-notes lure with AiTM link in description",
      "Recurring-event persistence (reminder re-fires weekly)",
      "AI-assistant prompt injection via invite text"
    ],
    kits: ["Commodity .ics generators", "PhaaS calendar modules"],
    surfaces: ["calendar.google.com", "Outlook tentative-accept UI", "ICS attachments"],
    attack: ["T1566.001 — Spearphishing Attachment", "T1566.003 — Spearphishing via Service"],
    detections: [
      "Mail flow rules flagging .ics with URLs in DESCRIPTION/LOCATION",
      "Endpoint: calendar events from external organizers with link payloads",
      "User-report pipeline tuned for calendar lures"
    ],
    mitigations: [
      "Google Calendar: 'only add invitations I respond to' / disable auto-add from unknown senders",
      "SEG coverage for invite-body URLs",
      "Block external .ics at gateway for high-risk user groups"
    ],
    refs: [
      { title: "Google Calendar — invitation settings", url: "https://support.google.com/calendar/" }
    ],
    since: "2019 (first waves) / 2024+ (resurgence + AI angle)"
  },

  {
    id: "canva-design-lures",
    name: "Design-Tool Hosted Lures",
    category: "Reputation Laundering",
    vendors: ["Canva", "Adobe Express", "Figma", "Lucid"],
    summary: "Design platforms let anyone publish a shareable page on the platform's own domain (canva.com design links, etc.) — complete with platform TLS, reputation, and categories like 'business/graphics' in every web filter.",
    abuse: "The lure page is a real Canva design: 'this email is encrypted — click to view' with a button to the actual phishing flow (device code, AiTM). Observed in production in the Kali365/Octopi365 campaigns: Tencent-hosted kits, but the victim's first click is canva.com. No filter can block Canva; the abuse is architectural.",
    variants: [
      "Canva 'encrypted message' envelopes (Kali365 pattern)",
      "Figma/Lucid whiteboard 'project review' lures",
      "Design-link → shortener → device-code chain (multi-hop reputation laundering)",
      "QR embedded in the design image itself"
    ],
    kits: ["Kali365 / Octopi365 (observed)", "Commodity PhaaS templates"],
    surfaces: ["canva.com", "*.my.canva.site", "figma.com", "adobe.ly shorteners"],
    attack: ["T1566.002 — Spearphishing Link", "T1608.001 — Stage Capabilities: Upload Malware/Lures"],
    detections: [
      "Web proxy: design-tool pageview → identity-domain navigation within seconds",
      "New-domain-relationship alerts on canva.site subdomains",
      "Passive DNS / certificate transparency on design subdomains with brand keywords"
    ],
    mitigations: [
      "URL isolation for design-platform links from email",
      "Behavioral correlation controls (design click + auth event = alert)",
      "Vendor abuse-report pipelines (Canva removes reported lures)"
    ],
    refs: [
      { title: "Huntress — Kali365 lure hosting on Canva", url: "https://www.huntress.com/blog/kali365-device-code-phishing-kit" },
      { title: "LOTS Project", url: "https://lots-project.com/" }
    ],
    since: "2024-25 (observed in PhaaS chains)"
  },

  {
    id: "serverless-hosting",
    name: "Serverless & JAMstack Phish Hosting",
    category: "Reputation Laundering",
    vendors: ["Cloudflare Workers/Pages", "Vercel", "Netlify", "Azure Static Web Apps", "Firebase", "GitHub Pages", "Render", "Railway"],
    summary: "Every major platform hands out free HTTPS subdomains on its own domain — workers.dev, vercel.app, web.app, azurestaticapps.net — with the platform's IP reputation, TLS, and web-filter category.",
    abuse: "Phishing pages deploy in seconds to pristine infrastructure: wildcard TLS, CDN IPs shared with Fortune 500 traffic, categories like 'computers/software'. Takedown is per-subdomain whack-a-mole against platforms with millions of legit users. AiTM kits ship with one-click deploys to these targets, and redirect chains use them as clean middle hops.",
    variants: [
      "Workers/Pages as AiTM proxy frontends (edge compute = relay logic)",
      "Per-campaign burner subdomains with brand-keyword names",
      "Chained hops: bit.ly → vercel.app → workers.dev → kit",
      "Firebase dynamic links / GitHub Pages redirectors"
    ],
    kits: ["Tycoon 2FA", "Greatness", "W3LL", "Most PhaaS panels ship one-click deploys"],
    surfaces: ["workers.dev", "pages.dev", "vercel.app", "netlify.app", "web.app / firebaseapp.com", "azurestaticapps.net", "github.io", "onrender.com", "up.railway.app"],
    attack: ["T1608.001 — Stage Capabilities", "T1583.006 — Acquire Infrastructure: Web Services", "T1566.002 — Spearphishing Link"],
    detections: [
      "Passive DNS: brand-keyword subdomains on platform domains",
      "Certificate Transparency monitoring for lookalike names",
      "Egress analytics: rare subdomains + form POSTs + identity-domain referrers"
    ],
    mitigations: [
      "Subdomain-level (not platform-level) blocking with rapid feedback loops",
      "URL isolation/remote browsing for uncategorized platform subdomains",
      "CT-log brand monitoring + automated abuse reports"
    ],
    refs: [
      { title: "LOTS Project — trusted-site abuse catalog", url: "https://lots-project.com/" }
    ],
    since: "2020+ (default PhaaS posture by 2023)"
  },

  {
    id: "ipfs-hosting",
    name: "IPFS / Decentralized Phish Hosting",
    category: "Reputation Laundering",
    vendors: ["IPFS gateways", "Filecoin/Arweave ecosystem"],
    summary: "IPFS content is addressed by hash (CID) and served through public HTTP gateways (ipfs.io, dweb.link, cloudflare-ipfs.com). No account, no hosting provider, no takedown handle on the content itself.",
    abuse: "Phishing pages pinned to IPFS ride high-reputation gateway domains; the same content reappears on any of dozens of gateways after a single-gateway block. Blocking ipfs.io wholesale breaks legitimate Web3 traffic; blocking per-CID is Sisyphean. Used for credential pages and malware staging alike.",
    variants: [
      "Gateway rotation after takedown (same CID, new host)",
      "CID-in-path vs CID-in-subdomain encoding tricks vs regex blocks",
      "IPFS + ENS/.crypto naming for semi-permanent brand squatting",
      "Phishing kits bundling IPFS publish scripts"
    ],
    kits: ["Commodity kit modules", "Pinning-service abuse (Pinata etc.)"],
    surfaces: ["ipfs.io", "dweb.link", "cloudflare-ipfs.com", "gateway.pinata.cloud", "arweave.net"],
    attack: ["T1608.001 — Stage Capabilities", "T1583.006 — Acquire Infrastructure: Web Services"],
    detections: [
      "Egress: gateway domains + credential-form POST behavior",
      "Brand monitoring across gateway + CID combinations",
      "Email SEG: URL rewriting that inspects CID-path links"
    ],
    mitigations: [
      "Gateway restriction to sanctioned business gateways, others to isolation",
      "Click-time protection on CID-pattern URLs",
      "Abuse reporting to gateway operators (they can denylist CIDs)"
    ],
    refs: [
      { title: "LOTS Project", url: "https://lots-project.com/" }
    ],
    since: "2022+ (steady background hum)"
  },

  {
    id: "url-rewriter-laundering",
    name: "URL Rewriter & Open-Redirect Laundering",
    category: "Reputation Laundering",
    vendors: ["Proofpoint URL Defense", "Microsoft Safe Links", "Google", "LinkedIn", "Bing", "Any SEG"],
    summary: "Secure email gateways rewrite inbound links through their own scanning domains (urldefense.com, *.safelinks.protection.outlook.com). Major platforms run open-redirect endpoints (google.com/url, linkedin.com/slink, bing.com/ck/a) for click tracking.",
    abuse: "Attackers send their phishing link through a target that already has the SEG — the inbound copy arrives pre-wrapped in the victim's own protection vendor's domain. Filters see urldefense.com (trusted); users were trained that 'wrapped = scanned = safe'. Open redirects do the same with household brands: the visible domain is google.com, the detonation happens at the redirect target. Reputation laundering as a service, performed by your own security stack.",
    variants: [
      "Cross-tenant wrapping: attacker mails themselves first to obtain wrapped links",
      "Safe Links link re-sharing (wrapped link harvested, reused against other tenants)",
      "Google/Bing/LinkedIn open-redirect chains as final hop",
      "Multi-SEG wrapping (rewrite-in-rewrite) to defeat decoder heuristics"
    ],
    kits: ["Commodity — no kit needed, just a victim tenant with an SEG", "Redirect-chain builders in PhaaS panels"],
    surfaces: ["urldefense.com", "*.safelinks.protection.outlook.com", "google.com/url", "bing.com/ck/a", "lnkd.in / linkedin.com/slink"],
    attack: ["T1566.002 — Spearphishing Link", "T1027 — Obfuscated Files or Information"],
    detections: [
      "Decoder that unwraps all known rewriter schemes to the terminal URL",
      "Alert on wrapped links whose terminal domain is newly registered",
      "Click telemetry: rewrite-domain click from a tenant that never received the original mail"
    ],
    mitigations: [
      "SEG click-time re-scanning (not just delivery-time verdict)",
      "Block known open-redirect patterns at the proxy",
      "Train users that wrapped links are *links*, not verdicts"
    ],
    refs: [
      { title: "Proofpoint — URL Defense documentation", url: "https://www.proofpoint.com/" },
      { title: "Microsoft — Safe Links documentation", url: "https://learn.microsoft.com/en-us/defender-office-365/safe-links-about" }
    ],
    since: "2021+ (chronic, under-cataloged)"
  },

  {
    id: "trusted-mail-relays",
    name: "Transactional Mail Relay Laundering",
    category: "Trusted Delivery",
    vendors: ["SendGrid", "Amazon SES", "Mailgun", "Postmark", "Brevo", "SMTP2GO"],
    summary: "Transactional email providers exist so apps can send mail that inboxes trust — their IPs and domains carry decades of deliverability reputation.",
    abuse: "Free-tier or compromised relay accounts send phishing that passes SPF/DKIM alignment through the provider's infrastructure. BEC and callback-phishing (TOAD) operations favor relays precisely because 'received: from sendgrid.net' defuses both filters and analysts. Compromised legitimate sender accounts are the premium tier: real brand, real domain, real signatures.",
    variants: [
      "Free-tier account farming for clean-IP bursts",
      "Compromised customer accounts (real brand sends the lure)",
      "Relay reply-chain hijack (thread hijacking from real inboxes)",
      "Webhook-configured bounce/tracking domains as redirectors"
    ],
    kits: ["Commodity BEC tooling", "TOAD/callback phishing operations"],
    surfaces: ["sendgrid.net", "amazonses.com", "mailgun.org", "postmarkapp.com"],
    attack: ["T1566 — Phishing", "T1586.002 — Compromise Accounts: Email Accounts"],
    detections: [
      "First-time sender analytics even on 'trusted' relay domains",
      "Content/brand mismatch: relay sender + credential lure",
      "DMARC aggregate reports showing unowned sending sources"
    ],
    mitigations: [
      "Strict DMARC (p=reject) to shrink spoofing surface",
      "Inbound policy: relay-origin mail still subject to full content inspection",
      "Provider abuse pipelines + key rotation hygiene for your own accounts"
    ],
    refs: [
      { title: "LOTS Project", url: "https://lots-project.com/" }
    ],
    since: "Chronic / industrialized 2022+"
  }
];

/* Derived stats for the header */
const STATS = {
  entries: ENTRIES.length,
  variants: ENTRIES.reduce((n, e) => n + e.variants.length, 0),
  kits: ENTRIES.reduce((n, e) => n + e.kits.length, 0),
  categories: [...new Set(ENTRIES.map(e => e.category))]
};

const CATEGORY_META = {
  "Identity Flow Abuse":     { color: "#6fd3d3", blurb: "Abused auth mechanisms — the phish happens on the real login page" },
  "User-Assisted Execution": { color: "#d3b46f", blurb: "The victim is the dropper — clipboard, QR, paste-to-run tricks" },
  "Trusted Delivery":        { color: "#b48fd3", blurb: "The lure arrives from infrastructure your filters were told to trust" },
  "Reputation Laundering":   { color: "#8fd3a0", blurb: "Hosting and redirect chains that inherit someone else's good name" }
};
