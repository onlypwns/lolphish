# LOLPHISH content review

Reviewed 2026-10-28 against the 28-entry catalog and its 39 detection snippets.

## Intended use

LOLPHISH is a defender-focused catalog of legitimate mechanisms that can be abused in phishing,
post-compromise, lateral-movement, persistence, and delivery chains. It is useful as:

- a threat-modeling and research index;
- a map from abuse prerequisites to useful telemetry and controls;
- a source of detection-hunting starting points; and
- reusable structured data for defensive tooling.

It is not currently a production detection pack or a vulnerability database. Detection snippets
must be tested against the target product, connector, schema, baseline, and false-positive profile.

## Evidence standard

Course labs are legitimate groundwork for plausible paths and observed behavior under specific
conditions. They are used alongside vendor documentation, public research, independent testing,
and campaign reporting. A scenario does not need campaign attribution to belong in the catalog.

Entries should distinguish:

- **Lab scenario:** behavior observed under a stated lab configuration.
- **Vendor documentation:** product behavior or limits described by its vendor.
- **Public research:** analysis published by an attributable third party.
- **Independent test:** behavior reproduced outside the originating lab.
- **Observed campaign:** behavior documented in real-world activity.

A difference between a lab result and vendor documentation warrants investigation. It does not
automatically invalidate the lab. Wording should retain the observation while limiting it to its
demonstrated prerequisites and scope.

## Changes made from this review

- Added optional `prerequisites` and `evidence` fields to the schema and renderer.
- Applied those fields to the supplied SMTP AUTH, ROPC, TAP, and cross-tenant lab scenarios.
- Marked every existing detection snippet as `hunting-starting-point` by default in generated data.
- Added an API-level usage note so downstream consumers receive the same qualification as site users.
- Corrected documented table fields, KQL operations, case-sensitive values, and OAuth error/protocol
  constants across affected queries.
- Corrected the OAuth consent ATT&CK link mapping and the design-hosting ATT&CK mapping.
- Reframed broad SMTP AUTH, ROPC, TAP, cross-tenant trust, FOCI, and PIM language around starting
  access, configuration, authorization, and observed outcomes.
- Corrected the SAS recommendation: `srt=o` on an account SAS does not restrict access to one blob.
- Reworked the URL-rewriter hunt to use `EmailUrlInfo`; wrappers still require vendor-specific decoding
  before a terminal destination can be claimed.
- Added visibility limits where endpoint telemetry may contain only a hostname rather than a full URL.

## Lab-backed scenarios incorporated

### SMTP AUTH

The supplied course example reports successful password-based SMTP sending for a mailbox with
SMTP AUTH enabled per user despite an MFA policy targeting the user and all cloud apps. The entry
preserves this as a configuration-dependent post-compromise path. It does not generalize the result
to OAuth-based SMTP AUTH or to environments where legacy authentication is successfully blocked.

### ROPC and Microsoft Graph

The supplied example reports successful Microsoft Graph token acquisition using compromised
credentials, ROPC, a first-party client ID, and a mobile-looking User-Agent under the lab policy.
The entry preserves the result while noting that a User-Agent string does not establish device
compliance and ROPC cannot satisfy an interactive MFA challenge when one is actually enforced.

### Temporary Access Pass and cross-tenant access

The supplied narrative reports a compromised application with scoped Authentication Administrator
authority creating a TAP for an in-scope user, authenticating as that user, and switching into a
mapped resource tenant without another MFA prompt under configured cross-tenant trust. It also
reports access-token usability for 70–75 minutes after a ten-minute TAP. Both observations are
retained as lab results rather than universal behavior.

## Remaining validation work

- Execute every KQL snippet in its named product with representative positive and benign fixtures.
- Record connector/table requirements, licensing, expected fields, tuning guidance, and measured
  false positives for queries promoted to `validated`.
- Add `prerequisites` and `evidence` metadata to the remaining historical entries as their sources
  are re-reviewed; optional fields preserve API compatibility during this migration.
- Replace homepage-level references with direct research or documentation for specific campaign,
  patch-status, persistence, and token-lifetime claims.
- Recheck time-sensitive product behavior, retirement schedules, and `active`/`patched` statuses on
  a documented review cadence.
- Validate ATT&CK mappings against the described action rather than mapping an entire attack chain
  to every entry.

## Review limits

Schema validation and browser tests were executed. Queries were checked against published table
schemas where available, but no Sentinel, Defender, Entra, Exchange, Azure Storage, GitHub, or AWS
tenant was connected for live execution. Screenshots referenced by the supplied TAP narrative were
not available in the pasted text. Private course content should not be copied into public records;
entries retain only bounded defensive observations and prerequisites.
