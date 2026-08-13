# Contributing to LOLPHISH

The catalog is only as good as its coverage. Three ways to contribute, easiest first:

## 1. Propose an entry (no Git knowledge needed)

Open a **[New Entry Proposal](../../issues/new?template=new-entry.yml)** issue and fill in the YAML template. A maintainer reviews it; when it's labeled `approved`, automation turns it into a PR, and merging the PR rebuilds the site within about a minute. You get credited in the PR and issue thread.

## 2. Report a variant or fix

- **[New Variant](../../issues/new?template=new-variant.yml)** — e.g. the latest ClickFix mutation. One line + one source.
- **[Correction](../../issues/new?template=correction.yml)** — wrong detail, dead link, or a technique a vendor has since killed. Killed techniques are *valuable* — we track them as killed, we don't delete history.

## 3. PR directly

```bash
cp entries/_template.yml entries/my-entry-slug.yml   # fill it in
python3 build.py --check                              # validate (needs: pyyaml jsonschema)
python3 build.py                                      # regenerate data.js + api/entries.json
```

PR the new `entries/*.yml` file **and** the regenerated `data.js` / `api/entries.json` (or leave them — CI rebuilds on merge anyway).

## Ground rules

1. **Public research only.** Every claim links to a published source in `refs`. This project aggregates and structures; it does not disclose.
2. **Detections + mitigations are mandatory.** An entry that's only an attacker's menu doesn't get merged. Detection-as-code (KQL/Sigma/Splunk) is the gold standard.
3. **Variants must be real.** Named, observed in the wild or in published research, sourced. No speculative taxonomies.
4. **Mechanism over campaign.** Entries describe the abusable *primitive*; campaigns and actors belong in the `kits` field as examples, not as the entry itself.
5. **Neutral voice.** Describe what the thing does and how it's abused. No vendor bashing, no fear-mongering, no marketing.

## Schema reference

See `entries/_template.yml` (annotated) and `schema/entry.schema.json` (enforced in CI). The four categories are fixed: **Identity Flow Abuse**, **User-Assisted Execution**, **Trusted Delivery**, **Reputation Laundering** — propose a fifth by opening an issue first.

## Credit

Contributors are credited in PRs and in the git history of their entries. If this grows, we'll add a contributors section to the site — built from git blame, because that's the honest way.
