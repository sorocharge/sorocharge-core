# Security — IOC management guide

This directory holds the data files consumed by `scripts/malware_scan.py`, the
CI gate that checks every PR and push for known supply-chain indicators and
generic heuristics.

---

## Files

| File | Purpose |
|------|---------|
| `malware_iocs.json` | Threat-specific indicators of compromise (IOCs) |
| `scan_allowlist.json` | Per-file exceptions for files the generic heuristics would otherwise flag |

---

## `malware_iocs.json` schema

The file contains a top-level JSON object with these keys:

```jsonc
{
  "campaigns": {
    "<CampaignName>": {
      "_source": "Human-readable citation for where these IOCs come from",
      "literal_strings": ["exact string to match"],
      "domains": ["hostname.example"],
      "malicious_packages": {
        "npm": ["package-name"],
        "packagist_namespaces": ["vendor"]
      },
      "suspicious_filenames": ["tasks.json"]
    }
  },
  "non_project_blockchain_domains": {
    "_comment": "...",
    "domains": ["chain-rpc.example"]
  },
  "generic_exfil_hosts": {
    "_comment": "...",
    "domains": ["paste-site.example"]
  },
  "suspicious_filename_patterns": {
    "_comment": "...",
    "exact_names": ["tasks.json"],
    "extensions": [".bat"]
  }
}
```

### Adding a new campaign

1. Research the campaign thoroughly before adding any IOCs. Confirm each
   indicator is unique to the malicious campaign and not shared with legitimate
   packages in this ecosystem.

2. Create a new key under `"campaigns"` named after the campaign (e.g.
   `"PolinRider"`).

3. Populate `"_source"` with a human-readable citation: at minimum the campaign
   name, the threat actor family if known, the first confirmed sighting date,
   and a URL or PR reference where the evidence is documented. Example:

   ```
   "DPRK-linked (Lazarus/APT37) supply-chain campaign, active 2026. Confirmed
   sighting against sorolens via contributor Onefie10, 2026-10-18."
   ```

4. Add `"literal_strings"`, `"domains"`, `"malicious_packages"`, or
   `"suspicious_filenames"` entries — only the keys that apply. The scanner
   checks each `literal_strings` entry as an exact substring match across all
   tracked files.

5. Each addition **must** cite a source (commit message, linked PR, or
   `_source` field) so a future auditor can verify the IOC is still relevant
   and not a false positive.

---

## `scan_allowlist.json` schema

Lists specific tracked file paths whose use of an otherwise-flagged pattern is
pre-vetted and intentional:

```jsonc
{
  "exec_functions": [
    {
      "path": "scripts/example.py",
      "reason": "subprocess.run(['gh', ...]) only — no user-controlled input"
    }
  ]
}
```

Adding an entry here is a **security-sensitive change**: it permanently
suppresses a finding for that file, even for future edits. Before allowlisting,
read the file's actual use of the flagged call and confirm it cannot be abused
by a supply-chain attacker.

---

## Protected-files guard

`scripts/malware_scan.py`, `security/malware_iocs.json`, and
`security/scan_allowlist.json` are **protected files**: the scanner
intentionally contains the IOC strings it searches for, so it excludes itself
from pattern checks. Instead, any PR that touches one of these three files
**fails the malware-scan CI job outright**, requiring a maintainer to review
the diff manually before it can merge.

This is enforced in `.github/workflows/ci.yml` via the `malware-scan` job.
It is not enough for the CI scan to pass; the right human must be asked. That
is what the `CODEOWNERS` entry for `security/` and `scripts/malware_scan.py`
ensures: GitHub automatically requests a review from the designated code owner
whenever these files change.

Do not remove or weaken either safeguard without replacing it with something
at least as strong.
