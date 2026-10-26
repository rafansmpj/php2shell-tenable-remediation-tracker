# PHP2Shell Tenable Remediation Tracker

A Claude skill that builds an exposure and remediation tracker for **PHP2Shell** (CVE-2026-109618, CVE-2026-109619), the pre-auth PHP remote code execution disclosed on 2026-10-21, from live Tenable data. Each run produces an HTML, PDF and CSV report and appends to an execution history, so every new report shows what changed since the last one.

The skill is **read-only**: it never launches scans, creates tags or changes anything in Tenable.

## What it does

- **Finds every applicable plugin by CVE** on each run (WAS, VM and Cloud/container), instead of relying on a hard-coded plugin list that goes stale as Tenable publishes new distro and container checks.
- **Pulls vulnerable (ACTIVE/RESURFACED) and fixed (FIXED) findings** per plugin from Tenable One, with first-seen and fixed dates from a Workbenches export and the installed PHP version from plugin output.
- **Tracks remediation against an SLA** (7 days by default, or a number you choose): due date, days open and SLA outcome for every finding.
- **Compares runs**: new, remediated since, regressed, still open and no longer reported, with KPI deltas and a trend chart across the full execution history.
- **Writes a CISO-ready report**: posture label (CRITICAL / HIGH / GUARDED / CONTROLLED), executive summary, eight KPIs, and a per-plugin drill-down with affected assets, target PHP version, remediation steps and interim mitigations.
- **Supports several languages**: English, Portuguese-BR and Spanish are bundled. Other languages work through a translation file.

## Prerequisites

- **Claude** with skills support: Claude Code, Claude Desktop or Cowork.
- **Tenable Hexa AI MCP** connected to Claude. This needs Tenable One Foundation or Advanced with *Enable Hexa AI MCP* turned on, API keys from *Settings > My Account > API Keys*, and a Standard User role or higher.
- **Python 3** (standard library only) to run `scripts/render.py`.
- **Playwright with Chromium** (optional), only for the PDF output. Without it, pass `--no-pdf` and you still get the HTML and CSV outputs.
- Network access to the [Tenable Research PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote). The skill uses it to confirm fixed releases and mitigations.

## Installation

### Claude Code

Clone the repo into your skills directory:

```bash
git clone https://github.com/rafansmpj/php2shell-tenable-remediation-tracker.git \
  ~/.claude/skills/php2shell-tenable-remediation-tracker
```

To install it for a single project, clone it into `.claude/skills/` in that project instead.

### Claude Desktop / Cowork

Download `php2shell-tenable-remediation-tracker.skill` from this repo and add it under *Settings > Capabilities > Skills*.

## Usage

Ask Claude in plain language, for example:

- "Which of our assets are exposed to PHP2Shell?"
- "Run the PHP2Shell tracker."
- "How has PHP2Shell remediation progressed since the last report?" (attach the previous `report_*.html` or `history_*.json`)

In Claude Code, you can also run `/php2shell-tenable-remediation-tracker`.

Before it calls Tenable, the skill asks three things:

1. Whether this is the first run, and if not, for the previous report or history file.
2. Which language to write the report in.
3. Which remediation SLA to use (7 days or a custom number of days).

### Try the renderer on demo data

You can run the renderer locally on the bundled sample data. You don't need a Tenable connection for this. The demo plugin catalog is fake.

```bash
python3 scripts/render.py assets/sample_findings_run1.json ./php2shell-reports/demo-run1 \
  --plugins assets/sample_plugins.json --banner "DEMO DATA" --no-pdf
python3 scripts/render.py assets/sample_findings_run2.json ./php2shell-reports/demo-run2 \
  --plugins assets/sample_plugins.json --banner "DEMO DATA" --no-pdf
```

The second command produces a report that compares against the first.

## Outputs

Each run writes its own timestamped files, so no run overwrites another:

```
php2shell-reports/
├── history.json                  rolling ledger of every run (input to the next run)
├── latest.json                   newest run's files + index of all runs
└── <YYYY-MM-DD-HHMM>/
    ├── report_<stamp>.html       interactive report (embeds the full history)
    ├── report_<stamp>.pdf
    ├── history_<stamp>.json      snapshot of the ledger after this run
    ├── run_<stamp>.json          this run's KPIs and finding status
    ├── report_<stamp>.csv        findings
    ├── plugins_<stamp>.csv       applicable plugins per CVE
    └── changes_<stamp>.csv       run-to-run changes
```

Keep `history_<stamp>.json` or `report_<stamp>.html`. Either one is enough to continue the history on the next run.

## Repository layout

| Path | Purpose |
|---|---|
| `SKILL.md` | The skill instructions Claude follows |
| `scripts/render.py` | Renders reports, updates the history ledger, finds the latest comparable run |
| `scripts/lang/es.json` | Spanish strings (English and Portuguese-BR are built in) |
| `assets/` | Sample findings and plugin catalog for demos and testing |
| `VERSION`, `CHANGELOG.md` | Skill version and change history |
| `php2shell-tenable-remediation-tracker.skill` | Packaged copy of the skill for Claude Desktop / Cowork upload |

## Known limitations

- Status comes from the PHP version alone. Distro backports (Ubuntu, RHEL) can show as vulnerable when they're actually patched, so check the vendor advisories.
- WAS plugins were published on 21 Oct 2026. Scans from before that date can't report PHP2Shell, so an empty result on a stale asset means it hasn't been assessed, not that it's clean.
- The Workbenches export is the expected source for first-seen and fixed dates, but it hasn't been validated on a tenant with PHP2Shell findings yet. Check the first run's tracker against the Tenable UI.
- The run comparison matches findings on asset name + plugin ID, so keep asset naming consistent across runs.
- "No longer reported" doesn't prove a fix. The asset may be unscanned, offline or decommissioned.
- Interim mitigations (php.ini settings, WAF rules) reduce exposure but don't fix the vulnerability.

## License

[MIT](LICENSE)
