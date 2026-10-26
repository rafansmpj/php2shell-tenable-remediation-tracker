# Tenable PHP2Shell Remediation Tracker

A Claude Desktop Skill that works with the Tenable Hexa AI MCP to build an exposure and remediation tracker for **PHP2Shell** (CVE-2026-109618, CVE-2026-109619) — and the related **Node2Shell** Brotli RCE (CVE-2026-111497) — from live Tenable data, with a CISO summary, per-finding SLA tracking, execution history and run-to-run comparison.

![Version](https://img.shields.io/badge/version-2.14.0-E7FF00?labelColor=44494B) ![Mode](https://img.shields.io/badge/mode-read--only-44494B) ![Languages](https://img.shields.io/badge/lang-EN%20%7C%20PT--BR%20%7C%20ES-44494B)

## Table of Contents

- [What it does](#what-it-does)
- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Report Layout](#report-layout)
- [Output Files](#output-files)
- [Architecture](#architecture)
- [Installation Verification](#installation-verification)
- [Troubleshooting](#troubleshooting)
- [Known Limitations](#known-limitations)
- [Development](#development)
- [Content Agreement](#content-agreement)

## What it does

Identifies every asset exposed to PHP2Shell — the pre-auth PHP remote code execution disclosed on **2026-10-21** — using Tenable One and Tenable VM data via MCP. It discovers every applicable plugin per CVE (WAS, VM and Cloud), pulls vulnerable and fixed findings, measures each one against a remediation SLA, and keeps a ledger of every execution so each new report shows what changed since the last one.

The same report also tracks **Node2Shell** (CVE-2026-111497), an out-of-bounds write in the Google Brotli decoder disclosed the same day, which reaches Node.js, libbrotli, Python Brotli / brotlicffi and software bundling Brotli (curl, Bun, Envoy, Istio). Node2Shell gets its own section with the same views, and its numbers are **never mixed** into PHP2Shell's.

Delivers an interactive HTML report, a PDF and CSV exports in the conversation.

### Audience

- CISOs and security leadership (executive summary and posture)
- Vulnerability Managers
- SOC Leads
- Remediation / Patch Engineers
- Infrastructure, Web Application and Platform (Node.js / Envoy / Istio) owners

### Typical Use

Answer "which assets are exposed to PHP2Shell — and Node2Shell?" on day one, then re-run the tracker daily or weekly to show how remediation is progressing: new exposures, findings remediated since the last run, regressions, findings still open and findings past SLA.

### Why This Matters

PHP2Shell is a pre-auth RCE exploited in the wild, with a short window between disclosure and exploitation. Leadership needs a defensible answer to "are we exposed, and how fast are we closing it?" — and Tenable only keeps the *current* state of each finding. This skill keeps the history itself, so progress, regressions and SLA compliance can be proven run after run instead of reconstructed by hand. Because teams handling PHP2Shell are usually asked about Node2Shell in the same breath, both are answered in one report without one inflating the other.

### Mode

**Read-only with execution history** — the skill only reads from Tenable; it never launches scans, creates tags or changes anything in the platform. Patching and mitigation remain manual, but each plugin's drill-down tells the owner which assets to fix, the target version per asset, and which interim mitigations apply until then.

## Quick Start

Get up and running in 5 minutes.

### Prerequisites

- Claude Desktop (or Claude Code) with skills support
- The **Tenable Hexa AI MCP** connected and authenticated:
  - Tenable One Foundation or Advanced, with *Enable Hexa AI MCP* turned on
  - API keys from **Settings > My Account > API Keys** (Standard User or higher)
  - In Claude Desktop, the computer running the MCP must be linked to the chat
- Python 3 (standard library); Playwright with Chromium for the optional PDF

### Installation

#### Claude Desktop

1. Open Claude Desktop Settings
2. Navigate to Skills
3. Click "Add Skill"
4. Upload `php2shell-tenable-remediation-tracker.skill` (or browse to "PHP2Shell Tenable Remediation Tracker")
5. Click Install
6. **Restart Claude Desktop** so it picks up the skill

Claude Desktop handles file placement automatically.

#### Claude Code

Clone this repo into your skills directory:

```bash
git clone https://github.com/rafansmpj/Tenable-PHP2Shell-Remediation-Tracker.git ~/.claude/skills/php2shell-tenable-remediation-tracker
```

Or copy the repo folder into `~/.claude/skills/` manually. Claude Code auto-discovers skills in that directory — no restart required, just start a new session.

### Configuration

1. Ensure the **Tenable One Hexa AI MCP connector** is set up and active in the same Claude environment.
2. Before every run, the skill asks three questions in one prompt (skipped if your request already answers them):

   | Setting | Description | Default |
   |---|---|---|
   | **First run?** | If not, provide the previous `report_<stamp>.html` or `history_<stamp>.json` (or a whole `php2shell-reports/` folder) so the run can be compared | Asked every run |
   | **Report language** | English, Portuguese-BR, Spanish, or any other language (translated from `render.py --dump-lang`) | Language you are writing in |
   | **Remediation SLA** | Days allowed to remediate each finding, optionally with a policy reference (e.g. "VM Policy 4.2 – Critical"). Applies to both PHP2Shell and Node2Shell | 7 days (skill default for a pre-auth RCE exploited in the wild) |

   The SLA is required: the skill never fills it in for you. If it differs from the previous run's SLA, you are warned that past-SLA counts won't be like-for-like.
3. **No API keys or .env files needed** inside the skill itself — credentials live entirely in the MCP connector config.

### Usage

After installation, simply prompt Claude with any of the following:

- "Which assets are exposed to PHP2Shell?"
- "Am I exposed to Node2Shell?"
- "Run the PHP2Shell remediation tracker"
- "Re-run the PHP2Shell tracker in Portuguese, SLA 15 days"
- "How has PHP2Shell remediation progressed since the last run?" (attach the previous report or history file)

#### What Happens

The skill will:

1. ❓ Ask the intake questions: first run, report language, SLA
2. 🗂️ Restore earlier execution history (workspace, connected folder or attached files — `--find-latest` picks the newest automatically)
3. 🔍 Fetch the Tenable Research FAQ for fixed releases and mitigations, then search plugins **by CVE** across WAS, VM and Cloud (no hard-coded plugin list) — a separate catalog for Node2Shell
4. 📥 Pull vulnerable (ACTIVE / RESURFACED) and fixed (FIXED) findings per plugin, cross-check by CVE, and get first-seen / fixed dates from a Workbenches export
5. 📊 Render the interactive report (see [Report Layout](#report-layout))
6. ✅ Screenshot and check the report, including the drill-downs
7. 💾 Deliver HTML, PDF, CSVs and the timestamped history file to keep for the next run

## Report Layout

The report opens with an **Export** menu (HTML / JSON history download) and a **remediation history disclaimer** — green when it continues an earlier history, orange when it starts a new baseline. Below it, a **switcher** selects one section per CVE, each showing its posture:

- **PHP2Shell** — CVE-2026-109618 / CVE-2026-109619
- **Node2Shell** — CVE-2026-111497

Each section has the same views, computed only from that CVE's data:

| View | What it shows |
|---|---|
| **Executive summary** | Posture label (**CRITICAL / HIGH / GUARDED / CONTROLLED**), one-line verdict, business risk and asks |
| **Headline strip** | Assets running PHP (or Node.js / Brotli), confirmed vulnerable, not assessed since disclosure, open, remediated, remediation rate, MTTR, open past SLA |
| **SLA basis and calculation** | Collapsible: SLA source, clock start, formulas, outcome rules, data sources and a worked example from this run |
| **This run against the SLA** | Open within / past SLA, fixed met / missed / no date |
| **Key indicators** | Assets in scope, exposed assets, open and remediated findings, remediation rate, MTTR, past SLA, assets not scanned since disclosure |
| **Assets by version status** | Vulnerable – EOL, Vulnerable – backport only, Vulnerable – patch available, Unknown – verify, Patched, Not affected (each asset counted once) |
| **Business risk / Decisions and asks** | Business impact plus two standing asks: confirm scan coverage since 21 October, and reduce exposure while patching |
| **Run comparison** | KPI deltas and clickable scenario cards — new, remediated since, regressed, still open, no longer reported — drilling down by asset or by plugin |
| **Execution history** | Every run with timestamp, run ID, skill version, posture and KPIs, plus a trend chart |
| **Open vs remediated** | Split bar and daily timeline from disclosure |
| **Applicable plugins by CVE** | Every plugin Tenable maps to the CVE (zero-result plugins included), each expanding to vulnerable/fixed assets, installed and target version, remediation and mitigation steps |
| **Remediation tracker** | First seen, SLA due, fixed date, days open, SLA outcome and last seen per finding |
| **All findings, mitigations, limitations** | Filterable findings table and per-CVE guidance |

🖱️ **Every figure is clickable** — headline strip, KPI tiles and version-status tiles each open a filterable, sortable panel listing the assets or findings behind the number.

## Output Files

Every execution writes its own timestamped files (`<stamp>` = UTC `YYYY-MM-DD_HHMMSSZ`), so earlier runs are never overwritten:

```
php2shell-reports/
├── history.json                       rolling ledger, every run (input to the next run)
├── latest.json                        newest run's files + index of every run, newest first
└── <YYYY-MM-DD-HHMM>/                 one folder per run (the run ID)
    ├── report_<stamp>.html            interactive report; embeds the full history
    ├── report_<stamp>.pdf             both CVE sections, drill-downs expanded
    ├── history_<stamp>.json           ledger snapshot — keep this for the next run
    ├── run_<stamp>.json               this run only
    ├── report_<stamp>.csv             PHP2Shell findings
    ├── plugins_<stamp>.csv            PHP2Shell plugin catalog with counts
    ├── changes_<stamp>.csv            change type per finding vs. baseline (both CVEs, `track` column)
    ├── node2shell_<stamp>.csv         Node2Shell findings
    ├── node2shell_plugins_<stamp>.csv Node2Shell plugin catalog with counts
    ├── findings.json, plugins.json
    └── node2shell_findings.json, node2shell_plugins.json
```

> 💡 The **Export → JSON** button in the report downloads the same `history_<stamp>.json`, so the report alone is enough to continue the history next time.

## Architecture

### Data Flow

```
Tenable Research FAQ (fixed releases, mitigations)
        ↓
Tenable One / VM (via Hexa AI MCP)
  plugins_search_plugins(cve=…)          → plugin catalogs (PHP2Shell and Node2Shell, kept separate)
  plugins_get_plugin_details             → Tenable synopsis, solution, references
  tenable_one_search_findings            → vulnerable + fixed findings per plugin
  workbenches_export_workbenches         → first seen / fixed dates
  workbenches_get_vulnerability_outputs  → installed versions
        ↓
findings.json + plugins.json   |   node2shell_findings.json + node2shell_plugins.json
        ↓
render.py  ←  history.json (previous runs)
        ↓
HTML + PDF + CSV report  →  updated history ledger + latest.json
```

### Key Components

| Component | Purpose |
|---|---|
| **Tenable Connector** | Searches plugins by CVE, pulls findings (all states) and Workbenches dates via MCP |
| **Plugin Catalog** | Built fresh every run, so new distro/container advisories are picked up automatically |
| **Version Evaluator** | PHP2Shell: fixed releases 8.5.12, 8.4.27, 8.3.36, 8.2.35 (branches < 8.2 = EOL). Node2Shell: Node.js 22.23.4 / 24.22.1 / 26.12.1 (20.x and older, 23.x, 25.x = EOL); Brotli 1.0.10 / 1.1.1 / 1.2.1 (< 1.0.3 not affected); Python Brotli 1.2.1 |
| **SLA Engine** | SLA due date, days open and outcome (due / breached / met / missed / no date) per finding, clock starting 2026-10-21 |
| **History Ledger** | Records every run (KPIs, per-finding status, version breakdown, skill version) with a separate `n2s` block for Node2Shell; full detail kept for the latest 60 runs |
| **Run Comparator** | Classifies each finding against any earlier run: new, remediated since, regressed, still open, no longer reported |
| **Report Renderer** | `scripts/render.py` — standalone HTML (EN / PT-BR / ES or custom), PDF via Playwright, CSV exports |

### Remediation Paths

Each plugin's drill-down picks remediation steps based on its path:

**PHP2Shell**
- ⬆️ **upstream** — upgrade PHP to the fixed release of the branch
- 🌐 **was** — upgrade PHP behind the web application, then re-scan with WAS
- 📦 **distro** — install the OS vendor package (backports may not match upstream version strings)
- 🚫 **unpatched** — no vendor fix yet; mitigation is the primary control
- 🐳 **container** — rebuild and redeploy the image

**Node2Shell** — Node.js runtime, Brotli library, Python package, OS package, container image, or other bundling software (curl, Bun, Envoy, Istio).

### Interim Mitigations

| PHP2Shell | Node2Shell |
|---|---|
| `memory_limit=-1` | Reject `Content-Encoding: br` on inbound requests |
| `session.upload_progress.enabled=0` | Drop `br` from outbound `Accept-Encoding` |
| `fatal_error_backtraces=0` (PHP 8.5 only) | `inflate: false` where supported |
| Restart every PHP worker | Remove the Envoy / Istio Brotli decompressor |
| WAF rules on internet-facing PHP | |

These reduce exposure but are not a fix.

### Comparison: PHP2Shell Exposure Report vs. Remediation Tracker

| Aspect | `php2shell-tenable` (Exposure Report) | `php2shell-tenable-remediation-tracker` |
|---|---|---|
| **Focus** | Point-in-time exposure | Exposure **and** remediation progress over time |
| **CVEs** | PHP2Shell | PHP2Shell + Node2Shell (separate sections) |
| **Plugin Source** | Fixed plugin set | Discovered by CVE search on every run (WAS / VM / Cloud) |
| **Primary Audience** | Security analysts | CISO, VM managers, remediation teams |
| **State Model** | Stateless | Execution history ledger with run-to-run comparison |
| **SLA** | — | Per-finding SLA tracking (7 days default or custom) |
| **Interactivity** | Static tables | Clickable figures, scenario cards, plugin and finding drill-downs |
| **Output** | HTML + CSV (+ PDF) | HTML + PDF + CSVs + timestamped history |
| **Languages** | — | English, Portuguese-BR, Spanish, any other on request |

## Installation Verification

1. Open Claude Desktop or Claude Code
2. Start a new conversation
3. Prompt: `"List my available skills"`
4. Confirm "php2shell-tenable-remediation-tracker" appears in the list
5. Prompt: `"Run the PHP2Shell tracker"` and confirm the intake questions appear
6. Verify the HTML report renders with both the PHP2Shell and Node2Shell sections

For an offline renderer test with the bundled demo data:

```bash
python3 scripts/render.py assets/sample_findings_run1.json ./out/run1 \
  --plugins assets/sample_plugins.json \
  --node2shell-findings assets/sample_node2shell_run1.json \
  --node2shell-plugins assets/sample_node2shell_plugins.json \
  --banner "DEMO" --no-pdf
```

Demo runs (`--banner`) are written to `history.demo.json`, so they never mix with real history.

## Troubleshooting

### Skill doesn't appear after installation
- **Claude Desktop**: Restart the application (Cmd+Q / Ctrl+Q, then reopen)
- **Claude Code**: Start a new session or reload the window

### "Tenable Hexa AI MCP must be connected"
- Verify the MCP connector is connected and authenticated, and that Hexa AI MCP is enabled in Tenable One
- In Claude Desktop, link the computer running the MCP to the chat

### Report says "first run" when it shouldn't
- Attach the newest `report_<stamp>.html` or `history_<stamp>.json` from the previous run, or connect the `php2shell-reports/` folder
- Fresh cloud sessions start with an empty workspace — the history file is what carries progress between runs

### Everything shows as "New" in the comparison
- Asset naming changed between runs (hostname vs. IP). The comparison matches on `asset + plugin ID`; keep naming consistent

### Node2Shell section says data was not collected
- The Node2Shell inputs were not passed to the renderer. This does **not** mean "not affected" — re-run so the Node2Shell catalog and findings are collected

### Node2Shell KPI deltas show "—"
- The baseline run is from 2.10.0 (older KPI names) or earlier (no Node2Shell data). Finding-level changes still compare

### Tracker shows "No first-seen date"
- The Workbenches export failed or lacked date columns; SLA is then measured from disclosure (2026-10-21)

### PDF missing
- Install Playwright: `pip install --break-system-packages playwright`. The PDF is best effort; HTML and CSVs are always produced

## Known Limitations

- PHP2Shell status comes from the PHP version alone; distro backports (Ubuntu, RHEL) can show as vulnerable when patched — check vendor advisories
- WAS plugins were published on 2026-10-21; assets not scanned since then are **unassessed, not clean**
- "No longer reported" is not proof of a fix — the asset may be unscanned, offline or decommissioned
- The Workbenches date route has not yet been validated on every tenant; check the first run's tracker against the Tenable UI
- The comparison is only as consistent as the asset naming across runs
- Node2Shell status comes from the installed version; it does not show whether a service actually decodes attacker-controlled Brotli, so a version match can overstate real exposure, and software that statically bundles Brotli may not be found by version checks
- The 7-day default SLA is argued for PHP2Shell (exploited in the wild); as of 23 Oct 2026 Node2Shell had a public PoC but no reported exploitation and was not in CISA KEV

## Development

1. Clone the repository
2. Edit `SKILL.md` (skill definition) and/or `scripts/render.py` (renderer)
3. Bump `VERSION` and add an entry at the top of `CHANGELOG.md` (semantic versioning; MAJOR changes must describe comparability impact under `### Comparability`)
4. Test with the demo data in `assets/` (always with `--banner`)
5. Submit a pull request

### Repository Structure

```
php2shell-tenable-remediation-tracker/
├── SKILL.md                 skill definition
├── VERSION                  current version, stamped on every report and run
├── CHANGELOG.md             version history
├── scripts/
│   ├── render.py            report renderer, history ledger, --find-latest
│   └── lang/es.json         Spanish strings (EN and PT-BR are built in)
└── assets/                  demo inputs (PHP2Shell and Node2Shell) — never for real runs
```

Current version: **2.14.0** — see [`VERSION`](VERSION) and [`CHANGELOG.md`](CHANGELOG.md).

### Sources

- [Tenable Research — PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)

### Acknowledgements

The PHP2Shell exposure-report workflow was originally inspired by the community project securibee/php2shell-tenable-skill. All code in this version is new.

## License

MIT — see [LICENSE](LICENSE) for details.

## Support

For issues, feature requests, or questions, open an issue on [GitHub Issues](https://github.com/rafansmpj/Tenable-PHP2Shell-Remediation-Tracker/issues).

## Content Agreement

I have reviewed and accept the CyberAgents Exchange Contribution Agreement.
