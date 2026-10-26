# Changelog — php2shell-tenable-tracker

All notable changes to this skill are recorded here. Versions follow semantic versioning:
- **MAJOR** — the findings.json contract, the history ledger format or report KPIs change in a way that makes runs from older versions not directly comparable.
- **MINOR** — new report sections, new options, new data sources; older runs stay comparable.
- **PATCH** — fixes and wording, no change to numbers.

The single source of truth for the current version is the `VERSION` file at the skill root. `scripts/render.py` reads it, stamps it on every report and records it on every run in the history ledger, so a comparison between two runs always shows which skill version produced each one.

How to release a change:
1. Edit the skill.
2. Bump `VERSION`.
3. Add an entry at the top of this file: `## [x.y.z] — YYYY-MM-DD`, then `### Added / Changed / Fixed` bullets.
4. If the change is MAJOR, say under `### Comparability` what an older run can no longer be compared on.

## [2.9.0] — 2026-10-25

### Added
- **Timestamped output files.** Every run writes `report_<stamp>.html`, `report_<stamp>.pdf`, `history_<stamp>.json` (snapshot of the ledger after this run), `run_<stamp>.json`, `report_<stamp>.csv`, `plugins_<stamp>.csv` and `changes_<stamp>.csv`, where `<stamp>` is the execution time in UTC (`YYYY-MM-DD_HHMMSSZ`). Earlier runs are never overwritten and names sort chronologically.
- **`php2shell-reports/latest.json`**: relative paths of the newest run's files plus an index of every run, newest first (`latest.demo.json` for demo runs).
- **`render.py --find-latest <folders/files>`**: ranks every history-bearing file (stamped or pre-2.9 names) by the newest run with finding detail, then run count, then the stamp, and prints the best one as JSON.
- **`--import <folder>`** imports the newest history found under that folder.
- The renderer prints `files=` and `latest=` lines with the exact output paths.

### Changed
- Steps 0, 2, 6, 7, 8 and 9 of SKILL.md use the stamped names; step 2 uses `--find-latest` when several history files are available.
- The history disclaimer in the report names this run's actual files (EN, PT-BR, ES) and explains that each run keeps its own timestamped copy.

### Comparability
- No change to numbers, KPIs, the findings.json contract or the ledger format (runs gain `stamp`, `folder` and `files` fields, which older versions ignore). Pre-2.9 `report.html` / `history.json` import as before.

## [2.8.0] — 2026-10-25

### Added
- **Intake step (step 0) before every run.** The skill now asks, in one prompt, before any Tenable call:
  - whether this is the first run — if not, it asks for the previous `report.html` and/or `history.json` (or uses the one it finds in the workspace or a connected folder), and gets an explicit OK before starting a new baseline without it;
  - the report language: English, Portuguese-BR, Spanish or any other language;
  - the remediation SLA: standard 7 days or a custom number of days. The SLA is required — the run does not collect data or render until it is answered. If the chosen SLA differs from the previous run's, the user is told and asked to confirm.
- **Spanish report** (`--lang es`, strings in `scripts/lang/es.json`).
- **Any other language** via `--lang <code> --lang-file <translation.json>`; `render.py --dump-lang` prints the English strings to translate. Missing keys fall back to English and are reported as `lang_missing=`.
- The **mean time to remediate** tile shows the SLA and whether MTTR is within it.

### Changed
- Executive summary verdicts, decisions and asks, interim mitigations and known limitations moved from hard-coded EN/PT text into the translation table, so every language gets them. The posture verdict and the past-SLA ask now name the SLA in days.
- Timestamps in the report are formatted in the report's language.

### Comparability
- No change to numbers, KPIs, the findings.json contract or the ledger format; runs from 2.7.x compare directly.

## [2.7.0] — 2026-10-25

### Changed
- **"This run against the SLA" is its own section**, right after "SLA basis and calculation": a one-line intro and the five tiles (open within SLA, open past SLA, fixed and met, fixed and missed, fixed with no date), plus the no-dates note when it applies.
- **"SLA basis and calculation" is collapsible.** It starts collapsed, showing only the title and a one-line summary (SLA days, clock start rule, skill default or requester's policy with its reference). Clicking the title, or pressing Enter on it, shows or hides the full explanation. Printing from the browser and the PDF always show it expanded.

### Comparability
- Layout only; no change to numbers.

## [2.6.1] — 2026-10-25

### Changed
- The remediation history disclaimer now has two versions:
  - **First run** ("Remediation history — first run", orange): explains that this report is the baseline, what the history will show from the next run on (scenarios, KPI changes, trend, choice of baseline) and how to run it next time (keep report.html / history.json; same conversation picks it up; new conversation: attach it or connect the php2shell-reports/ folder; same SLA and hostnames).
  - **Later runs** ("Remediation history — comparison with earlier runs", green): states which earlier runs this one is compared with and where the history came from, explains why the history file is required (Tenable keeps only the current state; the earlier status of each finding exists only in the history, and the comparison is computed from it), that the next run needs the newest file, and what keeps comparisons like-for-like.

### Comparability
- Wording only; no change to numbers.

## [2.6.0] — 2026-10-25

### Added
- **Remediation history disclaimer** before the executive summary. It states this run's history status:
  - green: continues a history of N earlier runs (dates, and the source — workspace history file or an imported report.html / history.json);
  - orange: started a new history, so nothing is compared.

  It also explains that the history is not tied to a conversation and how to keep it for the next run (same conversation, connected folder with `php2shell-reports/`, or attach `report.html` / `history.json`), plus what keeps comparisons like-for-like (same SLA, stable hostnames, "No longer reported" is not a fix, detail kept for the latest 60 runs). English and Portuguese.

### Comparability
- Display only; no change to KPIs, the finding key or the ledger.

## [2.5.0] — 2026-10-25

### Added
- **Remediation tracker: Last seen column** (sortable).
- **Remediation tracker: plugin details on open findings.** Click (or press Enter on) any open finding to expand the same detail as in "Applicable plugins by CVE": remediation path and steps, Tenable solution and references, mitigation steps with applicability, and every asset with vulnerable or fixed findings for that plugin. The finding's own asset is highlighted in those lists. Fixed findings stay as plain rows. The product and text filters and column sorting keep each detail attached to its finding.
- Tracker hint line explaining the drill-down.

### Changed
- "Expand all / Collapse all" in the plugins section only affects that section.
- The expand caret switches between ▸ and ▾ instead of rotating.

### Comparability
- Display only; no change to KPIs, the finding key or the ledger. Runs from earlier versions compare normally.

## [2.4.0] — 2026-10-25

### Added
- **Run comparison drill-down**: the change section now opens with the total number of finding changes against the baseline and one clickable card per scenario — New, Remediated since, Regressed, Still open, No longer reported — plus All changes. Clicking a card opens that scenario's detail: what the scenario means, then the assets and plugins behind it, switchable between a **by asset** view (asset, IP, product, finding count, plugins with ID / product / name) and a **by plugin** view (plugin, product, name, finding count, assets with IP). Each scenario has its own product and text filter. Click the card again to close it. The PDF prints the detail of every non-empty scenario.
- Ledger entries carry `plugin_meta` (plugin name and product) and `asset_meta` (IP) so the drill-down can name plugins and assets that only appear in the baseline run.
- `changes.csv` adds `ip`, `plugin_name` and `product`.

### Changed
- The flat change table is replaced by the scenario drill-down (the same rows are in the "All changes" card and in `changes.csv`).

### Comparability
- No change to KPIs, the finding key or how changes are classified. Baselines from versions before 2.4.0 have no plugin names or IPs stored; the drill-down falls back to the current run's catalog for those and shows only the plugin ID otherwise.

## [2.3.0] — 2026-10-25

### Added
- **SLA basis and calculation** section right after the executive summary: where the SLA comes from (skill default for a pre-auth RCE exploited in the wild, or the requester's policy), when the clock starts (later of disclosure and first seen), the formulas for SLA due, days open and mean time to remediate, how each outcome (due in / breached / met / missed / no fixed date) is assigned, where the dates come from in Tenable, a worked example taken from this run's data, and this run's split across those outcomes.
- `--sla-ref` option: a policy reference shown in that section (e.g. "VM Policy 4.2 – Critical").
- Ledger entries record `sla_source` (default or user) and `sla_ref`.

### Changed
- `--sla-days` has no hard default in argparse any more; when omitted the renderer still uses 7 days and labels it as the skill default.

### Comparability
- No change to KPIs, the finding key or how SLA dates are computed; runs from 2.2.x and earlier compare normally.

## [2.2.0] — 2026-10-25

### Added
- **Plugin drill-down** in "Applicable plugins by CVE": click (or press Enter on) any plugin to expand it and see
  - the assets with **vulnerable** findings (asset, IP, FQDN, product, port, PHP version and status, **target version**, state, first seen, SLA due, days open, SLA outcome, last seen),
  - the assets with **fixed** findings (fixed date, days open, SLA outcome),
  - **remediation steps** chosen by the plugin's remediation path (upstream PHP upgrade, web application, OS vendor package, no vendor fix yet, container image rebuild), with Tenable's own solution, synopsis and references when collected,
  - **mitigation steps** with an applicability note (applicable / primary control when there is no vendor fix / not required when everything is fixed or nothing fired); the PHP 8.5-only setting is dimmed when no reported version is on 8.5.
  - "Expand all / Collapse all" buttons; the PDF prints the details of every plugin that has findings.
- **Product filter** (WAS / VM / Cloud) on the applicable-plugins table, the remediation tracker and the all-findings table, combined with the existing CVE, status and text filters.
- `plugins.json` accepts optional `plugin_type`, `synopsis`, `solution` and `see_also` (collected with `plugins_get_plugin_details`); `plugins.csv` adds `remediation_path`, `vulnerable_assets`, `fixed_assets` and `tenable_solution`.
- Demo data: one container (Cloud) and one fixed Ubuntu finding in `sample_findings_run2.json`; demo catalog carries labeled solutions.

### Changed
- Product labels are normalised to WAS / VM / Cloud everywhere in the report.
- Column sorting keeps each plugin's detail row attached to its plugin.

### Comparability
- No change to KPIs, the finding key or the ledger format; runs from 2.1.x and 2.0.x compare normally.

## [2.1.0] — 2026-10-23

### Changed
- Plugins are no longer taken from a hard-coded list. Every run discovers the applicable plugins with `plugins_search_plugins` for each CVE (CVE-2026-109618 and CVE-2026-109619 separately), across WAS, VM and Cloud, and records which CVE(s) each plugin covers. Inventory (PHP version) plugins are found by name, not ID.
- Findings are pulled per applicable plugin (`finding_detection_id`), open and FIXED, with a per-CVE `finding_cves` search as a cross-check, so plugin IDs are reliable instead of matched by name.

### Added
- **Applicable plugins by CVE** section in the report: every plugin per CVE with vulnerable (ACTIVE/RESURFACED) and fixed (FIXED) finding counts, assets and plugin status (Vulnerable / Fixed only / No findings), filterable by CVE and status. Zero-result plugins are listed.
- `plugins.json` input (`--plugins`) and `plugins.csv` output; `cves` column in `report.csv` and the findings table.
- Ledger entries now carry `plugin_summary` and per-plugin open/fixed counts.
- `assets/sample_plugins.json` demo catalog.

### Fixed
- Wrapped table cells inherited the page container's padding, making rows very tall.

### Comparability
- No change to KPIs or the finding key; runs from 2.0.x compare normally. Runs from 2.0.x have no plugin summary in the history.

## [2.0.1] — 2026-10-23

### Changed
- Removed the "Skill version history" panel from the HTML and PDF report; version history now lives only in this CHANGELOG. The report still shows the skill version in its header and footer, and still warns when compared runs came from different versions.

### Comparability
- No change; runs from 2.0.0 compare normally.

## [2.0.0] — 2026-10-23

### Added
- Bundled renderer `scripts/render.py` — the skill is fully self-contained; nothing is downloaded at run time.
- **Execution history ledger** (`php2shell-reports/history.json`): every run is recorded with its timestamp, run ID, skill version, SLA, posture, KPIs and per-finding / per-asset status.
- **Run comparison** in the HTML report: pick any earlier run as the baseline and see KPI deltas plus findings that are new, remediated since, regressed, still open or no longer reported. Defaults to the previous run.
- **Execution history** table and run-over-run trend chart in the HTML report.
- History import: a previous `report.html` (it embeds the ledger) or `history.json` can be fed back with `--import`, so tracking survives fresh cloud sessions.
- `changes.csv` with one row per finding and its change type versus the baseline run.
- Version tracker: `VERSION` + this changelog; the report footer shows the version and a "Skill version history" panel; comparisons across different versions show a notice.
- `--lang en|pt` report language (technical terms stay in English).
- Report styling follows the dark design system (#44494B background, #E7FF00 accent).

### Comparability
- First version with a history ledger; there are no earlier runs to compare against.

### Acknowledgements
- The PHP2Shell exposure-report workflow was originally inspired by the community project securibee/php2shell-tenable-skill. All code in this version is new.
