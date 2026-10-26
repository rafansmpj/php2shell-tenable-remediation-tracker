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

## [2.15.0] — 2026-10-26

### Added
- **VPR, ACR and AES in every table where they apply**, in both CVE sections: plugin VPR in the applicable-plugins table, the plugin drill-down header, the remediation tracker, the all-findings table, the finding tile panels and the comparison "by plugin" view; asset ACR and AES in the plugin drill-down asset tables (vulnerable and fixed), the tracker, the all-findings table, the asset and finding tile panels and the comparison "by asset" view. Colour-coded, sortable; "—" when Tenable returned no value, with a note when a score is missing for the whole run.
- Collection: VPR from `plugins_get_plugin_details` (`vpr` in `plugins.json`, optional `vpr` per finding row); ACR/AES per asset from `tenable_one_search_assets` filtered by `asset_id` (`acr` / `aes` on each finding row).
- `vpr`, `acr`, `aes` columns appended to report, plugins, changes, node2shell and node2shell_plugins CSVs; `plugin_vpr` and `asset_scores` stored on each run (and its `n2s` block); renderer prints a `scores` line.
- EN, PT-BR, ES strings (`c_vpr`, `c_acr`, `c_aes`, `sc_note`, `sc_missing`). Demo inputs carry sample scores.

### Comparability
- No change to numbers, KPIs, posture or the ledger format. Runs from earlier versions have no scores; their comparison rows show "—" unless the current run has the value. Existing CSV columns keep their positions.

## [2.14.0] — 2026-10-26

### Added
- **Clickable figures with drill-down** in both CVE sections: every KPI tile, every "Assets by version status" tile and every cell of the new headline strip opens a panel below its row listing the assets (with their findings: plugin, state, target version, SLA due and outcome) or the findings (asset plus vulnerability and SLA detail) behind the number; filterable, sortable, closable, keyboard accessible. Data comes from a compact per-section JSON embedded in the report.
- **Headline strip under the executive summary** (both sections): assets running PHP / Node.js-Brotli, confirmed vulnerable (assets with an open finding — new figure), not assessed since disclosure, open findings, remediated, remediation rate, mean time to remediate, open past the SLA.
- EN, PT-BR and ES strings for all of the above (`dd_*`, `hs_*`, `as_*`, `c_vgroup`, `c_astatus`, `c_open_n`).

### Comparability
- No change to numbers, KPIs, posture or the ledger format.

## [2.13.0] — 2026-10-26

### Added
- **Assets by version status** row under Key indicators in both CVE sections: Vulnerable – EOL, Vulnerable – backport only, Vulnerable – patch available, Unknown – verify, Patched, Not affected. Each asset is counted once (first matching group, left to right), so the tiles sum to the assets in scope; definitions on hover, specific to each CVE. EN, PT-BR, ES.
- `version_breakdown` stored on each run and on its `n2s` block.
- Version status `na` ("Not affected"): PHP branches newer than every affected branch, Brotli before 1.0.3. Treated like Patched for asset status and posture.

### Removed
- The Node2Shell-only "Open on EOL Node.js lines" KPI tile — covered by "Vulnerable – EOL".

### Comparability
- No change to KPIs, posture or comparison numbers. In CSVs, `version_status` can now read `na` where it read `patched` for those out-of-range versions.

## [2.12.1] — 2026-10-26

### Changed
- Node2Shell **Business risk / Decisions and asks** reworded to mirror the PHP2Shell panel sentence for sentence (attack, worst-case impact, exposure window; confirm scan coverage; reduce exposure while patching), adjusted for Node2Shell facts: code execution is possible rather than routine, and public proof-of-concept code — not exploitation — appeared at disclosure. EN, PT-BR, ES.

### Comparability
- Wording only; no change to numbers.

## [2.12.0] — 2026-10-26

### Added
- **Export menu** in the report header (top right): **HTML** downloads the report as rendered, named `report_<stamp>.html`; **JSON** downloads the execution history named `history_<stamp>.json` (`history.demo_<stamp>.json` for demo runs) — the same names and content as the files the renderer writes, so a download can be used as the history for the next run. Hidden in the PDF.
- **Business risk / Decisions and asks** panel under Key indicators in each CVE section: business impact of the flaw and two standing asks (confirm scan coverage since 21 October; reduce exposure while patching). PHP2Shell and Node2Shell each have their own wording, in EN, PT-BR and ES (`ctx_*` strings; Node2Shell's in `n2s_over`).

### Changed
- The ledger embedded in the HTML now carries `"skill"` like `history_<stamp>.json`.

### Comparability
- No change to numbers, KPIs, posture or the ledger format.

## [2.11.0] — 2026-10-26

### Changed
- **One section per CVE.** The report is split into a PHP2Shell section (CVE-2026-109618 / CVE-2026-109619) and a Node2Shell section (CVE-2026-111497), picked from a switcher at the top that shows each section's posture. The PDF prints both. The history disclaimer stays above the sections and sources are listed once at the end.
- **Node2Shell gets every PHP2Shell view**: executive summary with posture, verdict and asks; SLA basis and "this run against the SLA"; the eight KPIs plus open findings on EOL Node.js lines; run comparison with clickable scenario cards and asset/plugin drill-down; execution history and trend; open vs remediated chart and daily timeline; applicable plugins with drill-down; remediation tracker; all findings; mitigations; limitations. It is computed by the same pipeline on its own data, CVE, disclosure date and version logic.
- Node2Shell wording (verdicts, asks, SLA basis, KPI labels) lives in `n2s_over`, layered over the report language (EN, PT-BR, ES; custom translations fall back to English for missing keys).
- Report title is now "PHP2Shell & Node2Shell — Exposure & Remediation Tracker". The 2.10 cross-links (header "Related" link, the Node2Shell line and asks in the PHP2Shell summary, the "Node2Shell open" history column) are replaced by the section switcher.

### Added
- `node2shell_plugins_<stamp>.csv`; a `track` column in `changes_<stamp>.csv` with Node2Shell changes included; a fuller `node2shell=` output line (posture, rate, MTTR, unscanned, delta).
- The ledger's `n2s` block now carries posture, asset status, plugin counts and plugin/asset names (trimmed like the main block after 60 runs).

### Comparability
- PHP2Shell numbers, KPIs, posture and the findings.json contract are unchanged. Node2Shell KPIs now use the PHP2Shell KPI names; 2.10.0 runs used other names, so Node2Shell KPI deltas against a 2.10.0 run show "—" (finding-level changes still compare). Runs before 2.10.0 have no Node2Shell data.

## [2.10.0] — 2026-10-26

### Added
- **Related exposure: Node2Shell (CVE-2026-111497)** — a separate report section for the Google Brotli decoder RCE disclosed the same day as PHP2Shell (Node.js, libbrotli, Python Brotli / brotlicffi, software bundling Brotli). It has its own KPIs (assets, open, fixed, past SLA, open on EOL runtimes, plugins), change since the previous run with Node2Shell data, an applicable-plugins table with drill-down (assets, installed and target versions, remediation by component, mitigations), a findings table, and Node2Shell mitigations. EN, PT-BR and ES.
- New inputs `--node2shell-findings` / `--node2shell-plugins` (`node2shell_findings.json`, `node2shell_plugins.json`), new output `node2shell_<stamp>.csv` (also listed in `latest.json`), and a `node2shell=` line in the renderer output.
- Version logic for Node2Shell (`N2S_FIXED`): Node.js 22.23.4 / 24.22.1 / 26.12.1 (20.x and older, 23.x, 25.x EOL), Brotli 1.0.10 / 1.1.1 / 1.2.1 (before 1.0.3 not affected), Python Brotli 1.2.1; OS packages, container images and other bundling software point to the vendor fix / image rebuild.
- Header link, executive-summary status line and separate asks for Node2Shell; "Node2Shell open" column in the execution history; Node2Shell limitations and sources.
- Demo inputs `assets/sample_node2shell_run1.json`, `run2.json`, `sample_node2shell_plugins.json`.

### Changed
- SKILL.md steps 3–9 collect, render, check, deliver and summarise Node2Shell alongside PHP2Shell; the description mentions it for triggering.

### Comparability
- PHP2Shell numbers, KPIs, posture, the findings.json contract and the ledger format are unchanged; Node2Shell never feeds them. Runs gain an optional `n2s` block (KPIs + finding status), which older versions ignore. Runs before 2.10.0 have no Node2Shell data, so the first 2.10.0 run is the Node2Shell baseline.

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
