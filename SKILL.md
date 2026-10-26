---
name: "php2shell-tenable-remediation-tracker"
description: "PHP2Shell (CVE-2026-109618, CVE-2026-109619) exposure and remediation tracker from live Tenable data: HTML, PDF and CSV report with a CISO summary, every plugin per CVE (found by CVE search) with vulnerable and fixed findings, per-finding SLA tracking, execution history and run-to-run comparison (new, remediated, regressed, still open). Each run saves timestamped files (report_TIMESTAMP.html, history_TIMESTAMP.json) plus latest.json, so runs never overwrite each other and the newest comparable run is found automatically. Use whenever someone asks which assets are exposed to PHP2Shell, wants a PHP2Shell report, tracker, status update, follow-up or re-run, asks how remediation progressed since the last run, or uploads a previous PHP2Shell report or history file, even without saying tracker. Before running it asks whether this is the first run (and for the previous report/history if not), the report language and the remediation SLA (7 days or custom). Read-only."
---

# PHP2Shell Tenable Tracker

Version: see `VERSION` (changes in `CHANGELOG.md`).

Builds a remediation tracker for PHP2Shell — the pre-auth PHP remote code execution disclosed on 2026-10-21 (CVE-2026-109618, CVE-2026-109619) — from Tenable One and Tenable VM data, and keeps a ledger of every execution so each new report can be compared with earlier ones.

The report has:
- **Remediation history disclaimer** at the top. On a first run it explains that this report is the baseline, what the history will show from the next run on and how to run it next time. On later runs it states which earlier runs this one is compared with and where the history came from, and why the history file is required for the comparison (Tenable keeps only the current state)
- **Executive summary** for the CISO: posture label (CRITICAL / HIGH / GUARDED / CONTROLLED), one-line verdict, business risk and data-driven asks
- **SLA basis and calculation**, right after the executive summary, collapsed to a one-line summary until clicked: where the SLA number comes from, when the clock starts, the formulas, how outcomes are assigned, which Tenable data the dates come from and a worked example from this run (always expanded in the PDF)
- **This run against the SLA**: open within / past SLA, fixed met / missed / no date
- **Eight KPIs**: assets with PHP, exposed assets, open and remediated findings, remediation rate, mean time to remediate, findings past SLA, PHP assets not scanned since disclosure
- **Run comparison**: KPI deltas, the total number of finding changes, and one clickable card per scenario (new, remediated since, regressed, still open, no longer reported, all) against any earlier run (defaults to the previous one). Each card drills down to the assets and plugins behind it, by asset or by plugin, with product and text filters
- **Execution history**: every run with timestamp, run ID, skill version, posture and KPIs, plus a trend chart
- **Open vs remediated** split bar and daily timeline from disclosure
- **Applicable plugins by CVE**: every plugin Tenable maps to each CVE (WAS, VM, Cloud), with its vulnerable (ACTIVE/RESURFACED) and fixed (FIXED) finding counts and assets, filterable by product (WAS / VM / Cloud), CVE and status — plugins with zero results are listed too. Each plugin expands on click into a **drill-down**: the assets with vulnerable findings and the assets with fixed findings, the target PHP version per asset, the remediation steps for that plugin and the mitigation steps with whether they apply
- **Remediation tracker**: first seen, SLA due, fixed date, days open, SLA outcome and last seen per vulnerable finding, filterable by product; each open finding expands into its plugin's detail (remediation, mitigation, vulnerable and fixed assets, with this asset highlighted)
- **All findings** (filterable by product), interim mitigations, known limitations and sources

Every asset, version, date and finding must trace back to a Tenable MCP call made during this run, because the report is used to make patching and escalation decisions. The skill is read-only: never launch scans, create tags or change anything in Tenable.

Source of truth for CVEs, fixed versions and mitigations: [Tenable Research PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote). Fixed releases: 8.5.12, 8.4.27, 8.3.36, 8.2.35 (`FIXED` in `scripts/render.py`). SLA clock start: disclosure, 2026-10-21.

## Bundled files

| File | Purpose |
|---|---|
| `scripts/render.py` | Turns `findings.json` + `plugins.json` into timestamped report files (see "Output files and naming"), updates the history ledger and `latest.json`, and with `--find-latest` locates the newest comparable history. Standard library plus Playwright (PDF only). |
| `scripts/lang/es.json` | Spanish strings. English and Portuguese-BR are built into `render.py`; any other language is a translation of `render.py --dump-lang` passed with `--lang-file`. |
| `VERSION` | Current skill version; stamped on every report and every ledger entry. |
| `CHANGELOG.md` | Version history of the skill (kept here only; not shown in reports). |
| `assets/sample_findings_run1.json`, `run2.json`, `sample_plugins.json` | Demo inputs for testing the renderer (always render them with `--banner`). The demo plugin catalog is fake; never use it on a real run. |

Use `<skill-dir>` below for this skill's directory (where this SKILL.md lives).

## Output files and naming

Every execution writes its own files, stamped with the execution time in UTC (`<stamp>` = `YYYY-MM-DD_HHMMSSZ`, e.g. `2026-10-25_221430Z`). The stamp sorts chronologically as plain text, has no characters Windows or macOS reject, and is the same on every file of a run, so a whole run can be picked out at a glance and nothing from an earlier run is ever overwritten.

```
php2shell-reports/
├── history.json                  rolling ledger, every run (input to the next run)
├── latest.json                   newest run's files + an index of every run, newest first
└── <YYYY-MM-DD-HHMM>/            one folder per run (the folder name is the run ID)
    ├── report_<stamp>.html       the report; embeds the full history up to this run
    ├── report_<stamp>.pdf
    ├── history_<stamp>.json      snapshot of the ledger right after this run
    ├── run_<stamp>.json          this run only (KPIs, finding status, file names)
    ├── report_<stamp>.csv        findings
    ├── plugins_<stamp>.csv
    ├── changes_<stamp>.csv
    ├── findings.json, plugins.json   inputs collected in steps 3–5
```

Why both a rolling ledger and per-run snapshots: `history.json` is what the next run reads, but it changes every run; the stamped `history_<stamp>.json` and `report_<stamp>.html` freeze the history exactly as it was at that execution, so any past report can be reopened or re-used as a baseline, and a user who keeps several files can tell from the name which one is newest. Demo runs (`--banner`) use `history.demo.json`, `latest.demo.json` and `history.demo_<stamp>.json` so they never mix with real history.

`latest.json` → `latest` gives the relative paths of the newest run's `html`, `history`, `run`, `pdf` and CSVs; `runs` lists every run rendered into that folder with the same fields, newest first. Re-rendering a run folder adds a new stamped set and replaces that run's entry in the ledger and in `latest.json`.

**Finding the latest comparable run.** `render.py --find-latest <folder or files>...` scans for every file that carries a history (`history*.json`, `report*.html`, legacy unstamped names included), reads them, and ranks them by the newest run that has finding detail (the detail the comparison needs), then by number of runs, then by the stamp in the name. It prints JSON with `latest.file` and all candidates. Ranking by content, not just file name, matters because a user may attach an older copy, rename a file or mix stamped and pre-2.9 files. `--import <folder>` applies the same rule and imports the best file under that folder.

## Which plugins count

The skill keeps **no fixed list of plugin IDs**. On every run, the set of applicable plugins is whatever Tenable returns for each CVE (`plugins_search_plugins(cve=...)`), across WAS, VM and Cloud/container sensors. Tenable keeps publishing distro and container advisories for a CVE like this for weeks, so a hard-coded list goes stale fast and silently under-counts exposure; searching by CVE each time picks new plugins up automatically.

Every plugin returned for either CVE is an **applicable plugin** and is shown in the report with:
- the CVE(s) it covers (one or both),
- **vulnerable findings** — findings in state ACTIVE or RESURFACED,
- **fixed findings** — findings in state FIXED,
- the number of assets, and a plugin status: *Vulnerable* (any open finding), *Fixed only*, or *No findings*.

**Plugin drill-down.** Clicking a plugin row opens its detail; this is where a reader goes from "plugin X has 4 vulnerable findings" to "these are the four servers, this is what to install on each, and this is what to do until then". It shows:
- **Vulnerable assets** (ACTIVE/RESURFACED) with PHP version, **target version** (the fixed release of that asset's branch, "EOL – move to a supported branch", "Vendor package update" for distro plugins, "No vendor fix yet", or "Rebuild image" for containers), state, first seen, SLA due, days open and SLA outcome.
- **Fixed assets** (FIXED) with fixed date, days open and SLA outcome.
- **Remediation steps** picked from the plugin's remediation path, which the renderer derives from product, family and name: `upstream` (PHP upgrade), `was` (PHP upgrade behind a web app, WAS re-scan), `distro` (OS vendor package — backports mean the version string may not match upstream), `unpatched` ("Linux Distros Unpatched Vulnerability" plugins: no vendor fix yet) and `container` (rebuild and redeploy the image). Tenable's own synopsis, solution and references are shown above the steps when `plugins.json` carries them (step 3).
- **Mitigation steps** with an applicability note: applicable while the plugin has vulnerable findings, the **primary** control when no vendor fix exists, not required when every finding is fixed or the plugin never fired. The PHP 8.5-only setting is dimmed when no reported version is on 8.5.
The PDF prints the detail of every plugin that has findings.

Plugins with zero results stay in the list on purpose: they show the reader which checks exist and have not fired, which matters when assets have not been scanned since disclosure.

**Inventory plugins** (PHP version detection) are not tied to the CVEs, but they carry the installed PHP version, which the renderer turns into a status against the fixed releases (branches older than 8.2 count as EOL and vulnerable). Find them by name each run too (step 3), not by ID.

## Steps

Set up a task list with these steps.

0. **Intake — ask before doing anything else.** Three answers shape the whole run, so get them before preflight, before any Tenable call and before writing files. A wrong guess here is expensive: the language is baked into every string of the report, the SLA drives every due date, outcome, past-SLA count, the posture label and the MTTR-vs-SLA reading, and a missing history turns a follow-up into a new baseline that cannot show progress.

   Ask all three at once with AskUserQuestion (one call, three questions); without that tool, ask in plain text as a short numbered list. Skip any question the request already answers (e.g. "re-run the PHP2Shell tracker in Spanish, SLA 15 days", an attached `report.html`, or a scheduled task prompt that states them) and say in one line what you took from it.

   1. **First run?** — "Is this the first time the PHP2Shell tracker is run for this environment?" Options: *Yes, first run* / *No, I have a previous report*.
      - *No*: ask for the previous report and/or history file — `report_<stamp>.html` / `history_<stamp>.json`, or `report.html` / `history.json` from runs before 2.9 (the HTML embeds the full ledger, so either is enough; the newest one matters — an older file leaves the runs after it out of the comparison, which is why the timestamp is in the name). If the user hands over several, or a whole `php2shell-reports/` folder, use `--find-latest` (step 2) instead of asking which one is newest. Before asking, check the places in step 2 — if the history is already in the workspace or a connected folder, say which file you found and use it instead of asking. If the user says it is not first run but cannot provide the file, tell them in one sentence that this run will then start a new baseline and cannot show what changed, and get an explicit OK before going on.
      - *Yes*: this run becomes the baseline; still check step 2 quietly, and if a history turns up, mention it and ask whether to continue it.
   2. **Report language** — "Which language should the HTML report be in?" Options: *English* / *Portuguese-BR* / *Spanish* (the user picks "Other" to name any other language). Put the language the user is writing in first, marked (Recommended). Mapping: English → `--lang en`, Portuguese-BR → `--lang pt`, Spanish → `--lang es`; any other language → see "Other languages" in step 6.
   3. **SLA** — "What remediation SLA should findings be measured against?" Options: *Standard — 7 days (Recommended)* / *Other (inform the number of days)*. If the user picks Other without a number, ask for it; accept only a positive whole number of days. If they name the policy or clause it comes from, keep it for `--sla-ref`.

   **The SLA is required.** Do not collect data or render until it has an answer, and never fill it in yourself — the report states whose number it is. If no one can answer (scheduled or unattended session) and the request did not state it, do the read-only preparation (preflight, history restore, plugin catalog), then stop and ask; the run continues once it is answered.

   Once the history is known (step 2), compare the chosen SLA with the SLA of the latest earlier run (`sla_days` on the runs in the history, or the "SLA" in the previous report's header). If they differ, tell the user that past-SLA counts will not be like-for-like with that run (the report flags it too) and confirm which SLA to use.
   *Done when first-run status (with the history file if not first), language and SLA are all settled.*

1. **Preflight.** Find the Tenable MCP tools. In a cloud session linked to the user's computer they are proxied as `mcp__remote-devices__tenable__*` (other prefixes are possible, e.g. `mcp__tenable__*` or `mcp__claude-device__lcl-tenable-*`), so match on the suffix: `tenable_one_search_findings`, `plugins_search_plugins`, `workbenches_get_vulnerability_outputs`, `workbenches_get_asset_info`, `workbenches_export_workbenches`, `workbenches_check_export_status`, `workbenches_download_export`. Load deferred ones with ToolSearch in a single call. If none exist, tell the user the Tenable Hexa AI MCP must be connected (Tenable One Foundation or Advanced, Enable Hexa AI MCP on, API keys from Settings > My Account > API Keys, Standard User or higher) and, in the desktop app, the computer running the MCP must be linked to this chat; then stop.
   *Done when the Tenable tools are callable, or the user has the setup notes.*

2. **Restore execution history.** The comparison is only as good as the ledger, and a fresh cloud session starts with an empty workspace, so look for earlier runs before collecting data, in this order:
   - `./php2shell-reports/` in the workspace (same session, earlier run): `history.json`, and `latest.json` for the newest run's files.
   - A connected folder on the user's computer: stage its `php2shell-reports/` (at least `history.json`, `latest.json` and the newest run folder; `latest.json` → `latest` names the files) into the workspace.
   - Files the user attached: any `report_*.html`, `history_*.json`, or pre-2.9 `report.html` / `history.json` — the HTML embeds the full ledger, so either kind works.
   When there is more than one candidate, do not guess from dates in the conversation: run `python3 <skill-dir>/scripts/render.py --find-latest <every folder and file found>` and use `latest.file`. Tell the user in one line which file (and its newest run) the comparison will continue from. Pass it to the renderer with `--import` in step 6 (or pass the folder itself; `--import <folder>` picks the newest file under it). This step follows the intake answer: if the user said it is not the first run, the file they gave (or the one found here) must be imported, and if nothing was found and nothing was provided, ask for it (step 0) rather than silently starting over. If they said it is the first run and nothing exists, the run starts a new history; the report's disclaimer explains how to continue it next time.
   *Done when you know which history files, if any, will be imported.*

3. **Coverage.**
   - **FAQ:** WebFetch the FAQ URL. If it is blocked, WebSearch for the PHP2Shell fixed releases and fetch a reputable result (e.g. Help Net Security, Canadian Centre for Cyber Security). Take the CVE list (the two above plus any the FAQ adds), the fixed release per branch and the interim mitigations. If the fixed releases differ from `FIXED` in `render.py`, tell the user before rendering, because every version status would be wrong. If every fetch fails, carry on with the two known CVEs and say so in the summary.
   - **Applicable plugins (the catalog):** `plugins_search_plugins(cve=<CVE>)` for **each** CVE separately, every page (50 per page) until a page comes back short. Merge by plugin ID and record, per plugin, which CVE searches returned it — that is how the report knows whether a plugin covers CVE-2026-109618, CVE-2026-109619 or both (if the result itself lists CVEs, union them in). Sensor `tenable_was` → `WAS`, `nessus` → `VM`, anything else (cloud/container) → `Cloud`. A plugin under several sensors is one plugin. Keep the plugin name and family.
   - **Inventory plugins:** `plugins_search_plugins` by name for "PHP Version Detection", "PHP Unsupported Version" and "PHP Scripting Language Installed"; keep only results whose name matches and mark them `role: "inventory"`.
   - **Plugin details (remediation text):** for every CVE plugin, call `plugins_get_plugin_details(plugin_id, plugin_type)` with the `plugin_type` the search reported for it (`nessus`, `was`, `cloud-security`, `container-security`; a wrong type returns 404). Keep `synopsis`, `solution` and `see_also` (reference URLs). These feed the drill-down's "Tenable solution", which is what a patch owner trusts most — especially for distro plugins, where the fixed package version only appears in the vendor advisory. If a lookup fails, leave the fields blank; the drill-down still shows the generic remediation steps for that plugin's path. With many plugins, script the loop.
   - Write `plugins.json` into the run folder (step 5) as a list of `{plugin_id, name, product, family, cves, role, plugin_type, synopsis, solution, see_also}` — `role` is `vulnerable` for CVE plugins and `inventory` for version-detection plugins; `see_also` is a list of URLs.
   - Tell the user how many plugins each CVE returned before pulling findings.
   *Done when every CVE has been searched on every page, `plugins.json` lists every plugin returned, and each CVE plugin has a details lookup attempted.*

4. **Pull data.** Read each tool's schema first. Back off and retry on HTTP 429. Save large results to files and process them in Python rather than in the conversation.
   - **Findings per applicable plugin (primary route):** for **every** plugin in the catalog, `tenable_one_search_findings` with `filters` = `[{"property":"finding_detection_id","operator":"contains","value":["<plugin_id>"]}]`, then again adding `{"property":"state","operator":"=","value":["FIXED"]}` so fixed findings are certainly included. Use `contains` (`=` matches nothing); because `contains` also matches longer IDs (`58987` hits 158987), keep only findings whose name matches the catalog plugin's name. Page with `offset` while `total` exceeds what you have. Record the result count for every plugin, zeros included — the report shows them. Each finding gets the plugin's ID, product and CVEs from the catalog. With many plugins, script the loop and save results to files rather than running it through the conversation.
   - **Cross-check by CVE:** `tenable_one_search_findings` with `[{"property":"finding_cves","operator":"=","value":["<CVE>"]}]` for each CVE, all states and again with state FIXED. Any finding not already collected above is still kept: match its name to the catalog to get a plugin ID; if nothing matches, keep it with a blank plugin ID, its CVE in `cves` and source `VM`, and list it in the summary (the report counts these as unmatched).
   - Keep FIXED findings everywhere — the plugin table, chart, tracker and comparison depend on them.
   - **Inventory findings:** same `finding_detection_id` `contains` query per inventory plugin ID from step 3, keeping only findings whose name contains "PHP".
   - **Dates (first seen, fixed):** `tenable_one_search_findings` returns no dates and ignores date filters. Get them from a Workbenches export: `workbenches_export_workbenches(format="csv", report_type="vulnerabilities")`, poll `workbenches_check_export_status`, then `workbenches_download_export`. Save the CSV; in Python keep rows whose plugin ID is in the step 3 catalog and map the first-discovered and last-fixed columns (inspect the header first; names vary) to `first_seen` and `fixed_date` by asset + plugin. If the export fails or lacks those columns, leave the dates blank and say so: the tracker then shows "No first-seen date", SLA is measured from disclosure and the daily timeline is replaced by a note. Never estimate dates.
   - **PHP version for VM plugins:** `workbenches_get_vulnerability_outputs(plugin_id)` returns up to 10 distinct outputs per call; repeat with `age` = 7, 14, 30, 90, 180, 365 and merge by asset ID. When an output lists several versions, use the lowest.
   - **Assets with no output:** `workbenches_get_asset_info(asset_id)` for hostname, IP and last seen; leave the version blank (renders "Unknown – verify").
   *Done when every catalog plugin ID has a recorded result count for open and fixed findings (zeros included) and every asset is a row.*

5. **Write `findings.json` and `plugins.json`.** Run folder: `./php2shell-reports/<YYYY-MM-DD-HHMM>/` — the folder name becomes the run ID in the history, so keep it unique and chronological. `plugins.json` is the step 3 catalog, unfiltered (zero-result plugins included). `findings.json` has one row per asset × plugin, as a JSON list with: `asset`, `ip`, `fqdn`, `source` (`VM`/`WAS`/`Cloud`), `plugin_id`, `plugin_name`, `cves` (list), `php_version`, `port`, `last_seen` (YYYY-MM-DD), `role` (`vulnerable` or `inventory`), `state` (`ACTIVE`/`RESURFACED`/`FIXED`), `first_seen`, `fixed_date` (YYYY-MM-DD or blank), and `plugin_output` when `php_version` is blank. Fill `fqdn`, `ip` and `port` whenever Tenable returns them — the plugin drill-down lists them so owners can find the box. Fill `php_version` on a vulnerable row from the same asset's inventory row when available. Use the same `asset` naming (hostname) on every run, because the comparison matches findings on asset + plugin ID; switching between hostnames and IPs would show everything as new.

6. **Render.**
   ```bash
   python3 <skill-dir>/scripts/render.py ./php2shell-reports/<run>/findings.json ./php2shell-reports/<run> \
     --plugins ./php2shell-reports/<run>/plugins.json \
     [--sla-days <N>] [--sla-ref "<policy reference>"] --lang <en|pt|es|code> [--lang-file <translation.json>] \
     [--import <history_*.json|report_*.html|folder> ...]
   ```
   - Always pass `--plugins`. Without it the plugin table can only show plugins that returned findings, and the report says the catalog is missing.
   - SLA, from the intake answer: *Standard — 7 days* → omit `--sla-days` (the report labels it the skill default for a pre-auth RCE exploited in the wild); *Other* → `--sla-days <N>` with the user's number, labelled as set by the requester. If the user named the policy or clause, pass it with `--sla-ref`. The SLA feeds every due date, SLA outcome, past-SLA count and the posture, and the MTTR tile shows whether mean time to remediate is within that SLA.
   - Language, from the intake answer: `--lang en`, `--lang pt` (Portuguese-BR) or `--lang es` (Spanish, bundled in `scripts/lang/es.json`). Technical terms (finding, plugin, SLA, asset states, CVE IDs, php.ini settings) stay in English in every language.
   - **Other languages:** run `python3 <skill-dir>/scripts/render.py --dump-lang > en.json`, translate every value into the requested language (keep the keys, the `{placeholders}`, the list structure, the `<code>` tags and the technical terms above unchanged; set `html_lang` to the language's BCP-47 code, e.g. `fr`, `de`, `it`, `ja`), save it in the run folder as `lang-<code>.json`, and render with `--lang <code> --lang-file ./php2shell-reports/<run>/lang-<code>.json`. Missing keys fall back to English and the renderer prints `lang_missing=` — fill them and re-render. Deliver the translation file with the report and reuse it on later runs in that language so the wording stays the same.
   - The ledger is `./php2shell-reports/history.json` (override with `--history`). Re-rendering the same run folder replaces that run's entry instead of duplicating it.
   - PDF uses Playwright with the preinstalled Chromium (`/opt/pw-browsers`); if Playwright is missing, `pip install --break-system-packages playwright` and retry. The PDF is best effort; `--no-pdf` skips it.
   - `--banner`, `--today` and `--executed-at` exist for labeled demos and tests only; never pass them on a real run. A bannered run is recorded as a demo in a separate `history.demo.json` so demo data never mixes with real history.
   - Output names are stamped automatically from the execution time (see "Output files and naming"); never rename them. The renderer prints them on the `files=` line and the manifest on the `latest=` line — use those paths in steps 7–8.
   *Done when no `lang_missing=` line is printed, the output prints `rows=` equal to the rows written, a `plugins=` line whose total and per-CVE counts match the catalog with no `catalog=missing`, a `posture=` line, a `delta_vs=` line, a `files=` line whose files all exist, and `latest.json` names this run as `latest`.*

7. **Check.** Screenshot `report_<stamp>.html` with Playwright (full page) and look at it: every heading and sentence is in the chosen language and the header shows the chosen SLA; history disclaimer (green when a history was continued, orange when this run started a new one — make sure that matches what step 2 found), executive summary, SLA basis section (collapsed; click it open and check the worked example), "This run against the SLA" tiles (or the no-dates note), KPI tiles, run comparison (or its first-run note — on a later run, click a scenario card and confirm its assets and plugins appear), execution history, chart (or its empty-state note), applicable-plugins table, tracker and findings table should all render. Then click the first plugin that has findings and screenshot again: its drill-down must list the vulnerable and fixed assets, remediation steps and mitigation steps; pick a value in the product filter and confirm the rows change; click an open finding in the remediation tracker and confirm the same detail opens with that asset highlighted. Fix and re-render if anything is broken.

8. **Deliver.** SendUserFile `report_<stamp>.html` and `report_<stamp>.pdf` (display: render), then `history_<stamp>.json`, `report_<stamp>.csv`, `plugins_<stamp>.csv`, `changes_<stamp>.csv` and, for a custom language, `lang-<code>.json` — the exact paths are on the renderer's `files=` line. The stamped history is the file to keep for the next run. If a folder on the user's computer is connected, also write the run folder, `history.json` and `latest.json` into its `php2shell-reports/` via the device bridge, without deleting earlier run folders, so the next session finds the newest run automatically and older reports stay available.

9. **Summarize** in the reply, briefly:
   - whether this run continued an earlier history or started a new one (and from which file), the execution timestamp of this run, and how to keep it for the next run (keep `history_<stamp>.json` / `report_<stamp>.html`, or the connected `php2shell-reports/` folder)
   - posture label and the one-line verdict
   - the report language and the SLA applied with its basis (standard 7 days, or the user's number with the policy reference if given), and whether mean time to remediate is within that SLA
   - open vs remediated counts, remediation rate, mean time to remediate, findings past SLA
   - versus the previous run: new, remediated since, regressed, still open, no longer reported, and KPI direction — or that this is the first run in the history
   - a skill-version change between the compared runs, if the renderer reported one (`version_change=`)
   - PHP assets not scanned since disclosure (a coverage gap, not safety)
   - applicable plugins per CVE (count for each CVE), then a short table of the plugins that have findings — plugin ID, product, CVE(s), vulnerable findings, fixed findings — plus how many plugins returned nothing; the full list is in the report and `plugins.csv`, and each plugin expands in the HTML to its assets, remediation and mitigation
   - any plugin on the `unpatched` path (no vendor fix yet), since its assets rely on mitigation alone
   - the ten worst open assets
   - whether dates came through (tracker reliability), unmatched finding names, FAQ fetch problems
   - interim mitigations: `memory_limit=-1`, `session.upload_progress.enabled=0`, and `fatal_error_backtraces=0` on PHP 8.5, then restart every PHP worker; WAF rules on internet-facing PHP. These reduce exposure but are not a fix.
   - sources, including the FAQ link

## How the comparison works

Each run stores, per vulnerable finding (key `asset|plugin_id`), whether it was open or remediated, plus per-asset status and the KPIs. Against a baseline run:
- **New** — open now, absent from the baseline.
- **Remediated since** — open in the baseline, FIXED now.
- **Regressed** — FIXED in the baseline, open now (e.g. RESURFACED).
- **Still open** — open in both.
- **No longer reported** — open in the baseline, absent now. Not proof of a fix: the asset may be unscanned, offline or decommissioned, so call these out for verification rather than counting them as wins.

The ledger keeps full finding detail for the latest 60 runs and KPIs only for older ones.

## Maintaining this skill

Every change gets a version bump in `VERSION` and an entry at the top of `CHANGELOG.md` (rules are at the top of that file). The version is recorded on each run and printed in the report header, and the report warns when two compared runs came from different versions (pointing readers to the CHANGELOG), so a MAJOR bump should explain under "Comparability" what can no longer be compared.

## Known limitations
- Status comes from the PHP version alone; distro backports (Ubuntu, RHEL) can show as vulnerable when patched — check vendor advisories.
- WAS plugins were published 21 Oct 2026; earlier scans cannot report PHP2Shell, so an empty result on stale assets means unassessed, not clean.
- The Workbenches date route is the expected source for first seen / fixed but has not yet been validated on a tenant with PHP2Shell findings; check the first run's tracker against the Tenable UI.
- The comparison is only as consistent as the asset naming across runs (step 5).
