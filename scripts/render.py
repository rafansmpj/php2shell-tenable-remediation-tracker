#!/usr/bin/env python3
"""PHP2Shell exposure & remediation tracker renderer.

Reads findings.json (one row per asset x plugin, collected from Tenable MCP)
and plugins.json (every plugin Tenable maps to the PHP2Shell CVEs, discovered
by CVE at run time), writes report_<stamp>.html, report_<stamp>.pdf,
report_<stamp>.csv, plugins_<stamp>.csv, changes_<stamp>.csv, run_<stamp>.json and a
history snapshot history_<stamp>.json into the run folder (<stamp> = execution time
in UTC, YYYY-MM-DD_HHMMSSZ, so names sort chronologically), appends the run to the
rolling ledger <reports>/history.json and updates <reports>/latest.json, which
points at the newest run's files and lists every run.

Usage:
  python3 render.py <findings.json> <run_dir> --plugins <plugins.json>
                    [--sla-days 7] [--sla-ref TEXT] [--lang en|pt|es|<code> [--lang-file tr.json]]
                    [--history <ledger.json>] [--import <history*.json|report*.html|folder>]...
                    [--no-pdf] [--banner TEXT --today YYYY-MM-DD --executed-at ISO]
  python3 render.py --find-latest <folder|file>... [--include-demo]
      prints (JSON) the newest history file that can be compared against

An --import that names a folder loads the newest history found under it.

--banner/--today/--executed-at are for labeled demos and tests only.
"""
import argparse, csv, html, json, os, re, statistics, sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
FALLBACK_VERSION = "2.15.0"
LEDGER_FORMAT = 1
MAX_DETAILED_RUNS = 60  # older runs keep KPIs only

DISCLOSURE = date(2026, 10, 21)
FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
CVES = ["CVE-2026-109618", "CVE-2026-109619"]
FAQ_URL = ("https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-"
           "frequently-asked-questions-about-critical-php-remote")

# Node2Shell (CVE-2026-111497): Brotli decoder out-of-bounds write, disclosed the same day as PHP2Shell.
# Not a PHP flaw, so it is tracked in its own section and NEVER feeds the PHP2Shell KPIs, posture or comparison.
N2S_CVE = "CVE-2026-111497"
N2S_DISCLOSURE = date(2026, 10, 21)   # Node.js security release; CVE record published 2026-10-22
N2S_FIXED = {                          # component -> {branch: fixed release}; branch = (major,) or (major, minor)
    "nodejs": {(22,): (22, 23, 4), (24,): (24, 22, 1), (26,): (26, 12, 1)},
    "brotli": {(1, 0): (1, 0, 10), (1, 1): (1, 1, 1), (1, 2): (1, 2, 1)},
    "python": {(1, 2): (1, 2, 1)},
}
N2S_NODE_EOL = lambda major: major <= 20 or major in (21, 23, 25)  # no fix from Node.js
N2S_SOURCES = [
    ("Debian security tracker — CVE-2026-111497", "https://security-tracker.debian.org/tracker/CVE-2026-111497"),
    ("Rescana — Node2Shell: Node.js Brotli flaw, fixed releases", "https://www.rescana.com/post/nodejs-cve-2026-111497-node2shell-brotli-rce-october-2026"),
    ("Aikido — Node2Shell impact beyond Node.js (Python, curl, Envoy, Istio)", "https://www.aikido.dev/blog/python-packages-vulnerable-node2shell-brotli-cve-2026-111497"),
]


def skill_version():
    try:
        return (SKILL_ROOT / "VERSION").read_text().strip() or FALLBACK_VERSION
    except OSError:
        return FALLBACK_VERSION


# ---------------------------------------------------------------- i18n
T = {
 "en": {
  "title": "PHP2Shell & Node2Shell \u2014 Exposure & Remediation Tracker",
  "executed": "Executed", "run": "Run", "version": "Skill version", "sla": "SLA",
  "days": "days", "disclosure": "Disclosure", "exec_summary": "Executive summary",
  "decisions": "Decisions and asks", "kpis": "Key indicators",
  "k_php": "Assets with PHP", "k_exposed": "Exposed assets", "k_open": "Open findings",
  "k_rem": "Remediated findings", "k_rate": "Remediation rate", "k_mttr": "Mean time to remediate",
  "k_breach": "Findings past SLA", "k_unscanned": "PHP assets not scanned since disclosure",
  "compare": "Run comparison", "compare_with": "Compare this run with",
  "no_prev": "This is the first recorded run. Later runs will be compared with it.",
  "new": "New", "fixed_since": "Remediated since", "regressed": "Regressed",
  "still_open": "Still open", "gone": "No longer reported",
  "gone_note": "\"No longer reported\" means the finding is absent from this run's data; it is not proof of a fix (asset may be unscanned or decommissioned).",
  "ver_mismatch": "These runs were produced by different skill versions ({a} → {b}). Check the skill's CHANGELOG before reading the deltas.",
  "sla_mismatch": "These runs used different SLAs ({a} → {b} days); SLA-based numbers are not like-for-like.",
  "demo_mismatch": "One of these runs is a labeled demo; do not mix demo and real data.",
  "history": "Execution history", "h_when": "Executed", "h_run": "Run ID", "h_ver": "Version",
  "h_posture": "Posture", "h_open": "Open", "h_rem": "Remediated", "h_rate": "Rate",
  "h_breach": "Past SLA", "h_assets": "Exposed assets", "trend": "Open vs remediated findings across runs",
  "chart": "Open vs remediated", "timeline": "Daily timeline since disclosure",
  "no_dates": "No first-seen / fixed dates were available from Tenable for this run, so the daily timeline cannot be drawn. Counts above are still accurate.",
  "tracker": "Remediation tracker", "findings": "All findings", "search": "Filter…",
  "c_asset": "Asset", "c_ip": "IP", "c_src": "Source", "c_plugin": "Plugin", "c_ver": "PHP version",
  "c_vstatus": "Version status", "c_state": "State", "c_first": "First seen", "c_due": "SLA due",
  "c_fixed": "Fixed", "c_daysopen": "Days open", "c_outcome": "SLA outcome", "c_last": "Last seen",
  "c_vpr": "VPR", "c_acr": "ACR", "c_aes": "AES",
  "sc_note": "VPR = Tenable Vulnerability Priority Rating of the plugin (0–10). ACR = Asset Criticality Rating (1–10) and AES = Asset Exposure Score (0–1000), both from Tenable One for the asset at run time. “—” = Tenable returned no value.",
  "sc_missing": "Tenable returned no {what} for this run, so those columns show “—”.",
  "c_role": "Role", "c_change": "Change",
  "mitig": "Interim mitigations (reduce exposure, not a fix)",
  "limits": "Known limitations", "sources": "Sources",
  "readonly": "Read-only report generated from Tenable data. No scans, tags or settings were changed.",
  "no_first": "No first-seen date", "met": "Met", "missed": "Missed",
  "breached": "Breached by {n} d", "due_in": "Due in {n} d", "due_today": "Due today",
  "st_vulnerable": "Vulnerable", "st_patched": "Patched", "st_eol": "EOL branch – vulnerable",
  "st_unknown": "Unknown – verify", "open": "Open", "remediated": "Remediated",
  "p_CRITICAL": "CRITICAL", "p_HIGH": "HIGH", "p_GUARDED": "GUARDED", "p_CONTROLLED": "CONTROLLED",
  "plugins": "Applicable plugins by CVE", "pl_total": "Applicable plugins",
  "pl_for": "Plugins for {cve}", "pl_open": "Plugins with vulnerable findings",
  "pl_fixed": "Plugins with only fixed findings", "pl_none": "Plugins with no findings",
  "pl_all": "All CVEs", "pl_any": "Any status", "c_cves": "CVEs", "c_product": "Product",
  "c_family": "Family", "c_vuln_n": "Vulnerable findings", "c_fixed_n": "Fixed findings", "c_assets_n": "Assets",
  "c_pstatus": "Plugin status", "c_name": "Name",
  "ps_vulnerable": "Vulnerable", "ps_fixed": "Fixed only", "ps_none": "No findings",
  "pl_note": "Every plugin Tenable maps to the PHP2Shell CVEs, discovered by CVE on this run. Vulnerable = findings still ACTIVE/RESURFACED; Fixed = findings in state FIXED. A plugin with no findings has not fired in this tenant — not proof of safety if the assets were not scanned since disclosure.",
  "pl_nocat": "No plugin catalog was supplied for this run, so only plugins that returned findings are listed; plugins with zero results are missing.",
  "pl_extra": "Seen in findings but not returned by the CVE plugin search",
  "pl_unmatched": "{n} vulnerable finding(s) could not be tied to a plugin ID and are not counted in this table.",
  "inv_plugins": "Inventory plugins (PHP version source, not CVE-specific)",
  "disc_h_first": "Remediation history — first run",
  "disc_h_next": "Remediation history — comparison with earlier runs",
  "disc_first_stat": "This is the first recorded run of the PHP2Shell tracker, so this report is the starting point (baseline) of the remediation history. Nothing in it is compared with a previous run yet.",
  "disc_first_what_h": "What the history will give you from the next run on",
  "disc_first_what": ["This run's findings, asset status and KPIs were saved to the execution history ({json}, also embedded in this {html}).",
    "Each later run is compared with this one and shows which findings are New, Remediated since, Regressed, Still open or No longer reported, with the assets and plugins behind each.",
    "The KPIs show their change since the previous run, and the execution history table and trend chart grow with every run.",
    "You can pick any earlier run as the comparison baseline, not just the previous one."],
  "disc_first_how_h": "How to run it next time",
  "disc_first_how": ["Keep this {html} (or {json}) — it is the history. Every run writes its own timestamped files, so earlier runs are never overwritten. It is not tied to this conversation.",
    "Same conversation: just ask to re-run the PHP2Shell tracker; the history is picked up automatically.",
    "New conversation: attach the newest report_*.html or history_*.json (the timestamp in the name shows which is newest), or connect the folder on your computer that holds php2shell-reports/ — the tracker finds the newest run there by itself.",
    "Use the same SLA ({n} days on this run) and let the tracker keep naming assets by hostname, so findings match across runs.",
    "If the next run gets no history, it becomes another first run and cannot show what changed since this one."],
  "disc_next_stat1": "This run is compared with 1 earlier run, from {last}, loaded from the execution history.",
  "disc_next_stat": "This run is compared with an execution history of {n} earlier runs, from {first} to {last}. The latest one is the default baseline; any of them can be selected in Run comparison.",
  "disc_src": "History source: {src}.", "src_ledger": "history file in the workspace", "src_import": "imported from {f}",
  "disc_why_h": "Why the history file is required for the comparison",
  "disc_why": ["Tenable reports the current state of each finding. It does not keep what this tracker reported on earlier dates, which assets were open in an earlier run, or which findings have since disappeared.",
    "That earlier picture exists only in the history file: every run stores the open / remediated status of each finding (asset + plugin), its asset status and its KPIs.",
    "The comparison — New, Remediated since, Regressed, Still open, No longer reported, KPI changes and the trend — is computed by matching this run against that stored status. Without the file, those numbers cannot be rebuilt.",
    "This run has just been added to the history. For the next run, provide the newest history: this {html} or {json} (or the connected php2shell-reports/ folder, where latest.json points at the newest run). An older file would leave the runs after it out of the comparison."],
  "disc_keep_h": "For like-for-like comparisons",
  "disc_keep": ["Keep the same SLA ({n} days on this run); a different SLA is flagged and past-SLA numbers stop being comparable.",
    "Keep asset naming stable (hostname): renamed or re-IP'd assets show as New / No longer reported.",
    "\"No longer reported\" is not proof of a fix — the asset may not have been scanned.",
    "Full finding detail is kept for the latest {m} runs; older runs keep their KPIs only."],
  "trk_click": "Click an open finding (or press Enter on it) to see its plugin's details: the remediation and mitigation steps and every asset with vulnerable or fixed findings for that plugin. This asset is highlighted.",
  "cmp_total": "{n} finding changes against the baseline run",
  "cmp_click": "Click a scenario to see the assets and plugins behind it.",
  "cmp_all": "All changes", "by_asset": "By asset", "by_plugin": "By plugin",
  "c_plugins": "Plugins", "c_findings": "Findings", "c_assets": "Assets", "scn_empty": "No findings in this scenario.",
  "new_d": "Vulnerable now and absent from the baseline run: newly detected, newly scanned or newly vulnerable.",
  "fixed_since_d": "Open in the baseline run and FIXED now: remediation confirmed by Tenable.",
  "regressed_d": "FIXED in the baseline run and open again now (e.g. RESURFACED): the fix did not hold or was rolled back.",
  "still_open_d": "Open in both runs: the remediation backlog carried over.",
  "gone_d": "Open in the baseline run and absent now. Not proof of a fix — the asset may be unscanned, offline or decommissioned; verify before closing.",
  "all_d": "Every finding that changed or stayed open between the two runs.",
  "sla_h": "SLA basis and calculation",
  "sla_intro": "Every vulnerable finding in this report is measured against a remediation SLA of {n} days. This section explains where that number comes from and how each date and outcome in the tracker is calculated, so the figures can be audited and reproduced.",
  "sla_src_h": "Where the SLA comes from",
  "sla_src_default": "{n} days is this skill's default for PHP2Shell. CVE-2026-109618 / CVE-2026-109619 is a pre-authentication remote code execution with reported in-the-wild exploitation, which sits in the highest tier of common remediation policies (CISA BOD 22-01 KEV deadlines, PCI DSS critical patching, most internal critical-severity SLAs).",
  "sla_src_user": "{n} days was set for this run by the requester, per the organization's remediation policy.",
  "sla_src_ref": "Policy reference: {ref}",
  "sla_clock_h": "When the clock starts",
  "sla_clock": ["The clock starts at the later of two dates: the public disclosure ({d}) and the finding's first-seen date in Tenable.",
    "A finding first seen before disclosure (for example by a generic PHP version plugin) starts on {d}: nobody could remediate PHP2Shell before it was public.",
    "A finding first seen after disclosure starts on its first-seen date: the asset was new, newly scanned or newly vulnerable.",
    "If Tenable returned no first-seen date, the clock starts at disclosure and the tracker shows \"No first-seen date\"."],
  "sla_formula_h": "Formulas",
  "sla_f": ["Clock start = max(first seen, disclosure)", "SLA due = clock start + {n} days",
    "Days open (open finding) = today − first seen", "Days open (fixed finding) = fixed date − first seen",
    "Mean time to remediate = average days open of fixed findings that have both dates"],
  "sla_out_h": "How outcomes are assigned",
  "sla_out": [["Due in N d / Due today", "Open finding, today is on or before the SLA due date."],
    ["Breached by N d", "Open finding, today is past the SLA due date. Counted in “Findings past SLA” and drives the CRITICAL posture."],
    ["Met", "Fixed finding whose fixed date is on or before the SLA due date."],
    ["Missed", "Fixed finding, fixed after the SLA due date."],
    ["—", "Fixed finding without a fixed date in Tenable: the outcome cannot be judged and is left blank."]],
  "sla_data_h": "Data behind the dates",
  "sla_data": ["Finding state (ACTIVE, RESURFACED, FIXED) comes from Tenable One findings; ACTIVE and RESURFACED count as open.",
    "First-seen and fixed dates come from the Tenable VM Workbenches export (first discovered / last fixed), matched by asset and plugin.",
    "A RESURFACED finding keeps its original first-seen date, so a regression stays measured against the original due date.",
    "\"Today\" is the execution date of this run ({t}). Dates are calendar days, not business days."],
  "sla_now_h": "This run against the SLA",
  "sla_sum": "{n}-day SLA · clock starts at the later of disclosure ({d}) and first seen · {src}",
  "sla_sum_default": "skill default", "sla_sum_user": "set by the requester",
  "sla_toggle": "Show / hide how the SLA is calculated",
  "sla_now_intro": "Every vulnerable finding of this run, measured against the {n}-day SLA (see SLA basis and calculation for how each outcome is assigned).",
  "sla_now": ["Open, within SLA", "Open, past SLA", "Fixed, SLA met", "Fixed, SLA missed", "Fixed, no fixed date"],
  "sla_ex_h": "Worked example",
  "sla_ex": "{a} (plugin {p}): first seen {fs} → clock starts {cs} → due {due}. {state}",
  "sla_ex_open": "Still open on {t}: {o}.", "sla_ex_fixed": "Fixed on {fx}: SLA {o}.",
  "sla_nodates": "No first-seen dates came back from Tenable for this run, so every finding is measured from disclosure ({d}) and mean time to remediate cannot be calculated.",
  "sla_change": "Keep the same SLA across runs: the run comparison flags baselines that used a different SLA, because past-SLA counts are then not like-for-like.",
  "pl_click": "Click a plugin (or press Enter on it) to see which assets have vulnerable and fixed findings, with the remediation and mitigation steps.",
  "pl_expand": "Expand all", "pl_collapse": "Collapse all", "prod_all": "All products",
  "d_vuln": "Assets with vulnerable findings ({n})", "d_fixed": "Assets with fixed findings ({n})",
  "d_empty": "No assets in this state.", "d_synopsis": "Synopsis", "d_solution": "Tenable solution",
  "d_remed": "Remediation steps", "d_mitig": "Mitigation steps", "d_refs": "References",
  "c_fqdn": "FQDN", "c_port": "Port", "c_target": "Target version", "c_due_fixed": "SLA due",
  "tgt_ok": "Already on a fixed release", "tgt_eol": "EOL – move to a supported branch",
  "tgt_unknown": "Verify version", "tgt_vendor": "Vendor package update", "tgt_none": "No vendor fix yet",
  "tgt_image": "Rebuild image", "k_upstream": "Upstream PHP upgrade", "k_was": "Web application (PHP upgrade on server)",
  "k_distro": "OS vendor package update", "k_unpatched": "No vendor fix yet – mitigate", "k_container": "Container image rebuild",
  "rem_upstream": ["Upgrade PHP on each asset to the fixed release of its branch: 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (see Target version per asset).",
    "Branches older than 8.2 are end-of-life and get no fix: migrate them to a supported branch.",
    "Restart PHP-FPM, Apache mod_php and every other PHP worker so the patched binary is loaded.",
    "Re-run a credentialed scan to confirm the finding moves to FIXED."],
  "rem_was": ["Upgrade PHP on the server behind the web application to 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (branches older than 8.2 must move to a supported branch).",
    "Restart PHP-FPM / mod_php and every PHP worker, and purge any reverse-proxy cache that pins the old version banner.",
    "If the application is internet-facing, keep the WAF rules below in place until the re-scan is clean.",
    "Re-run the Tenable Web App Scanning scan for the application to confirm the finding moves to FIXED."],
  "rem_distro": ["Apply the OS vendor's PHP package update (apt / dnf / yum / zypper), not an upstream build: vendors backport the fix, so the version string may stay below 8.x.y.",
    "Check the vendor advisory in the plugin references for the exact fixed package version.",
    "Restart every PHP worker after the package update.",
    "Re-run a credentialed scan to confirm the finding moves to FIXED."],
  "rem_unpatched": ["The OS vendor has not shipped a fixed package yet; Tenable flags the installed package as affected.",
    "Apply the mitigation steps below now — they are the main control until a fix exists.",
    "Where the risk is not acceptable, replace the distro package with an upstream fixed PHP release, or isolate the asset from untrusted networks.",
    "Watch the vendor advisory; update the package and re-scan as soon as the fix is published."],
  "rem_container": ["Rebuild the image on a base image or php package that contains the fix (8.5.12, 8.4.27, 8.3.36, 8.2.35 or the distro's patched package).",
    "Redeploy every running workload from the new image — patching a running container does not persist.",
    "Re-scan the image / registry to confirm the finding moves to FIXED."],
  "mit_items": ["php.ini: <code>memory_limit=-1</code>", "php.ini: <code>session.upload_progress.enabled=0</code>",
    "php.ini: <code>fatal_error_backtraces=0</code> (PHP 8.5 only)", "Restart every PHP worker after changing php.ini.",
    "WAF rules in front of internet-facing PHP; restrict access to the affected services where possible."],
  "mit_open": "Applicable: this plugin still has vulnerable findings. Apply on those assets until the remediation is in place — mitigations reduce exposure but are not a fix.",
  "mit_primary": "Applicable and primary: no vendor fix exists yet, so these settings are the main control.",
  "mit_fixed": "Not required for these assets: every finding of this plugin is FIXED. Keep the settings only where a re-scan is still pending.",
  "mit_none": "Not required: this plugin has no findings. Apply only on PHP assets not scanned since disclosure.",
  "mit_no85": "The 8.5-only setting does not apply to the versions reported for this plugin.",
  "html_lang": "en",
  "verdict_CRITICAL": "{open} open PHP2Shell findings on {exposed} assets, {breached} already past the {n}-day SLA.",
  "verdict_HIGH": "{exposed} assets are still exposed to PHP2Shell; none past the {n}-day SLA yet.",
  "verdict_GUARDED": "No confirmed exposure, but some PHP assets have an unknown version or were not scanned since disclosure.",
  "verdict_CONTROLLED": "No open PHP2Shell exposure, and every PHP asset has been assessed since disclosure.",
  "biz": "PHP2Shell (CVE-2026-109618 / CVE-2026-109619) is a pre-authentication remote code execution with reported in-the-wild exploitation. An exposed PHP server can be taken over without credentials, leading to data theft, ransomware and lateral movement.",
  "ask_breached": "Escalate the {breached} findings past the {n}-day SLA to their owners today.",
  "ask_patch": "Patch the {exposed} exposed assets to PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, with interim mitigations until then.",
  "ask_unscanned": "Re-scan the {unscanned} PHP assets not assessed since {d} — a coverage gap, not a clean bill.",
  "ask_unknown": "Verify the PHP version on {unknown} assets with unknown status.",
  "ask_nodates": "First-seen/fixed dates were unavailable: SLA is measured from disclosure.",
  "ask_none": "Keep monitoring; no further action needed.",
  "mttr_vs_sla": "SLA {n} days",
  "mttr_within": "within SLA",
  "mttr_over": "over SLA",
  "mitig_restart": "Restart every PHP worker; WAF rules on internet-facing PHP.",
  "limits_list": ["Status comes from the PHP version alone; distro backports (Ubuntu, RHEL) can show as vulnerable when patched — check vendor advisories.", "WAS plugins were published 21 Oct 2026; earlier scans cannot report PHP2Shell, so an empty result on a stale asset means unassessed, not clean.", "\"No longer reported\" in the run comparison does not prove a fix."],
  "kpi_only": "Baseline kept KPIs only (older than the detail window).",
  "n2s_h": "Node2Shell (CVE-2026-111497)",
  "n2s_status": "Status as of 23 Oct 2026: CVSS 4.0 score 9.2 (Google, CNA); no exploitation in the wild reported and not in the CISA KEV catalog; public proof-of-concept code exists. A service is exposed only if it, or a library it uses, decodes Brotli data an attacker controls.",
  "n2s_none": "No Node2Shell data was collected on this run, so this section is empty. That is not evidence that no asset is affected.",
  "dd_hint": "Click any tile — here, under Assets by version status or in the strip under the executive summary — to see the assets and findings behind it.",
  "dd_asset1": "{n} asset",
  "dd_finding1": "{n} finding",
  "dd_close": "Close",
  "dd_assets": "{n} assets",
  "dd_findings": "{n} findings",
  "dd_empty": "Nothing in this tile.",
  "dd_nofind": "No vulnerable findings",
  "dd_unscanned": "not scanned since disclosure",
  "c_vgroup": "Version group",
  "c_astatus": "Asset status",
  "c_open_n": "Open findings",
  "as_open": "Open findings",
  "as_at_risk": "Vulnerable version, no open finding",
  "as_remediated": "Remediated",
  "as_patched": "Patched",
  "as_unknown": "Unknown",
  "hs_assets": "Assets running PHP",
  "hs_confirmed": "Confirmed vulnerable",
  "hs_unassessed": "Not assessed since disclosure",
  "hs_open": "Open findings",
  "hs_rem": "Remediated",
  "hs_rate": "Remediation rate",
  "hs_mttr": "Mean time to remediate",
  "hs_breach": "Open past {n}-day SLA",
  "vb_h": "Assets by version status",
  "vb_hint": "Each asset is counted once, in the first group that applies from left to right, so the six add up to the {n} assets in scope. Hover a tile for its definition.",
  "vb_eol": "Vulnerable – EOL",
  "vb_backport": "Vulnerable – backport only",
  "vb_patch": "Vulnerable – patch available",
  "vb_unknown": "Unknown – verify",
  "vb_patched": "Patched",
  "vb_na": "Not affected",
  "vb_eol_d": "Running a PHP branch older than 8.2: end-of-life, no fix will be published — move to a supported branch.",
  "vb_backport_d": "Vulnerable through an OS-vendor PHP package (distro plugin, or no vendor fix yet): the fix arrives as a backported package, so the version string alone cannot confirm it.",
  "vb_patch_d": "Vulnerable and an upstream fix exists: PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, or an image rebuild for containers.",
  "vb_unknown_d": "PHP found but no version could be read and no open finding decides it — verify on the host.",
  "vb_patched_d": "On a fixed release, or every finding for the asset is FIXED.",
  "vb_na_d": "Version outside the affected range.",
  "st_na": "Not affected",
  "n2s_cmp_none": "No earlier run in the history has Node2Shell data; the next run will be compared with this one.",
  "c_component": "Component",
  "c_inst": "Installed version",
  "comp_nodejs": "Node.js",
  "comp_brotli": "Brotli library",
  "comp_python": "Python Brotli / brotlicffi",
  "comp_container": "Container image",
  "n2s_rem_container": ["Rebuild the image on a base image with Node.js 22.23.4 / 24.22.1 / 26.12.1 or Brotli 1.0.10 / 1.1.1 / 1.2.1 (or the distro's patched package).", "Redeploy every running workload from the new image — patching a running container does not persist.", "Re-scan the image / registry to confirm the finding moves to FIXED."],
  "comp_distro": "OS package",
  "comp_other": "Bundled Brotli (other software)",
  "n2s_tgt_eol": "EOL – move to Node.js 22, 24 or 26",
  "n2s_tgt_na": "Not affected (before 1.0.3)",
  "n2s_rem_nodejs": ["Upgrade Node.js to the fixed release of its line: 22.23.4, 24.22.1 or 26.12.1 — on servers, container and serverless images and CI runners.", "Lines 20.x and older, 23.x and 25.x are end-of-life and get no fix: move them to 22, 24 or 26.", "Updating npm packages such as Express does not fix this; the runtime itself must be upgraded.", "Restart every Node.js process and re-scan to confirm the finding moves to FIXED."],
  "n2s_rem_brotli": ["Update the Brotli library to 1.2.1, or 1.1.1 / 1.0.10 on older branches.", "Rebuild or update software that links or bundles libbrotli statically (curl, Bun, Envoy, Istio) to its fixed release.", "Restart the services that load the library and re-scan to confirm the finding moves to FIXED."],
  "n2s_rem_python": ["Upgrade the Python packages Brotli to 1.2.1 and brotlicffi to 1.2.1.0 in every environment and image.", "Restart the Python services and re-scan to confirm the finding moves to FIXED."],
  "n2s_rem_distro": ["Apply the OS vendor's brotli / nodejs package update (apt / dnf / yum / zypper); vendors backport the fix, so the version string may stay below the upstream fixed release.", "Check the vendor advisory in the plugin references for the exact fixed package version; some distributions have not shipped one yet.", "Restart the services that use the package and re-scan to confirm the finding moves to FIXED."],
  "n2s_rem_other": ["Update the product that bundles Brotli to its fixed release (e.g. Bun 1.4.4; Envoy 1.40.0 / 1.39.3 / 1.38.6 / 1.37.8; Istio 1.29.9 / 1.30.6 / 1.31.2).", "Where no update is available yet, apply the mitigations below.", "Re-scan to confirm the finding moves to FIXED."],
  "n2s_mit": ["Reject inbound requests whose Content-Encoding contains <code>br</code> at the proxy, WAF or middleware.", "For outbound calls, drop <code>br</code> from Accept-Encoding and reject Brotli responses before decoding — changing the header alone is not enough.", "Express / body-parser: <code>inflate: false</code> rejects encoded request bodies (inbound only; fetched responses are not covered).", "Envoy / Istio: remove the Brotli decompressor filter if configured; curl: drop <code>--compressed</code>.", "Python: uninstall Brotli / brotlicffi only as a last resort (servers that send Brotli may then fail)."],
  "n2s_limits": ["Node2Shell status comes from the installed Node.js / Brotli version; it does not show whether the service actually decodes attacker-controlled Brotli, so a version match can overstate real exposure.", "Software that statically bundles Brotli (curl, Bun, Envoy, Istio, desktop apps) may not be found by version checks."],
  "export": "Export",
  "ctx_risk_h": "Business risk",
  "ctx_asks_h": "Decisions and asks",
  "ctx_risk": "Unauthenticated attackers can run code on a vulnerable PHP server with a single request. Typical impact is full compromise of the web tier: data theft, ransomware staging and a foothold for lateral movement. Public exploitation began at disclosure, so the window between scan and patch is the exposure the business carries.",
  "ctx_asks": [["Confirm scan coverage.", "Check that credentialed Nessus and Web App Scanning have covered the web estate since 21 October with current plugins. An empty result can mean no PHP, or assets that were never scanned or have aged out of the inventory."], ["Reduce exposure while patching.", "Apply the interim settings below and WAF rules on internet-facing PHP; they lower risk but do not remove it."]],
  "php_h": "PHP2Shell (CVE-2026-109618 / CVE-2026-109619)",
  "sections": "Sections by CVE",
  "tabs_hint": "One section per CVE. Pick a section above; each has its own summary, SLA, KPIs, run comparison, history, plugins, tracker and findings. The PDF prints both.",
  "not_collected": "Not collected",
  "n2s_why": "Not a PHP vulnerability: Node2Shell was disclosed the same day as PHP2Shell but is measured here on its own — Node.js, Brotli and Python Brotli versions against their own fixed releases — and never changes the PHP2Shell numbers.",
  "n2s_over": {"hs_assets": "Assets running Node.js / Brotli", "c_target": "Target version", "vb_eol_d": "Running Node.js 20.x or older, 23.x or 25.x: end-of-life, Node.js will not fix it — move to 22, 24 or 26.", "vb_backport_d": "Vulnerable through an OS-vendor brotli / nodejs package: the fix arrives as a backported package, so the version string alone cannot confirm it.", "vb_patch_d": "Vulnerable and a fix exists: Node.js 22.23.4 / 24.22.1 / 26.12.1, Brotli 1.0.10 / 1.1.1 / 1.2.1, Python Brotli 1.2.1, a vendor release of the bundling product, or an image rebuild.", "vb_unknown_d": "No Node.js / Brotli version could be read and no open finding decides it — verify on the host.", "vb_na_d": "Brotli older than 1.0.3, or a version outside the affected range.", "ctx_risk": "Unauthenticated attackers can corrupt memory and potentially run code on a vulnerable Node.js server or any service that decodes Brotli, with crafted compressed data. Worst-case impact is full compromise of the affected service — APIs, Python services and proxies such as Envoy and Istio: data theft, ransomware staging and a foothold for lateral movement. Public proof-of-concept code appeared at disclosure, so the window between scan and patch is the exposure the business carries.", "ctx_asks": [["Confirm scan coverage.", "Check that credentialed Nessus and container image scanning have covered the Node.js and Brotli estate since 21 October with current plugins. An empty result can mean no affected runtime, or assets that were never scanned or have aged out of the inventory."], ["Reduce exposure while patching.", "Apply the interim mitigations below and reject Brotli-encoded (br) requests at the proxy or WAF on internet-facing services; they lower risk but do not remove it."]], "k_php": "Assets with Node2Shell findings", "k_unscanned": "Assets not scanned since disclosure", "c_ver": "Installed version", "c_vstatus": "Target version", "verdict_CRITICAL": "{open} open Node2Shell findings on {exposed} assets, {breached} already past the {n}-day SLA.", "verdict_HIGH": "{exposed} assets are still exposed to Node2Shell; none past the {n}-day SLA yet.", "verdict_GUARDED": "No confirmed Node2Shell exposure, but some assets have an unknown version or were not scanned since disclosure.", "verdict_CONTROLLED": "No open Node2Shell exposure, and every affected asset has been assessed since disclosure.", "biz": "Node2Shell (CVE-2026-111497) is an out-of-bounds write in the Google Brotli decoder (1.0.3 to 1.2.0) that a remote, unauthenticated attacker can trigger with a crafted Brotli stream, with possible remote code execution. It reaches Node.js (bundled Brotli), Python Brotli / brotlicffi, libbrotli and software that bundles it (curl, Bun, Envoy, Istio): an exposed service can crash, leak memory or, at worst, be taken over.", "ask_patch": "Upgrade the {exposed} exposed assets to Node.js 22.23.4 / 24.22.1 / 26.12.1 or Brotli 1.0.10 / 1.1.1 / 1.2.1 (Python Brotli 1.2.1), with interim mitigations until then.", "ask_unscanned": "Re-scan the {unscanned} assets not assessed since {d} — a coverage gap, not a clean bill.", "ask_unknown": "Verify the Node.js / Brotli version on {unknown} assets with unknown status.", "sla_src_default": "{n} days is this skill's default, set for PHP2Shell and applied here so both exposures are measured alike. Node2Shell is a pre-authentication, remotely triggerable flaw with a CVSS 4.0 score of 9.2 and public proof-of-concept code; as of 23 Oct 2026 no in-the-wild exploitation was reported and it was not in CISA KEV.", "sla_clock": ["The clock starts at the later of two dates: the public disclosure ({d}) and the finding's first-seen date in Tenable.", "A finding first seen before disclosure (for example by a generic Node.js version plugin) starts on {d}: nobody could remediate Node2Shell before it was public.", "A finding first seen after disclosure starts on its first-seen date: the asset was new, newly scanned or newly vulnerable.", "If Tenable returned no first-seen date, the clock starts at disclosure and the tracker shows \"No first-seen date\"."], "pl_note": "Every plugin Tenable maps to CVE-2026-111497, discovered by CVE on this run. Vulnerable = findings still ACTIVE/RESURFACED; Fixed = findings in state FIXED. A plugin with no findings has not fired in this tenant — not proof of safety if the assets were not scanned since disclosure.", "mit_none": "Not required: this plugin has no findings. Apply only on assets not scanned since disclosure.", "mitig": "Interim mitigations for Node2Shell (reduce exposure, not a fix)"},
 },
 "pt": {
  "title": "PHP2Shell e Node2Shell — Tracker de Exposição e Remediação",
  "executed": "Executado em", "run": "Execução", "version": "Versão da skill", "sla": "SLA",
  "days": "dias", "disclosure": "Divulgação", "exec_summary": "Resumo executivo",
  "decisions": "Decisões e pedidos", "kpis": "Indicadores-chave",
  "k_php": "Ativos com PHP", "k_exposed": "Ativos expostos", "k_open": "Findings abertos",
  "k_rem": "Findings remediados", "k_rate": "Taxa de remediação", "k_mttr": "Tempo médio de remediação",
  "k_breach": "Findings fora do SLA", "k_unscanned": "Ativos PHP sem scan desde a divulgação",
  "compare": "Comparação entre execuções", "compare_with": "Comparar esta execução com",
  "no_prev": "Esta é a primeira execução registrada. As próximas serão comparadas com ela.",
  "new": "Novos", "fixed_since": "Remediados desde então", "regressed": "Regrediram",
  "still_open": "Ainda abertos", "gone": "Não reportados mais",
  "gone_note": "\"Não reportados mais\" significa que o finding não aparece nos dados desta execução; não é prova de correção (o ativo pode estar sem scan ou desativado).",
  "ver_mismatch": "Estas execuções foram geradas por versões diferentes da skill ({a} → {b}). Consulte o CHANGELOG da skill antes de ler os deltas.",
  "sla_mismatch": "Estas execuções usaram SLAs diferentes ({a} → {b} dias); números baseados em SLA não são comparáveis diretamente.",
  "demo_mismatch": "Uma destas execuções é uma demo rotulada; não misture dados de demo e reais.",
  "history": "Histórico de execuções", "h_when": "Executado em", "h_run": "ID da execução", "h_ver": "Versão",
  "h_posture": "Postura", "h_open": "Abertos", "h_rem": "Remediados", "h_rate": "Taxa",
  "h_breach": "Fora do SLA", "h_assets": "Ativos expostos", "trend": "Findings abertos vs remediados por execução",
  "chart": "Abertos vs remediados", "timeline": "Linha do tempo diária desde a divulgação",
  "no_dates": "O Tenable não retornou datas de first seen / fixed nesta execução, então a linha do tempo diária não pode ser desenhada. As contagens acima continuam corretas.",
  "tracker": "Tracker de remediação", "findings": "Todos os findings", "search": "Filtrar…",
  "c_asset": "Ativo", "c_ip": "IP", "c_src": "Fonte", "c_plugin": "Plugin", "c_ver": "Versão do PHP",
  "c_vstatus": "Status da versão", "c_state": "Estado", "c_first": "First seen", "c_due": "Prazo SLA",
  "c_fixed": "Corrigido", "c_daysopen": "Dias aberto", "c_outcome": "Resultado SLA", "c_last": "Last seen",
  "c_vpr": "VPR", "c_acr": "ACR", "c_aes": "AES",
  "sc_note": "VPR = Vulnerability Priority Rating do plugin na Tenable (0–10). ACR = Asset Criticality Rating (1–10) e AES = Asset Exposure Score (0–1000), ambos do Tenable One para o asset no momento da execução. “—” = a Tenable não retornou valor.",
  "sc_missing": "A Tenable não retornou {what} nesta execução; essas colunas mostram “—”.",
  "c_role": "Papel", "c_change": "Mudança",
  "mitig": "Mitigações temporárias (reduzem a exposição, não corrigem)",
  "limits": "Limitações conhecidas", "sources": "Fontes",
  "readonly": "Relatório somente leitura gerado a partir de dados do Tenable. Nenhum scan, tag ou configuração foi alterado.",
  "no_first": "Sem data de first seen", "met": "Cumprido", "missed": "Não cumprido",
  "breached": "Estourado em {n} d", "due_in": "Vence em {n} d", "due_today": "Vence hoje",
  "st_vulnerable": "Vulnerável", "st_patched": "Corrigido", "st_eol": "Branch EOL – vulnerável",
  "st_unknown": "Desconhecido – verificar", "open": "Aberto", "remediated": "Remediado",
  "p_CRITICAL": "CRÍTICA", "p_HIGH": "ALTA", "p_GUARDED": "ATENÇÃO", "p_CONTROLLED": "CONTROLADA",
  "plugins": "Plugins aplicáveis por CVE", "pl_total": "Plugins aplicáveis",
  "pl_for": "Plugins para {cve}", "pl_open": "Plugins com findings vulneráveis",
  "pl_fixed": "Plugins só com findings corrigidos", "pl_none": "Plugins sem findings",
  "pl_all": "Todas as CVEs", "pl_any": "Qualquer status", "c_cves": "CVEs", "c_product": "Produto",
  "c_family": "Família", "c_vuln_n": "Findings vulneráveis", "c_fixed_n": "Findings corrigidos", "c_assets_n": "Ativos",
  "c_pstatus": "Status do plugin", "c_name": "Nome",
  "ps_vulnerable": "Vulnerável", "ps_fixed": "Só corrigidos", "ps_none": "Sem findings",
  "pl_note": "Todos os plugins que o Tenable associa às CVEs do PHP2Shell, descobertos por CVE nesta execução. Vulneráveis = findings ainda ACTIVE/RESURFACED; Corrigidos = findings em estado FIXED. Plugin sem findings não disparou neste tenant — não é prova de segurança se os ativos não tiveram scan desde a divulgação.",
  "pl_nocat": "Nenhum catálogo de plugins foi fornecido nesta execução; só aparecem plugins que retornaram findings, e plugins com zero resultados ficam de fora.",
  "pl_extra": "Visto nos findings, mas não retornado pela busca de plugins por CVE",
  "pl_unmatched": "{n} finding(s) vulnerável(is) não puderam ser associados a um plugin ID e não entram nesta tabela.",
  "inv_plugins": "Plugins de inventário (fonte da versão do PHP, não específicos da CVE)",
  "disc_h_first": "Histórico de remediação — primeira execução",
  "disc_h_next": "Histórico de remediação — comparação com execuções anteriores",
  "disc_first_stat": "Esta é a primeira execução registrada do tracker de PHP2Shell, então este relatório é o ponto de partida (baseline) do histórico de remediação. Ainda não há comparação com uma execução anterior.",
  "disc_first_what_h": "O que o histórico vai mostrar a partir da próxima execução",
  "disc_first_what": ["Os findings, o status dos ativos e os KPIs desta execução foram gravados no histórico de execuções ({json}, também embutido neste {html}).",
    "Cada execução seguinte é comparada com esta e mostra quais findings são Novos, Remediados desde então, Regrediram, Ainda abertos ou Não reportados mais, com os ativos e plugins de cada cenário.",
    "Os KPIs mostram a variação desde a execução anterior, e a tabela de histórico e o gráfico de tendência crescem a cada execução.",
    "É possível escolher qualquer execução anterior como referência da comparação, não só a anterior."],
  "disc_first_how_h": "Como executar da próxima vez",
  "disc_first_how": ["Guarde este {html} (ou o {json}) — ele é o histórico. Cada execução grava seus próprios arquivos com data e hora no nome, então execuções anteriores nunca são sobrescritas. Ele não depende desta conversa.",
    "Mesma conversa: basta pedir para executar o tracker de PHP2Shell de novo; o histórico é recuperado automaticamente.",
    "Nova conversa: anexe o report_*.html ou history_*.json mais recente (a data e hora no nome mostram qual é o mais novo), ou conecte a pasta do seu computador que contém php2shell-reports/ — o tracker encontra sozinho a execução mais recente.",
    "Use o mesmo SLA ({n} dias nesta execução) e deixe o tracker nomear os ativos por hostname, para que os findings coincidam entre execuções.",
    "Se a próxima execução não receber o histórico, ela vira outra primeira execução e não consegue mostrar o que mudou desde esta."],
  "disc_next_stat1": "Esta execução é comparada com 1 execução anterior, de {last}, carregada do histórico de execuções.",
  "disc_next_stat": "Esta execução é comparada com um histórico de {n} execuções anteriores, de {first} a {last}. A mais recente é a referência padrão; qualquer uma pode ser escolhida em Comparação entre execuções.",
  "disc_src": "Origem do histórico: {src}.", "src_ledger": "arquivo de histórico no workspace", "src_import": "importado de {f}",
  "disc_why_h": "Por que o arquivo de histórico é necessário para a comparação",
  "disc_why": ["O Tenable reporta o estado atual de cada finding. Ele não guarda o que este tracker reportou em datas anteriores, quais ativos estavam abertos numa execução anterior, nem quais findings deixaram de aparecer.",
    "Essa visão anterior existe só no arquivo de histórico: cada execução grava o status aberto / remediado de cada finding (ativo + plugin), o status dos ativos e os KPIs.",
    "A comparação — Novos, Remediados desde então, Regrediram, Ainda abertos, Não reportados mais, variação dos KPIs e tendência — é calculada cruzando esta execução com esse status gravado. Sem o arquivo, esses números não podem ser reconstruídos.",
    "Esta execução acabou de ser adicionada ao histórico. Para a próxima, forneça o histórico mais recente: este {html} ou o {json} (ou a pasta php2shell-reports/ conectada, onde o latest.json aponta para a execução mais recente). Um arquivo mais antigo deixaria de fora as execuções posteriores a ele."],
  "disc_keep_h": "Para comparações equivalentes",
  "disc_keep": ["Mantenha o mesmo SLA ({n} dias nesta execução); SLA diferente é sinalizado e os números fora do SLA deixam de ser comparáveis.",
    "Mantenha o nome dos ativos estável (hostname): ativos renomeados ou com novo IP aparecem como Novos / Não reportados mais.",
    "\"Não reportados mais\" não é prova de correção — o ativo pode não ter tido scan.",
    "O detalhe completo dos findings é mantido para as {m} execuções mais recentes; as mais antigas guardam só os KPIs."],
  "trk_click": "Clique em um finding aberto (ou pressione Enter) para ver os detalhes do plugin: passos de remediação e mitigação e todos os ativos com findings vulneráveis ou corrigidos desse plugin. Este ativo fica destacado.",
  "cmp_total": "{n} mudanças de findings em relação à execução de referência",
  "cmp_click": "Clique em um cenário para ver os ativos e plugins por trás dele.",
  "cmp_all": "Todas as mudanças", "by_asset": "Por ativo", "by_plugin": "Por plugin",
  "c_plugins": "Plugins", "c_findings": "Findings", "c_assets": "Ativos", "scn_empty": "Nenhum finding neste cenário.",
  "new_d": "Vulnerável agora e ausente na execução de referência: detectado agora, com scan recente ou que ficou vulnerável.",
  "fixed_since_d": "Aberto na execução de referência e FIXED agora: remediação confirmada pelo Tenable.",
  "regressed_d": "FIXED na execução de referência e aberto de novo agora (ex.: RESURFACED): a correção não se manteve ou foi revertida.",
  "still_open_d": "Aberto nas duas execuções: o backlog de remediação que continua.",
  "gone_d": "Aberto na execução de referência e ausente agora. Não é prova de correção — o ativo pode estar sem scan, offline ou desativado; verificar antes de encerrar.",
  "all_d": "Todos os findings que mudaram ou continuaram abertos entre as duas execuções.",
  "sla_h": "Base e cálculo do SLA",
  "sla_intro": "Cada finding vulnerável deste relatório é medido contra um SLA de remediação de {n} dias. Esta seção explica de onde vem esse número e como cada data e resultado do tracker é calculado, para que os números possam ser auditados e reproduzidos.",
  "sla_src_h": "De onde vem o SLA",
  "sla_src_default": "{n} dias é o padrão desta skill para o PHP2Shell. A CVE-2026-109618 / CVE-2026-109619 é uma execução remota de código pré-autenticação com exploração ativa reportada, o que a coloca no nível mais alto das políticas de remediação usuais (prazos do catálogo KEV da CISA BOD 22-01, patching crítico do PCI DSS, SLAs internos para severidade crítica).",
  "sla_src_user": "{n} dias foi definido para esta execução pelo solicitante, conforme a política de remediação da organização.",
  "sla_src_ref": "Referência da política: {ref}",
  "sla_clock_h": "Quando o relógio começa",
  "sla_clock": ["O relógio começa na mais tardia de duas datas: a divulgação pública ({d}) e o first seen do finding no Tenable.",
    "Finding com first seen anterior à divulgação (por exemplo, de um plugin genérico de versão do PHP) começa em {d}: ninguém poderia remediar o PHP2Shell antes de ele ser público.",
    "Finding com first seen posterior à divulgação começa no próprio first seen: o ativo é novo, teve scan recente ou ficou vulnerável depois.",
    "Se o Tenable não retornou first seen, o relógio começa na divulgação e o tracker mostra \"Sem data de first seen\"."],
  "sla_formula_h": "Fórmulas",
  "sla_f": ["Início do relógio = max(first seen, divulgação)", "Prazo SLA = início do relógio + {n} dias",
    "Dias aberto (finding aberto) = hoje − first seen", "Dias aberto (finding corrigido) = data de correção − first seen",
    "Tempo médio de remediação = média dos dias aberto dos findings corrigidos com as duas datas"],
  "sla_out_h": "Como os resultados são atribuídos",
  "sla_out": [["Vence em N d / Vence hoje", "Finding aberto, hoje é anterior ou igual ao prazo SLA."],
    ["Estourado em N d", "Finding aberto, hoje já passou do prazo SLA. Entra em “Findings fora do SLA” e leva à postura CRÍTICA."],
    ["Cumprido", "Finding corrigido com data de correção até o prazo SLA."],
    ["Não cumprido", "Finding corrigido após o prazo SLA."],
    ["—", "Finding corrigido sem data de correção no Tenable: o resultado não pode ser avaliado e fica em branco."]],
  "sla_data_h": "Dados por trás das datas",
  "sla_data": ["O estado do finding (ACTIVE, RESURFACED, FIXED) vem dos findings do Tenable One; ACTIVE e RESURFACED contam como abertos.",
    "As datas de first seen e de correção vêm do export de Workbenches do Tenable VM (first discovered / last fixed), cruzadas por ativo e plugin.",
    "Um finding RESURFACED mantém o first seen original, então uma regressão continua medida contra o prazo original.",
    "\"Hoje\" é a data de execução desta rodada ({t}). As datas são dias corridos, não dias úteis."],
  "sla_now_h": "Esta execução frente ao SLA",
  "sla_sum": "SLA de {n} dias · o relógio começa na mais tardia entre a divulgação ({d}) e o first seen · {src}",
  "sla_sum_default": "padrão da skill", "sla_sum_user": "definido pelo solicitante",
  "sla_toggle": "Mostrar / ocultar como o SLA é calculado",
  "sla_now_intro": "Todos os findings vulneráveis desta execução, medidos contra o SLA de {n} dias (veja Base e cálculo do SLA para como cada resultado é atribuído).",
  "sla_now": ["Abertos, dentro do SLA", "Abertos, fora do SLA", "Corrigidos, SLA cumprido", "Corrigidos, SLA não cumprido", "Corrigidos, sem data de correção"],
  "sla_ex_h": "Exemplo",
  "sla_ex": "{a} (plugin {p}): first seen {fs} → relógio começa {cs} → prazo {due}. {state}",
  "sla_ex_open": "Ainda aberto em {t}: {o}.", "sla_ex_fixed": "Corrigido em {fx}: SLA {o}.",
  "sla_nodates": "O Tenable não retornou datas de first seen nesta execução, então todos os findings são medidos a partir da divulgação ({d}) e o tempo médio de remediação não pode ser calculado.",
  "sla_change": "Mantenha o mesmo SLA entre execuções: a comparação sinaliza baselines com SLA diferente, porque as contagens fora do SLA deixam de ser comparáveis.",
  "pl_click": "Clique em um plugin (ou pressione Enter) para ver quais ativos têm findings vulneráveis e corrigidos, com os passos de remediação e mitigação.",
  "pl_expand": "Expandir todos", "pl_collapse": "Recolher todos", "prod_all": "Todos os produtos",
  "d_vuln": "Ativos com findings vulneráveis ({n})", "d_fixed": "Ativos com findings corrigidos ({n})",
  "d_empty": "Nenhum ativo neste estado.", "d_synopsis": "Sinopse", "d_solution": "Solução do Tenable",
  "d_remed": "Passos de remediação", "d_mitig": "Passos de mitigação", "d_refs": "Referências",
  "c_fqdn": "FQDN", "c_port": "Porta", "c_target": "Versão alvo", "c_due_fixed": "Prazo SLA",
  "tgt_ok": "Já em release corrigido", "tgt_eol": "EOL – migrar para branch suportado",
  "tgt_unknown": "Verificar versão", "tgt_vendor": "Atualização do pacote do fornecedor", "tgt_none": "Sem correção do fornecedor",
  "tgt_image": "Reconstruir imagem", "k_upstream": "Upgrade do PHP upstream", "k_was": "Aplicação web (upgrade do PHP no servidor)",
  "k_distro": "Atualização de pacote do SO", "k_unpatched": "Sem correção do fornecedor – mitigar", "k_container": "Reconstrução da imagem de container",
  "rem_upstream": ["Atualizar o PHP de cada ativo para o release corrigido do seu branch: 8.5.12, 8.4.27, 8.3.36 ou 8.2.35 (ver Versão alvo por ativo).",
    "Branches anteriores ao 8.2 são EOL e não recebem correção: migrar para um branch suportado.",
    "Reiniciar PHP-FPM, Apache mod_php e todos os workers PHP para carregar o binário corrigido.",
    "Executar novo scan credenciado para confirmar que o finding passa para FIXED."],
  "rem_was": ["Atualizar o PHP do servidor por trás da aplicação web para 8.5.12, 8.4.27, 8.3.36 ou 8.2.35 (branches anteriores ao 8.2 devem migrar para um branch suportado).",
    "Reiniciar PHP-FPM / mod_php e todos os workers PHP, e limpar caches de proxy reverso que fixem o banner antigo.",
    "Se a aplicação estiver exposta à internet, manter as regras de WAF abaixo até o re-scan ficar limpo.",
    "Executar novamente o scan do Tenable Web App Scanning da aplicação para confirmar que o finding passa para FIXED."],
  "rem_distro": ["Aplicar a atualização do pacote PHP do fornecedor do SO (apt / dnf / yum / zypper), não um build upstream: o fornecedor faz backport da correção, então a versão pode continuar abaixo de 8.x.y.",
    "Consultar o advisory do fornecedor nas referências do plugin para a versão exata do pacote corrigido.",
    "Reiniciar todos os workers PHP após a atualização.",
    "Executar novo scan credenciado para confirmar que o finding passa para FIXED."],
  "rem_unpatched": ["O fornecedor do SO ainda não publicou pacote corrigido; o Tenable marca o pacote instalado como afetado.",
    "Aplicar agora os passos de mitigação abaixo — são o controle principal até existir correção.",
    "Se o risco não for aceitável, substituir o pacote da distro por um release PHP upstream corrigido, ou isolar o ativo de redes não confiáveis.",
    "Acompanhar o advisory do fornecedor; atualizar o pacote e refazer o scan assim que a correção sair."],
  "rem_container": ["Reconstruir a imagem sobre uma imagem base ou pacote php que contenha a correção (8.5.12, 8.4.27, 8.3.36, 8.2.35 ou o pacote corrigido da distro).",
    "Refazer o deploy de todas as cargas a partir da nova imagem — corrigir um container em execução não persiste.",
    "Refazer o scan da imagem / registry para confirmar que o finding passa para FIXED."],
  "mit_items": ["php.ini: <code>memory_limit=-1</code>", "php.ini: <code>session.upload_progress.enabled=0</code>",
    "php.ini: <code>fatal_error_backtraces=0</code> (somente PHP 8.5)", "Reiniciar todos os workers PHP após alterar o php.ini.",
    "Regras de WAF à frente de PHP exposto à internet; restringir o acesso aos serviços afetados quando possível."],
  "mit_open": "Aplicável: este plugin ainda tem findings vulneráveis. Aplicar nesses ativos até a remediação — mitigações reduzem a exposição, mas não corrigem.",
  "mit_primary": "Aplicável e principal: ainda não há correção do fornecedor, então estas configurações são o controle principal.",
  "mit_fixed": "Não necessária para estes ativos: todos os findings deste plugin estão FIXED. Manter só onde o re-scan ainda está pendente.",
  "mit_none": "Não necessária: este plugin não tem findings. Aplicar apenas em ativos PHP sem scan desde a divulgação.",
  "mit_no85": "A configuração exclusiva do 8.5 não se aplica às versões reportadas para este plugin.",
  "html_lang": "pt-BR",
  "verdict_CRITICAL": "{open} findings PHP2Shell abertos em {exposed} ativos, {breached} já fora do SLA de {n} dias.",
  "verdict_HIGH": "{exposed} ativos ainda expostos ao PHP2Shell; nenhum finding fora do SLA de {n} dias até agora.",
  "verdict_GUARDED": "Nenhuma exposição confirmada, mas há ativos PHP sem versão conhecida ou sem scan desde a divulgação.",
  "verdict_CONTROLLED": "Nenhuma exposição aberta ao PHP2Shell e todos os ativos PHP foram avaliados desde a divulgação.",
  "biz": "PHP2Shell (CVE-2026-109618 / CVE-2026-109619) é uma execução remota de código pré-autenticação com exploração ativa reportada. Um servidor PHP exposto pode ser assumido sem credenciais, levando a vazamento de dados, ransomware e movimentação lateral.",
  "ask_breached": "Escalar os {breached} findings fora do SLA de {n} dias para os owners hoje.",
  "ask_patch": "Aplicar PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 nos {exposed} ativos expostos e mitigações temporárias até o patch.",
  "ask_unscanned": "Re-scan dos {unscanned} ativos PHP sem avaliação desde {d} — lacuna de cobertura, não segurança.",
  "ask_unknown": "Verificar a versão do PHP em {unknown} ativos com status desconhecido.",
  "ask_nodates": "Datas de first seen/fixed indisponíveis: SLA calculado a partir da divulgação.",
  "ask_none": "Manter monitoramento; nenhuma ação adicional necessária.",
  "mttr_vs_sla": "SLA {n} dias",
  "mttr_within": "dentro do SLA",
  "mttr_over": "acima do SLA",
  "mitig_restart": "Reiniciar todos os workers PHP; regras de WAF em PHP exposto à internet.",
  "limits_list": ["Status vem só da versão do PHP; backports de distro (Ubuntu, RHEL) podem aparecer como vulneráveis já corrigidos — consulte os advisories do fornecedor.", "Plugins WAS publicados em 21/10/2026; scans anteriores não detectam PHP2Shell — vazio em ativo sem scan recente é não avaliado, não limpo.", "\"Não reportados mais\" na comparação não comprova correção."],
  "kpi_only": "A baseline guardou apenas os KPIs (mais antiga que a janela de detalhe).",
  "n2s_h": "Node2Shell (CVE-2026-111497)",
  "n2s_status": "Situação em 23/10/2026: CVSS 4.0 9,2 (Google, CNA); nenhuma exploração ativa reportada e fora do catálogo KEV da CISA; existe código de prova de conceito público. Um serviço só fica exposto se ele, ou uma biblioteca que usa, decodifica dados Brotli controlados pelo atacante.",
  "n2s_none": "Nenhum dado de Node2Shell foi coletado nesta execução, por isso esta seção está vazia. Isso não é evidência de que nenhum ativo esteja afetado.",
  "dd_hint": "Clique em qualquer bloco — aqui, em Ativos por status de versão ou na faixa abaixo do resumo executivo — para ver os ativos e findings por trás dele.",
  "dd_asset1": "{n} ativo",
  "dd_finding1": "{n} finding",
  "dd_close": "Fechar",
  "dd_assets": "{n} ativos",
  "dd_findings": "{n} findings",
  "dd_empty": "Nada neste bloco.",
  "dd_nofind": "Nenhum finding vulnerável",
  "dd_unscanned": "sem scan desde a divulgação",
  "c_vgroup": "Grupo de versão",
  "c_astatus": "Status do ativo",
  "c_open_n": "Findings abertos",
  "as_open": "Findings abertos",
  "as_at_risk": "Versão vulnerável, sem finding aberto",
  "as_remediated": "Remediado",
  "as_patched": "Corrigido",
  "as_unknown": "Desconhecido",
  "hs_assets": "Ativos com PHP",
  "hs_confirmed": "Vulneráveis confirmados",
  "hs_unassessed": "Sem avaliação desde a divulgação",
  "hs_open": "Findings abertos",
  "hs_rem": "Remediados",
  "hs_rate": "Taxa de remediação",
  "hs_mttr": "Tempo médio de remediação",
  "hs_breach": "Abertos fora do SLA de {n} dias",
  "vb_h": "Ativos por status de versão",
  "vb_hint": "Cada ativo é contado uma vez, no primeiro grupo que se aplica da esquerda para a direita, então os seis somam os {n} ativos no escopo. Passe o mouse em um bloco para ver a definição.",
  "vb_eol": "Vulnerável – EOL",
  "vb_backport": "Vulnerável – só backport",
  "vb_patch": "Vulnerável – patch disponível",
  "vb_unknown": "Desconhecido – verificar",
  "vb_patched": "Corrigido",
  "vb_na": "Não afetado",
  "vb_eol_d": "Rodando um branch do PHP anterior ao 8.2: EOL, nenhuma correção será publicada — migrar para um branch suportado.",
  "vb_backport_d": "Vulnerável por um pacote PHP do fornecedor do SO (plugin de distro, ou ainda sem correção do fornecedor): a correção chega como pacote com backport, então só a versão não a confirma.",
  "vb_patch_d": "Vulnerável e existe correção upstream: PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, ou reconstrução da imagem para containers.",
  "vb_unknown_d": "PHP encontrado, mas a versão não pôde ser lida e nenhum finding aberto decide — verificar no host.",
  "vb_patched_d": "Em um release corrigido, ou todos os findings do ativo estão FIXED.",
  "vb_na_d": "Versão fora da faixa afetada.",
  "st_na": "Não afetado",
  "n2s_cmp_none": "Nenhuma execução anterior do histórico tem dados de Node2Shell; a próxima será comparada com esta.",
  "c_component": "Componente",
  "c_inst": "Versão instalada",
  "comp_nodejs": "Node.js",
  "comp_brotli": "Biblioteca Brotli",
  "comp_python": "Brotli / brotlicffi do Python",
  "comp_container": "Imagem de container",
  "n2s_rem_container": ["Reconstruir a imagem sobre uma imagem base com Node.js 22.23.4 / 24.22.1 / 26.12.1 ou Brotli 1.0.10 / 1.1.1 / 1.2.1 (ou o pacote corrigido da distro).", "Refazer o deploy de todas as cargas a partir da nova imagem — corrigir um container em execução não persiste.", "Refazer o scan da imagem / registry para confirmar que o finding passa para FIXED."],
  "comp_distro": "Pacote do SO",
  "comp_other": "Brotli embutido (outro software)",
  "n2s_tgt_eol": "EOL – migrar para Node.js 22, 24 ou 26",
  "n2s_tgt_na": "Não afetado (anterior a 1.0.3)",
  "n2s_rem_nodejs": ["Atualizar o Node.js para o release corrigido da sua linha: 22.23.4, 24.22.1 ou 26.12.1 — em servidores, imagens de container e serverless e runners de CI.", "As linhas 20.x e anteriores, 23.x e 25.x são EOL e não recebem correção: migrar para 22, 24 ou 26.", "Atualizar pacotes npm como o Express não corrige; é o runtime que precisa ser atualizado.", "Reiniciar todos os processos Node.js e refazer o scan para confirmar que o finding passa para FIXED."],
  "n2s_rem_brotli": ["Atualizar a biblioteca Brotli para 1.2.1, ou 1.1.1 / 1.0.10 nos branches antigos.", "Reconstruir ou atualizar softwares que embutem a libbrotli estaticamente (curl, Bun, Envoy, Istio) para o release corrigido.", "Reiniciar os serviços que carregam a biblioteca e refazer o scan para confirmar que o finding passa para FIXED."],
  "n2s_rem_python": ["Atualizar os pacotes Python Brotli para 1.2.1 e brotlicffi para 1.2.1.0 em todos os ambientes e imagens.", "Reiniciar os serviços Python e refazer o scan para confirmar que o finding passa para FIXED."],
  "n2s_rem_distro": ["Aplicar a atualização do pacote brotli / nodejs do fornecedor do SO (apt / dnf / yum / zypper); o fornecedor faz backport da correção, então a versão pode ficar abaixo do release upstream corrigido.", "Consultar o advisory do fornecedor nas referências do plugin para a versão exata do pacote corrigido; algumas distribuições ainda não publicaram.", "Reiniciar os serviços que usam o pacote e refazer o scan para confirmar que o finding passa para FIXED."],
  "n2s_rem_other": ["Atualizar o produto que embute o Brotli para o release corrigido (ex.: Bun 1.4.4; Envoy 1.40.0 / 1.39.3 / 1.38.6 / 1.37.8; Istio 1.29.9 / 1.30.6 / 1.31.2).", "Onde ainda não houver atualização, aplicar as mitigações abaixo.", "Refazer o scan para confirmar que o finding passa para FIXED."],
  "n2s_mit": ["Rejeitar requisições de entrada cujo Content-Encoding contenha <code>br</code> no proxy, WAF ou middleware.", "Em chamadas de saída, remover <code>br</code> do Accept-Encoding e rejeitar respostas Brotli antes de decodificar — mudar só o cabeçalho não basta.", "Express / body-parser: <code>inflate: false</code> rejeita corpos de requisição codificados (só entrada; respostas obtidas não são cobertas).", "Envoy / Istio: remover o filtro descompressor Brotli, se configurado; curl: remover <code>--compressed</code>.", "Python: desinstalar Brotli / brotlicffi só como último recurso (servidores que enviam Brotli podem passar a falhar)."],
  "n2s_limits": ["O status do Node2Shell vem da versão instalada do Node.js / Brotli; não mostra se o serviço realmente decodifica Brotli controlado pelo atacante, então a versão pode superestimar a exposição real.", "Softwares que embutem o Brotli estaticamente (curl, Bun, Envoy, Istio, apps desktop) podem não ser encontrados por checagem de versão."],
  "export": "Exportar",
  "ctx_risk_h": "Risco para o negócio",
  "ctx_asks_h": "Decisões e pedidos",
  "ctx_risk": "Atacantes sem autenticação podem executar código em um servidor PHP vulnerável com uma única requisição. O impacto típico é o comprometimento total da camada web: roubo de dados, preparação de ransomware e ponto de apoio para movimentação lateral. A exploração pública começou na divulgação, então a janela entre o scan e o patch é a exposição que o negócio carrega.",
  "ctx_asks": [["Confirmar a cobertura de scan.", "Verificar se o Nessus credenciado e o Web App Scanning cobriram o ambiente web desde 21 de outubro com plugins atualizados. Um resultado vazio pode significar ausência de PHP, ou ativos que nunca tiveram scan ou saíram do inventário por idade."], ["Reduzir a exposição enquanto o patch não sai.", "Aplicar as configurações temporárias abaixo e regras de WAF no PHP exposto à internet; elas reduzem o risco, mas não o eliminam."]],
  "php_h": "PHP2Shell (CVE-2026-109618 / CVE-2026-109619)",
  "sections": "Seções por CVE",
  "tabs_hint": "Uma seção por CVE. Escolha a seção acima; cada uma tem seu próprio resumo, SLA, KPIs, comparação entre execuções, histórico, plugins, tracker e findings. O PDF imprime as duas.",
  "not_collected": "Não coletado",
  "n2s_why": "Não é uma vulnerabilidade do PHP: o Node2Shell foi divulgado no mesmo dia do PHP2Shell, mas é medido aqui separadamente — versões de Node.js, Brotli e Brotli do Python contra seus próprios releases corrigidos — e nunca altera os números do PHP2Shell.",
  "n2s_over": {"hs_assets": "Ativos com Node.js / Brotli", "c_target": "Versão alvo", "vb_eol_d": "Rodando Node.js 20.x ou anterior, 23.x ou 25.x: EOL, o Node.js não vai corrigir — migrar para 22, 24 ou 26.", "vb_backport_d": "Vulnerável por um pacote brotli / nodejs do fornecedor do SO: a correção chega como pacote com backport, então só a versão não a confirma.", "vb_patch_d": "Vulnerável e existe correção: Node.js 22.23.4 / 24.22.1 / 26.12.1, Brotli 1.0.10 / 1.1.1 / 1.2.1, Brotli do Python 1.2.1, release do fornecedor do produto que embute, ou reconstrução da imagem.", "vb_unknown_d": "Nenhuma versão de Node.js / Brotli pôde ser lida e nenhum finding aberto decide — verificar no host.", "vb_na_d": "Brotli anterior a 1.0.3, ou versão fora da faixa afetada.", "ctx_risk": "Atacantes sem autenticação podem corromper a memória e potencialmente executar código em um servidor Node.js vulnerável ou em qualquer serviço que decodifique Brotli, com dados comprimidos manipulados. O impacto no pior caso é o comprometimento total do serviço afetado — APIs, serviços Python e proxies como Envoy e Istio: roubo de dados, preparação de ransomware e ponto de apoio para movimentação lateral. Código de prova de conceito público surgiu na divulgação, então a janela entre o scan e o patch é a exposição que o negócio carrega.", "ctx_asks": [["Confirmar a cobertura de scan.", "Verificar se o Nessus credenciado e o scan de imagens de container cobriram o ambiente com Node.js e Brotli desde 21 de outubro com plugins atualizados. Um resultado vazio pode significar ausência de runtime afetado, ou ativos que nunca tiveram scan ou saíram do inventário por idade."], ["Reduzir a exposição enquanto o patch não sai.", "Aplicar as mitigações temporárias abaixo e rejeitar requisições com codificação Brotli (br) no proxy ou WAF dos serviços expostos à internet; elas reduzem o risco, mas não o eliminam."]], "k_php": "Ativos com findings Node2Shell", "k_unscanned": "Ativos sem scan desde a divulgação", "c_ver": "Versão instalada", "c_vstatus": "Versão alvo", "verdict_CRITICAL": "{open} findings Node2Shell abertos em {exposed} ativos, {breached} já fora do SLA de {n} dias.", "verdict_HIGH": "{exposed} ativos ainda expostos ao Node2Shell; nenhum finding fora do SLA de {n} dias até agora.", "verdict_GUARDED": "Nenhuma exposição confirmada ao Node2Shell, mas há ativos sem versão conhecida ou sem scan desde a divulgação.", "verdict_CONTROLLED": "Nenhuma exposição aberta ao Node2Shell e todos os ativos afetados foram avaliados desde a divulgação.", "biz": "Node2Shell (CVE-2026-111497) é uma escrita fora dos limites no decodificador Brotli do Google (1.0.3 a 1.2.0) que um atacante remoto, sem autenticação, pode disparar com um fluxo Brotli manipulado, com possível execução remota de código. Atinge o Node.js (Brotli embutido), Brotli / brotlicffi do Python, a libbrotli e softwares que a embutem (curl, Bun, Envoy, Istio): um serviço exposto pode cair, vazar memória ou, no pior caso, ser assumido.", "ask_patch": "Atualizar os {exposed} ativos expostos para Node.js 22.23.4 / 24.22.1 / 26.12.1 ou Brotli 1.0.10 / 1.1.1 / 1.2.1 (Brotli do Python 1.2.1), com mitigações temporárias até lá.", "ask_unscanned": "Re-scan dos {unscanned} ativos sem avaliação desde {d} — lacuna de cobertura, não segurança.", "ask_unknown": "Verificar a versão do Node.js / Brotli em {unknown} ativos com status desconhecido.", "sla_src_default": "{n} dias é o padrão desta skill, definido para o PHP2Shell e aplicado aqui para que as duas exposições sejam medidas da mesma forma. O Node2Shell é uma falha pré-autenticação, disparável remotamente, com CVSS 4.0 9,2 e código de prova de conceito público; em 23/10/2026 não havia exploração ativa reportada e não estava no KEV da CISA.", "sla_clock": ["O relógio começa na mais tardia de duas datas: a divulgação pública ({d}) e o first seen do finding no Tenable.", "Finding com first seen anterior à divulgação (por exemplo, de um plugin genérico de versão do Node.js) começa em {d}: ninguém poderia remediar o Node2Shell antes de ele ser público.", "Finding com first seen posterior à divulgação começa no próprio first seen: o ativo é novo, teve scan recente ou ficou vulnerável depois.", "Se o Tenable não retornou first seen, o relógio começa na divulgação e o tracker mostra \"Sem data de first seen\"."], "pl_note": "Todos os plugins que o Tenable associa à CVE-2026-111497, descobertos por CVE nesta execução. Vulneráveis = findings ainda ACTIVE/RESURFACED; Corrigidos = findings em estado FIXED. Plugin sem findings não disparou neste tenant — não é prova de segurança se os ativos não tiveram scan desde a divulgação.", "mit_none": "Não necessária: este plugin não tem findings. Aplicar apenas em ativos sem scan desde a divulgação.", "mitig": "Mitigações temporárias do Node2Shell (reduzem a exposição, não corrigem)"},
 },
}


# ---------------------------------------------------------------- helpers
def pdate(s):
    if not s:
        return None
    s = str(s).strip()
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y", "%d/%m/%Y"):
        try:
            return datetime.strptime(s[:19] if "T" in s else s[:10], fmt).date()
        except ValueError:
            continue
    m = re.match(r"(\d{4}-\d{2}-\d{2})", s)
    return date.fromisoformat(m.group(1)) if m else None


def parse_version(v):
    if not v:
        return None
    found = [tuple(int(x) for x in m.groups()) for m in re.finditer(r"(\d+)\.(\d+)\.(\d+)", str(v))]
    return min(found) if found else None  # lowest when several are listed


def version_status(v):
    t = parse_version(v)
    if not t:
        return "unknown"
    branch = t[:2]
    if branch in FIXED:
        return "vulnerable" if t < FIXED[branch] else "patched"
    if branch < min(FIXED):
        return "eol"
    if branch > max(FIXED):
        return "na"  # newer than every affected branch
    return "unknown"


def esc(x):
    return html.escape("" if x is None else str(x))


# ---------------------------------------------------------------- VPR / ACR / AES
# VPR is per plugin (0-10); ACR (1-10) and AES (0-1000) are per asset, from Tenable One. Never estimated:
# a value Tenable did not return stays None and renders as "—".
SC_BANDS = {"vpr": ((9, "c"), (7, "h"), (4, "m"), (0, "l")),   # Tenable VPR: critical / high / medium / low
            "acr": ((9, "c"), (7, "h"), (4, "m"), (0, "l")),   # ACR 9-10 / 7-8 / 4-6 / 1-3
            "aes": ((650, "h"), (350, "m"), (0, "l"))}          # AES high / medium / low


def num(x):
    """A score as float, or None when Tenable gave nothing usable (blank, N/A, null)."""
    if x is None or isinstance(x, bool):
        return None
    if isinstance(x, dict):
        x = x.get("score", x.get("value"))
    s = str(x).strip()
    m = re.match(r"^-?\d+(?:\.\d+)?", s)
    return float(m.group(0)) if m else None


def fmt_score(x, kind):
    return "" if x is None else (f"{x:.1f}" if kind == "vpr" else str(int(round(x))))


def sc_html(x, kind):
    if x is None:
        return '<span class="muted">—</span>'
    band = next((b for lo, b in SC_BANDS[kind] if x >= lo), "l")
    return f'<span class="sc sc-{band}" title="{kind.upper()}">{fmt_score(x, kind)}</span>'


def sc_td(x, kind):
    return f'<td data-s="{-1 if x is None else x}">{sc_html(x, kind)}</td>'


def first_num(r, keys):
    for k in keys:
        v = num(r.get(k))
        if v is not None:
            return v
    return None


def enrich_scores(rows, catalog):
    """VPR on each row (its own value, else the plugin's from the catalog); ACR / AES on each row from
    whichever row of the same asset carries them. Returns which of the three Tenable returned at all."""
    cv = {p["plugin_id"]: p.get("vpr") for p in catalog or []}
    acr, aes = {}, {}
    for r in rows:
        a = r.get("asset") or r.get("ip") or "unknown"
        v = first_num(r, ("acr", "acr_score", "asset_criticality_rating"))
        if v is not None:
            acr.setdefault(a, v)
        v = first_num(r, ("aes", "aes_score", "exposure_score", "asset_exposure_score"))
        if v is not None:
            aes.setdefault(a, v)
    for r in rows:
        a = r.get("asset") or r.get("ip") or "unknown"
        v = first_num(r, ("vpr", "vpr_score"))
        r["vpr"] = v if v is not None else cv.get(str(r.get("plugin_id") or "").strip())
        r["acr"], r["aes"] = acr.get(a), aes.get(a)
    return {"vpr": any(r["vpr"] is not None for r in rows) or any(v is not None for v in cv.values()),
            "acr": bool(acr), "aes": bool(aes)}


def sc_missing_note(flags, keys, L):
    miss = [k.upper() for k in keys if not (flags or {}).get(k)]
    return f'<div class="note">{esc(safe_fmt(L["sc_missing"], what=" / ".join(miss)))}</div>' if miss else ""


def vpr_line(e, L):
    return f'<p class="mnote"><b>{esc(L["c_vpr"])}</b> {sc_html(e.get("vpr"), "vpr")}</p>'


def prod(x):
    """Normalise a source / product label to WAS, VM or Cloud."""
    x = str(x or "").strip()
    u = x.lower()
    if u in ("was", "tenable_was", "web app scanning", "webapp"):
        return "WAS"
    if u in ("vm", "nessus", "tenable_vm", ""):
        return "VM" if u else ""
    if u in ("cloud", "container", "cloud-security", "container-security", "cs", "cnapp"):
        return "Cloud"
    return x


def plugin_kind(e):
    """Which remediation path a plugin implies."""
    name, fam, pr = (e.get("name") or "").lower(), (e.get("family") or "").lower(), prod(e.get("product"))
    if "unpatched" in name:
        return "unpatched"
    if pr == "Cloud":
        return "container"
    if pr == "WAS":
        return "was"
    if "local security checks" in fam or re.match(r"^(ubuntu|debian|rhel|red hat|centos|oracle linux|alma|rocky|suse|opensuse|amazon linux|alpine|fedora)\b", name):
        return "distro"
    return "upstream"


def target_version(v, kind, L):
    if kind == "distro":
        return L["tgt_vendor"], "pending"
    if kind == "unpatched":
        return L["tgt_none"], "vulnerable"
    if kind == "container":
        return L["tgt_image"], "pending"
    t = parse_version(v)
    if not t:
        return L["tgt_unknown"], "unknown"
    br = t[:2]
    if br in FIXED:
        f = FIXED[br]
        return (L["tgt_ok"], "patched") if t >= f else (".".join(map(str, f)), "vulnerable")
    if br < min(FIXED):
        return L["tgt_eol"], "eol"
    return L["tgt_ok"], "patched"


def fkey(r):
    return f"{r.get('asset','')}|{r.get('plugin_id') or r.get('plugin_name','')}"


# ---------------------------------------------------------------- analysis
def analyse(rows, sla_days, today, disclosure=DISCLOSURE, vfn=None):
    """Generic for both tracks: vfn(row) gives the version status (PHP by default)."""
    asset_info = {}
    for r in rows:
        a = r.get("asset") or r.get("ip") or "unknown"
        r["asset"] = a
        ai = asset_info.setdefault(a, {"ip": r.get("ip", ""), "last_seen": None, "vstat": set(),
                                       "open": 0, "rem": 0, "acr": r.get("acr"), "aes": r.get("aes")})
        ls = pdate(r.get("last_seen"))
        if ls and (not ai["last_seen"] or ls > ai["last_seen"]):
            ai["last_seen"] = ls
        r["version_status"] = vfn(r) if vfn else version_status(r.get("php_version"))
        ai["vstat"].add(r["version_status"])

    vulns = []
    for r in rows:
        if r.get("role") != "vulnerable":
            continue
        state = (r.get("state") or "ACTIVE").upper()
        fs, fx = pdate(r.get("first_seen")), pdate(r.get("fixed_date"))
        start = max(fs, disclosure) if fs else disclosure
        due = start + timedelta(days=sla_days)
        rec = dict(r)
        rec.update(state=state, first_seen=fs, fixed=fx, due=due, key=fkey(r))
        if state == "FIXED":
            rec["status"] = "remediated"
            asset_info[r["asset"]]["rem"] += 1
            rec["days_open"] = (fx - fs).days if fs and fx else None
            rec["outcome"] = None if not fx else ("met" if fx <= due else "missed")
        else:
            rec["status"] = "open"
            asset_info[r["asset"]]["open"] += 1
            rec["days_open"] = (today - fs).days if fs else None
            rec["over"] = (today - due).days
            rec["outcome"] = "breached" if today > due else "pending"
        vulns.append(rec)

    for a, ai in asset_info.items():
        if ai["open"]:
            ai["status"] = "open"
        elif ai["vstat"] & {"vulnerable", "eol"}:
            ai["status"] = "at_risk"
        elif ai["rem"]:
            ai["status"] = "remediated"
        elif ai["vstat"] & {"patched", "na"}:
            ai["status"] = "patched"
        else:
            ai["status"] = "unknown"

    open_v = [v for v in vulns if v["status"] == "open"]
    rem_v = [v for v in vulns if v["status"] == "remediated"]
    breached = [v for v in open_v if v["outcome"] == "breached"]
    durations = [v["days_open"] for v in rem_v if v["days_open"] is not None]
    unscanned = [a for a, ai in asset_info.items() if not ai["last_seen"] or ai["last_seen"] < disclosure]
    exposed = [a for a, ai in asset_info.items() if ai["status"] in ("open", "at_risk")]
    unknown = [a for a, ai in asset_info.items() if ai["status"] == "unknown"]
    total = len(open_v) + len(rem_v)
    kpis = {
        "php_assets": len(asset_info), "exposed_assets": len(exposed), "open": len(open_v),
        "remediated": len(rem_v), "rate": round(100 * len(rem_v) / total, 1) if total else None,
        "mttr": round(statistics.mean(durations), 1) if durations else None,
        "breached": len(breached), "unscanned": len(unscanned), "unknown_assets": len(unknown),
        "missed_sla_fixed": sum(1 for v in rem_v if v["outcome"] == "missed"),
    }
    if open_v and breached:
        posture = "CRITICAL"
    elif open_v or exposed:
        posture = "HIGH"
    elif unknown or unscanned:
        posture = "GUARDED"
    else:
        posture = "CONTROLLED"
    dates_ok = any(v["first_seen"] for v in vulns)
    return dict(vulns=vulns, assets=asset_info, kpis=kpis, posture=posture, dates_ok=dates_ok,
                unscanned=unscanned, exposed=exposed, breached=breached, open_v=open_v)


def timeline(vulns, today, disclosure=DISCLOSURE):
    dated = [v for v in vulns if v["first_seen"]]
    if not dated:
        return []
    start = min(min(v["first_seen"] for v in dated), disclosure)
    start = max(start, disclosure - timedelta(days=30))
    out, d = [], start
    while d <= today:
        o = sum(1 for v in dated if v["first_seen"] <= d and not (v["fixed"] and v["fixed"] <= d))
        r = sum(1 for v in dated if v["fixed"] and v["fixed"] <= d)
        out.append((d, o, r))
        d += timedelta(days=1)
    return out


# ---------------------------------------------------------------- plugin coverage
def norm_cves(x):
    if not x:
        return []
    if isinstance(x, str):
        x = re.split(r"[,\s;]+", x)
    return sorted({str(c).strip().upper() for c in x if str(c).strip()})


def load_catalog(path):
    """plugins.json: list of {plugin_id, name, product, family, cves, role}."""
    if not path:
        return None
    data = json.loads(Path(path).read_text())
    if isinstance(data, dict):
        data = data.get("plugins", [])
    out = []
    for p in data:
        pid = str(p.get("plugin_id") or p.get("id") or "").strip()
        if pid:
            out.append({"plugin_id": pid, "name": p.get("name") or p.get("plugin_name") or "",
                        "product": p.get("product") or p.get("source") or "",
                        "family": p.get("family") or "", "cves": norm_cves(p.get("cves")),
                        "role": p.get("role") or ("inventory" if not p.get("cves") else "vulnerable"),
                        "plugin_type": p.get("plugin_type") or "", "component": p.get("component") or "",
                        "vpr": first_num(p, ("vpr", "vpr_score")),
                        "synopsis": p.get("synopsis") or "", "solution": p.get("solution") or "",
                        "see_also": [u for u in (p.get("see_also") or []) if isinstance(u, str)]
                                    if not isinstance(p.get("see_also"), str)
                                    else [u for u in re.split(r"\s+", p["see_also"]) if u]})
    return out


def plugin_coverage(catalog, rows, cves=CVES):
    cat = {}
    for p in catalog or []:
        cat[p["plugin_id"]] = dict(p, open=0, fixed=0, assets=set(), in_catalog=True)
    unmatched = 0
    for r in rows:
        if r.get("role") != "vulnerable":
            continue
        pid = str(r.get("plugin_id") or "").strip()
        if not pid:
            unmatched += 1
            continue
        e = cat.get(pid)
        if e is None:
            e = cat[pid] = {"plugin_id": pid, "name": r.get("plugin_name", ""), "product": r.get("source", ""),
                            "family": "", "cves": [], "role": "vulnerable", "open": 0, "fixed": 0,
                            "plugin_type": "", "synopsis": "", "solution": "", "see_also": [],
                            "vpr": None, "assets": set(), "in_catalog": False}
        if e.get("vpr") is None and r.get("vpr") is not None:
            e["vpr"] = r["vpr"]  # not in the catalog lookup: take it from the finding
        e["cves"] = sorted(set(e["cves"]) | set(norm_cves(r.get("cves"))))
        if (r.get("state") or "ACTIVE").upper() == "FIXED":
            e["fixed"] += 1
        else:
            e["open"] += 1
        e["assets"].add(r.get("asset") or r.get("ip") or "")
    plugins = [e for e in cat.values() if e["role"] != "inventory"]
    inventory = [e for e in cat.values() if e["role"] == "inventory"]
    for e in plugins:
        if not e["cves"]:
            e["cves"] = list(cves)  # came only from the CVE-filtered findings
        e["status"] = "vulnerable" if e["open"] else ("fixed" if e["fixed"] else "none")
    plugins.sort(key=lambda e: ({"vulnerable": 0, "fixed": 1, "none": 2}[e["status"]],
                                -(e["open"] + e["fixed"]), e["product"], e["plugin_id"]))
    by_cve = {c: sum(1 for e in plugins if c in e["cves"]) for c in sorted({c for e in plugins for c in e["cves"]} | set(cves))}
    summary = {"total": len(plugins), "by_cve": by_cve,
               "with_open": sum(1 for e in plugins if e["status"] == "vulnerable"),
               "fixed_only": sum(1 for e in plugins if e["status"] == "fixed"),
               "no_findings": sum(1 for e in plugins if e["status"] == "none"),
               "not_in_catalog": sum(1 for e in plugins if not e["in_catalog"]),
               "unmatched_rows": unmatched, "catalog": catalog is not None}
    return plugins, inventory, summary


# ---------------------------------------------------------------- Node2Shell (related, separate)
N2S_COMPONENTS = ("nodejs", "brotli", "python", "distro", "container", "other")
DISTRO_RE = re.compile(r"^(ubuntu|debian|rhel|red hat|centos|oracle linux|alma|rocky|suse|opensuse|amazon linux|alpine|fedora)\b")


def n2s_component(name, family="", given="", product=""):
    """Which product a Node2Shell plugin / finding is about (decides target version and remediation)."""
    g = str(given or "").strip().lower()
    if g in N2S_COMPONENTS:
        return g
    n, f = (name or "").lower(), (family or "").lower()
    if prod(product) == "Cloud":
        return "container"
    if "unpatched" in n or "local security checks" in f or DISTRO_RE.match(n):
        return "distro"
    if "node" in n:
        return "nodejs"
    if "brotlicffi" in n or "python" in n or "pypi" in n:
        return "python"
    if any(x in n for x in ("envoy", "istio", "curl", "bun ")):
        return "other"
    if "brotli" in n:
        return "brotli"
    return "other"


def n2s_target(comp, v, L):
    """(label, status) for an installed version of a Node2Shell component."""
    if comp in ("distro", "other"):
        return L["tgt_vendor"], "pending"
    if comp == "container":
        return L["tgt_image"], "pending"
    t = parse_version(v)
    if not t:
        return L["tgt_unknown"], "unknown"
    if comp == "nodejs":
        fx = N2S_FIXED["nodejs"].get((t[0],))
        if fx:
            return (L["tgt_ok"], "patched") if t >= fx else (".".join(map(str, fx)), "vulnerable")
        if N2S_NODE_EOL(t[0]):
            return L["n2s_tgt_eol"], "eol"
        return (L["tgt_ok"], "patched") if t[0] > 26 else (L["tgt_unknown"], "unknown")
    if t < (1, 0, 3):
        return L["n2s_tgt_na"], "na"
    table = N2S_FIXED["python" if comp == "python" else "brotli"]
    fx = table.get(t[:2])
    if fx:
        return (L["tgt_ok"], "patched") if t >= fx else (".".join(map(str, fx)), "vulnerable")
    if t > max(table.values()):
        return L["tgt_ok"], "patched"
    # python brotli < 1.2 has no separate fixed line: upgrade to 1.2.1
    return ((".".join(map(str, N2S_FIXED["python"][(1, 2)])), "vulnerable") if comp == "python"
            else (L["tgt_unknown"], "unknown"))


def n2s_detail(e, vulns, L, me=None):
    vs = sorted(vulns, key=lambda v: (-(v.get("over") or -999), v["asset"]))
    open_v = [v for v in vs if v["status"] == "open"]
    fix_v = [v for v in vs if v["status"] == "remediated"]
    tr = lambda v: '<tr class="me">' if me and v["asset"] == me else "<tr>"

    def row(v, is_open):
        cells = (f'<td>{esc(v["asset"])}</td><td>{esc(v.get("ip"))}</td><td>{esc(v.get("fqdn"))}</td>'
                 f'<td>{esc(prod(v.get("source")))}</td>' + sc_td(v.get("acr"), "acr") + sc_td(v.get("aes"), "aes")
                 + f'<td>{esc(L["comp_" + v["component"]])}</td>'
                 f'<td>{esc(v["version"] or "—")}</td>')
        if is_open:
            cells += (f'<td><span class="pill s-{v["tstatus"]}">{esc(v["target"])}</span></td><td>{esc(v["state"])}</td>'
                      f'<td>{esc(v["first_seen"] or L["no_first"])}</td><td>{esc(v["due"])}</td>')
        else:
            cells += f'<td>{esc(v["first_seen"] or L["no_first"])}</td><td>{esc(v["fixed"] or "")}</td>'
        return (tr(v) + cells + f'<td>{esc("" if v["days_open"] is None else v["days_open"])}</td>'
                + outcome_cell(v, L) + f'<td>{esc(v.get("last_seen"))}</td></tr>')

    base = ("c_asset", "c_ip", "c_fqdn", "c_src", "c_acr", "c_aes", "c_component", "c_inst")
    vh = "".join(f"<th>{esc(L[k])}</th>" for k in base + ("c_target", "c_state", "c_first", "c_due", "c_daysopen", "c_outcome", "c_last"))
    fh = "".join(f"<th>{esc(L[k])}</th>" for k in base + ("c_first", "c_fixed", "c_daysopen", "c_outcome", "c_last"))
    tbl = lambda h, rs: (f'<div class="tablewrap"><table class="sub"><thead><tr>{h}</tr></thead><tbody>{rs}</tbody></table></div>'
                         if rs else f'<p class="muted">{esc(L["d_empty"])}</p>')
    info = vpr_line(e, L) + (f'<p><b>{esc(L["d_synopsis"])}:</b> {esc(e["synopsis"])}</p>' if e.get("synopsis") else "") + \
           (f'<div class="sol"><b>{esc(L["d_solution"])}:</b> {esc(e["solution"])}</div>' if e.get("solution") else "")
    comp = e.get("component") or "other"
    remed = "<ol>" + "".join(f"<li>{esc(x)}</li>" for x in L["n2s_rem_" + comp]) + "</ol>"
    refs = ("" if not e.get("see_also") else f'<p style="font-size:12px"><b>{esc(L["d_refs"])}:</b> '
            + " · ".join(f'<a href="{esc(u)}" target="_blank" rel="noopener">{esc(u)}</a>' for u in e["see_also"][:6]) + "</p>")
    mnote, mcls = ((L["mit_open"], "s-pending") if open_v else (L["mit_fixed"], "s-fixed") if fix_v else (L["mit_none"], "s-none"))
    mit = "<ul>" + "".join(f"<li>{x}</li>" for x in L["n2s_mit"]) + "</ul>"
    return (f'<div class="detail-in"><div class="dgrid">'
            f'<div><h4>{esc(L["d_remed"])} <span class="kind">{esc(L["comp_" + comp])}</span></h4>{info}{remed}{refs}</div>'
            f'<div><h4>{esc(L["d_mitig"])}</h4><p class="mnote"><span class="pill {mcls}">●</span> {esc(mnote)}</p>{mit}</div></div>'
            f'<h4 class="dv">{esc(L["d_vuln"].format(n=len(open_v)))}</h4>{tbl(vh, "".join(row(v, True) for v in open_v))}'
            f'<h4 class="df">{esc(L["d_fixed"].format(n=len(fix_v)))}</h4>{tbl(fh, "".join(row(v, False) for v in fix_v))}</div>')


# ---------------------------------------------------------------- history ledger
EMBED_RE = re.compile(r'<script id="run-history" type="application/json">(.*?)</script>', re.S)


def safe_fmt(s, **kw):
    """str.format that leaves unknown {placeholders} alone (custom translations may lack or add some)."""
    class D(dict):
        def __missing__(self, k): return "{" + k + "}"
    try:
        return s.format_map(D(kw))
    except (ValueError, IndexError):
        return s


def stamp_of(executed_at):
    """2026-10-25T22:14:30Z -> 2026-10-25_221430Z (sortable, safe on every OS)."""
    return executed_at.replace(":", "").replace("T", "_")


HIST_GLOBS = ("history*.json", "report*.html", "report*.htm")


def history_candidates(paths, include_demo=False):
    """Every file under paths that carries a ledger: rolling history.json, history_<stamp>.json
    snapshots and report*.html (embedded ledger), legacy unstamped names included."""
    seen, out = set(), []
    for p in map(Path, paths):
        files = [p] if p.is_file() else [f for g in HIST_GLOBS for f in p.rglob(g)] if p.is_dir() else []
        for f in files:
            if not include_demo and ".demo" in f.name:
                continue
            k = f.resolve()
            if k not in seen:
                seen.add(k); out.append(f)
    return out


def rank_history(paths, include_demo=False):
    """Rank history files by the newest comparable run they contain (a run with finding detail),
    then by number of runs, then by the timestamp in the file name. Best first."""
    ranked = []
    for f in history_candidates(paths, include_demo):
        runs = [r for r in load_runs(f, quiet=True) if include_demo or not r.get("demo")]
        if not runs:
            continue
        comp = [r for r in runs if r.get("findings")]
        newest = max((r.get("executed_at", "") for r in comp), default="")
        ranked.append({"file": str(f), "newest_run": max(runs, key=lambda r: r.get("executed_at", ""))["run_id"],
                       "newest_comparable_at": newest, "runs": len(runs), "comparable_runs": len(comp),
                       "_k": (newest, len(runs), f.name)})
    ranked.sort(key=lambda x: x["_k"], reverse=True)
    for x in ranked:
        x.pop("_k")
    return ranked


def load_runs(path, quiet=False):
    p = Path(path)
    if p.is_dir():  # a folder: use the newest history under it
        best = rank_history([p])
        if not best:
            print(f"warn=no history found under {p}", file=sys.stderr)
            return []
        print(f"import_latest={best[0]['file']} newest_run={best[0]['newest_run']}")
        p = Path(best[0]["file"])
    if not p.exists():
        return []
    text = p.read_text(encoding="utf-8", errors="replace")
    if p.suffix.lower() in (".html", ".htm"):
        m = EMBED_RE.search(text)
        if not m:
            if not quiet:
                print(f"warn=no embedded history in {p}", file=sys.stderr)
            return []
        text = m.group(1).replace("<\\/", "</")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        if not quiet:
            print(f"warn=unreadable history {p}: {e}", file=sys.stderr)
        return []
    runs = data.get("runs", []) if isinstance(data, dict) else data
    return [r for r in runs if isinstance(r, dict) and r.get("run_id")]


def merge_runs(*lists):
    by_id = {}
    for lst in lists:
        for r in lst:
            old = by_id.get(r["run_id"])
            if not old or (r.get("findings") and not old.get("findings")):
                by_id[r["run_id"]] = r
    runs = sorted(by_id.values(), key=lambda r: r.get("executed_at", ""))
    for r in runs[:-MAX_DETAILED_RUNS]:
        for f in ("findings", "assets", "plugins", "plugin_meta", "asset_meta", "plugin_vpr", "asset_scores"):
            r.pop(f, None)
        if isinstance(r.get("n2s"), dict):
            for f in ("findings", "assets", "plugins", "plugin_meta", "asset_meta", "plugin_vpr", "asset_scores"):
                r["n2s"].pop(f, None)
    return runs


def compare(cur, base):
    cf, bf = cur.get("findings", {}), base.get("findings", {})
    res = {"new": [], "fixed_since": [], "regressed": [], "still_open": [], "gone": []}
    for k, s in cf.items():
        b = bf.get(k)
        if b is None:
            if s == "o":
                res["new"].append(k)
        elif b == "o" and s == "r":
            res["fixed_since"].append(k)
        elif b == "r" and s == "o":
            res["regressed"].append(k)
        elif b == "o" and s == "o":
            res["still_open"].append(k)
    for k, b in bf.items():
        if k not in cf and b == "o":
            res["gone"].append(k)
    return res


# ---------------------------------------------------------------- SVG charts
C = {"bg": "#44494B", "panel": "#3A3F41", "panel2": "#33383A", "line": "#5A6062", "text": "#F2F4F5",
     "muted": "#B9BEC0", "accent": "#E7FF00", "blue": "#4EA5FF", "green": "#71FFC6",
     "purple": "#BB8FF2", "orange": "#FF8837", "red": "#FF4B4B"}


def split_bar(open_n, rem_n, L):
    total = open_n + rem_n
    if not total:
        return f'<p class="muted">—</p>'
    w = 1000
    ow = round(w * open_n / total)
    return (f'<svg viewBox="0 0 {w} 64" class="chart" role="img" aria-label="{esc(L["chart"])}">'
            f'<rect x="0" y="8" width="{ow}" height="34" fill="{C["red"]}" rx="3"/>'
            f'<rect x="{ow}" y="8" width="{w-ow}" height="34" fill="{C["green"]}" rx="3"/>'
            f'<text x="6" y="60" fill="{C["text"]}" font-size="13">{esc(L["open"])}: {open_n}</text>'
            f'<text x="{w-6}" y="60" fill="{C["text"]}" font-size="13" text-anchor="end">'
            f'{esc(L["remediated"])}: {rem_n}</text></svg>')


def line_svg(series, labels, colors, names, height=220, marks=None):
    if not labels:
        return ""
    w, h, pl, pr, pt, pb = 1000, height, 44, 16, 14, 34
    ymax = max(1, max(max(s) for s in series))
    n = len(labels)
    def x(i): return pl + (w - pl - pr) * (i / (n - 1) if n > 1 else 0.5)
    def y(v): return pt + (h - pt - pb) * (1 - v / ymax)
    g = []
    for t in range(5):
        v = ymax * t / 4
        g.append(f'<line x1="{pl}" x2="{w-pr}" y1="{y(v):.1f}" y2="{y(v):.1f}" stroke="{C["line"]}" stroke-width="1"/>'
                 f'<text x="{pl-6}" y="{y(v)+4:.1f}" fill="{C["muted"]}" font-size="11" text-anchor="end">{v:.0f}</text>')
    step = max(1, n // 8)
    for i in range(0, n, step):
        g.append(f'<text x="{x(i):.1f}" y="{h-10}" fill="{C["muted"]}" font-size="11" text-anchor="middle">{esc(labels[i])}</text>')
    for s, col in zip(series, colors):
        pts = " ".join(f"{x(i):.1f},{y(v):.1f}" for i, v in enumerate(s))
        g.append(f'<polyline points="{pts}" fill="none" stroke="{col}" stroke-width="2.5"/>')
        if n <= 40:
            g += [f'<circle cx="{x(i):.1f}" cy="{y(v):.1f}" r="3" fill="{col}"/>' for i, v in enumerate(s)]
    if marks:
        for i, lab in marks:
            g.append(f'<line x1="{x(i):.1f}" x2="{x(i):.1f}" y1="{pt}" y2="{h-pb}" stroke="{C["accent"]}" stroke-dasharray="4 4"/>'
                     + (f'<text x="{x(i)-4:.1f}" y="{pt+10}" fill="{C["accent"]}" font-size="11" text-anchor="end">{esc(lab)}</text>'
                        if x(i) > w * 0.85 else
                        f'<text x="{x(i)+4:.1f}" y="{pt+10}" fill="{C["accent"]}" font-size="11">{esc(lab)}</text>'))
    legend = "".join(f'<span class="lg"><i style="background:{c}"></i>{esc(nm)}</span>' for c, nm in zip(colors, names))
    return f'<div class="chartbox"><div class="legend">{legend}</div><svg viewBox="0 0 {w} {h}" class="chart">{"".join(g)}</svg></div>'


# ---------------------------------------------------------------- HTML
CSS = """
:root{--bg:#44494B;--panel:#3A3F41;--panel2:#33383A;--line:#5A6062;--text:#F2F4F5;--muted:#B9BEC0;
--accent:#E7FF00;--blue:#4EA5FF;--green:#71FFC6;--purple:#BB8FF2;--orange:#FF8837;--red:#FF4B4B}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 "Segoe UI",Inter,system-ui,-apple-system,Arial,sans-serif}
.wrap{max-width:1200px;margin:0 auto;padding:24px 16px 48px}
header{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-start;justify-content:space-between;
border-bottom:2px solid var(--accent);padding-bottom:16px}
h1{margin:0;font-size:24px}h2{font-size:18px;margin:32px 0 12px;color:var(--accent)}
h3{font-size:15px;margin:16px 0 8px}
.meta{color:var(--muted);font-size:13px}.meta b{color:var(--text);font-weight:600}
.badge{display:inline-block;padding:6px 14px;border-radius:4px;font-weight:700;letter-spacing:.06em;color:#1d1f20}
.p-CRITICAL{background:var(--red)}.p-HIGH{background:var(--orange)}.p-GUARDED{background:var(--accent)}.p-CONTROLLED{background:var(--green)}
.banner{background:var(--purple);color:#1d1f20;padding:8px 12px;border-radius:4px;font-weight:600;margin:12px 0}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:16px}
.verdict{font-size:16px;font-weight:600}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}
.tile{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--blue);border-radius:6px;padding:12px}
.tile .v{font-size:26px;font-weight:700}.tile .l{color:var(--muted);font-size:12px}
.tile .d{font-size:12px;margin-top:2px}
.t-red{border-left-color:var(--red)}.t-green{border-left-color:var(--green)}.t-orange{border-left-color:var(--orange)}
.t-purple{border-left-color:var(--purple)}.t-accent{border-left-color:var(--accent)}
.up{color:var(--red)}.down{color:var(--green)}.flat{color:var(--muted)}
.good.up{color:var(--green)}.good.down{color:var(--red)}
.chart{width:100%;height:auto;display:block}
.legend{display:flex;gap:16px;font-size:12px;color:var(--muted);margin-bottom:4px}
.lg i{display:inline-block;width:12px;height:12px;border-radius:2px;margin-right:6px;vertical-align:-1px}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:6px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:7px 9px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap;vertical-align:middle}
th{background:var(--panel2);color:var(--muted);font-weight:600;position:sticky;top:0;cursor:pointer}
tr:hover td{background:rgba(231,255,0,.04)}
td.wrap{padding:7px 9px;white-space:normal;min-width:260px;max-width:460px;line-height:1.35}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;color:#1d1f20}
.s-open,.s-breached,.s-vulnerable,.s-eol,.s-missed,.s-regressed{background:var(--red)}
.s-remediated,.s-patched,.s-met,.s-fixed_since{background:var(--green)}
.s-pending,.s-unknown,.s-still_open{background:var(--orange)}
.s-new{background:var(--accent)}.s-gone{background:var(--purple)}
.s-at_risk{background:var(--orange)}.s-fixed{background:var(--green)}.s-none{background:var(--muted)}.s-na{background:#8E9496}
.sc{display:inline-block;min-width:30px;text-align:center;padding:1px 6px;border-radius:4px;font-size:12px;font-weight:700;color:#1d1f20}
.sc-c{background:var(--red)}.sc-h{background:var(--orange)}.sc-m{background:var(--accent)}.sc-l{background:var(--green)}
.cve{display:inline-block;padding:0 6px;margin:1px 2px 1px 0;border:1px solid var(--line);border-radius:3px;font-size:11px;color:var(--muted)}
.ctrls{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
input.filter,select{background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:4px;
padding:6px 10px;font:inherit;margin:0 0 8px}
input.filter{width:min(320px,100%)}
.note{background:var(--panel2);border-left:4px solid var(--accent);padding:8px 12px;border-radius:4px;margin:8px 0;font-size:13px}
.muted{color:var(--muted)}ul{margin:6px 0 0 18px;padding:0}li{margin:3px 0}
tr.cur td{background:rgba(231,255,0,.08)}
footer{margin-top:32px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:12px}
a{color:var(--blue)}
.two{display:grid;grid-template-columns:1fr;gap:12px}
.formula{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;background:var(--panel2);border-left:3px solid var(--accent);padding:5px 10px;border-radius:3px;margin:4px 0}
.scn-card{cursor:pointer;transition:transform .1s,border-color .1s}.scn-card:hover{transform:translateY(-1px);border-color:var(--accent)}
.scn-card[aria-pressed="true"]{outline:2px solid var(--accent);background:var(--panel2)}.scn-card.zero{opacity:.55}
.scn-card:focus{outline:2px solid var(--accent)}
.scn-panel{display:none;margin-top:12px;border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:6px;padding:10px 12px;background:var(--panel2)}
.scn-panel.open{display:block}.scn-panel h4{margin:2px 0 4px;font-size:14px}
.seg{display:inline-flex}.seg .btn{border-radius:0}.seg .btn:first-child{border-radius:4px 0 0 4px}.seg .btn:last-child{border-radius:0 4px 4px 0}
.btn.on{background:var(--accent);color:#1d1f20;border-color:var(--accent);font-weight:600}
.pchip{display:inline-block;font-size:12px;margin:1px 0}.achip{display:inline-block;padding:1px 7px;margin:2px 3px 2px 0;border:1px solid var(--line);border-radius:10px;font-size:12px}
table.sub tr.me td{background:rgba(231,255,0,.12);font-weight:600}table.sub tr.me td:first-child{box-shadow:inset 3px 0 0 var(--accent)}
.disc{margin:20px 0 0;background:var(--panel);border:1px solid var(--line);border-left:5px solid var(--accent);border-radius:6px;padding:12px 16px}
.disc h3{margin:0 0 6px;color:var(--accent)}.disc h4{margin:8px 0 4px;font-size:13px}.disc ul{font-size:13px}
.disc .dstat{font-weight:600;margin:4px 0 6px}.disc-ok{border-left-color:var(--green)}.disc-ok .dstat{color:var(--green)}
.disc-new{border-left-color:var(--orange)}.disc-new .dstat{color:var(--orange)}
.fold>summary{list-style:none;cursor:pointer;display:block}.fold>summary::-webkit-details-marker{display:none}
.fold>summary h2{display:inline-block;margin-bottom:4px}
.fold>summary h2::before{content:"▸";display:inline-block;width:1.1em;color:var(--accent)}
.fold[open]>summary h2::before{content:"▾"}
.fold>summary:focus-visible h2{outline:2px solid var(--accent);outline-offset:3px}
.fold-sum{display:block;color:var(--muted);font-size:13px;margin:0 0 4px 1.3em}
.fold-tip{display:block;color:var(--accent);font-size:12px;margin:0 0 12px 1.3em}.fold[open] .fold-tip{display:none}
.fold>summary:hover h2{text-decoration:underline;text-underline-offset:4px}
.hint{font-size:12px;color:var(--accent);margin:4px 0 8px}
.btn{background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:4px;padding:6px 10px;
font:inherit;font-size:12px;margin:0 0 8px;cursor:pointer}.btn:hover{border-color:var(--accent)}
tr.pl-row{cursor:pointer}tr.pl-row:focus{outline:2px solid var(--accent);outline-offset:-2px}
.caret{display:inline-block;color:var(--accent);transition:transform .15s}

tr.pl-row[aria-expanded="true"] td{background:rgba(231,255,0,.07)}
tr.detail{display:none}tr.detail.open{display:table-row}
tr.detail>td{white-space:normal;background:var(--panel2);padding:0;border-left:3px solid var(--accent)}
tr.detail:hover td{background:var(--panel2)}
.detail-in{padding:12px 14px 14px;position:sticky;left:0;box-sizing:border-box;width:var(--dw,100%)}
.detail-in h4{margin:12px 0 6px;font-size:13px}.detail-in h4.dv{color:var(--red)}.detail-in h4.df{color:var(--green)}
.dgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}
.dgrid ol,.dgrid ul{margin:4px 0 0 20px;padding:0}.dgrid li{margin:4px 0;line-height:1.4}
.kind{display:inline-block;margin-left:6px;padding:0 7px;border:1px solid var(--accent);border-radius:10px;font-size:11px;
color:var(--accent);font-weight:600;vertical-align:1px}
.sol{background:var(--panel);border-left:3px solid var(--blue);padding:6px 10px;border-radius:3px;margin:6px 0;font-size:13px}
.mnote{font-size:13px;margin:4px 0}.mnote .pill{font-size:10px;padding:0 5px}
li.dim{opacity:.45}
code{background:var(--panel);padding:0 4px;border-radius:3px;font-size:12px}
table.sub{font-size:12px}table.sub th{position:static;cursor:pointer;background:var(--panel)}
.tablewrap .tablewrap{border-color:var(--line)}
.tabs{position:sticky;top:0;z-index:5;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:8px;
background:var(--bg);padding:10px 0 8px;margin-top:12px;border-bottom:1px solid var(--line)}
.tab{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;padding:10px 14px;border:1px solid var(--line);border-radius:6px;
background:var(--panel);color:var(--text);text-decoration:none}.tab:hover{border-color:var(--accent)}
.tab.on{border-color:var(--accent);box-shadow:inset 0 -3px 0 var(--accent);background:var(--panel2)}
.tab-t{font-weight:700;font-size:15px}.tab-c{color:var(--muted);font-size:12px;flex:1}.tab .badge{padding:3px 10px;font-size:12px}
.p-none{background:var(--muted)}
.exp{display:flex;flex-wrap:wrap;align-items:center;gap:6px;justify-content:flex-end;margin-left:auto}
.exp-l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em;margin-right:2px}
.exp-b{margin:0;font-weight:600}.exp-b:hover{background:var(--accent);color:#1d1f20}
.exp-n{flex-basis:100%;text-align:right;color:var(--muted);font-size:11px;line-height:1.4}
.vb-h{margin:18px 0 8px;color:var(--muted);font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.07em}
.vb{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px}
.vbt{position:relative;background:var(--panel);border-top:3px solid var(--muted);padding:16px 18px 18px;min-height:112px;
clip-path:polygon(0 0,calc(100% - 22px) 0,100% 22px,100% 100%,0 100%)}
.vbt .v{font-size:34px;font-weight:300;line-height:1.1}.vbt .l{margin-top:10px;color:var(--muted);font-size:12px;
font-weight:600;text-transform:uppercase;letter-spacing:.08em;line-height:1.7}
.vb-eol{border-top-color:#A51D3A}.vb-bp{border-top-color:var(--red)}.vb-pa{border-top-color:var(--orange)}
.vb-un{border-top-color:#9A9FA1}.vb-ok{border-top-color:var(--blue)}.vb-na{border-top-color:#5A6062}
@media (max-width:980px){.vb{grid-template-columns:repeat(3,minmax(0,1fr))}}@media (max-width:520px){.vb{grid-template-columns:repeat(2,minmax(0,1fr))}}
.dd-card{cursor:pointer;transition:transform .1s,border-color .1s}.dd-card:hover{transform:translateY(-1px)}
.tile.dd-card:hover{border-color:var(--accent)}.dd-card:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.tile.dd-card[aria-pressed="true"]{outline:2px solid var(--accent);background:var(--panel2)}
.vbt.dd-card[aria-pressed="true"],.hs-c[aria-pressed="true"]{background:var(--panel2);box-shadow:inset 0 -3px 0 var(--accent)}
.dd-panel{display:none;margin-top:12px;border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:6px;padding:10px 12px;background:var(--panel2)}
.dd-panel.open{display:block}.dd-h{display:flex;justify-content:space-between;align-items:center;gap:8px}.dd-h h4{margin:2px 0 8px;font-size:14px}
.dd-x{margin:0}td.ddw{min-width:340px;max-width:520px}.ddf{margin:3px 0;line-height:1.4}.ddf .pill{font-size:10px;padding:0 6px}
.s-vb-eol{background:#A51D3A;color:#fff}.s-vb-backport{background:var(--red)}.s-vb-patch{background:var(--orange)}
.s-vb-unknown{background:#9A9FA1}.s-vb-patched{background:var(--blue)}.s-vb-na{background:#8E9496}
.hs{display:grid;grid-template-columns:repeat(8,minmax(0,1fr));margin-top:12px;background:var(--panel2);border:1px solid var(--line);border-radius:6px}
.hs-c{padding:16px 14px 18px;border-left:1px solid var(--line)}.hs-c:first-child{border-left:0}
.hs-c .v{font-size:34px;font-weight:300;line-height:1.1}.hs-c .l{margin-top:10px;color:var(--muted);font-size:12px;font-weight:600;
text-transform:uppercase;letter-spacing:.08em;line-height:1.7}.hs-c:hover{background:var(--panel)}
@media (max-width:1100px){.hs{grid-template-columns:repeat(4,minmax(0,1fr))}.hs-c:nth-child(5){border-left:0}.hs-c:nth-child(n+5){border-top:1px solid var(--line)}}
@media (max-width:560px){.hs{grid-template-columns:repeat(2,minmax(0,1fr))}.hs-c:nth-child(odd){border-left:0}.hs-c:nth-child(n+3){border-top:1px solid var(--line)}}
.ctx{display:grid;grid-template-columns:1fr 1fr;gap:36px;margin-top:14px;padding:20px 22px;background:var(--panel2);
border:1px solid var(--line);border-radius:6px}
.ctx h3{margin:0 0 10px;color:var(--accent);font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.07em}
.ctx p{margin:0;font-size:16px;line-height:1.6;color:#d9dddf}.ctx ol{margin:0 0 0 22px;padding:0}
.ctx li{font-size:16px;line-height:1.6;color:#d9dddf;margin:0 0 12px}.ctx li b{color:var(--text)}
@media (max-width:760px){.ctx{grid-template-columns:1fr;gap:18px}.exp{justify-content:flex-start;margin-left:0}.exp-n{text-align:left}}
section.trk{margin-top:8px}.sec-h{display:flex;flex-wrap:wrap;gap:12px;justify-content:space-between;align-items:center;
margin-top:22px;padding:12px 16px;background:var(--panel);border:1px solid var(--line);border-left:5px solid var(--accent);border-radius:6px}
.sec-t{margin:0!important;font-size:21px!important;color:var(--text)!important}
@media print{body{background:var(--bg);-webkit-print-color-adjust:exact;print-color-adjust:exact}
th{position:static}.tablewrap{overflow:visible}input.filter{display:none}
section.trk[hidden]{display:block!important}section.trk+section.trk{break-before:page}.tabs{position:static}.exp{display:none}.ctx,.vb,.hs{break-inside:avoid}.dd-panel{display:none!important}.tab-hint{display:none}h2{break-after:avoid}.tile,tr,.chartbox{break-inside:avoid}@page{margin:0}.wrap{padding:14mm 10mm}
tr.detail.has{display:table-row}.fold-tip{display:none!important}.scn-panel{display:block}.scn-panel[data-scn=all]{display:none}.view-p{display:none}.view-a{display:block!important}.detail-in{position:static;width:auto}tr.detail.has>td{break-inside:auto}.btn,select,.hint,.caret{display:none}}
"""

JS = r"""
(function(){
const ORIG='<!doctype html>\n'+document.documentElement.outerHTML; // as rendered, before any script changes
const H=JSON.parse(document.getElementById('run-history').textContent);
const L=JSON.parse(document.getElementById('i18n').textContent);
const CUR=document.body.dataset.run;
const runs=H.runs||[];
const byId=Object.fromEntries(runs.map(r=>[r.run_id,r]));
function fmt(ts){try{return new Date(ts).toLocaleString(L.html_lang||undefined);}catch(e){try{return new Date(ts).toLocaleString()}catch(_){return ts}}}
document.querySelectorAll('[data-ts]').forEach(e=>e.textContent=fmt(e.dataset.ts));
function cmp(c,b){const cf=c.findings||{},bf=b.findings||{};const r={new:[],fixed_since:[],regressed:[],still_open:[],gone:[]};
 for(const k in cf){const s=cf[k],p=bf[k];
  if(p===undefined){if(s==='o')r.new.push(k)}else if(p==='o'&&s==='r')r.fixed_since.push(k);
  else if(p==='r'&&s==='o')r.regressed.push(k);else if(p==='o'&&s==='o')r.still_open.push(k);}
 for(const k in bf){if(!(k in cf)&&bf[k]==='o')r.gone.push(k)}return r}
const KP=[['open','k_open',false],['remediated','k_rem',true],['rate','k_rate',true],['breached','k_breach',false],
 ['exposed_assets','k_exposed',false],['mttr','k_mttr',false],['unscanned','k_unscanned',false]];
const SCB={vpr:[[9,'c'],[7,'h'],[4,'m'],[0,'l']],acr:[[9,'c'],[7,'h'],[4,'m'],[0,'l']],aes:[[650,'h'],[350,'m'],[0,'l']]};
function sc(x,k){if(x===null||x===undefined||x===''||isNaN(Number(x)))return '<span class="muted">—</span>';x=Number(x);
 const b=(SCB[k].find(z=>x>=z[0])||[0,'l'])[1];return '<span class="sc sc-'+b+'">'+(k==='vpr'?x.toFixed(1):Math.round(x))+'</span>'}
function scd(x,k){return '<td data-s="'+(x==null||x===''?-1:x)+'">'+sc(x,k)+'</td>'}
function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function render(box,baseId){
 const key=box.dataset.key||'',pfx=box.dataset.pfx;let KL={};try{KL=JSON.parse(box.dataset.kl||'{}')}catch(e){}
 const V=r=>!r?null:(key?(r[key]&&typeof r[key]==='object'?r[key]:null):r);
 const body=box.querySelector('.cmp-body');
 const curR=byId[CUR],baseR=byId[baseId],cur=V(curR),base=V(baseR);
 if(!cur||!base){body.innerHTML='<p class="muted">'+esc(box.dataset.empty||L.no_prev)+'</p>';return}
 let notes='';
 if((baseR.skill_version||'?')!==(curR.skill_version||'?'))notes+='<div class="note">'+esc(L.ver_mismatch.replace('{a}',baseR.skill_version||'?').replace('{b}',curR.skill_version||'?'))+'</div>';
 if(baseR.sla_days!==curR.sla_days)notes+='<div class="note">'+esc(L.sla_mismatch.replace('{a}',baseR.sla_days).replace('{b}',curR.sla_days))+'</div>';
 if(!!baseR.demo!==!!curR.demo)notes+='<div class="note">'+esc(L.demo_mismatch)+'</div>';
 let t='<div class="tiles">';
 for(const [k,lab,good] of KP){const a=base.kpis?.[k],b=cur.kpis?.[k];
  let d='';if(a!=null&&b!=null){const x=Math.round((b-a)*10)/10;const cls=x>0?'up':x<0?'down':'flat';
   d='<div class="d '+(good?'good ':'')+cls+'">'+(x>0?'▲ +':x<0?'▼ ':'= ')+x+(k==='rate'?' pp':'')+' vs '+esc(a)+'</div>'}
  t+='<div class="tile"><div class="v">'+(b==null?'—':esc(b)+(k==='rate'?'%':''))+'</div><div class="l">'+esc(KL[lab]||L[lab])+'</div>'+d+'</div>'}
 t+='</div>';
 if(!base.findings){body.innerHTML=notes+t+'<p class="muted">'+esc(L.kpi_only)+'</p>';return}
 const r=cmp(cur,base);const order=['new','fixed_since','regressed','still_open','gone'];
 const PM=Object.assign({},base.plugin_meta||{},cur.plugin_meta||{}),AM=Object.assign({},base.asset_meta||{},cur.asset_meta||{});
 const PV=Object.assign({},base.plugin_vpr||{},cur.plugin_vpr||{}),AS=Object.assign({},base.asset_scores||{},cur.asset_scores||{});
 const TC={new:'t-accent',fixed_since:'t-green',regressed:'t-red',still_open:'t-orange',gone:'t-purple',all:''};
 const all=[];for(const k of order)for(const key of r[k])all.push([k,key]);r.all=all.map(x=>x[1]);
 const card=k=>{const n=r[k].length;return '<div class="tile scn-card '+TC[k]+(n?'':' zero')+'" role="button" tabindex="0" aria-pressed="false" data-scn="'+k+'"><div class="v">'+n+'</div><div class="l">'+esc(k==='all'?L.cmp_all:L[k])+'</div></div>'};
 let c='<h3>'+esc(L.cmp_total.replace('{n}',all.length))+'</h3><p class="hint">'+esc(L.cmp_click)+'</p><div class="tiles scn">'+order.map(card).join('')+card('all')+'</div>';
 const chip=p=>{const m=PM[p]||[];return '<div class="pchip"><b>'+esc(p)+'</b>'+(PV[p]!=null?' '+sc(PV[p],'vpr'):'')+(m[1]?' · '+esc(m[1]):'')+(m[0]?' · '+esc(m[0]):'')+'</div>'};
 function panel(k){const items=k==='all'?all:r[k].map(x=>[k,x]);
  if(!items.length)return '<div class="scn-panel" data-scn="'+k+'"><p class="muted">'+esc(L.scn_empty)+'</p></div>';
  const byA={},byP={};for(const [kk,key] of items){const i=key.indexOf('|'),a=key.slice(0,i),p=key.slice(i+1);
   (byA[a]=byA[a]||[]).push([kk,p]);(byP[p]=byP[p]||[]).push([kk,a])}
  const pill=kk=>k==='all'?'<span class="pill s-'+kk+'">'+esc(L[kk])+'</span> ':'';
  const id=pfx+'-cmp-'+k;
  let ra='';for(const a of Object.keys(byA).sort()){const ps=byA[a];const prods=[...new Set(ps.map(x=>(PM[x[1]]||[])[1]).filter(Boolean))];
   ra+='<tr data-prod="'+esc(prods.join(' '))+'"><td>'+esc(a)+'</td><td>'+esc(AM[a]||'')+'</td>'+scd((AS[a]||[])[0],'acr')+scd((AS[a]||[])[1],'aes')+'<td>'+esc(prods.join(', '))+'</td><td data-s="'+ps.length+'">'+ps.length+'</td><td class="wrap">'+ps.map(x=>'<div>'+pill(x[0])+chip(x[1])+'</div>').join('')+'</td></tr>'}
  let rp='';for(const p of Object.keys(byP).sort()){const as=byP[p];const m=PM[p]||[];
   rp+='<tr data-prod="'+esc(m[1]||'')+'"><td>'+esc(p)+'</td><td>'+esc(m[1]||'')+'</td>'+scd(PV[p],'vpr')+'<td class="wrap">'+esc(m[0]||'')+'</td><td data-s="'+as.length+'">'+as.length+'</td><td class="wrap">'+as.map(x=>pill(x[0])+'<span class="achip">'+esc(x[1])+(AM[x[1]]?' <span class="muted">'+esc(AM[x[1]])+'</span>':'')+'</span>').join(' ')+'</td></tr>'}
  const prods=[...new Set(items.map(x=>(PM[x[1].slice(x[1].indexOf('|')+1)]||[])[1]).filter(Boolean))].sort();
  const ps='<select data-t="'+id+'-a '+id+'-p" data-f="prod"><option value="">'+esc(L.prod_all)+'</option>'+prods.map(x=>'<option>'+esc(x)+'</option>').join('')+'</select>';
  return '<div class="scn-panel" data-scn="'+k+'"><h4><span class="pill s-'+(k==='all'?'none':k)+'">'+esc(k==='all'?L.cmp_all:L[k])+'</span> '+items.length+' · '+Object.keys(byA).length+' '+esc(L.c_assets.toLowerCase())+' · '+Object.keys(byP).length+' '+esc(L.c_plugins.toLowerCase())+'</h4>'
   +'<p class="muted" style="font-size:12px">'+esc(L[k+'_d'])+'</p>'
   +'<div class="ctrls"><span class="seg"><button type="button" class="btn on" data-view="a">'+esc(L.by_asset)+'</button><button type="button" class="btn" data-view="p">'+esc(L.by_plugin)+'</button></span>'+ps
   +'<input class="filter" data-t="'+id+'-a '+id+'-p" placeholder="'+esc(L.search)+'"></div>'
   +'<div class="view-a"><div class="tablewrap"><table id="'+id+'-a"><thead><tr><th>'+esc(L.c_asset)+'</th><th>'+esc(L.c_ip)+'</th><th>'+esc(L.c_acr)+'</th><th>'+esc(L.c_aes)+'</th><th>'+esc(L.c_product)+'</th><th>'+esc(L.c_findings)+'</th><th>'+esc(L.c_plugins)+'</th></tr></thead><tbody>'+ra+'</tbody></table></div></div>'
   +'<div class="view-p" hidden><div class="tablewrap"><table id="'+id+'-p"><thead><tr><th>'+esc(L.c_plugin)+'</th><th>'+esc(L.c_product)+'</th><th>'+esc(L.c_vpr)+'</th><th>'+esc(L.c_name)+'</th><th>'+esc(L.c_findings)+'</th><th>'+esc(L.c_assets)+'</th></tr></thead><tbody>'+rp+'</tbody></table></div></div></div>'}
 body.innerHTML=notes+t+c+[...order,'all'].map(panel).join('')+'<p class="muted" style="font-size:12px">'+esc(L.gone_note)+'</p>';
 const cards=body.querySelectorAll('.scn-card');
 function pick(k){cards.forEach(x=>{const on=x.dataset.scn===k&&x.getAttribute('aria-pressed')!=='true';x.setAttribute('aria-pressed',on?'true':'false')});
  const act=[...cards].find(x=>x.getAttribute('aria-pressed')==='true');
  body.querySelectorAll('.scn-panel').forEach(pn=>pn.classList.toggle('open',!!act&&pn.dataset.scn===act.dataset.scn));
  if(act)body.querySelector('.scn-panel.open').scrollIntoView({block:'nearest',behavior:'smooth'})}
 cards.forEach(x=>{x.addEventListener('click',()=>pick(x.dataset.scn));x.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();pick(x.dataset.scn)}})});
 body.querySelectorAll('.scn-panel').forEach(pn=>pn.querySelectorAll('[data-view]').forEach(bt=>bt.addEventListener('click',()=>{
  pn.querySelectorAll('[data-view]').forEach(z=>z.classList.toggle('on',z===bt));
  pn.querySelector('.view-a').hidden=bt.dataset.view!=='a';pn.querySelector('.view-p').hidden=bt.dataset.view!=='p'})));
 wire();
}
function applyF(tid){const tb=document.getElementById(tid);if(!tb)return;
 const cs=[...document.querySelectorAll('[data-t]')].filter(c=>c.dataset.t.split(' ').includes(tid));
 [...tb.tBodies[0].rows].forEach(tr=>{if(tr.classList.contains('detail'))return;let ok=true;
  cs.forEach(c=>{const v=(c.value||'').trim();if(!v)return;const f=c.dataset.f;
   if(!f){ok=ok&&tr.textContent.toLowerCase().includes(v.toLowerCase())}
   else if(f==='cves'||f==='prod'){ok=ok&&(' '+(tr.dataset[f]||'')+' ').includes(' '+v+' ')}
   else{ok=ok&&(tr.dataset[f]||'')===v}});
  tr.style.display=ok?'':'none';const d=tr.nextElementSibling;
  if(d&&d.classList.contains('detail'))d.style.display=ok?'':'none'})}
function wire(){document.querySelectorAll('[data-t]').forEach(c=>{if(c.dataset.w)return;c.dataset.w=1;
 c.addEventListener(c.tagName==='SELECT'?'change':'input',()=>c.dataset.t.split(' ').forEach(applyF))});
 document.querySelectorAll('th').forEach(th=>{if(th.dataset.w)return;th.dataset.w=1;th.addEventListener('click',()=>{
  const tb=th.closest('table').tBodies[0];if(!tb)return;const i=[...th.parentNode.children].indexOf(th);const asc=th.dataset.asc!=='1';th.dataset.asc=asc?'1':'0';
  const main=[...tb.rows].filter(r=>!r.classList.contains('detail'));
  const det=new Map(main.map(r=>{const d=r.nextElementSibling;return [r,d&&d.classList.contains('detail')?d:null]}));
  main.sort((a,b)=>{const x=a.cells[i]?.dataset.s??a.cells[i]?.textContent??'',y=b.cells[i]?.dataset.s??b.cells[i]?.textContent??'';
   const nx=parseFloat(x),ny=parseFloat(y);const r=(!isNaN(nx)&&!isNaN(ny))?nx-ny:x.localeCompare(y);return asc?r:-r})
   .forEach(r=>{tb.appendChild(r);const d=det.get(r);if(d)tb.appendChild(d)})})})}
function sizeD(){document.querySelectorAll('table.dtbl').forEach(t=>{const w=t.closest('.tablewrap');if(w.clientWidth)w.style.setProperty('--dw',(w.clientWidth-3)+'px')})}
document.querySelectorAll('.cmpbox').forEach(box=>{const sel=box.querySelector('.cmp-sel');
 if(sel){sel.addEventListener('change',()=>render(box,sel.value));render(box,sel.value)}
 else box.querySelector('.cmp-body').innerHTML='<p class="muted">'+esc(box.dataset.empty||L.no_prev)+'</p>'});
wire();
function toggle(tr,open){const d=tr.nextElementSibling;if(!d||!d.classList.contains('detail'))return;
 const o=open===undefined?!d.classList.contains('open'):open;d.classList.toggle('open',o);tr.setAttribute('aria-expanded',o?'true':'false');const cr=tr.querySelector('.caret');if(cr)cr.textContent=o?'▾':'▸'}
document.querySelectorAll('tr.pl-row').forEach(tr=>{tr.addEventListener('click',e=>{if(e.target.closest('a'))return;toggle(tr)});
 tr.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();toggle(tr)}})});
document.querySelectorAll('[data-act]').forEach(b=>b.addEventListener('click',()=>{const o=b.dataset.act==='expand';
 b.closest('.panel').querySelectorAll('tr.pl-row').forEach(tr=>{if(tr.style.display!=='none')toggle(tr,o)})}));
// one section per CVE, switched from the tabs; print shows them all
const secs=[...document.querySelectorAll('section.trk')];let curSec=null;
function show(id){curSec=id;secs.forEach(s=>s.hidden=s.id!==id);
 document.querySelectorAll('[data-tab]').forEach(b=>{const on=b.dataset.tab===id;b.classList.toggle('on',on);b.setAttribute('aria-current',on?'true':'false')});sizeD()}
document.querySelectorAll('[data-tab]').forEach(b=>b.addEventListener('click',e=>{e.preventDefault();show(b.dataset.tab);
 try{history.replaceState(null,'','#'+b.dataset.tab)}catch(_){}
 const n=document.querySelector('nav.tabs');if(n&&n.getBoundingClientRect().top<0)n.scrollIntoView()}));
const h0=(location.hash||'').slice(1);if(secs.length)show(secs.some(s=>s.id===h0)?h0:secs[0].id);
window.addEventListener('resize',sizeD);
window.addEventListener('beforeprint',()=>{secs.forEach(s=>s.hidden=false);document.querySelectorAll('details.fold').forEach(d=>d.open=true)});
window.addEventListener('afterprint',()=>{if(curSec)show(curSec)});
// tile drill-down: assets or findings behind each KPI / version-status tile
const DD={};document.querySelectorAll('script.dd-data').forEach(x=>{try{DD[x.dataset.trk]=JSON.parse(x.textContent)}catch(e){}});
const DDF={k_php:['a',x=>true],k_exposed:['a',x=>x.st==='open'||x.st==='at_risk'],k_confirmed:['a',x=>x.open>0],
 k_unscanned:['a',x=>x.uns],k_open:['f',x=>x.st==='open'],k_rem:['f',x=>x.st==='remediated'],k_rate:['f',x=>true],
 k_mttr:['f',x=>x.st==='remediated'&&x.days!==null],k_breach:['f',x=>x.ocls==='breached']};
const pl=(c,t)=>'<span class="pill s-'+esc(c)+'">'+esc(t)+'</span>';
function ddShow(card){const g=card.closest('[data-ddg]'),trk=g.dataset.trk,d=DD[trk],panel=document.getElementById(g.dataset.ddg+'-dd');
 const on=card.getAttribute('aria-pressed')!=='true';
 document.querySelectorAll('section.trk#'+card.closest('section').id+' .dd-card').forEach(x=>x.setAttribute('aria-pressed','false'));
 document.querySelectorAll('section.trk#'+card.closest('section').id+' .dd-panel').forEach(p=>{p.classList.remove('open');p.innerHTML=''});
 if(!on||!d||!panel)return;card.setAttribute('aria-pressed','true');
 const key=card.dataset.dd,f=key.startsWith('vb_')?['a',x=>x.vb===key.slice(3)]:DDF[key];if(!f)return;
 const lab=(card.querySelector('.l')||{}).textContent||'',tid=g.dataset.ddg+'-tbl';
 const byA={};d.findings.forEach(x=>(byA[x.a]=byA[x.a]||[]).push(x));
 const items=(f[0]==='a'?d.assets:d.findings).filter(f[1]);
 let head,rows;
 if(f[0]==='a'){
  head=['c_asset','c_ip','c_fqdn','c_src','c_acr','c_aes','c_ver','c_vgroup','c_findings','c_astatus','c_open_n','c_fixed_n','c_last'];
  rows=items.map(x=>'<tr><td><b>'+esc(x.a)+'</b></td><td>'+esc(x.ip)+'</td><td>'+esc(x.fqdn)+'</td><td>'+esc(x.src)+'</td>'+scd(x.acr,'acr')+scd(x.aes,'aes')+'<td>'+esc(x.ver||'—')+'</td><td>'+pl('vb-'+x.vb,x.vbl)+'</td><td class="wrap ddw">'
   +((byA[x.a]||[]).map(v=>'<div class="ddf">'+pl(v.st,L[v.st])+' <b>'+esc(v.pid)+'</b> '+(v.vpr!=null?sc(v.vpr,'vpr')+' ':'')+esc(v.name)+'<br><span class="muted">'+esc((d.lab||{}).c_ver||L.c_ver)+': '+esc(v.ver||'—')+' → '+esc(v.tgt)+' · '+esc(L.c_due)+' '+esc(v.due)+' · '+esc(v.out)+'</span></div>').join('')||'<span class="muted">'+esc(L.dd_nofind)+'</span>')
   +'</td><td>'+pl(x.st,x.stl)+'</td><td data-s="'+x.open+'">'+x.open+'</td><td data-s="'+x.fixed+'">'+x.fixed+'</td><td>'+esc(x.last||'—')+(x.uns?' '+pl('unknown',L.dd_unscanned):'')+'</td></tr>').join('')}
 else{
  head=['c_asset','c_ip','c_src','c_acr','c_aes','c_plugin','c_vpr','c_name','c_cves','c_ver','c_target','c_state','c_first','c_due','c_fixed','c_daysopen','c_outcome','c_last'];
  rows=items.map(x=>'<tr><td><b>'+esc(x.a)+'</b></td><td>'+esc(x.ip)+'</td><td>'+esc(x.src)+'</td>'+scd(x.acr,'acr')+scd(x.aes,'aes')+'<td>'+esc(x.pid)+'</td>'+scd(x.vpr,'vpr')+'<td class="wrap">'+esc(x.name)+'</td><td>'+x.cves.map(c=>'<span class="cve">'+esc(c)+'</span>').join('')+'</td><td>'+esc(x.ver||'—')+'</td><td>'+pl(x.tcls,x.tgt)+'</td><td>'+esc(x.state)+'</td><td>'+esc(x.fs||L.no_first)+'</td><td>'+esc(x.due)+'</td><td>'+esc(x.fx)+'</td><td data-s="'+(x.days??'')+'">'+esc(x.days??'')+'</td><td>'+pl(x.ocls,x.out)+'</td><td>'+esc(x.last)+'</td></tr>').join('')}
 const n=(f[0]==='a'?(items.length===1?L.dd_asset1:L.dd_assets):(items.length===1?L.dd_finding1:L.dd_findings)).replace('{n}',items.length);
 panel.innerHTML='<div class="dd-h"><h4>'+esc(lab)+' <span class="muted">· '+esc(n)+'</span></h4><button type="button" class="btn dd-x">'+esc(L.dd_close)+' ✕</button></div>'
  +(items.length?'<input class="filter" data-t="'+tid+'" placeholder="'+esc(L.search)+'"><div class="tablewrap"><table id="'+tid+'" class="sub"><thead><tr>'+head.map(h=>'<th>'+esc((d.lab||{})[h]||L[h]||h)+'</th>').join('')+'</tr></thead><tbody>'+rows+'</tbody></table></div>'
  :'<p class="muted">'+esc(L.dd_empty)+'</p>');
 panel.classList.add('open');panel.querySelector('.dd-x').addEventListener('click',()=>ddShow(card));wire();
 panel.scrollIntoView({block:'nearest',behavior:'smooth'})}
document.querySelectorAll('.dd-card').forEach(c=>{c.addEventListener('click',()=>ddShow(c));
 c.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();ddShow(c)}})});
// export: same stamped names as the files the skill writes (report_<stamp>.html / history_<stamp>.json)
function dl(name,text,type){const b=new Blob([text],{type:type});const u=URL.createObjectURL(b);const a=document.createElement('a');
 a.href=u;a.download=name;a.style.display='none';document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(u);a.remove()},1500)}
document.querySelectorAll('[data-export]').forEach(b=>b.addEventListener('click',()=>{const d=document.body.dataset;
 if(b.dataset.export==='html')dl(d.htmlName||'report.html',ORIG,'text/html;charset=utf-8');
 else dl(d.jsonName||'history.json',JSON.stringify({format:H.format,skill:H.skill||'php2shell-tenable-tracker',runs:runs},null,1),'application/json;charset=utf-8')}));
})();
"""


def tile(v, label, cls="", sub="", dd=None):
    act = (f' dd-card" role="button" tabindex="0" aria-pressed="false" data-dd="{dd}' if dd else "")
    return (f'<div class="tile {cls}{act}"><div class="v">{esc(v)}</div><div class="l">{esc(label)}</div>'
            + (f'<div class="d muted">{esc(sub)}</div>' if sub else "") + "</div>")


def outcome_cell(v, L):
    if v["status"] == "remediated":
        if v["outcome"] is None:
            return '<td>—</td>'
        return f'<td data-s="{0 if v["outcome"]=="met" else 1}"><span class="pill s-{v["outcome"]}">{esc(L[v["outcome"]])}</span></td>'
    over = v["over"]
    if over > 0:
        txt, cls = L["breached"].format(n=over), "breached"
    elif over == 0:
        txt, cls = L["due_today"], "pending"
    else:
        txt, cls = L["due_in"].format(n=-over), "pending"
    return f'<td data-s="{1000+over}"><span class="pill s-{cls}">{esc(txt)}</span></td>'


def plugin_detail(e, vulns, L, kind, me=None):
    """Drill-down for one plugin: assets (vulnerable / fixed), remediation and mitigation."""
    vs = sorted(vulns, key=lambda v: (-(v.get("over") or -999), v["asset"]))
    open_v = [v for v in vs if v["status"] == "open"]
    fix_v = sorted([v for v in vs if v["status"] == "remediated"], key=lambda v: (str(v["fixed"] or ""), v["asset"]))

    def tr(v):
        return '<tr class="me">' if me and v["asset"] == me else "<tr>"

    def vrow(v):
        tgt, tcls = target_version(v.get("php_version"), kind, L)
        vst = version_status(v.get("php_version"))
        return (tr(v) + f'<td>{esc(v["asset"])}</td><td>{esc(v.get("ip"))}</td><td>{esc(v.get("fqdn"))}</td>'
                f'<td>{esc(prod(v.get("source")))}</td>' + sc_td(v.get("acr"), "acr") + sc_td(v.get("aes"), "aes")
                + f'<td>{esc(v.get("port") or "")}</td>'
                f'<td>{esc(v.get("php_version") or "—")} <span class="pill s-{vst}">{esc(L["st_"+vst])}</span></td>'
                f'<td><span class="pill s-{tcls}">{esc(tgt)}</span></td><td>{esc(v.get("state"))}</td>'
                f'<td>{esc(v["first_seen"] or L["no_first"])}</td><td>{esc(v["due"])}</td>'
                f'<td>{esc("" if v["days_open"] is None else v["days_open"])}</td>' + outcome_cell(v, L)
                + f'<td>{esc(v.get("last_seen"))}</td></tr>')

    def frow(v):
        return (tr(v) + f'<td>{esc(v["asset"])}</td><td>{esc(v.get("ip"))}</td><td>{esc(v.get("fqdn"))}</td>'
                f'<td>{esc(prod(v.get("source")))}</td>' + sc_td(v.get("acr"), "acr") + sc_td(v.get("aes"), "aes")
                + f'<td>{esc(v.get("php_version") or "—")}</td>'
                f'<td>{esc(v["first_seen"] or L["no_first"])}</td><td>{esc(v["fixed"] or "")}</td>'
                f'<td>{esc("" if v["days_open"] is None else v["days_open"])}</td>' + outcome_cell(v, L)
                + f'<td>{esc(v.get("last_seen"))}</td></tr>')

    vh = "".join(f"<th>{esc(L[k])}</th>" for k in ("c_asset", "c_ip", "c_fqdn", "c_src", "c_acr", "c_aes", "c_port", "c_ver",
                                                    "c_target", "c_state", "c_first", "c_due", "c_daysopen",
                                                    "c_outcome", "c_last"))
    fh = "".join(f"<th>{esc(L[k])}</th>" for k in ("c_asset", "c_ip", "c_fqdn", "c_src", "c_acr", "c_aes", "c_ver", "c_first",
                                                    "c_fixed", "c_daysopen", "c_outcome", "c_last"))
    vt = (f'<div class="tablewrap"><table class="sub"><thead><tr>{vh}</tr></thead><tbody>{"".join(map(vrow, open_v))}</tbody></table></div>'
          if open_v else f'<p class="muted">{esc(L["d_empty"])}</p>')
    ft = (f'<div class="tablewrap"><table class="sub"><thead><tr>{fh}</tr></thead><tbody>{"".join(map(frow, fix_v))}</tbody></table></div>'
          if fix_v else f'<p class="muted">{esc(L["d_empty"])}</p>')

    info = vpr_line(e, L)
    if e.get("synopsis"):
        info += f'<p><b>{esc(L["d_synopsis"])}:</b> {esc(e["synopsis"])}</p>'
    if e.get("solution"):
        info += f'<div class="sol"><b>{esc(L["d_solution"])}:</b> {esc(e["solution"])}</div>'
    remed = "<ol>" + "".join(f"<li>{esc(x)}</li>" for x in L["rem_" + kind]) + "</ol>"

    # mitigation: applicability depends on open findings, plugin kind and branches seen
    if open_v:
        mnote, mcls = (L["mit_primary"], "s-vulnerable") if kind == "unpatched" else (L["mit_open"], "s-pending")
    elif fix_v:
        mnote, mcls = L["mit_fixed"], "s-fixed"
    else:
        mnote, mcls = L["mit_none"], "s-none"
    branches = {parse_version(v.get("php_version"))[:2] for v in open_v if parse_version(v.get("php_version"))}
    unknown_ver = any(not parse_version(v.get("php_version")) for v in open_v)
    items = list(L["mit_items"])
    show85 = (8, 5) in branches or unknown_ver or not open_v or kind in ("distro", "unpatched", "container")
    mit = "<ul>" + "".join(f'<li{"" if (i != 2 or show85) else " class=dim"}>{x}</li>' for i, x in enumerate(items)) + "</ul>"
    if not show85:
        mit += f'<p class="muted" style="font-size:12px">{esc(L["mit_no85"])}</p>'
    refs = ""
    if e.get("see_also"):
        refs = (f'<p style="font-size:12px"><b>{esc(L["d_refs"])}:</b> '
                + " · ".join(f'<a href="{esc(u)}" target="_blank" rel="noopener">{esc(u)}</a>' for u in e["see_also"][:6]) + "</p>")

    return (f'<div class="detail-in"><div class="dgrid">'
            f'<div><h4>{esc(L["d_remed"])} <span class="kind">{esc(L["k_" + kind])}</span></h4>{info}{remed}{refs}</div>'
            f'<div><h4>{esc(L["d_mitig"])}</h4><p class="mnote"><span class="pill {mcls}">●</span> {esc(mnote)}</p>{mit}</div></div>'
            f'<h4 class="dv">{esc(L["d_vuln"].format(n=len(open_v)))}</h4>{vt}'
            f'<h4 class="df">{esc(L["d_fixed"].format(n=len(fix_v)))}</h4>{ft}</div>')


def prod_select(tid, values, L):
    opts = f'<option value="">{esc(L["prod_all"])}</option>' + "".join(f'<option>{esc(v)}</option>' for v in values)
    return f'<select data-t="{tid}" data-f="prod" aria-label="{esc(L["c_product"])}">{opts}</select>'


def plugin_section(tk):
    P, L, A, pid = tk["P"], tk["L"], tk["A"], tk["id"]
    plugins, inventory, s = P
    cves = list(s["by_cve"])
    tid = f"{pid}-pl-tbl"
    by_pid = {}
    for v in A["vulns"]:
        by_pid.setdefault(str(v.get("plugin_id") or ""), []).append(v)
    tiles_ = tile(s["total"], L["pl_total"], "t-accent") + "".join(
        tile(s["by_cve"][c], L["pl_for"].format(cve=c), "t-purple") for c in cves) + \
        tile(s["with_open"], L["pl_open"], "t-red") + tile(s["fixed_only"], L["pl_fixed"], "t-green") + \
        tile(s["no_findings"], L["pl_none"], "")
    notes = f'<p class="muted" style="font-size:12px">{esc(L["pl_note"])}</p>'
    if not s["catalog"]:
        notes += f'<div class="note">{esc(L["pl_nocat"])}</div>'
    if s["unmatched_rows"]:
        notes += f'<div class="note">{esc(L["pl_unmatched"].format(n=s["unmatched_rows"]))}</div>'
    notes += f'<p class="muted" style="font-size:12px">{esc(L["sc_note"])}</p>' + sc_missing_note(tk.get("sc"), ("vpr",), L)
    notes += f'<p class="hint">{esc(L["pl_click"])}</p>'
    opts = f'<option value="">{esc(L["pl_all"])}</option>' + "".join(f'<option>{esc(c)}</option>' for c in cves)
    sopts = f'<option value="">{esc(L["pl_any"])}</option>' + "".join(
        f'<option value="{k}">{esc(L["ps_" + k])}</option>' for k in ("vulnerable", "fixed", "none"))
    prods = sorted({prod(e["product"]) for e in plugins if prod(e["product"])})
    ctrls = (f'<div class="ctrls">{prod_select(tid, prods, L)}'
             + (f'<select data-t="{tid}" data-f="cves">{opts}</select>' if len(cves) > 1 else "")
             + f'<select data-t="{tid}" data-f="st">{sopts}</select>'
             f'<input class="filter" data-t="{tid}" placeholder="{esc(L["search"])}">'
             f'<button type="button" class="btn" data-act="expand">{esc(L["pl_expand"])}</button>'
             f'<button type="button" class="btn" data-act="collapse">{esc(L["pl_collapse"])}</button></div>')
    trs = ""
    for e in plugins:
        extra = "" if e["in_catalog"] else f' <span class="muted" title="{esc(L["pl_extra"])}">*</span>'
        pr = prod(e["product"])
        has = " has" if (e["open"] or e["fixed"]) else ""
        trs += (f'<tr class="pl-row" tabindex="0" aria-expanded="false" data-prod="{esc(pr)}" '
                f'data-cves="{esc(" ".join(e["cves"]))}" data-st="{e["status"]}">'
                f'<td><span class="caret">▸</span> {esc(e["plugin_id"])}{extra}</td><td>{esc(pr)}</td>'
                f'<td class="wrap">{esc(e["name"])}</td><td>{esc(tk["family"](e))}</td>'
                f'<td>{"".join(f"<span class=cve>{esc(c)}</span>" for c in e["cves"])}</td>' + sc_td(e.get("vpr"), "vpr")
                + f'<td data-s="{e["open"]}">{e["open"]}</td><td data-s="{e["fixed"]}">{e["fixed"]}</td>'
                f'<td data-s="{len(e["assets"])}">{len(e["assets"])}</td>'
                f'<td><span class="pill s-{e["status"]}">{esc(L["ps_" + e["status"]])}</span></td></tr>'
                f'<tr class="pl-detail detail{has}"><td colspan="10">'
                + tk["detail"](e, by_pid.get(e["plugin_id"], []), L) + '</td></tr>')
    table = (f'<div class="tablewrap"><table id="{tid}" class="dtbl"><thead><tr><th>{esc(L["c_plugin"])}</th>'
             f'<th>{esc(L["c_product"])}</th><th>{esc(L["c_name"])}</th><th>{esc(L["c_family"])}</th>'
             f'<th>{esc(L["c_cves"])}</th><th>{esc(L["c_vpr"])}</th><th>{esc(L["c_vuln_n"])}</th><th>{esc(L["c_fixed_n"])}</th>'
             f'<th>{esc(L["c_assets_n"])}</th><th>{esc(L["c_pstatus"])}</th></tr></thead><tbody>{trs}</tbody></table></div>')
    if s["not_in_catalog"]:
        table += f'<p class="muted" style="font-size:12px">* {esc(L["pl_extra"])}</p>'
    inv = ""
    if inventory:
        inv = (f'<h3>{esc(L["inv_plugins"])}</h3><p class="muted">'
               + ", ".join(f'{esc(e["plugin_id"])} — {esc(e["name"])}' for e in inventory) + "</p>")
    return (f'<h2>{esc(L["plugins"])}</h2><div class="tiles">{tiles_}</div>'
            f'<div class="panel" style="margin-top:10px">{notes}{ctrls}{table}{inv}</div>')


def sla_section(tk, args, today):
    A, L, d0, pid = tk["A"], tk["L"], tk["disclosure"], tk["id"]
    n = args.sla_days
    src = L["sla_src_user" if args.sla_source == "user" else "sla_src_default"].format(n=n)
    if args.sla_ref:
        src += " " + L["sla_src_ref"].format(ref=args.sla_ref)
    vulns = A["vulns"]
    counts = [sum(1 for v in vulns if v["status"] == "open" and v["outcome"] == "pending"),
              sum(1 for v in vulns if v["status"] == "open" and v["outcome"] == "breached"),
              sum(1 for v in vulns if v["status"] == "remediated" and v["outcome"] == "met"),
              sum(1 for v in vulns if v["status"] == "remediated" and v["outcome"] == "missed"),
              sum(1 for v in vulns if v["status"] == "remediated" and v["outcome"] is None)]
    cls = ["t-orange", "t-red", "t-green", "t-red", ""]
    now = "".join(tile(c, lab, k) for c, lab, k in zip(counts, L["sla_now"], cls))
    ex = ""
    dated = [v for v in vulns if v["first_seen"]]
    pick = next((v for v in dated if v["first_seen"] < d0), dated[0] if dated else None)
    if pick:
        cs = max(pick["first_seen"], d0)
        if pick["status"] == "open":
            over = pick["over"]
            o = (L["breached"].format(n=over) if over > 0 else L["due_today"] if over == 0 else L["due_in"].format(n=-over))
            st = L["sla_ex_open"].format(t=today, o=o)
        else:
            st = L["sla_ex_fixed"].format(fx=pick["fixed"] or "—", o=L.get(pick["outcome"] or "", "—"))
        ex = (f'<h3>{esc(L["sla_ex_h"])}</h3><p class="formula">' + esc(L["sla_ex"].format(
            a=pick["asset"], p=pick.get("plugin_id") or "—", fs=pick["first_seen"], cs=cs, due=pick["due"], state=st)) + "</p>")
    nodates = "" if A["dates_ok"] else f'<div class="note">{esc(L["sla_nodates"].format(d=d0))}</div>'
    li = lambda xs: "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in xs) + "</ul>"
    out_rows = "".join(f"<tr><td><b>{esc(a)}</b></td><td class=\"wrap\">{esc(b)}</td></tr>" for a, b in L["sla_out"])
    formulas = "".join(f'<div class="formula">{esc(f.format(n=n))}</div>' for f in L["sla_f"])
    summary = L["sla_sum"].format(n=n, d=d0,
                                  src=L["sla_sum_user" if args.sla_source == "user" else "sla_sum_default"]
                                  + (f" ({args.sla_ref})" if args.sla_ref else ""))
    basis = (f'<details class="fold" id="{pid}-sla-basis"><summary><h2>{esc(L["sla_h"])}</h2>'
             f'<span class="fold-sum">{esc(summary)}</span><span class="fold-tip">{esc(L["sla_toggle"])}</span></summary>'
             f'<div class="panel">'
             f'<p>{esc(L["sla_intro"].format(n=n))}</p>'
             f'<div class="dgrid"><div><h3>{esc(L["sla_src_h"])}</h3><p>{esc(src)}</p>'
             f'<h3>{esc(L["sla_clock_h"])}</h3>{li([x.format(d=d0) for x in L["sla_clock"]])}</div>'
             f'<div><h3>{esc(L["sla_formula_h"])}</h3>{formulas}{ex}</div></div>'
             f'<h3>{esc(L["sla_out_h"])}</h3><div class="tablewrap"><table class="sub">{out_rows}</table></div>'
             f'<h3>{esc(L["sla_data_h"])}</h3>{li([x.format(t=today) for x in L["sla_data"]])}'
             f'<p class="muted" style="font-size:12px;margin-top:10px">{esc(L["sla_change"])}</p></div></details>')
    now_sec = (f'<h2>{esc(L["sla_now_h"])}</h2><div class="panel">'
               f'<p class="muted" style="margin-top:0">{esc(L["sla_now_intro"].format(n=n))}</p>{nodates}'
               f'<div class="tiles">{now}</div></div>')
    return basis + now_sec


def disclaimer(runs, cur_run, args, L, hist_src):
    prior = sorted((r for r in runs if r["run_id"] != cur_run["run_id"]
                    and r.get("executed_at", "") <= cur_run["executed_at"]
                    and bool(r.get("demo")) == bool(cur_run.get("demo"))), key=lambda r: r["executed_at"])
    fmt = lambda r: r["executed_at"][:16].replace("T", " ") + " UTC"
    li = lambda xs: "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in xs) + "</ul>"
    n, m = args.sla_days, MAX_DETAILED_RUNS
    fn = getattr(args, "file_names", {"html": "report.html", "json": "history.json"})
    fx = lambda xs, **k: [safe_fmt(x, **fn, **k) for x in xs]
    if not prior:
        return (f'<div class="disc disc-new"><h3>{esc(L["disc_h_first"])}</h3><p class="dstat">{esc(L["disc_first_stat"])}</p>'
                f'<div class="dgrid"><div><h4>{esc(L["disc_first_what_h"])}</h4>{li(fx(L["disc_first_what"]))}</div>'
                f'<div><h4>{esc(L["disc_first_how_h"])}</h4>{li(fx(L["disc_first_how"], n=n))}</div></div></div>')
    stat = (L["disc_next_stat1"] if len(prior) == 1 else L["disc_next_stat"]).format(
        n=len(prior), first=fmt(prior[0]), last=fmt(prior[-1]))
    if hist_src:
        stat += " " + L["disc_src"].format(src="; ".join(
            L["src_ledger"] if x == "ledger" else L["src_import"].format(f=x) for x in hist_src))
    return (f'<div class="disc disc-ok"><h3>{esc(L["disc_h_next"])}</h3><p class="dstat">{esc(stat)}</p>'
            f'<div class="dgrid"><div><h4>{esc(L["disc_why_h"])}</h4>{li(fx(L["disc_why"]))}</div>'
            f'<div><h4>{esc(L["disc_keep_h"])}</h4>{li([x.format(n=n, m=m) for x in L["disc_keep"]])}</div></div></div>')


VB_ORDER = ("eol", "backport", "patch", "unknown", "patched", "na")  # first that applies wins


def version_breakdown(rows, path_of):
    """Assets by version status, each asset once (VB_ORDER priority). path_of(row) -> "backport" | "patch"
    says how a vulnerable row gets fixed (OS-vendor backport vs. an upstream release / image rebuild)."""
    cls = {}
    for r in rows:
        st = r.get("version_status") or "unknown"
        is_vuln = r.get("role") == "vulnerable"
        fixed = is_vuln and (r.get("state") or "ACTIVE").upper() == "FIXED"
        if fixed:
            c = "patched"
        elif st == "eol":
            c = "eol"
        elif is_vuln or st == "vulnerable":
            c = path_of(r)
        else:
            c = {"patched": "patched", "na": "na"}.get(st, "unknown")
        a = r.get("asset") or r.get("ip") or "unknown"
        if a not in cls or VB_ORDER.index(c) < VB_ORDER.index(cls[a]):
            cls[a] = c
    return {k: sum(1 for v in cls.values() if v == k) for k in VB_ORDER}, cls


def dd_data(tk):
    """Compact per-section dataset behind the clickable tiles: every vulnerable finding and every asset."""
    L, A, vk = tk["L"], tk["A"], tk["ver_key"]
    fnd = []
    for v in A["vulns"]:
        tgt, tcls = tk["target"](v)
        if v["status"] == "remediated":
            out, ocls = (L[v["outcome"]], v["outcome"]) if v["outcome"] else ("—", "none")
        else:
            o = v["over"]
            out, ocls = ((L["breached"].format(n=o), "breached") if o > 0 else
                         (L["due_today"], "pending") if o == 0 else (L["due_in"].format(n=-o), "pending"))
        fnd.append({"a": v["asset"], "ip": v.get("ip") or "", "src": prod(v.get("source")), "pid": str(v.get("plugin_id") or ""),
                    "name": v.get("plugin_name") or "", "cves": norm_cves(v.get("cves")), "ver": str(v.get(vk) or ""),
                    "tgt": tgt, "tcls": tcls, "state": v["state"], "st": v["status"], "fs": str(v["first_seen"] or ""),
                    "due": str(v["due"]), "fx": str(v["fixed"] or ""), "days": v["days_open"], "out": out, "ocls": ocls,
                    "last": v.get("last_seen") or "", "vpr": v.get("vpr"), "acr": v.get("acr"), "aes": v.get("aes")})
    meta = {}
    for r in tk["rows"]:
        m = meta.setdefault(r["asset"], {"fqdn": "", "src": set(), "ver": set()})
        m["fqdn"] = m["fqdn"] or r.get("fqdn") or ""
        if prod(r.get("source")):
            m["src"].add(prod(r.get("source")))
        if r.get(vk):
            m["ver"].add(str(r.get(vk)))
    uns, vbc = set(A["unscanned"]), tk.get("vbc") or {}
    ast = []
    for a, ai in sorted(A["assets"].items()):
        m = meta.get(a, {"fqdn": "", "src": set(), "ver": set()})
        g = vbc.get(a, "unknown")
        ast.append({"a": a, "ip": ai.get("ip") or "", "fqdn": m["fqdn"], "src": ", ".join(sorted(m["src"])),
                    "ver": ", ".join(sorted(m["ver"])), "vb": g, "vbl": L["vb_" + g], "st": ai["status"],
                    "stl": L["as_" + ai["status"]], "last": str(ai["last_seen"] or ""), "open": ai["open"],
                    "fixed": ai["rem"], "uns": a in uns, "acr": ai.get("acr"), "aes": ai.get("aes")})
    lab = {x: L[x] for x in ("c_ver", "c_target")}
    return json.dumps({"assets": ast, "findings": fnd, "lab": lab}, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")


def headline_strip(tk, args):
    """Figures under the executive summary (same drill-down as the tiles)."""
    L, k, pid = tk["L"], tk["A"]["kpis"], tk["id"]
    confirmed = sum(1 for ai in tk["A"]["assets"].values() if ai["open"])
    cells = [(k["php_assets"], L["hs_assets"], "k_php"), (confirmed, L["hs_confirmed"], "k_confirmed"),
             (k["unscanned"], L["hs_unassessed"], "k_unscanned"), (k["open"], L["hs_open"], "k_open"),
             (k["remediated"], L["hs_rem"], "k_rem"), ("—" if k["rate"] is None else f"{k['rate']}%", L["hs_rate"], "k_rate"),
             ("—" if k["mttr"] is None else f"{k['mttr']} d", L["hs_mttr"], "k_mttr"),
             (k["breached"], safe_fmt(L["hs_breach"], n=args.sla_days), "k_breach")]
    cs = "".join(f'<div class="hs-c dd-card" role="button" tabindex="0" aria-pressed="false" data-dd="{d}">'
                 f'<div class="v">{esc(v)}</div><div class="l">{esc(lab)}</div></div>' for v, lab, d in cells)
    return (f'<div class="hs" data-ddg="{pid}-hs" data-trk="{pid}">{cs}</div><div class="dd-panel" id="{pid}-hs-dd"></div>')


def version_panel(L, vb, total, pid):
    color = {"eol": "vb-eol", "backport": "vb-bp", "patch": "vb-pa", "unknown": "vb-un", "patched": "vb-ok", "na": "vb-na"}
    tiles_ = "".join(f'<div class="vbt dd-card {color[k]}" role="button" tabindex="0" aria-pressed="false" data-dd="vb_{k}" '
                     f'title="{esc(L["vb_" + k + "_d"])}"><div class="v">{vb[k]}</div>'
                     f'<div class="l">{esc(L["vb_" + k])}</div></div>' for k in VB_ORDER)
    return (f'<h3 class="vb-h">{esc(L["vb_h"])}</h3><div class="vb" data-ddg="{pid}-vb" data-trk="{pid}">{tiles_}</div>'
            f'<p class="muted" style="font-size:12px;margin:6px 0 0">{esc(safe_fmt(L["vb_hint"], n=total))}</p>'
            f'<div class="dd-panel" id="{pid}-vb-dd"></div>')


def context_panel(L):
    """Business risk and decisions/asks narrative shown under Key indicators (per CVE section)."""
    asks = "".join(f"<li><b>{esc(a)}</b> {esc(b)}</li>" for a, b in L["ctx_asks"])
    return (f'<div class="ctx"><div><h3>{esc(L["ctx_risk_h"])}</h3><p>{esc(L["ctx_risk"])}</p></div>'
            f'<div><h3>{esc(L["ctx_asks_h"])}</h3><ol>{asks}</ol></div></div>')


def track_view(r, key):
    """The part of a ledger run that belongs to a track: the run itself (PHP2Shell) or its sub-block."""
    if not r:
        return None
    return r if not key else (r.get(key) if isinstance(r.get(key), dict) else None)


def track_section(tk, args, today, runs, cur_run):
    """One CVE section with every view: summary, SLA, KPIs, comparison, history, charts, plugins, tracker, findings."""
    L, A, pid, key, d0 = tk["L"], tk["A"], tk["id"], tk["key"], tk["disclosure"]
    badge = (f'<span class="badge p-{A["posture"]}">{esc(L["p_" + A["posture"]])}</span>' if A
             else f'<span class="badge p-none">{esc(L["not_collected"])}</span>')
    head = (f'<section class="trk" id="{tk["anchor"]}"><div class="sec-h"><div><h2 class="sec-t">{esc(tk["title"])}</h2>'
            f'<div class="meta">CVEs: <b>{esc(", ".join(tk["cves"]))}</b> · {esc(L["disclosure"])}: <b>{d0}</b> · '
            f'{esc(L["sla"])}: <b>{args.sla_days} {esc(L["days"])}</b></div></div>{badge}</div>')
    if A is None:
        return (head + f'<h2>{esc(L["exec_summary"])}</h2><div class="panel"><p>{esc(L["biz"])}</p>{tk.get("extra", "")}'
                f'<div class="note">{esc(tk["none_note"])}</div></div>' + context_panel(L) + '</section>')
    k = A["kpis"]
    fk = dict(open=k['open'], exposed=k['exposed_assets'], breached=k['breached'], n=args.sla_days,
              unscanned=k['unscanned'], unknown=k['unknown_assets'], d=d0)
    verdict = L["verdict_" + A["posture"]].format(**fk)
    asks = []
    if k["breached"]:
        asks.append(L["ask_breached"].format(**fk))
    if k["open"]:
        asks.append(L["ask_patch"].format(**fk))
    if k["unscanned"]:
        asks.append(L["ask_unscanned"].format(**fk))
    if k["unknown_assets"]:
        asks.append(L["ask_unknown"].format(**fk))
    if not A["dates_ok"]:
        asks.append(L["ask_nodates"])
    if not asks:
        asks.append(L["ask_none"])
    summary = (f'<h2>{esc(L["exec_summary"])}</h2><div class="panel"><p class="verdict">{esc(verdict)}</p><p>{esc(L["biz"])}</p>'
               f'{tk.get("extra", "")}<h3>{esc(L["decisions"])}</h3><ul>{"".join(f"<li>{esc(a)}</li>" for a in asks)}</ul></div>'
               + headline_strip(tk, args))

    tiles_ = "".join([
        tile(k["php_assets"], L["k_php"], "t-purple", dd="k_php"),
        tile(k["exposed_assets"], L["k_exposed"], "t-red", dd="k_exposed"),
        tile(k["open"], L["k_open"], "t-red", dd="k_open"),
        tile(k["remediated"], L["k_rem"], "t-green", dd="k_rem"),
        tile("—" if k["rate"] is None else f"{k['rate']}%", L["k_rate"], "t-green", dd="k_rate"),
        tile("—" if k["mttr"] is None else f"{k['mttr']} d", L["k_mttr"], "t-accent",
             L["mttr_vs_sla"].format(n=args.sla_days) + (" · " + (L["mttr_within"] if k["mttr"] <= args.sla_days else L["mttr_over"]) if k["mttr"] is not None else ""), dd="k_mttr"),
        tile(k["breached"], L["k_breach"], "t-orange", f"SLA {args.sla_days} {L['days']}", dd="k_breach"),
        tile(k["unscanned"], L["k_unscanned"], "t-orange", dd="k_unscanned"),
    ] + tk.get("tiles_extra", []))

    # comparison: only earlier runs that carry this track
    others = sorted((r for r in runs if r["run_id"] != cur_run["run_id"] and r.get("executed_at", "") <= cur_run["executed_at"]
                     and track_view(r, key) and track_view(r, key).get("kpis")), key=lambda r: r["executed_at"], reverse=True)
    sel = ""
    if others:
        opts = "".join(f'<option value="{esc(r["run_id"])}">{esc(r["executed_at"][:16].replace("T", " "))} UTC · {esc(r["run_id"])} · v{esc(r.get("skill_version", "?"))}{" · demo" if r.get("demo") else ""}</option>' for r in others)
        sel = f'<label class="muted">{esc(L["compare_with"])} </label><select class="cmp-sel">{opts}</select>'
    kl = {x: L[x] for x in ("k_open", "k_rem", "k_rate", "k_breach", "k_exposed", "k_mttr", "k_unscanned")}
    cmp_ = (f'<h2>{esc(L["compare"])}</h2><div class="panel cmpbox" data-key="{key}" data-pfx="{pid}" '
            f'data-kl="{esc(json.dumps(kl, ensure_ascii=False))}" data-empty="{esc(tk["cmp_empty"])}">{sel}<div class="cmp-body"></div></div>')

    # history for this track
    trk_runs = [r for r in runs if track_view(r, key)]
    hrows = ""
    for r in sorted(trk_runs, key=lambda r: r["executed_at"], reverse=True):
        t = track_view(r, key)
        kk, po = t.get("kpis", {}), t.get("posture", "")
        cls = ' class="cur"' if r["run_id"] == cur_run["run_id"] else ""
        hrows += (f'<tr{cls}><td data-s="{esc(r["executed_at"])}"><span data-ts="{esc(r["executed_at"])}">{esc(r["executed_at"])}</span></td>'
                  f'<td>{esc(r["run_id"])}{" (demo)" if r.get("demo") else ""}</td><td>v{esc(r.get("skill_version", "?"))}</td>'
                  f'<td>{f"""<span class="badge p-{esc(po)}" style="padding:1px 8px;font-size:11px">{esc(L.get("p_" + po, po))}</span>""" if po else "—"}</td>'
                  f'<td>{esc(kk.get("open", "—"))}</td><td>{esc(kk.get("remediated", "—"))}</td>'
                  f'<td>{"—" if kk.get("rate") is None else esc(kk.get("rate")) + "%"}</td><td>{esc(kk.get("breached", "—"))}</td>'
                  f'<td>{esc(kk.get("exposed_assets", "—"))}</td><td>{esc(r.get("sla_days"))} d</td></tr>')
    chron = sorted(trk_runs, key=lambda r: r["executed_at"])
    trend = ""
    if len(chron) >= 2:
        labels = [r["executed_at"][5:10] for r in chron]
        marks, prev = [], None
        for i, r in enumerate(chron):
            v = r.get("skill_version")
            if prev is not None and v != prev:
                marks.append((i, f"v{v}"))
            prev = v
        g = lambda r, x: (track_view(r, key).get("kpis", {}).get(x) or 0)
        trend = (f'<h3>{esc(L["trend"])}</h3>' + line_svg(
            [[g(r, "open") for r in chron], [g(r, "remediated") for r in chron]],
            labels, [C["red"], C["green"]], [L["open"], L["remediated"]], 200, marks))
    hist = (f'<h2>{esc(L["history"])}</h2><div class="panel"><div class="tablewrap"><table id="{pid}-hist-tbl"><thead><tr>'
            + "".join(f"<th>{esc(L[x])}</th>" for x in ("h_when", "h_run", "h_ver", "h_posture", "h_open", "h_rem", "h_rate", "h_breach", "h_assets"))
            + f'<th>SLA</th></tr></thead><tbody>{hrows}</tbody></table></div>{trend}</div>')

    tl = tk["tl"]
    if tl:
        tl_html = line_svg([[o for _, o, _ in tl], [r for _, _, r in tl]], [d.strftime("%m-%d") for d, _, _ in tl],
                           [C["red"], C["green"]], [L["open"], L["remediated"]], 240,
                           [(i, L["disclosure"]) for i, (d, _, _) in enumerate(tl) if d == d0])
    else:
        tl_html = f'<div class="note">{esc(L["no_dates"])}</div>'
    chart = (f'<h2>{esc(L["chart"])}</h2><div class="panel">{split_bar(k["open"], k["remediated"], L)}'
             f'<h3>{esc(L["timeline"])}</h3>{tl_html}</div>')

    # remediation tracker
    vk = tk["ver_key"]
    vs = sorted(A["vulns"], key=lambda v: (v["status"] != "open", -(v.get("over") or -999), v["asset"]))
    pmap = {e["plugin_id"]: e for e in tk["P"][0]}
    by_pid = {}
    for v in A["vulns"]:
        by_pid.setdefault(str(v.get("plugin_id") or ""), []).append(v)
    trows = ""
    for v in vs:
        ppid = str(v.get("plugin_id") or "")
        is_open = v["status"] == "open"
        cells = (f'<td>{"<span class=caret>▸</span> " if is_open else ""}{esc(v["asset"])}</td><td>{esc(v.get("ip"))}</td><td>{esc(prod(v.get("source")))}</td>'
                 f'<td>{esc(ppid)}</td>' + sc_td(v.get("vpr"), "vpr") + sc_td(v.get("acr"), "acr") + sc_td(v.get("aes"), "aes")
                 + f'<td>{esc(v.get(vk))}</td>'
                 f'<td><span class="pill s-{v["status"]}">{esc(L[v["status"]])}</span></td>'
                 f'<td>{esc(v["first_seen"] or L["no_first"])}</td><td>{esc(v["due"])}</td>'
                 f'<td>{esc(v["fixed"] or "")}</td><td>{esc("" if v["days_open"] is None else v["days_open"])}</td>'
                 + outcome_cell(v, L) + f'<td data-s="{esc(v.get("last_seen") or "")}">{esc(v.get("last_seen") or "")}</td>')
        if is_open:
            e = pmap.get(ppid) or {"plugin_id": ppid, "name": v.get("plugin_name", ""), "product": v.get("source", ""),
                                   "family": "", "synopsis": "", "solution": "", "see_also": [],
                                   "component": v.get("component", "")}
            trows += (f'<tr class="pl-row" tabindex="0" aria-expanded="false" data-prod="{esc(prod(v.get("source")))}">{cells}</tr>'
                      f'<tr class="pl-detail detail"><td colspan="15">'
                      + tk["detail"](e, by_pid.get(ppid, []), L, me=v["asset"]) + "</td></tr>")
        else:
            trows += f'<tr data-prod="{esc(prod(v.get("source")))}">{cells}</tr>'
    rows = tk["rows"]
    all_prods = sorted({prod(r.get("source")) for r in rows if prod(r.get("source"))})
    ttid, ftid = f"{pid}-trk-tbl", f"{pid}-fnd-tbl"
    tracker = (f'<h2>{esc(L["tracker"])}</h2><p class="hint">{esc(L["trk_click"])}</p>'
               f'<p class="muted" style="font-size:12px">{esc(L["sc_note"])}</p>' + sc_missing_note(tk.get("sc"), ("vpr", "acr", "aes"), L)
               + f'<div class="ctrls">{prod_select(ttid, all_prods, L)}'
               f'<input class="filter" placeholder="{esc(L["search"])}" data-t="{ttid}"></div>'
               f'<div class="tablewrap"><table id="{ttid}" class="dtbl"><thead><tr>'
               + "".join(f"<th>{esc(L[x])}</th>" for x in ("c_asset", "c_ip", "c_src", "c_plugin", "c_vpr", "c_acr", "c_aes", "c_ver", "c_state", "c_first",
                                                           "c_due", "c_fixed", "c_daysopen", "c_outcome", "c_last"))
               + f'</tr></thead><tbody>{trows}</tbody></table></div>')
    frows = ""
    for r in sorted(rows, key=lambda r: (r["asset"], r.get("role", ""), str(r.get("plugin_id")))):
        lab, vcls = tk["vcell"](r)
        frows += (f'<tr data-prod="{esc(prod(r.get("source")))}"><td>{esc(r["asset"])}</td><td>{esc(r.get("ip"))}</td><td>{esc(prod(r.get("source")))}</td>'
                  + sc_td(r.get("acr"), "acr") + sc_td(r.get("aes"), "aes")
                  + f'<td>{esc(r.get("plugin_id"))}</td><td class="wrap">{esc(r.get("plugin_name"))}</td>'
                  f'<td>{"".join(f"<span class=cve>{esc(c)}</span>" for c in norm_cves(r.get("cves")))}</td>'
                  + sc_td(r.get("vpr"), "vpr") + f'<td>{esc(r.get("role"))}</td>'
                  f'<td>{esc(r.get(vk))}</td><td><span class="pill s-{vcls}">{esc(lab)}</span></td>'
                  f'<td>{esc(r.get("state"))}</td><td>{esc(r.get("last_seen"))}</td></tr>')
    findings = (f'<h2>{esc(L["findings"])}</h2><div class="ctrls">{prod_select(ftid, all_prods, L)}'
                f'<input class="filter" placeholder="{esc(L["search"])}" data-t="{ftid}"></div>'
                f'<div class="tablewrap"><table id="{ftid}"><thead><tr>'
                + "".join(f"<th>{esc(L[x])}</th>" for x in ("c_asset", "c_ip", "c_src", "c_acr", "c_aes", "c_plugin", "c_name", "c_cves", "c_vpr", "c_role",
                                                           "c_ver", "c_vstatus", "c_state", "c_last"))
                + f'</tr></thead><tbody>{frows}</tbody></table></div>')
    limits = "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in tk["limits"]) + "</ul>"
    tail = (f'<h2>{esc(L["mitig"])}</h2><div class="panel">{tk["mitig"]}</div>'
            f'<h2>{esc(L["limits"])}</h2><div class="panel">{limits}</div>')
    return (head + summary + sla_section(tk, args, today) + f'<h2>{esc(L["kpis"])}</h2><p class="hint">{esc(L["dd_hint"])}</p><div class="tiles" data-ddg="{pid}-kp" data-trk="{pid}">{tiles_}</div>'
            + f'<div class="dd-panel" id="{pid}-kp-dd"></div>' + version_panel(L, tk["vb"], k["php_assets"], pid) + context_panel(L)
            + cmp_ + hist + chart + plugin_section(tk) + tracker + findings + tail
            + f'<script type="application/json" class="dd-data" data-trk="{pid}">{dd_data(tk)}</script></section>')


def build_html(tracks, runs, cur_run, args, L, version, today, executed_at, hist_src=()):
    nav = "".join(
        f'<a href="#{t["anchor"]}" class="tab" data-tab="{t["anchor"]}"><span class="tab-t">{esc(t["short"])}</span>'
        f'<span class="tab-c">{esc(" / ".join(t["cves"]))}</span>'
        + (f'<span class="badge p-{t["A"]["posture"]}">{esc(L["p_" + t["A"]["posture"]])}</span>' if t["A"]
           else f'<span class="badge p-none">{esc(L["not_collected"])}</span>') + "</a>" for t in tracks)
    srcs = "".join(f'<li><a href="{esc(u)}">{esc(t)}</a></li>' for t, u in [("Tenable Research — PHP2Shell FAQ", FAQ_URL)] + N2S_SOURCES)
    hist_json = json.dumps({"format": LEDGER_FORMAT, "skill": "php2shell-tenable-tracker", "runs": runs},
                           separators=(",", ":")).replace("</", "<\\/")
    fn = getattr(args, "file_names", {"html": "report.html", "json": "history.json"})
    export = (f'<div class="exp" role="group" aria-label="{esc(L["export"])}"><span class="exp-l">{esc(L["export"])}</span>'
              f'<button type="button" class="btn exp-b" data-export="html" title="{esc(fn["html"])}">⤓ HTML</button>'
              f'<button type="button" class="btn exp-b" data-export="json" title="{esc(fn["json"])}">⤓ JSON</button>'
              f'<span class="exp-n">{esc(fn["html"])}<br>{esc(fn["json"])}</span></div>')
    i18n_json = json.dumps(L).replace("</", "<\\/")
    banner = f'<div class="banner">{esc(args.banner)}</div>' if args.banner else ""
    return f"""<!doctype html><html lang="{esc(L.get('html_lang', 'en'))}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>PHP2Shell &amp; Node2Shell Tracker</title>
<meta name="generator" content="php2shell-tenable-tracker {esc(version)}"><style>{CSS}</style></head>
<body data-run="{esc(cur_run['run_id'])}" data-html-name="{esc(fn['html'])}" data-json-name="{esc(fn['json'])}"><div class="wrap">
<header><div><h1>{esc(L['title'])}</h1>
<div class="meta">{esc(L['executed'])}: <b data-ts="{esc(executed_at)}">{esc(executed_at)}</b> · {esc(L['run'])}: <b>{esc(cur_run['run_id'])}</b> ·
{esc(L['version'])}: <b>v{esc(version)}</b> · {esc(L['sla'])}: <b>{args.sla_days} {esc(L['days'])}</b></div></div>{export}</header>{banner}
<nav class="tabs" aria-label="{esc(L['sections'])}">{nav}</nav>
<p class="hint" style="margin-top:6px">{esc(L['tabs_hint'])}</p>
{disclaimer(runs, cur_run, args, L, hist_src)}
{''.join(track_section(t, args, today, runs, cur_run) for t in tracks)}
<h2>{esc(L['sources'])}</h2><div class="panel"><ul>{srcs}
<li>Tenable One / Tenable VM data via Tenable Hexa AI MCP ({esc(executed_at)})</li></ul></div>
<footer>php2shell-tenable-tracker v{esc(version)} · {esc(L['readonly'])}</footer></div>
<script id="run-history" type="application/json">{hist_json}</script>
<script id="i18n" type="application/json">{i18n_json}</script>
<script>{JS}</script></body></html>"""


# ---------------------------------------------------------------- language
LANG_DIR = Path(__file__).resolve().parent / "lang"


def load_lang(code, lang_file=None):
    """English is the base; built-in pt, bundled lang/<code>.json (es) or a --lang-file override it key by key."""
    L = dict(T["en"])
    code = (code or "en").strip()
    if lang_file:
        src = Path(lang_file)
    elif code in T:
        L.update(T[code]); return L
    else:
        src = LANG_DIR / f"{code.lower()}.json"
        if not src.exists():
            sys.exit(f"language '{code}' is not bundled (en, pt, es); translate the --dump-lang output and pass it with --lang-file")
    try:
        tr = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"cannot read translation {src}: {e}")
    bad = [k for k, v in tr.items() if k in T["en"] and type(v) is not type(T["en"][k])]
    if bad:
        sys.exit(f"translation {src} has the wrong type for: {', '.join(bad)}")
    L.update({k: v for k, v in tr.items() if k in T["en"]})
    if lang_file and "html_lang" not in tr:
        L["html_lang"] = code
    missing = [k for k in T["en"] if k not in tr and k != "html_lang"]
    if missing:
        print(f"lang_missing={len(missing)} (English used for: {', '.join(missing[:10])}{'…' if len(missing) > 10 else ''})")
    return L


def n2s_lang(L):
    """Strings for the Node2Shell section: the base language with the Node2Shell overrides on top."""
    over = dict(T["en"]["n2s_over"]); over.update(L.get("n2s_over") or {})
    return {**L, **over}


def write_latest(root, out, cur_run, F, pdf_ok, demo=""):
    """<reports>/latest.json: the newest run's files plus an index of every run, newest first,
    so the next run (or a person) can open the latest report without guessing."""
    path = root / f"latest{demo}.json"
    try:
        idx = json.loads(path.read_text(encoding="utf-8")).get("runs", [])
    except (OSError, json.JSONDecodeError, AttributeError):
        idx = []
    rel = lambda n: os.path.relpath(out / n, root).replace(os.sep, "/")
    me = {"run_id": cur_run["run_id"], "executed_at": cur_run["executed_at"], "stamp": cur_run["stamp"],
          "skill_version": cur_run["skill_version"], "posture": cur_run["posture"], "sla_days": cur_run["sla_days"],
          "lang": cur_run["lang"], "html": rel(F["report"]), "history": rel(F["history"]), "run": rel(F["run"]),
          "pdf": rel(F["pdf"]) if pdf_ok else None,
          "csv": {"findings": rel(F["csv"]), "plugins": rel(F["plugins"]), "changes": rel(F["changes"]),
                  "node2shell": rel(F["n2s"]), "node2shell_plugins": rel(F["n2s_plugins"])}}
    idx = [r for r in idx if isinstance(r, dict) and r.get("run_id") != me["run_id"]] + [me]
    idx.sort(key=lambda r: r.get("executed_at", ""), reverse=True)
    path.write_text(json.dumps({"skill": "php2shell-tenable-tracker", "ledger": "history" + demo + ".json",
                                "latest": idx[0], "runs": idx}, indent=1))


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings", nargs="?"); ap.add_argument("outdir", nargs="?")
    ap.add_argument("--plugins", help="plugins.json: every plugin returned by the CVE plugin search (plus inventory plugins)")
    ap.add_argument("--node2shell-findings", help="findings for CVE-2026-111497 (Node2Shell), same row format; tracked in its own section")
    ap.add_argument("--node2shell-plugins", help="plugins.json for CVE-2026-111497 (every plugin returned by the CVE plugin search)")
    ap.add_argument("--sla-days", type=int, default=None,
                    help="remediation SLA in days (default 7; record when it came from the user's policy)")
    ap.add_argument("--sla-ref", default="", help="policy reference shown in the SLA section, e.g. 'VM Policy 4.2 – Critical'")
    ap.add_argument("--lang", default="en",
                    help="report language: en, pt (Portuguese-BR), es (Spanish), or any other code together with --lang-file")
    ap.add_argument("--lang-file", help="JSON translation of the English strings (see --dump-lang) for a language not bundled; "
                    "missing keys fall back to English")
    ap.add_argument("--dump-lang", action="store_true", help="print the English strings as JSON (to translate for --lang-file) and exit")
    ap.add_argument("--history", help="ledger path (default: <outdir>/../history.json, or history.demo.json with --banner)")
    ap.add_argument("--import", dest="imports", action="append", default=[],
                    help="previous history*.json or report*.html, or a folder (its newest history is used), to merge into the ledger (repeatable)")
    ap.add_argument("--find-latest", nargs="+", metavar="PATH",
                    help="print, as JSON, the newest history file under these folders/files that can be compared against, and exit")
    ap.add_argument("--include-demo", action="store_true", help="with --find-latest: also consider demo (--banner) histories")
    ap.add_argument("--no-pdf", action="store_true")
    ap.add_argument("--banner", help="demo/test label shown on the report; marks the run as demo")
    ap.add_argument("--today", help="demo/test only: override today's date (YYYY-MM-DD)")
    ap.add_argument("--executed-at", help="demo/test only: override execution timestamp (ISO 8601)")
    args = ap.parse_args()
    if args.dump_lang:
        print(json.dumps(T["en"], ensure_ascii=False, indent=1)); return
    if args.find_latest:
        ranked = rank_history(args.find_latest, args.include_demo)
        print(json.dumps({"latest": ranked[0] if ranked else None, "candidates": ranked}, indent=1))
        return
    if not (args.findings and args.outdir):
        ap.error("findings and outdir are required")

    args.sla_source = "default" if args.sla_days is None else "user"
    if args.sla_days is None:
        args.sla_days = 7
    version = skill_version()
    L = load_lang(args.lang, args.lang_file)
    out = Path(args.outdir); out.mkdir(parents=True, exist_ok=True)
    rows = json.loads(Path(args.findings).read_text())
    if not isinstance(rows, list):
        sys.exit("findings.json must be a JSON list of rows")

    now = datetime.fromisoformat(args.executed_at) if args.executed_at else datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    executed_at = now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    today = date.fromisoformat(args.today) if args.today else now.date()
    stamp = stamp_of(executed_at)
    demo = ".demo" if args.banner else ""
    F = {k: f"{k}_{stamp}.{ext}" for k, ext in (("report", "html"), ("pdf", "pdf"), ("csv", "csv"), ("plugins", "csv"),
                                                  ("changes", "csv"), ("run", "json"))}
    F["pdf"] = f"report_{stamp}.pdf"; F["csv"] = f"report_{stamp}.csv"
    F["history"] = f"history{demo}_{stamp}.json"
    F["n2s"] = f"node2shell_{stamp}.csv"
    F["n2s_plugins"] = f"node2shell_plugins_{stamp}.csv"
    args.file_names = {"html": F["report"], "json": F["history"]}

    catalog = load_catalog(args.plugins)
    cat_cves = {p["plugin_id"]: p["cves"] for p in catalog or []}
    for r in rows:
        if not norm_cves(r.get("cves")):
            r["cves"] = cat_cves.get(str(r.get("plugin_id") or ""), [])
    sc_php = enrich_scores(rows, catalog)
    A = analyse(rows, args.sla_days, today)
    tl = timeline(A["vulns"], today)
    P = plugin_coverage(catalog, rows)
    n2s_rows = json.loads(Path(args.node2shell_findings).read_text()) if args.node2shell_findings else None
    if n2s_rows is not None and not isinstance(n2s_rows, list):
        sys.exit("node2shell findings must be a JSON list of rows")
    n2s_cat = load_catalog(args.node2shell_plugins)
    Ln = n2s_lang(L)
    An = Pn = tln = sc_n2s = None
    if n2s_rows is not None or n2s_cat is not None:
        # Node2Shell runs through the same pipeline as PHP2Shell, with its own disclosure, CVE and version logic
        n2s_rows = n2s_rows or []
        cmap = {c["plugin_id"]: c for c in n2s_cat or []}
        for r in n2s_rows:
            c = cmap.get(str(r.get("plugin_id") or "").strip(), {})
            r.setdefault("role", "vulnerable")
            r["asset"] = r.get("asset") or r.get("ip") or "unknown"
            if not norm_cves(r.get("cves")):
                r["cves"] = [N2S_CVE]
            r["version"] = r.get("version") or r.get("installed_version") or ""
            r["component"] = n2s_component(r.get("plugin_name") or c.get("name"), c.get("family", ""),
                                           r.get("component") or c.get("component"), r.get("source") or c.get("product"))
            r["target"], r["tstatus"] = n2s_target(r["component"], r["version"], Ln)
        sc_n2s = enrich_scores(n2s_rows, n2s_cat)
        An = analyse(n2s_rows, args.sla_days, today, N2S_DISCLOSURE,
                     vfn=lambda r: "unknown" if r["tstatus"] == "pending" else r["tstatus"])
        Pn = plugin_coverage(n2s_cat, n2s_rows, [N2S_CVE])
        for e in Pn[0]:
            e["component"] = n2s_component(e["name"], e.get("family", ""), e.get("component"), e.get("product"))
        tln = timeline(An["vulns"], today, N2S_DISCLOSURE)

    pcat = {e["plugin_id"]: e for e in P[0]}
    vb_php, vbc_php = version_breakdown(rows, lambda r: "backport" if plugin_kind(
        pcat.get(str(r.get("plugin_id") or ""), {"name": r.get("plugin_name", ""), "product": r.get("source", ""), "family": ""}))
        in ("distro", "unpatched") else "patch")
    vb_n2s, vbc_n2s = (version_breakdown(n2s_rows, lambda r: "backport" if r.get("component") == "distro" else "patch")
                       if An else (None, None))

    cur_run = {
        "run_id": out.name, "executed_at": executed_at, "skill_version": version,
        "ledger_format": LEDGER_FORMAT, "sla_days": args.sla_days, "sla_source": args.sla_source, "sla_ref": args.sla_ref, "disclosure": str(DISCLOSURE),
        "stamp": stamp, "folder": out.name, "files": dict(F),
        "today": str(today), "lang": args.lang, "posture": A["posture"], "dates_available": A["dates_ok"],
        "rows": len(rows), "demo": bool(args.banner), "kpis": A["kpis"],
        "findings": {v["key"]: ("o" if v["status"] == "open" else "r") for v in A["vulns"]},
        "assets": {a: ai["status"] for a, ai in A["assets"].items()},
        "plugin_summary": P[2],
        "plugins": {e["plugin_id"]: [e["open"], e["fixed"]] for e in P[0]},
        "plugin_meta": {e["plugin_id"]: [e["name"], prod(e["product"])] for e in P[0]},
        "asset_meta": {a: ai.get("ip") or "" for a, ai in A["assets"].items()},
        "plugin_vpr": {e["plugin_id"]: e.get("vpr") for e in P[0] if e.get("vpr") is not None},
        "asset_scores": {a: [ai.get("acr"), ai.get("aes")] for a, ai in A["assets"].items()
                         if ai.get("acr") is not None or ai.get("aes") is not None},
        "version_breakdown": vb_php,
    }
    if An is not None:  # separate block: never merged into the PHP2Shell findings/KPIs
        cur_run["n2s"] = {"cve": N2S_CVE, "disclosure": str(N2S_DISCLOSURE), "posture": An["posture"],
                          "dates_available": An["dates_ok"], "rows": len(n2s_rows), "kpis": An["kpis"], "version_breakdown": vb_n2s,
                          "findings": {v["key"]: ("o" if v["status"] == "open" else "r") for v in An["vulns"]},
                          "assets": {a: ai["status"] for a, ai in An["assets"].items()},
                          "plugin_summary": Pn[2],
                          "plugins": {e["plugin_id"]: [e["open"], e["fixed"]] for e in Pn[0]},
                          "plugin_meta": {e["plugin_id"]: [e["name"], prod(e["product"])] for e in Pn[0]},
                          "asset_meta": {a: ai.get("ip") or "" for a, ai in An["assets"].items()},
                          "plugin_vpr": {e["plugin_id"]: e.get("vpr") for e in Pn[0] if e.get("vpr") is not None},
                          "asset_scores": {a: [ai.get("acr"), ai.get("aes")] for a, ai in An["assets"].items()
                                           if ai.get("acr") is not None or ai.get("aes") is not None}}

    ledger = Path(args.history) if args.history else out.parent / ("history.demo.json" if args.banner else "history.json")
    imported, hist_src = [], []
    for p in args.imports:
        if Path(p).is_dir():  # a folder: continue from the newest history under it
            best = rank_history([p], bool(args.banner))
            if best:
                print(f"import_latest={best[0]['file']} newest_run={best[0]['newest_run']}")
                p = best[0]["file"]
        got = load_runs(p)
        print(f"imported={len(got)} from {p}")
        imported.append(got)
        if [r for r in got if r["run_id"] != cur_run["run_id"]]:
            hist_src.append(Path(p).name)
    existing = load_runs(ledger)
    existing = [r for r in existing if r["run_id"] != cur_run["run_id"]]  # re-render replaces
    if existing:
        hist_src.insert(0, "ledger")
    runs = merge_runs(existing, *imported, [cur_run])
    if not any(r["run_id"] == cur_run["run_id"] for r in runs):
        runs.append(cur_run)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger_text = json.dumps({"format": LEDGER_FORMAT, "skill": "php2shell-tenable-tracker", "runs": runs}, indent=1)
    ledger.write_text(ledger_text)
    (out / F["history"]).write_text(ledger_text)  # this run's own, never-overwritten copy of the history
    (out / F["run"]).write_text(json.dumps(cur_run, indent=1))

    prev = [r for r in runs if r["run_id"] != cur_run["run_id"] and r["executed_at"] <= executed_at
            and bool(r.get("demo")) == bool(args.banner)]
    prev = max(prev, key=lambda r: r["executed_at"]) if prev else None
    delta = compare(cur_run, prev) if prev and prev.get("findings") else None
    n2s_prev = [r for r in runs if r["run_id"] != cur_run["run_id"] and r["executed_at"] <= executed_at
                and bool(r.get("demo")) == bool(args.banner) and (r.get("n2s") or {}).get("findings") is not None]
    n2s_prev = max(n2s_prev, key=lambda r: r["executed_at"]) if n2s_prev else None
    n2s_delta = compare(cur_run["n2s"], n2s_prev["n2s"]) if An is not None and n2s_prev else None

    # CSVs
    with open(out / F["csv"], "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["asset", "ip", "fqdn", "source", "plugin_id", "plugin_name", "cves", "role", "php_version",
                    "version_status", "state", "finding_status", "first_seen", "sla_due", "fixed_date",
                    "days_open", "sla_outcome", "last_seen", "port", "run_id", "executed_at", "skill_version",
                    "vpr", "acr", "aes"])
        vmap = {v["key"]: v for v in A["vulns"]}
        for r in rows:
            v = vmap.get(fkey(r)) if r.get("role") == "vulnerable" else None
            w.writerow([r.get("asset"), r.get("ip"), r.get("fqdn"), r.get("source"), r.get("plugin_id"),
                        r.get("plugin_name"), " ".join(norm_cves(r.get("cves"))), r.get("role"),
                        r.get("php_version"), r["version_status"],
                        r.get("state"), v["status"] if v else "", v["first_seen"] if v and v["first_seen"] else "",
                        v["due"] if v else "", v["fixed"] if v and v["fixed"] else "",
                        "" if not v or v["days_open"] is None else v["days_open"], v["outcome"] if v and v["outcome"] else "",
                        r.get("last_seen"), r.get("port"), cur_run["run_id"], executed_at, version,
                        fmt_score(r.get("vpr"), "vpr"), fmt_score(r.get("acr"), "acr"), fmt_score(r.get("aes"), "aes")])
    with open(out / F["changes"], "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["change", "asset", "ip", "plugin", "plugin_name", "product", "baseline_run", "current_run",
                    "baseline_version", "current_version", "track", "vpr", "acr", "aes"])
        if delta:
            pm = dict(prev.get("plugin_meta") or {}); pm.update(cur_run["plugin_meta"])
            am = dict(prev.get("asset_meta") or {}); am.update(cur_run["asset_meta"])
            for kind, keys in delta.items():
                for key in keys:
                    a, p = key.split("|", 1)
                    m = pm.get(p) or ["", ""]
                    sa = cur_run["asset_scores"].get(a) or (prev.get("asset_scores") or {}).get(a) or [None, None]
                    w.writerow([kind, a, am.get(a, ""), p, m[0], m[1], prev["run_id"], cur_run["run_id"],
                                prev.get("skill_version"), version, "php2shell",
                                fmt_score(cur_run["plugin_vpr"].get(p, (prev.get("plugin_vpr") or {}).get(p)), "vpr"),
                                fmt_score(sa[0], "acr"), fmt_score(sa[1], "aes")])
        if n2s_delta:
            pb, cb = n2s_prev["n2s"], cur_run["n2s"]
            pm = dict(pb.get("plugin_meta") or {}); pm.update(cb["plugin_meta"])
            am = dict(pb.get("asset_meta") or {}); am.update(cb["asset_meta"])
            for kind, keys in n2s_delta.items():
                for key in keys:
                    a, p = key.split("|", 1)
                    m = pm.get(p) or ["", ""]
                    sa = cb["asset_scores"].get(a) or (pb.get("asset_scores") or {}).get(a) or [None, None]
                    w.writerow([kind, a, am.get(a, ""), p, m[0], m[1], n2s_prev["run_id"], cur_run["run_id"],
                                n2s_prev.get("skill_version"), version, "node2shell",
                                fmt_score(cb["plugin_vpr"].get(p, (pb.get("plugin_vpr") or {}).get(p)), "vpr"),
                                fmt_score(sa[0], "acr"), fmt_score(sa[1], "aes")])

    with open(out / F["plugins"], "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        cve_cols = list(P[2]["by_cve"])
        w.writerow(["plugin_id", "product", "name", "family", "cves"] + cve_cols +
                   ["vulnerable_findings", "fixed_findings", "assets", "plugin_status", "from_cve_search",
                    "remediation_path", "vulnerable_assets", "fixed_assets", "tenable_solution",
                    "run_id", "executed_at", "skill_version", "vpr"])
        by_pid = {}
        for v in A["vulns"]:
            by_pid.setdefault(str(v.get("plugin_id") or ""), []).append(v)
        for e in P[0]:
            w.writerow([e["plugin_id"], e["product"], e["name"], e["family"], " ".join(e["cves"])] +
                       ["yes" if c in e["cves"] else "" for c in cve_cols] +
                       [e["open"], e["fixed"], len(e["assets"]), e["status"], "yes" if e["in_catalog"] else "no",
                        plugin_kind(e),
                        " ".join(sorted({v["asset"] for v in by_pid.get(e["plugin_id"], []) if v["status"] == "open"})),
                        " ".join(sorted({v["asset"] for v in by_pid.get(e["plugin_id"], []) if v["status"] == "remediated"})),
                        e.get("solution", ""), cur_run["run_id"], executed_at, version, fmt_score(e.get("vpr"), "vpr")])

    with open(out / F["n2s"], "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cve", "asset", "ip", "fqdn", "source", "plugin_id", "plugin_name", "component", "installed_version",
                    "target_version", "version_status", "state", "finding_status", "first_seen", "sla_due", "fixed_date",
                    "days_open", "sla_outcome", "last_seen", "port", "run_id", "executed_at", "skill_version",
                    "vpr", "acr", "aes"])
        for v in (An["vulns"] if An else []):
            w.writerow([N2S_CVE, v["asset"], v.get("ip"), v.get("fqdn"), v.get("source"), v.get("plugin_id"), v.get("plugin_name"),
                        v["component"], v["version"], v["target"], v["tstatus"], v["state"], v["status"],
                        v["first_seen"] or "", v["due"], v["fixed"] or "", "" if v["days_open"] is None else v["days_open"],
                        v["outcome"] or "", v.get("last_seen"), v.get("port"), cur_run["run_id"], executed_at, version,
                        fmt_score(v.get("vpr"), "vpr"), fmt_score(v.get("acr"), "acr"), fmt_score(v.get("aes"), "aes")])

    with open(out / F["n2s_plugins"], "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["plugin_id", "product", "name", "family", "component", "cves", "vulnerable_findings", "fixed_findings",
                    "assets", "plugin_status", "from_cve_search", "vulnerable_assets", "fixed_assets", "tenable_solution",
                    "run_id", "executed_at", "skill_version", "vpr"])
        by_pid = {}
        for v in (An["vulns"] if An else []):
            by_pid.setdefault(str(v.get("plugin_id") or ""), []).append(v)
        for e in (Pn[0] if Pn else []):
            w.writerow([e["plugin_id"], e["product"], e["name"], e["family"], e["component"], " ".join(e["cves"]),
                        e["open"], e["fixed"], len(e["assets"]), e["status"], "yes" if e["in_catalog"] else "no",
                        " ".join(sorted({v["asset"] for v in by_pid.get(e["plugin_id"], []) if v["status"] == "open"})),
                        " ".join(sorted({v["asset"] for v in by_pid.get(e["plugin_id"], []) if v["status"] == "remediated"})),
                        e.get("solution", ""), cur_run["run_id"], executed_at, version, fmt_score(e.get("vpr"), "vpr")])

    php_tk = {"id": "php", "key": "", "anchor": "php2shell", "short": "PHP2Shell", "title": L["php_h"], "cves": list(CVES),
              "disclosure": DISCLOSURE, "L": L, "A": A, "P": P, "tl": tl, "rows": rows, "ver_key": "php_version",
              "detail": lambda e, vs, LL, me=None: plugin_detail(e, vs, LL, plugin_kind(e), me),
              "family": lambda e: e["family"],
              "vcell": lambda r: (L["st_" + r["version_status"]], r["version_status"]),
              "mitig": ("<ul><li><code>memory_limit=-1</code></li><li><code>session.upload_progress.enabled=0</code></li>"
                        "<li><code>fatal_error_backtraces=0</code> (PHP 8.5)</li>" f"<li>{esc(L['mitig_restart'])}</li></ul>"),
              "limits": L["limits_list"], "cmp_empty": L["no_prev"], "none_note": "", "vb": vb_php, "vbc": vbc_php, "sc": sc_php,
              "target": lambda v: target_version(v.get("php_version"), plugin_kind(pcat.get(str(v.get("plugin_id") or ""),
                  {"name": v.get("plugin_name", ""), "product": v.get("source", ""), "family": ""})), L)}
    n2s_tk = {"id": "n2s", "key": "n2s", "anchor": "node2shell", "short": "Node2Shell", "title": Ln["n2s_h"], "cves": [N2S_CVE],
              "disclosure": N2S_DISCLOSURE, "L": Ln, "A": An, "P": Pn, "tl": tln, "rows": n2s_rows or [], "ver_key": "version",
              "detail": n2s_detail,
              "family": lambda e: f'{e["family"]} · {Ln["comp_" + e["component"]]}' if e["family"] else Ln["comp_" + e["component"]],
              "vcell": lambda r: (r["target"], r["tstatus"]),
              "mitig": "<ul>" + "".join(f"<li>{x}</li>" for x in Ln["n2s_mit"]) + "</ul>",
              "limits": Ln["n2s_limits"], "cmp_empty": Ln["n2s_cmp_none"], "none_note": Ln["n2s_none"],
              "extra": (f'<p class="muted" style="font-size:12px">{esc(Ln["n2s_status"])}</p>'
                        f'<div class="note">{esc(Ln["n2s_why"])}</div>'),
              "vb": vb_n2s, "vbc": vbc_n2s, "sc": sc_n2s, "target": lambda v: (v["target"], v["tstatus"])}
    html_text = build_html([php_tk, n2s_tk], runs, cur_run, args, L, version, today, executed_at, hist_src)
    (out / F["report"]).write_text(html_text, encoding="utf-8")

    pdf = "skipped"
    if not args.no_pdf:
        if Path("/opt/pw-browsers").exists():
            os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers")
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                b = p.chromium.launch()
                pg = b.new_page(viewport={"width": 1280, "height": 900})
                pg.goto((out / F["report"]).resolve().as_uri())
                pg.evaluate("document.querySelectorAll('details.fold').forEach(d=>d.open=true);"
                            "document.querySelectorAll('section.trk').forEach(s=>s.hidden=false)")
                pg.emulate_media(media="print")
                pg.pdf(path=str(out / F["pdf"]), format="A4", landscape=True, print_background=True,
                       margin={"top": "0", "bottom": "0", "left": "0", "right": "0"}, prefer_css_page_size=True)
                b.close()
            pdf = "ok"
        except Exception as e:  # PDF is best effort; HTML/CSV are the deliverables
            pdf = f"failed ({e.__class__.__name__}: {str(e)[:120]})"

    write_latest(ledger.parent, out, cur_run, F, pdf == "ok", demo)

    k = A["kpis"]
    print(f"rows={len(rows)} findings={len(A['vulns'])} assets={k['php_assets']}")
    print(f"posture={A['posture']} open={k['open']} remediated={k['remediated']} rate={k['rate']} "
          f"mttr={k['mttr']} past_sla={k['breached']} unscanned={k['unscanned']} dates={'yes' if A['dates_ok'] else 'no'}")
    s = P[2]
    print(f"plugins={s['total']} " + " ".join(f"{c}={n}" for c, n in s["by_cve"].items())
          + f" with_vulnerable={s['with_open']} fixed_only={s['fixed_only']} no_findings={s['no_findings']}"
          + f" not_in_catalog={s['not_in_catalog']} unmatched_rows={s['unmatched_rows']}"
          + ("" if s["catalog"] else " catalog=missing"))
    if An is None:
        print("node2shell=not_collected")
    else:
        nk, ns = An["kpis"], Pn[2]
        print(f"node2shell={N2S_CVE} posture={An['posture']} open={nk['open']} remediated={nk['remediated']} rate={nk['rate']} "
              f"mttr={nk['mttr']} past_sla={nk['breached']} exposed_assets={nk['exposed_assets']} unscanned={nk['unscanned']} "
              f"dates={'yes' if An['dates_ok'] else 'no'} plugins={ns['total']} with_vulnerable={ns['with_open']} "
              f"no_findings={ns['no_findings']} unmatched_rows={ns['unmatched_rows']}" + ("" if ns["catalog"] else " catalog=missing")
              + (" delta_vs=" + n2s_prev["run_id"] + " " + " ".join(f"{kk}={len(vv)}" for kk, vv in n2s_delta.items()) if n2s_delta else " delta_vs=none"))
    print("scores php2shell " + " ".join(f"{k}={'yes' if v else 'no'}" for k, v in sc_php.items())
          + ("" if sc_n2s is None else " node2shell " + " ".join(f"{k}={'yes' if v else 'no'}" for k, v in sc_n2s.items())))
    print(f"version={version} run={cur_run['run_id']} executed_at={executed_at} ledger={ledger} runs_in_ledger={len(runs)}")
    if delta:
        print("delta_vs=" + prev["run_id"] + " " + " ".join(f"{kk}={len(vv)}" for kk, vv in delta.items())
              + (f" version_change={prev.get('skill_version')}->{version}" if prev.get("skill_version") != version else ""))
    else:
        print("delta_vs=none (first run in this ledger)")
    print(f"pdf={pdf}")
    print("files=" + " ".join(str(out / F[x]) for x in ("report", "history", "run", "csv", "plugins", "changes", "n2s", "n2s_plugins"))
          + (f" {out / F['pdf']}" if pdf == "ok" else ""))
    print(f"latest={ledger.parent / ('latest' + demo + '.json')}")


if __name__ == "__main__":
    main()
