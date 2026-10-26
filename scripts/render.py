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
FALLBACK_VERSION = "2.9.0"
LEDGER_FORMAT = 1
MAX_DETAILED_RUNS = 60  # older runs keep KPIs only

DISCLOSURE = date(2026, 10, 21)
FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
CVES = ["CVE-2026-109618", "CVE-2026-109619"]
FAQ_URL = ("https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-"
           "frequently-asked-questions-about-critical-php-remote")


def skill_version():
    try:
        return (SKILL_ROOT / "VERSION").read_text().strip() or FALLBACK_VERSION
    except OSError:
        return FALLBACK_VERSION


# ---------------------------------------------------------------- i18n
T = {
 "en": {
  "title": "PHP2Shell Exposure & Remediation Tracker",
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
 },
 "pt": {
  "title": "PHP2Shell — Tracker de Exposição e Remediação",
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
        return "patched"
    return "unknown"


def esc(x):
    return html.escape("" if x is None else str(x))


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
def analyse(rows, sla_days, today):
    asset_info = {}
    for r in rows:
        a = r.get("asset") or r.get("ip") or "unknown"
        r["asset"] = a
        ai = asset_info.setdefault(a, {"ip": r.get("ip", ""), "last_seen": None, "vstat": set(),
                                       "open": 0, "rem": 0})
        ls = pdate(r.get("last_seen"))
        if ls and (not ai["last_seen"] or ls > ai["last_seen"]):
            ai["last_seen"] = ls
        r["version_status"] = version_status(r.get("php_version"))
        ai["vstat"].add(r["version_status"])

    vulns = []
    for r in rows:
        if r.get("role") != "vulnerable":
            continue
        state = (r.get("state") or "ACTIVE").upper()
        fs, fx = pdate(r.get("first_seen")), pdate(r.get("fixed_date"))
        start = max(fs, DISCLOSURE) if fs else DISCLOSURE
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
        elif "patched" in ai["vstat"]:
            ai["status"] = "patched"
        else:
            ai["status"] = "unknown"

    open_v = [v for v in vulns if v["status"] == "open"]
    rem_v = [v for v in vulns if v["status"] == "remediated"]
    breached = [v for v in open_v if v["outcome"] == "breached"]
    durations = [v["days_open"] for v in rem_v if v["days_open"] is not None]
    unscanned = [a for a, ai in asset_info.items() if not ai["last_seen"] or ai["last_seen"] < DISCLOSURE]
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


def timeline(vulns, today):
    dated = [v for v in vulns if v["first_seen"]]
    if not dated:
        return []
    start = min(min(v["first_seen"] for v in dated), DISCLOSURE)
    start = max(start, DISCLOSURE - timedelta(days=30))
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
                        "plugin_type": p.get("plugin_type") or "",
                        "synopsis": p.get("synopsis") or "", "solution": p.get("solution") or "",
                        "see_also": [u for u in (p.get("see_also") or []) if isinstance(u, str)]
                                    if not isinstance(p.get("see_also"), str)
                                    else [u for u in re.split(r"\s+", p["see_also"]) if u]})
    return out


def plugin_coverage(catalog, rows):
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
                            "assets": set(), "in_catalog": False}
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
            e["cves"] = list(CVES)  # came only from the CVE-filtered findings
        e["status"] = "vulnerable" if e["open"] else ("fixed" if e["fixed"] else "none")
    plugins.sort(key=lambda e: ({"vulnerable": 0, "fixed": 1, "none": 2}[e["status"]],
                                -(e["open"] + e["fixed"]), e["product"], e["plugin_id"]))
    by_cve = {c: sum(1 for e in plugins if c in e["cves"]) for c in sorted({c for e in plugins for c in e["cves"]} | set(CVES))}
    summary = {"total": len(plugins), "by_cve": by_cve,
               "with_open": sum(1 for e in plugins if e["status"] == "vulnerable"),
               "fixed_only": sum(1 for e in plugins if e["status"] == "fixed"),
               "no_findings": sum(1 for e in plugins if e["status"] == "none"),
               "not_in_catalog": sum(1 for e in plugins if not e["in_catalog"]),
               "unmatched_rows": unmatched, "catalog": catalog is not None}
    return plugins, inventory, summary


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
        for f in ("findings", "assets", "plugins", "plugin_meta", "asset_meta"):
            r.pop(f, None)
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
.s-at_risk{background:var(--orange)}.s-fixed{background:var(--green)}.s-none{background:var(--muted)}
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
@media print{body{background:var(--bg);-webkit-print-color-adjust:exact;print-color-adjust:exact}
th{position:static}.tablewrap{overflow:visible}input.filter{display:none}
h2{break-after:avoid}.tile,tr,.chartbox{break-inside:avoid}@page{margin:0}.wrap{padding:14mm 10mm}
tr.detail.has{display:table-row}.fold-tip{display:none!important}.scn-panel{display:block}.scn-panel[data-scn=all]{display:none}.view-p{display:none}.view-a{display:block!important}.detail-in{position:static;width:auto}tr.detail.has>td{break-inside:auto}.btn,select,.hint,.caret{display:none}}
"""

JS = r"""
(function(){
const H=JSON.parse(document.getElementById('run-history').textContent);
const L=JSON.parse(document.getElementById('i18n').textContent);
const CUR=document.body.dataset.run;
const runs=H.runs||[];
const byId=Object.fromEntries(runs.map(r=>[r.run_id,r]));
const cur=byId[CUR];
function fmt(ts){try{return new Date(ts).toLocaleString(L.html_lang||undefined);}catch(e){try{return new Date(ts).toLocaleString()}catch(_){return ts}}}
document.querySelectorAll('[data-ts]').forEach(e=>e.textContent=fmt(e.dataset.ts));
function cmp(c,b){const cf=c.findings||{},bf=b.findings||{};const r={new:[],fixed_since:[],regressed:[],still_open:[],gone:[]};
 for(const k in cf){const s=cf[k],p=bf[k];
  if(p===undefined){if(s==='o')r.new.push(k)}else if(p==='o'&&s==='r')r.fixed_since.push(k);
  else if(p==='r'&&s==='o')r.regressed.push(k);else if(p==='o'&&s==='o')r.still_open.push(k);}
 for(const k in bf){if(!(k in cf)&&bf[k]==='o')r.gone.push(k)}return r}
const KP=[['open','k_open',false],['remediated','k_rem',true],['rate','k_rate',true],['breached','k_breach',false],
 ['exposed_assets','k_exposed',false],['mttr','k_mttr',false],['unscanned','k_unscanned',false]];
function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function render(baseId){
 const box=document.getElementById('cmp-body');
 const base=byId[baseId];
 if(!cur||!base){box.innerHTML='<p class="muted">'+esc(L.no_prev)+'</p>';return}
 let notes='';
 if((base.skill_version||'?')!==(cur.skill_version||'?'))notes+='<div class="note">'+esc(L.ver_mismatch.replace('{a}',base.skill_version||'?').replace('{b}',cur.skill_version||'?'))+'</div>';
 if(base.sla_days!==cur.sla_days)notes+='<div class="note">'+esc(L.sla_mismatch.replace('{a}',base.sla_days).replace('{b}',cur.sla_days))+'</div>';
 if(!!base.demo!==!!cur.demo)notes+='<div class="note">'+esc(L.demo_mismatch)+'</div>';
 let t='<div class="tiles">';
 for(const [k,lab,good] of KP){const a=base.kpis?.[k],b=cur.kpis?.[k];
  let d='';if(a!=null&&b!=null){const x=Math.round((b-a)*10)/10;const cls=x>0?'up':x<0?'down':'flat';
   d='<div class="d '+(good?'good ':'')+cls+'">'+(x>0?'▲ +':x<0?'▼ ':'= ')+x+(k==='rate'?' pp':'')+' vs '+esc(a)+'</div>'}
  t+='<div class="tile"><div class="v">'+(b==null?'—':esc(b)+(k==='rate'?'%':''))+'</div><div class="l">'+esc(L[lab])+'</div>'+d+'</div>'}
 t+='</div>';
 if(!base.findings){box.innerHTML=notes+t+'<p class="muted">'+esc(L.kpi_only)+'</p>';return}
 const r=cmp(cur,base);const order=['new','fixed_since','regressed','still_open','gone'];
 const PM=Object.assign({},base.plugin_meta||{},cur.plugin_meta||{}),AM=Object.assign({},base.asset_meta||{},cur.asset_meta||{});
 const TC={new:'t-accent',fixed_since:'t-green',regressed:'t-red',still_open:'t-orange',gone:'t-purple',all:''};
 const all=[];for(const k of order)for(const key of r[k])all.push([k,key]);r.all=all.map(x=>x[1]);
 const card=k=>{const n=r[k].length;return '<div class="tile scn-card '+TC[k]+(n?'':' zero')+'" role="button" tabindex="0" aria-pressed="false" data-scn="'+k+'"><div class="v">'+n+'</div><div class="l">'+esc(k==='all'?L.cmp_all:L[k])+'</div></div>'};
 let c='<h3>'+esc(L.cmp_total.replace('{n}',all.length))+'</h3><p class="hint">'+esc(L.cmp_click)+'</p><div class="tiles scn">'+order.map(card).join('')+card('all')+'</div>';
 const chip=p=>{const m=PM[p]||[];return '<div class="pchip"><b>'+esc(p)+'</b>'+(m[1]?' · '+esc(m[1]):'')+(m[0]?' · '+esc(m[0]):'')+'</div>'};
 function panel(k){const items=k==='all'?all:r[k].map(x=>[k,x]);
  if(!items.length)return '<div class="scn-panel" data-scn="'+k+'"><p class="muted">'+esc(L.scn_empty)+'</p></div>';
  const byA={},byP={};for(const [kk,key] of items){const i=key.indexOf('|'),a=key.slice(0,i),p=key.slice(i+1);
   (byA[a]=byA[a]||[]).push([kk,p]);(byP[p]=byP[p]||[]).push([kk,a])}
  const pill=kk=>k==='all'?'<span class="pill s-'+kk+'">'+esc(L[kk])+'</span> ':'';
  let ra='';for(const a of Object.keys(byA).sort()){const ps=byA[a];const prods=[...new Set(ps.map(x=>(PM[x[1]]||[])[1]).filter(Boolean))];
   ra+='<tr data-prod="'+esc(prods.join(' '))+'"><td>'+esc(a)+'</td><td>'+esc(AM[a]||'')+'</td><td>'+esc(prods.join(', '))+'</td><td data-s="'+ps.length+'">'+ps.length+'</td><td class="wrap">'+ps.map(x=>'<div>'+pill(x[0])+chip(x[1])+'</div>').join('')+'</td></tr>'}
  let rp='';for(const p of Object.keys(byP).sort()){const as=byP[p];const m=PM[p]||[];
   rp+='<tr data-prod="'+esc(m[1]||'')+'"><td>'+esc(p)+'</td><td>'+esc(m[1]||'')+'</td><td class="wrap">'+esc(m[0]||'')+'</td><td data-s="'+as.length+'">'+as.length+'</td><td class="wrap">'+as.map(x=>pill(x[0])+'<span class="achip">'+esc(x[1])+(AM[x[1]]?' <span class="muted">'+esc(AM[x[1]])+'</span>':'')+'</span>').join(' ')+'</td></tr>'}
  const prods=[...new Set(items.map(x=>(PM[x[1].slice(x[1].indexOf('|')+1)]||[])[1]).filter(Boolean))].sort();
  const ps='<select data-t="cmp-'+k+'-a cmp-'+k+'-p" data-f="prod"><option value="">'+esc(L.prod_all)+'</option>'+prods.map(x=>'<option>'+esc(x)+'</option>').join('')+'</select>';
  return '<div class="scn-panel" data-scn="'+k+'"><h4><span class="pill s-'+(k==='all'?'none':k)+'">'+esc(k==='all'?L.cmp_all:L[k])+'</span> '+items.length+' · '+Object.keys(byA).length+' '+esc(L.c_assets.toLowerCase())+' · '+Object.keys(byP).length+' '+esc(L.c_plugins.toLowerCase())+'</h4>'
   +'<p class="muted" style="font-size:12px">'+esc(L[k+'_d'])+'</p>'
   +'<div class="ctrls"><span class="seg"><button type="button" class="btn on" data-view="a">'+esc(L.by_asset)+'</button><button type="button" class="btn" data-view="p">'+esc(L.by_plugin)+'</button></span>'+ps
   +'<input class="filter" data-t="cmp-'+k+'-a cmp-'+k+'-p" placeholder="'+esc(L.search)+'"></div>'
   +'<div class="view-a"><div class="tablewrap"><table id="cmp-'+k+'-a"><thead><tr><th>'+esc(L.c_asset)+'</th><th>'+esc(L.c_ip)+'</th><th>'+esc(L.c_product)+'</th><th>'+esc(L.c_findings)+'</th><th>'+esc(L.c_plugins)+'</th></tr></thead><tbody>'+ra+'</tbody></table></div></div>'
   +'<div class="view-p" hidden><div class="tablewrap"><table id="cmp-'+k+'-p"><thead><tr><th>'+esc(L.c_plugin)+'</th><th>'+esc(L.c_product)+'</th><th>'+esc(L.c_name)+'</th><th>'+esc(L.c_findings)+'</th><th>'+esc(L.c_assets)+'</th></tr></thead><tbody>'+rp+'</tbody></table></div></div></div>'}
 box.innerHTML=notes+t+c+[...order,'all'].map(panel).join('')+'<p class="muted" style="font-size:12px">'+esc(L.gone_note)+'</p>';
 const cards=box.querySelectorAll('.scn-card');
 function pick(k){cards.forEach(x=>{const on=x.dataset.scn===k&&x.getAttribute('aria-pressed')!=='true';x.setAttribute('aria-pressed',on?'true':'false')});
  const act=[...cards].find(x=>x.getAttribute('aria-pressed')==='true');
  box.querySelectorAll('.scn-panel').forEach(pn=>pn.classList.toggle('open',!!act&&pn.dataset.scn===act.dataset.scn));
  if(act)box.querySelector('.scn-panel.open').scrollIntoView({block:'nearest',behavior:'smooth'})}
 cards.forEach(x=>{x.addEventListener('click',()=>pick(x.dataset.scn));x.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();pick(x.dataset.scn)}})});
 box.querySelectorAll('.scn-panel').forEach(pn=>pn.querySelectorAll('[data-view]').forEach(bt=>bt.addEventListener('click',()=>{
  pn.querySelectorAll('[data-view]').forEach(z=>z.classList.toggle('on',z===bt));
  pn.querySelector('.view-a').hidden=bt.dataset.view!=='a';pn.querySelector('.view-p').hidden=bt.dataset.view!=='p'})));
 wire();
}
const sel=document.getElementById('cmp-sel');
if(sel){sel.addEventListener('change',()=>render(sel.value));render(sel.value)}
else{document.getElementById('cmp-body').innerHTML='<p class="muted">'+esc(L.no_prev)+'</p>'}
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
  const tb=th.closest('table').tBodies[0];const i=[...th.parentNode.children].indexOf(th);const asc=th.dataset.asc!=='1';th.dataset.asc=asc?'1':'0';
  const main=[...tb.rows].filter(r=>!r.classList.contains('detail'));
  const det=new Map(main.map(r=>{const d=r.nextElementSibling;return [r,d&&d.classList.contains('detail')?d:null]}));
  main.sort((a,b)=>{const x=a.cells[i]?.dataset.s??a.cells[i]?.textContent??'',y=b.cells[i]?.dataset.s??b.cells[i]?.textContent??'';
   const nx=parseFloat(x),ny=parseFloat(y);const r=(!isNaN(nx)&&!isNaN(ny))?nx-ny:x.localeCompare(y);return asc?r:-r})
   .forEach(r=>{tb.appendChild(r);const d=det.get(r);if(d)tb.appendChild(d)})})})}
wire();
function toggle(tr,open){const d=tr.nextElementSibling;if(!d||!d.classList.contains('detail'))return;
 const o=open===undefined?!d.classList.contains('open'):open;d.classList.toggle('open',o);tr.setAttribute('aria-expanded',o?'true':'false');const cr=tr.querySelector('.caret');if(cr)cr.textContent=o?'▾':'▸'}
document.querySelectorAll('tr.pl-row').forEach(tr=>{tr.addEventListener('click',e=>{if(e.target.closest('a'))return;toggle(tr)});
 tr.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();toggle(tr)}})});
window.addEventListener('beforeprint',()=>document.querySelectorAll('details.fold').forEach(d=>d.open=true));
function sizeD(){document.querySelectorAll('#pl-tbl,#trk-tbl').forEach(t=>{const w=t.closest('.tablewrap');w.style.setProperty('--dw',(w.clientWidth-3)+'px')})}
sizeD();window.addEventListener('resize',sizeD);
document.querySelectorAll('[data-act]').forEach(b=>b.addEventListener('click',()=>{const o=b.dataset.act==='expand';
 b.closest('.panel').querySelectorAll('tr.pl-row').forEach(tr=>{if(tr.style.display!=='none')toggle(tr,o)})}));
})();
"""


def tile(v, label, cls="", sub=""):
    return (f'<div class="tile {cls}"><div class="v">{esc(v)}</div><div class="l">{esc(label)}</div>'
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
                f'<td>{esc(prod(v.get("source")))}</td><td>{esc(v.get("port") or "")}</td>'
                f'<td>{esc(v.get("php_version") or "—")} <span class="pill s-{vst}">{esc(L["st_"+vst])}</span></td>'
                f'<td><span class="pill s-{tcls}">{esc(tgt)}</span></td><td>{esc(v.get("state"))}</td>'
                f'<td>{esc(v["first_seen"] or L["no_first"])}</td><td>{esc(v["due"])}</td>'
                f'<td>{esc("" if v["days_open"] is None else v["days_open"])}</td>' + outcome_cell(v, L)
                + f'<td>{esc(v.get("last_seen"))}</td></tr>')

    def frow(v):
        return (tr(v) + f'<td>{esc(v["asset"])}</td><td>{esc(v.get("ip"))}</td><td>{esc(v.get("fqdn"))}</td>'
                f'<td>{esc(prod(v.get("source")))}</td><td>{esc(v.get("php_version") or "—")}</td>'
                f'<td>{esc(v["first_seen"] or L["no_first"])}</td><td>{esc(v["fixed"] or "")}</td>'
                f'<td>{esc("" if v["days_open"] is None else v["days_open"])}</td>' + outcome_cell(v, L)
                + f'<td>{esc(v.get("last_seen"))}</td></tr>')

    vh = "".join(f"<th>{esc(L[k])}</th>" for k in ("c_asset", "c_ip", "c_fqdn", "c_src", "c_port", "c_ver",
                                                    "c_target", "c_state", "c_first", "c_due", "c_daysopen",
                                                    "c_outcome", "c_last"))
    fh = "".join(f"<th>{esc(L[k])}</th>" for k in ("c_asset", "c_ip", "c_fqdn", "c_src", "c_ver", "c_first",
                                                    "c_fixed", "c_daysopen", "c_outcome", "c_last"))
    vt = (f'<div class="tablewrap"><table class="sub"><thead><tr>{vh}</tr></thead><tbody>{"".join(map(vrow, open_v))}</tbody></table></div>'
          if open_v else f'<p class="muted">{esc(L["d_empty"])}</p>')
    ft = (f'<div class="tablewrap"><table class="sub"><thead><tr>{fh}</tr></thead><tbody>{"".join(map(frow, fix_v))}</tbody></table></div>'
          if fix_v else f'<p class="muted">{esc(L["d_empty"])}</p>')

    info = ""
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


def plugin_section(P, L, A):
    plugins, inventory, s = P
    cves = list(s["by_cve"])
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
    notes += f'<p class="hint">{esc(L["pl_click"])}</p>'
    opts = f'<option value="">{esc(L["pl_all"])}</option>' + "".join(f'<option>{esc(c)}</option>' for c in cves)
    sopts = f'<option value="">{esc(L["pl_any"])}</option>' + "".join(
        f'<option value="{k}">{esc(L["ps_" + k])}</option>' for k in ("vulnerable", "fixed", "none"))
    prods = sorted({prod(e["product"]) for e in plugins if prod(e["product"])})
    ctrls = (f'<div class="ctrls">{prod_select("pl-tbl", prods, L)}'
             f'<select data-t="pl-tbl" data-f="cves">{opts}</select><select data-t="pl-tbl" data-f="st">{sopts}</select>'
             f'<input class="filter" data-t="pl-tbl" placeholder="{esc(L["search"])}">'
             f'<button type="button" class="btn" data-act="expand">{esc(L["pl_expand"])}</button>'
             f'<button type="button" class="btn" data-act="collapse">{esc(L["pl_collapse"])}</button></div>')
    trs = ""
    for e in plugins:
        extra = "" if e["in_catalog"] else f' <span class="muted" title="{esc(L["pl_extra"])}">*</span>'
        kind = plugin_kind(e)
        pr = prod(e["product"])
        has = " has" if (e["open"] or e["fixed"]) else ""
        trs += (f'<tr class="pl-row" tabindex="0" aria-expanded="false" data-prod="{esc(pr)}" '
                f'data-cves="{esc(" ".join(e["cves"]))}" data-st="{e["status"]}">'
                f'<td><span class="caret">▸</span> {esc(e["plugin_id"])}{extra}</td><td>{esc(pr)}</td>'
                f'<td class="wrap">{esc(e["name"])}</td><td>{esc(e["family"])}</td>'
                f'<td>{"".join(f"<span class=cve>{esc(c)}</span>" for c in e["cves"])}</td>'
                f'<td data-s="{e["open"]}">{e["open"]}</td><td data-s="{e["fixed"]}">{e["fixed"]}</td>'
                f'<td data-s="{len(e["assets"])}">{len(e["assets"])}</td>'
                f'<td><span class="pill s-{e["status"]}">{esc(L["ps_" + e["status"]])}</span></td></tr>'
                f'<tr class="pl-detail detail{has}"><td colspan="9">'
                + plugin_detail(e, by_pid.get(e["plugin_id"], []), L, kind) + '</td></tr>')
    table = (f'<div class="tablewrap"><table id="pl-tbl"><thead><tr><th>{esc(L["c_plugin"])}</th>'
             f'<th>{esc(L["c_product"])}</th><th>{esc(L["c_name"])}</th><th>{esc(L["c_family"])}</th>'
             f'<th>{esc(L["c_cves"])}</th><th>{esc(L["c_vuln_n"])}</th><th>{esc(L["c_fixed_n"])}</th>'
             f'<th>{esc(L["c_assets_n"])}</th><th>{esc(L["c_pstatus"])}</th></tr></thead><tbody>{trs}</tbody></table></div>')
    if s["not_in_catalog"]:
        table += f'<p class="muted" style="font-size:12px">* {esc(L["pl_extra"])}</p>'
    inv = ""
    if inventory:
        inv = (f'<h3>{esc(L["inv_plugins"])}</h3><p class="muted">'
               + ", ".join(f'{esc(e["plugin_id"])} — {esc(e["name"])}' for e in inventory) + "</p>")
    return (f'<h2>{esc(L["plugins"])}</h2><div class="tiles">{tiles_}</div>'
            f'<div class="panel" style="margin-top:10px">{notes}{ctrls}{table}{inv}</div>')


def sla_section(A, args, L, today):
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

    # worked example from this run's data: prefer a finding first seen before disclosure
    ex = ""
    dated = [v for v in vulns if v["first_seen"]]
    pick = next((v for v in dated if v["first_seen"] < DISCLOSURE), dated[0] if dated else None)
    if pick:
        cs = max(pick["first_seen"], DISCLOSURE)
        if pick["status"] == "open":
            over = pick["over"]
            o = (L["breached"].format(n=over) if over > 0 else L["due_today"] if over == 0 else L["due_in"].format(n=-over))
            st = L["sla_ex_open"].format(t=today, o=o)
        else:
            st = L["sla_ex_fixed"].format(fx=pick["fixed"] or "—", o=L.get(pick["outcome"] or "", "—"))
        ex = (f'<h3>{esc(L["sla_ex_h"])}</h3><p class="formula">' + esc(L["sla_ex"].format(
            a=pick["asset"], p=pick.get("plugin_id") or "—", fs=pick["first_seen"], cs=cs, due=pick["due"], state=st)) + "</p>")
    nodates = "" if A["dates_ok"] else f'<div class="note">{esc(L["sla_nodates"].format(d=DISCLOSURE))}</div>'

    li = lambda xs: "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in xs) + "</ul>"
    out_rows = "".join(f"<tr><td><b>{esc(a)}</b></td><td class=\"wrap\">{esc(b)}</td></tr>" for a, b in L["sla_out"])
    formulas = "".join(f'<div class="formula">{esc(f.format(n=n))}</div>' for f in L["sla_f"])
    summary = L["sla_sum"].format(n=n, d=DISCLOSURE,
                                  src=L["sla_sum_user" if args.sla_source == "user" else "sla_sum_default"]
                                  + (f" ({args.sla_ref})" if args.sla_ref else ""))
    basis = (f'<details class="fold" id="sla-basis"><summary><h2>{esc(L["sla_h"])}</h2>'
             f'<span class="fold-sum">{esc(summary)}</span><span class="fold-tip">{esc(L["sla_toggle"])}</span></summary>'
             f'<div class="panel">'
             f'<p>{esc(L["sla_intro"].format(n=n))}</p>'
             f'<div class="dgrid"><div><h3>{esc(L["sla_src_h"])}</h3><p>{esc(src)}</p>'
             f'<h3>{esc(L["sla_clock_h"])}</h3>{li([x.format(d=DISCLOSURE) for x in L["sla_clock"]])}</div>'
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


def build_html(A, rows, runs, cur_run, args, L, version, today, executed_at, tl, P, hist_src=()):
    k = A["kpis"]
    lang = args.lang
    pl = L["p_" + A["posture"]]
    # verdict + business paragraph
    fk = dict(open=k['open'], exposed=k['exposed_assets'], breached=k['breached'], n=args.sla_days,
              unscanned=k['unscanned'], unknown=k['unknown_assets'], d=DISCLOSURE)
    verdict = L["verdict_" + A["posture"]].format(**fk)
    biz = L["biz"]
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

    tiles = "".join([
        tile(k["php_assets"], L["k_php"], "t-purple"),
        tile(k["exposed_assets"], L["k_exposed"], "t-red"),
        tile(k["open"], L["k_open"], "t-red"),
        tile(k["remediated"], L["k_rem"], "t-green"),
        tile("—" if k["rate"] is None else f"{k['rate']}%", L["k_rate"], "t-green"),
        tile("—" if k["mttr"] is None else f"{k['mttr']} d", L["k_mttr"], "t-accent",
             L["mttr_vs_sla"].format(n=args.sla_days) + (" · " + (L["mttr_within"] if k["mttr"] <= args.sla_days else L["mttr_over"]) if k["mttr"] is not None else "")),
        tile(k["breached"], L["k_breach"], "t-orange", f"SLA {args.sla_days} {L['days']}"),
        tile(k["unscanned"], L["k_unscanned"], "t-orange"),
    ])

    # comparison selector
    others = [r for r in runs if r["run_id"] != cur_run["run_id"] and r.get("executed_at", "") <= cur_run["executed_at"]]
    others = sorted(others, key=lambda r: r["executed_at"], reverse=True)
    if others:
        opts = "".join(f'<option value="{esc(r["run_id"])}">{esc(r["executed_at"][:16].replace("T"," "))} UTC · {esc(r["run_id"])} · v{esc(r.get("skill_version","?"))}{" · demo" if r.get("demo") else ""}</option>' for r in others)
        cmp_ctrl = f'<label class="muted">{esc(L["compare_with"])} </label><select id="cmp-sel">{opts}</select>'
    else:
        cmp_ctrl = ""

    # history table + trend
    hrows = ""
    for r in sorted(runs, key=lambda r: r["executed_at"], reverse=True):
        kk = r.get("kpis", {})
        cls = ' class="cur"' if r["run_id"] == cur_run["run_id"] else ""
        hrows += (f'<tr{cls}><td data-s="{esc(r["executed_at"])}"><span data-ts="{esc(r["executed_at"])}">{esc(r["executed_at"])}</span></td>'
                  f'<td>{esc(r["run_id"])}{" (demo)" if r.get("demo") else ""}</td><td>v{esc(r.get("skill_version","?"))}</td>'
                  f'<td><span class="badge p-{esc(r.get("posture",""))}" style="padding:1px 8px;font-size:11px">{esc(L.get("p_"+r.get("posture",""), r.get("posture","")))}</span></td>'
                  f'<td>{esc(kk.get("open"))}</td><td>{esc(kk.get("remediated"))}</td>'
                  f'<td>{"—" if kk.get("rate") is None else esc(kk.get("rate"))+"%"}</td><td>{esc(kk.get("breached"))}</td>'
                  f'<td>{esc(kk.get("exposed_assets"))}</td><td>{esc(r.get("sla_days"))} d</td></tr>')
    chron = sorted(runs, key=lambda r: r["executed_at"])
    trend = ""
    if len(chron) >= 2:
        labels = [r["executed_at"][5:10] for r in chron]
        marks, prev = [], None
        for i, r in enumerate(chron):
            v = r.get("skill_version")
            if prev is not None and v != prev:
                marks.append((i, f"v{v}"))
            prev = v
        trend = (f'<h3>{esc(L["trend"])}</h3>' + line_svg(
            [[r.get("kpis", {}).get("open") or 0 for r in chron], [r.get("kpis", {}).get("remediated") or 0 for r in chron]],
            labels, [C["red"], C["green"]], [L["open"], L["remediated"]], 200, marks))

    # timeline
    if tl:
        tl_html = line_svg([[o for _, o, _ in tl], [r for _, _, r in tl]], [d.strftime("%m-%d") for d, _, _ in tl],
                           [C["red"], C["green"]], [L["open"], L["remediated"]], 240,
                           [(i, L["disclosure"]) for i, (d, _, _) in enumerate(tl) if d == DISCLOSURE])
    else:
        tl_html = f'<div class="note">{esc(L["no_dates"])}</div>'

    # tracker
    vs = sorted(A["vulns"], key=lambda v: (v["status"] != "open", -(v.get("over") or -999), v["asset"]))
    pmap = {e["plugin_id"]: e for e in P[0]}
    by_pid = {}
    for v in A["vulns"]:
        by_pid.setdefault(str(v.get("plugin_id") or ""), []).append(v)
    trows = ""
    for v in vs:
        pid = str(v.get("plugin_id") or "")
        is_open = v["status"] == "open"
        cells = (f'<td>{"<span class=caret>▸</span> " if is_open else ""}{esc(v["asset"])}</td><td>{esc(v.get("ip"))}</td><td>{esc(prod(v.get("source")))}</td>'
                 f'<td>{esc(pid)}</td><td>{esc(v.get("php_version"))}</td>'
                 f'<td><span class="pill s-{v["status"]}">{esc(L[v["status"]])}</span></td>'
                 f'<td>{esc(v["first_seen"] or L["no_first"])}</td><td>{esc(v["due"])}</td>'
                 f'<td>{esc(v["fixed"] or "")}</td><td>{esc("" if v["days_open"] is None else v["days_open"])}</td>'
                 + outcome_cell(v, L) + f'<td data-s="{esc(v.get("last_seen") or "")}">{esc(v.get("last_seen") or "")}</td>')
        if is_open:
            e = pmap.get(pid) or {"plugin_id": pid, "name": v.get("plugin_name", ""), "product": v.get("source", ""),
                                  "family": "", "synopsis": "", "solution": "", "see_also": []}
            trows += (f'<tr class="pl-row" tabindex="0" aria-expanded="false" data-prod="{esc(prod(v.get("source")))}">{cells}</tr>'
                      f'<tr class="pl-detail detail"><td colspan="12">'
                      + plugin_detail(e, by_pid.get(pid, []), L, plugin_kind(e), me=v["asset"]) + "</td></tr>")
        else:
            trows += f'<tr data-prod="{esc(prod(v.get("source")))}">{cells}</tr>'

    frows = ""
    for r in sorted(rows, key=lambda r: (r["asset"], r.get("role", ""), str(r.get("plugin_id")))):
        vs_ = r["version_status"]
        frows += (f'<tr data-prod="{esc(prod(r.get("source")))}"><td>{esc(r["asset"])}</td><td>{esc(r.get("ip"))}</td><td>{esc(prod(r.get("source")))}</td>'
                  f'<td>{esc(r.get("plugin_id"))}</td><td class="wrap">{esc(r.get("plugin_name"))}</td>'
                  f'<td>{"".join(f"<span class=cve>{esc(c)}</span>" for c in norm_cves(r.get("cves")))}</td><td>{esc(r.get("role"))}</td>'
                  f'<td>{esc(r.get("php_version"))}</td><td><span class="pill s-{vs_}">{esc(L["st_"+vs_])}</span></td>'
                  f'<td>{esc(r.get("state"))}</td><td>{esc(r.get("last_seen"))}</td></tr>')


    mitig = ("<ul><li><code>memory_limit=-1</code></li><li><code>session.upload_progress.enabled=0</code></li>"
             "<li><code>fatal_error_backtraces=0</code> (PHP 8.5)</li>"
             f"<li>{esc(L['mitig_restart'])}</li></ul>")
    limits = "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in L["limits_list"]) + "</ul>"

    all_prods = sorted({prod(r.get("source")) for r in rows if prod(r.get("source"))})
    hist_json = json.dumps({"format": LEDGER_FORMAT, "runs": runs}, separators=(",", ":")).replace("</", "<\\/")
    i18n_json = json.dumps(L).replace("</", "<\\/")
    banner = f'<div class="banner">{esc(args.banner)}</div>' if args.banner else ""

    return f"""<!doctype html><html lang="{esc(L.get('html_lang', 'en'))}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>PHP2Shell Tracker</title>
<meta name="generator" content="php2shell-tenable-tracker {esc(version)}"><style>{CSS}</style></head>
<body data-run="{esc(cur_run['run_id'])}"><div class="wrap">
<header><div><h1>{esc(L['title'])}</h1>
<div class="meta">{esc(L['executed'])}: <b data-ts="{esc(executed_at)}">{esc(executed_at)}</b> · {esc(L['run'])}: <b>{esc(cur_run['run_id'])}</b> ·
{esc(L['version'])}: <b>v{esc(version)}</b> · {esc(L['sla'])}: <b>{args.sla_days} {esc(L['days'])}</b> · {esc(L['disclosure'])}: <b>{DISCLOSURE}</b> · CVEs: <b>{', '.join(CVES)}</b></div></div>
<span class="badge p-{A['posture']}">{esc(pl)}</span></header>{banner}
{disclaimer(runs, cur_run, args, L, hist_src)}
<h2>{esc(L['exec_summary'])}</h2><div class="panel"><p class="verdict">{esc(verdict)}</p><p>{esc(biz)}</p>
<h3>{esc(L['decisions'])}</h3><ul>{''.join(f'<li>{esc(a)}</li>' for a in asks)}</ul></div>
{sla_section(A, args, L, today)}
<h2>{esc(L['kpis'])}</h2><div class="tiles">{tiles}</div>
<h2>{esc(L['compare'])}</h2><div class="panel">{cmp_ctrl}<div id="cmp-body"></div></div>
<h2>{esc(L['history'])}</h2><div class="panel">
<div class="tablewrap"><table id="hist-tbl"><thead><tr><th>{esc(L['h_when'])}</th><th>{esc(L['h_run'])}</th><th>{esc(L['h_ver'])}</th>
<th>{esc(L['h_posture'])}</th><th>{esc(L['h_open'])}</th><th>{esc(L['h_rem'])}</th><th>{esc(L['h_rate'])}</th><th>{esc(L['h_breach'])}</th>
<th>{esc(L['h_assets'])}</th><th>SLA</th></tr></thead><tbody>{hrows}</tbody></table></div>{trend}</div>
<h2>{esc(L['chart'])}</h2><div class="panel">{split_bar(k['open'], k['remediated'], L)}<h3>{esc(L['timeline'])}</h3>{tl_html}</div>
{plugin_section(P, L, A)}
<h2>{esc(L['tracker'])}</h2><p class="hint">{esc(L['trk_click'])}</p><div class="ctrls">{prod_select("trk-tbl", all_prods, L)}<input class="filter" placeholder="{esc(L['search'])}" data-t="trk-tbl"></div>
<div class="tablewrap"><table id="trk-tbl"><thead><tr><th>{esc(L['c_asset'])}</th><th>{esc(L['c_ip'])}</th><th>{esc(L['c_src'])}</th>
<th>{esc(L['c_plugin'])}</th><th>{esc(L['c_ver'])}</th><th>{esc(L['c_state'])}</th><th>{esc(L['c_first'])}</th><th>{esc(L['c_due'])}</th>
<th>{esc(L['c_fixed'])}</th><th>{esc(L['c_daysopen'])}</th><th>{esc(L['c_outcome'])}</th><th>{esc(L['c_last'])}</th></tr></thead><tbody>{trows}</tbody></table></div>
<h2>{esc(L['findings'])}</h2><div class="ctrls">{prod_select("fnd-tbl", all_prods, L)}<input class="filter" placeholder="{esc(L['search'])}" data-t="fnd-tbl"></div>
<div class="tablewrap"><table id="fnd-tbl"><thead><tr><th>{esc(L['c_asset'])}</th><th>{esc(L['c_ip'])}</th><th>{esc(L['c_src'])}</th>
<th>{esc(L['c_plugin'])}</th><th>{esc(L['c_name'])}</th><th>{esc(L['c_cves'])}</th><th>{esc(L['c_role'])}</th><th>{esc(L['c_ver'])}</th><th>{esc(L['c_vstatus'])}</th>
<th>{esc(L['c_state'])}</th><th>{esc(L['c_last'])}</th></tr></thead><tbody>{frows}</tbody></table></div>
<h2>{esc(L['mitig'])}</h2><div class="panel">{mitig}</div>
<h2>{esc(L['limits'])}</h2><div class="panel">{limits}</div>
<h2>{esc(L['sources'])}</h2><div class="panel"><ul><li><a href="{FAQ_URL}">Tenable Research — PHP2Shell FAQ</a></li>
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
          "csv": {"findings": rel(F["csv"]), "plugins": rel(F["plugins"]), "changes": rel(F["changes"])}}
    idx = [r for r in idx if isinstance(r, dict) and r.get("run_id") != me["run_id"]] + [me]
    idx.sort(key=lambda r: r.get("executed_at", ""), reverse=True)
    path.write_text(json.dumps({"skill": "php2shell-tenable-tracker", "ledger": "history" + demo + ".json",
                                "latest": idx[0], "runs": idx}, indent=1))


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings", nargs="?"); ap.add_argument("outdir", nargs="?")
    ap.add_argument("--plugins", help="plugins.json: every plugin returned by the CVE plugin search (plus inventory plugins)")
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
    args.file_names = {"html": F["report"], "json": F["history"]}

    catalog = load_catalog(args.plugins)
    cat_cves = {p["plugin_id"]: p["cves"] for p in catalog or []}
    for r in rows:
        if not norm_cves(r.get("cves")):
            r["cves"] = cat_cves.get(str(r.get("plugin_id") or ""), [])
    A = analyse(rows, args.sla_days, today)
    tl = timeline(A["vulns"], today)
    P = plugin_coverage(catalog, rows)

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
    }

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

    # CSVs
    with open(out / F["csv"], "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["asset", "ip", "fqdn", "source", "plugin_id", "plugin_name", "cves", "role", "php_version",
                    "version_status", "state", "finding_status", "first_seen", "sla_due", "fixed_date",
                    "days_open", "sla_outcome", "last_seen", "port", "run_id", "executed_at", "skill_version"])
        vmap = {v["key"]: v for v in A["vulns"]}
        for r in rows:
            v = vmap.get(fkey(r)) if r.get("role") == "vulnerable" else None
            w.writerow([r.get("asset"), r.get("ip"), r.get("fqdn"), r.get("source"), r.get("plugin_id"),
                        r.get("plugin_name"), " ".join(norm_cves(r.get("cves"))), r.get("role"),
                        r.get("php_version"), r["version_status"],
                        r.get("state"), v["status"] if v else "", v["first_seen"] if v and v["first_seen"] else "",
                        v["due"] if v else "", v["fixed"] if v and v["fixed"] else "",
                        "" if not v or v["days_open"] is None else v["days_open"], v["outcome"] if v and v["outcome"] else "",
                        r.get("last_seen"), r.get("port"), cur_run["run_id"], executed_at, version])
    with open(out / F["changes"], "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["change", "asset", "ip", "plugin", "plugin_name", "product", "baseline_run", "current_run",
                    "baseline_version", "current_version"])
        if delta:
            pm = dict(prev.get("plugin_meta") or {}); pm.update(cur_run["plugin_meta"])
            am = dict(prev.get("asset_meta") or {}); am.update(cur_run["asset_meta"])
            for kind, keys in delta.items():
                for key in keys:
                    a, p = key.split("|", 1)
                    m = pm.get(p) or ["", ""]
                    w.writerow([kind, a, am.get(a, ""), p, m[0], m[1], prev["run_id"], cur_run["run_id"],
                                prev.get("skill_version"), version])

    with open(out / F["plugins"], "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        cve_cols = list(P[2]["by_cve"])
        w.writerow(["plugin_id", "product", "name", "family", "cves"] + cve_cols +
                   ["vulnerable_findings", "fixed_findings", "assets", "plugin_status", "from_cve_search",
                    "remediation_path", "vulnerable_assets", "fixed_assets", "tenable_solution",
                    "run_id", "executed_at", "skill_version"])
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
                        e.get("solution", ""), cur_run["run_id"], executed_at, version])

    html_text = build_html(A, rows, runs, cur_run, args, L, version, today, executed_at, tl, P, hist_src)
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
                pg.evaluate("document.querySelectorAll('details.fold').forEach(d=>d.open=true)")
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
    print(f"version={version} run={cur_run['run_id']} executed_at={executed_at} ledger={ledger} runs_in_ledger={len(runs)}")
    if delta:
        print("delta_vs=" + prev["run_id"] + " " + " ".join(f"{kk}={len(vv)}" for kk, vv in delta.items())
              + (f" version_change={prev.get('skill_version')}->{version}" if prev.get("skill_version") != version else ""))
    else:
        print("delta_vs=none (first run in this ledger)")
    print(f"pdf={pdf}")
    print("files=" + " ".join(str(out / F[x]) for x in ("report", "history", "run", "csv", "plugins", "changes"))
          + (f" {out / F['pdf']}" if pdf == "ok" else ""))
    print(f"latest={ledger.parent / ('latest' + demo + '.json')}")


if __name__ == "__main__":
    main()
