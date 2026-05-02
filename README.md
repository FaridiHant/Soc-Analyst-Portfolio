# SOC Analyst Portfolio

Second-year cybersecurity student focusing on SOC operations — threat detection, log analysis, and incident response. This repo documents hands-on investigations using real-world datasets, written up the same way I would in an actual SOC environment.

Everything here is evidence-based. No guessing, no narrative filler — just logs, queries, and conclusions I can defend.

---

## What's in here

| Case | Scenario | Severity | Status |
|------|----------|----------|--------|
| [001 — Web Defacement](cases/001-web-defacement/) | Po1s0n1vy Group Attack on imreallynotbatman.com | Critical | Complete |
| [002 — Cerber Ransomware](cases/002-cerber-ransomware/) | Ransomware outbreak on we8105desk | Critical | In Progress |

Dataset: [Splunk Boss of the SOC v1 (BOTSv1)](https://github.com/splunk/botsv1) — a well-known open security dataset used for SOC training and CTF competitions.

---

## Skills this work covers

**SIEM & Log Analysis**
- Splunk SPL — field extraction, rex, stats, timechart, eval
- Multi-sourcetype correlation (HTTP stream, firewall, Sysmon, Windows Event Log, DNS, registry)
- Identifying gaps in log coverage before drawing conclusions

**Threat Detection**
- Vulnerability scanner fingerprinting
- Brute force detection and password analysis
- Web defacement indicators (server as src_ip anomaly)
- Ransomware behaviour patterns (file encryption telemetry, C2 DNS)

**Incident Response**
- Full attack chain reconstruction from raw logs
- Evidence-based findings (every claim has a source)
- IOC extraction and VirusTotal enrichment
- Timeline building across multiple sourcetypes

**Frameworks**
- IDEA investigation methodology (Identify, Define, Explore, Analyze)
- MITRE ATT&CK technique mapping
- TLP classification

**Tools**
- Splunk Enterprise (BOTSv1 environment)
- Python — automated PDF report generation (ReportLab)
- VirusTotal — external threat intelligence enrichment

---

## How I structure investigations

I use the IDEA methodology for every case. Short version:

1. **Identify** ->  what log sources exist, what's relevant, what's missing
2. **Define** -> map the fields across sourcetypes before writing a single query
3. **Explore** -> run the 6 universal questions (who, what, when, where, how often, rare)
4. **Analyze** -> cross-source correlation, only claim what two sources confirm

Full methodology doc is in [methodology/IDEA-framework.md](methodology/IDEA-framework.md).

---

## Repo layout

```
soc-portfolio/
├── cases/
│   ├── 001-web-defacement/
│   │   ├── README.md           case summary and findings
│   │   ├── report/             full incident report (PDF)
│   │   ├── queries/            all SPL queries, one file per investigation phase
│   │   └── evidence/           IOC list, key screenshots
│   └── 002-cerber-ransomware/
├── methodology/
│   ├── IDEA-framework.md       investigation process I follow
│   └── spl-reference.md        reusable SPL patterns
└── tools/
    └── report-generator/       Python script that builds the PDF reports
```

---

## Background

I'm building this portfolio while studying for my Security+ and working through blue team labs in my spare time. My main interest is SOC operations — specifically the analysis side, not just alert triage. I want to get good at reconstructing what actually happened from logs, not just flagging alerts.

Open to feedback, questions, or collaboration. Contact via GitHub or LinkedIn.

---

*Dataset credit: Splunk BOTSv1 — [github.com/splunk/botsv1](https://github.com/splunk/botsv1)*
