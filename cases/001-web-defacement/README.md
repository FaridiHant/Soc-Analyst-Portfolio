# Case 001 Website Defacement

**Dataset:** Splunk BOTSv1  
**Date:** 2016-08-10, 21:37–22:30 UTC  
**Threat Group:** Po1s0n1vy  
**Target:** imreallynotbatman.com (192.168.250.70)  
**Severity:** Critical  
**Status:** Closed — Post-Incident Review

---

## What happened

Po1s0n1vy ran a targeted attack that progressed through four clean phases. They scanned with Acunetix, fingerprinted the CMS as Joomla, brute-forced the admin portal with a custom 412-password wordlist, logged in with the compromised credential, uploaded a malicious executable, and pulled a defacement image from their own infrastructure onto the target server.

The attack wasn't noisy — the brute force wordlist was short and OSINT-informed (it included a Coldplay song tied to a named employee). The defacement file came from a pre-staged dynamic DNS domain, not a throwaway IP.

---

## Key findings

**01 Admin credentials compromised**  
Password `batman` appears twice in the POST form data across 412 brute force attempts. Every other password appears once. The second occurrence is the attacker logging in.  
*Sourcetype: stream:http | Field: form_data*

**02 Website defaced**  
The web server (192.168.250.70) appears as `src_ip` initiating an outbound GET request — which it should never do. It fetched `poisonivy-is-coming-for-you-batman.jpeg` from `prankglassinebracket.jumpingcrab.com`, an attacker-controlled dynamic DNS domain.  
*Sourcetype: stream:http | Field: request, site*

**03 Malicious executable deployed**  
`3791.exe` was uploaded post-compromise. FortiGate UTM logged the filename. Sysmon EventCode=1 confirms execution and provides the MD5.  
*MD5: AAE3F5A29935E6ABCC2C2754D12A9AF0*  
*Sourcetype: fgt_utm (filename) + Sysmon (MD5)*

**04 Pre-staged infrastructure confirmed**  
23.22.63.114 was linked to `jumpingcrab.com` domains before the attack date. VirusTotal shows `MirandaTateScreensaver.scr.exe` associated with this IP — a custom spear-phishing payload with a Po1s0n1vy signature embedded in hex inside the binary.  
*SHA256: 9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8*

---

## Attacker IPs

| IP | Role | Confirmed via |
|----|------|---------------|
| 40.80.148.42 | Acunetix vulnerability scanner | stream:http src_headers + fgt_utm msg |
| 23.22.63.114 | Brute force source + C2 infrastructure | stream:http form_data + VirusTotal |

---

## IOCs

Full list in [evidence/iocs.csv](evidence/iocs.csv)

| Type | Value |
|------|-------|
| IPv4 | 40.80.148.42 |
| IPv4 | 23.22.63.114 |
| Domain | prankglassinebracket.jumpingcrab.com |
| File | poisonivy-is-coming-for-you-batman.jpeg |
| File | 3791.exe |
| File | MirandaTateScreensaver.scr.exe |
| MD5 | AAE3F5A29935E6ABCC2C2754D12A9AF0 |
| SHA256 | 9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8 |
| Credential | admin / batman (Joomla administrator) |

---

## MITRE ATT&CK

| ID | Technique | Tactic |
|----|-----------|--------|
| T1595.002 | Active Scanning: Vulnerability Scanning | Reconnaissance |
| T1592 | Gather Victim Host Information | Reconnaissance |
| T1110.001 | Brute Force: Password Guessing | Credential Access |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1059 | Command and Scripting Interpreter | Execution |
| T1491.001 | Internal Defacement | Impact |
| T1566.001 | Spear Phishing: Attachment | Initial Access (Alt TTP) |

---

## Log sources used

| Sourcetype | What it provided |
|------------|-----------------|
| stream:http | Scanner IP, all HTTP requests, brute force POST data, defacement GET |
| fgt_utm | Acunetix tool signature, 3791.exe filename |
| XmlWinEventLog (Sysmon) | 3791.exe MD5 hash (EventCode=1) |
| wineventlog:security | Post-compromise auth — partially correlated |
| fgt_traffic | Network flow confirmation at perimeter |

---

## Files in this case

```
001-web-defacement/
├── README.md                        this file
├── report/
│   └── INC-BOTSv1-2016-S1-001.pdf  full incident report
├── queries/
│   ├── 01-recon-scanner-id.spl
│   ├── 02-cms-fingerprint.spl
│   ├── 03-brute-force-analysis.spl
│   ├── 04-credential-compromise.spl
│   ├── 05-executable-upload.spl
│   └── 06-defacement-detection.spl
└── evidence/
    └── iocs.csv
```

---

## A note on the hash gotcha

This tripped me up initially. `fgt_utm` stores a `file_hash` field — that's SHA256 (64 characters). The question asking for the MD5 of `3791.exe` requires Sysmon EventCode=1, which has a separate `MD5` field. Two different fields in two different sourcetypes for the same file. Don't confuse them.
