# MITRE ATT&CK Mapping Case 001 Web Defacement

All technique mappings are evidence-based. Each one links to the specific log evidence that confirmed it, not just the general concept.

---

## Techniques Observed

### T1595.002 ( Active Scanning: Vulnerability Scanning )
**Tactic:** Reconnaissance

40.80.148.42 ran Acunetix Web Vulnerability Scanner against imreallynotbatman.com starting at 21:37 UTC. The tool was identified via two independent sources.

Evidence:
- `stream:http` — `src_headers` field: `"Acunetix Web Vulnerability Scanner - Free Edition"`
- `fgt_utm` — `msg` field: `"tools: Acunetix.Web.Vulnerability.Scanner"`

---

### T1592 ( Gather Victim Host Information )
**Tactic:** Reconnaissance

The Acunetix scan identified Joomla as the CMS platform through HTTP 200 responses on `/joomla/*` URI paths. This directly informed the next attack phase (brute forcing the Joomla admin portal).

Evidence:
- `stream:http` — `uri` field on `status=200` responses contains `/joomla/` references

---

### T1110.001 ( Brute Force: Password Guessing )
**Tactic:** Credential Access

23.22.63.114 sent 412 POST requests to `/joomla/administrator/index.php` using a custom wordlist. Average password length was 6 characters. The list included OSINT-derived entries (employee-linked Coldplay song reference).

Evidence:
- `stream:http` — `form_data` field, `rex` extraction of `passwd=` parameter
- `stats dc(password)` = 412 unique passwords
- First password: `12345678` (sorted by `_time` ascending)

---

### T1190 ( Exploit Public-Facing Application )
**Tactic:** Initial Access

The Joomla admin portal was publicly accessible without additional access controls. Following the brute force, password `batman` was confirmed via frequency analysis (count=2 vs count=1 for all other candidates). The second occurrence represents the attacker authenticating.

Evidence:
- `stream:http` — `stats count by password` on `/joomla/administrator/index.php` POSTs
- `batman` count=2, all 411 other passwords count=1

---

### T1059 ( Command and Scripting Interpreter )
**Tactic:** Execution

Following authentication, `3791.exe` was uploaded via the Joomla admin panel and executed on the target host.

Evidence:
- `fgt_utm` — `filename` field: `3791.exe` uploaded from `40.80.148.42`
- `Sysmon EventCode=1` — process creation for `3791.exe`, MD5: `AAE3F5A29935E6ABCC2C2754D12A9AF0`

Note: `fgt_utm` stores SHA256 in `file_hash`. MD5 is only available via Sysmon.

---

### T1491.001  ( Internal Defacement )
**Tactic:** Impact

The web server (192.168.250.70) initiated an outbound GET request — appearing as `src_ip` — to `prankglassinebracket.jumpingcrab.com`, fetching `poisonivy-is-coming-for-you-batman.jpeg`. This file was served as the defaced homepage.

A web server appearing as `src_ip` for an outbound GET to an external domain is an anomaly. This was found via the "Rare" question in the Explore phase.

Evidence:
- `stream:http` — `src_ip="192.168.250.70"`, `http_method=GET`, `request` and `site` fields

---

### T1566.001 ( Phishing: Spear Phishing Attachment )
**Tactic:** Initial Access (Alternate TTP)

VirusTotal enrichment of 23.22.63.114 (Po1s0n1vy infrastructure IP) reveals an associated file: `MirandaTateScreensaver.scr.exe`. This is a custom-built malware sample — the binary contains a Po1s0n1vy group signature encoded in hex in the VirusTotal community tab.

This represents a fallback TTP used by the group alongside the web attack.

Evidence:
- VirusTotal — IP 23.22.63.114 → Relations tab → `MirandaTateScreensaver.scr.exe`
- SHA256: `9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8`
- Community tab hex decodes to group signature string

---

## Attack Flow

```
Reconnaissance          Credential Access       Initial Access
T1595.002          →    T1110.001           →   T1190
Acunetix scan           412-pass BF             Joomla admin login
                        (batman)                with batman creds
                                                        ↓
                                                Execution
                                                T1059
                                                3791.exe upload
                                                        ↓
                                                Impact
                                                T1491.001
                                                Defacement deployed
```

Alternate path (spear phishing):  
`T1566.001` → MirandaTateScreensaver.scr.exe delivered via email

---

