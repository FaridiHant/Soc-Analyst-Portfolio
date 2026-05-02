# IDEA Investigation Methodology

This is the framework I follow for every investigation in this portfolio. It comes from the Splunk threat hunting methodology and forces a structured approach — log coverage first, field mapping second, anomaly hunting third, conclusions last.

The reason I use it is simple: you can't analyze logs you don't know exist, and you can't write correct queries against fields you haven't mapped. Most investigation mistakes happen before the analysis phase even starts.

---

## The four phases

### I —> Identify

Before touching a single query, document what log sources are available and what each one covers.

The goal is to know your visibility ceiling. If wineventlog:security isn't in your environment, you can't conclude anything about Windows authentication. Document that gap so your findings don't overstate the evidence.

**What I record:**

```
Sourcetype             | Relevant? | What it provides         | Gaps
-----------------------|-----------|--------------------------|---------------------------
stream:http            | YES       | Full HTTP request/resp   | No payload decryption
fgt_utm                | YES       | IPS/AV/UTM alerts        | No raw packet data
XmlWinEventLog (Sysmon)| YES       | Process + file telemetry | Only on Windows hosts
wineventlog:security   | PARTIAL   | Auth events              | Not correlated this case
stream:dns             | YES       | DNS query log            | No response bodies
stream:smb             | NO        | SMB file operations      | Not relevant to S1
```

**SPL to start with:**
```
index=botsv1 | stats count by sourcetype | sort -count
```

---

### D —> Define

Map the key fields across sourcetypes before writing any investigation queries.

This matters because Splunk doesn't standardise field names across sourcetypes. `srcip` in fgt_utm is `src_ip` in stream:http. `request` and `uri` are sometimes both present and sometimes not. Writing a query with the wrong field name returns zero results and looks like nothing happened.

**Field mapping template:**

```
Concept          | stream:http    | fgt_utm      | Sysmon              | wineventlog
-----------------|----------------|--------------|---------------------|-------------
Source IP        | src_ip         | srcip        | src_ip              | IpAddress
Destination IP   | dest_ip        | dstip        | dest_ip             | —
HTTP URI         | request / uri  | —            | CommandLine         | —
HTTP Method      | http_method    | service      | —                   | —
HTTP Status      | status         | —            | —                   | —
POST Body        | form_data      | —            | —                   | —
User-Agent/Hdrs  | src_headers    | msg          | —                   | —
Filename         | —              | filename     | —                   | —
Hash (SHA256)    | —              | file_hash    | SHA256              | —
Hash (MD5)       | —              | —            | MD5                 | —
Process          | —              | —            | CommandLine         | ProcessName
Parent Process   | —              | —            | ParentProcessId     | —
Event Code       | —              | —            | EventCode           | EventCode
```

**SPL to validate a field exists:**
```
index=botsv1 sourcetype=stream:http | head 5 | fieldsummary | table field, count
```

---

### E —> Explore

Apply six universal questions to the data. Don't start with a hypothesis — let the data show you what's abnormal.

These questions work on any log type and any scenario. Answer each one with actual log evidence, not assumptions.

**The six questions:**

**01 — Who?**  
Which source IPs are most active? Who is talking to what?  
```
index=botsv1 sourcetype=stream:http | top limit=10 src_ip
```

**02 — What?**  
What actions are most common? What's the top URI, method, or event type?  
```
index=botsv1 sourcetype=stream:http | top limit=10 uri, http_method
```

**03 — When?**  
When did traffic spike? Build a timechart to see bursts.  
```
index=botsv1 sourcetype=stream:http | timechart span=1m count by src_ip
```

**04 — Where?**  
Where is the traffic going? Is it concentrated on one destination?  
```
index=botsv1 sourcetype=stream:http | stats count by src_ip, dest_ip | sort -count
```

**05 — How often?**  
What's the failure-to-success ratio? Look for the pattern of many failures followed by a success — that's compromise.  
```
index=botsv1 sourcetype=stream:http http_method=POST
| rex field=form_data "passwd=(?<password>[^&]+)"
| stats count by password | sort -count
```

**06 — Rare?**  
What only happened once or twice? Rare events are frequently the most significant. A web server appearing as `src_ip` for an outbound GET is a one-off event that turns out to be the defacement deployment.  
```
index=botsv1 sourcetype=stream:http | rare limit=20 src_ip, http_method
```

---

### A —> Analyze

Cross-correlate findings across sourcetypes. Every conclusion should have at least two sources where the dataset allows. Single-source conclusions are labelled as such.

**Evidence chain format I use:**

```
CLAIM: [What you're asserting]
  SOURCE 1: [sourcetype] | [field] = [value]
  SOURCE 2: [sourcetype] | [field] = [value]
  VERDICT: CONFIRMED / PARTIAL / UNCONFIRMED
```

**Example from Case 001:**
```
CLAIM: Acunetix Web Vulnerability Scanner confirmed
  SOURCE 1: stream:http | src_headers = "Acunetix Web Vulnerability Scanner"
  SOURCE 2: fgt_utm | msg = "tools: Acunetix.Web.Vulnerability.Scanner"
  VERDICT: CONFIRMED — dual source

CLAIM: Admin password compromised (batman)
  SOURCE 1: stream:http form_data | stats count by password → batman count=2
  SOURCE 2: Temporal — second occurrence follows end of brute force window
  VERDICT: CONFIRMED — statistical + temporal
```

If you can only confirm something with one source, say that. Overstating evidence is worse than admitting a gap.

---

## Common mistakes I've caught myself making

**Treating fgt_utm and stream:http as interchangeable**  
They're not. fgt_utm stores `srcip`, stream:http stores `src_ip`. Wrong field = zero results = missed evidence.

**Using the wrong hash field**  
fgt_utm has `file_hash` (SHA256, 64 chars). Sysmon has `MD5` (32 chars). If the question asks for MD5, fgt_utm is the wrong source regardless of how obvious it seems.

**Looking only at attacker IPs as src_ip**  
In Case 001, the defacement deployment is only visible when you look at the victim server as `src_ip` making an outbound GET. If you filter all queries to known attacker IPs only, you miss it entirely.

**Writing conclusions before running the six questions**  
Starting with "the attacker probably did X" and then looking for evidence of X. That's confirmation bias, not investigation. Run the explore phase with no hypothesis — let the anomalies surface.

**Claiming something is confirmed from one source**  
Especially with SIEM data, sensors miss things. One hit in stream:http for a file upload doesn't mean the upload happened — cross-check with fgt_utm or endpoint logs before writing "confirmed" in a finding.

---

## SPL patterns I reuse across cases

**Extract username and password from POST form data:**
```
| rex field=form_data "username=(?<username>[^&]+)"
| rex field=form_data "passwd=(?<password>[^&]+)"
```

**Find the rare/outlier events:**
```
| rare limit=20 [field]
```

**Check if a field exists in a sourcetype:**
```
| fieldsummary | search field="[fieldname]"
```

**Find fail-then-success pattern:**
```
| stats count(eval(status=200)) as success,
        count(eval(status!=200)) as failures by src_ip
| where failures > 10 AND success >= 1
```

**Build a timeline across sourcetypes:**
```
| eval sourcetype_tag=sourcetype
| timechart span=1m count by sourcetype_tag
```
