# SPL Reference (Patterns I Use Across Cases)

Not a tutorial. This is a quick reference for the query patterns that come up in almost every investigation. Organised by what I'm trying to find out, not by command name.

---

## Scoping an investigation

**What sourcetypes exist and how many events:**
```
index=botsv1 | stats count by sourcetype | sort -count
```

**What fields exist in a sourcetype:**
```
index=botsv1 sourcetype=stream:http | head 200 | fieldsummary | table field, count, distinct_count
```

**All events touching a specific IP (across all sourcetypes):**
```
index=botsv1 (src_ip="x.x.x.x" OR srcip="x.x.x.x" OR dest_ip="x.x.x.x" OR dstip="x.x.x.x")
| stats count by sourcetype
```

**Time range check — when did activity start and end:**
```
index=botsv1 sourcetype=stream:http src_ip="x.x.x.x"
| stats earliest(_time) as first_seen, latest(_time) as last_seen
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
```

---

## Finding the attacker

**Top source IPs by volume:**
```
index=botsv1 sourcetype=stream:http dest_ip="x.x.x.x"
| top limit=10 src_ip
```

**Traffic spike timeline (1-minute buckets):**
```
index=botsv1 sourcetype=stream:http
| timechart span=1m count by src_ip
```

**Find rare HTTP methods (WebDAV probes, unusual verbs):**
```
index=botsv1 sourcetype=stream:http dest_ip="x.x.x.x"
| rare limit=10 http_method
```

---

## Brute force detection

**Extract credentials from POST form data:**
```
index=botsv1 sourcetype=stream:http http_method=POST
| rex field=form_data "username=(?<username>[^&]+)"
| rex field=form_data "passwd=(?<password>[^&]+)"
| table _time, src_ip, uri, username, password
```

**Find fail-then-success pattern (the compromise signal):**
```
index=botsv1 sourcetype=stream:http http_method=POST
| rex field=form_data "passwd=(?<password>[^&]+)"
| stats count by password
| sort -count
```
The correct password appears more than once. Everything else appears once.

**Count unique passwords and average length:**
```
index=botsv1 sourcetype=stream:http http_method=POST
| rex field=form_data "passwd=(?<password>[^&]+)"
| eval pwlen=len(password)
| stats dc(password) as unique_passwords, avg(pwlen) as avg_len
```

**First password attempted (chronological):**
```
index=botsv1 sourcetype=stream:http http_method=POST
| rex field=form_data "passwd=(?<password>[^&]+)"
| sort _time
| table _time, password
| head 1
```

---

## Anomaly detection

**Server appearing as src_ip making outbound requests (defacement pattern):**
```
index=botsv1 sourcetype=stream:http src_ip="[your_server_ip]" http_method=GET
| search NOT (site="*.microsoft.com" OR site="*.windows.com" OR site="*.akamai.net")
| table _time, request, site, dest_ip, status
```

**Find events that only happened once (rare = significant):**
```
index=botsv1 sourcetype=stream:http
| rare limit=20 src_ip, uri, http_method
```

**HTTP status code breakdown for an attacker IP:**
```
index=botsv1 sourcetype=stream:http src_ip="x.x.x.x"
| stats count by status
| eval status_class=case(
    status>=500,"5xx Server Error",
    status>=400,"4xx Client Error",
    status>=300,"3xx Redirect",
    status>=200,"2xx Success",
    true(),"Other")
| stats sum(count) as total by status_class
| sort -total
```

---

## Multi-sourcetype correlation

**Confirm a file upload across two sourcetypes:**
```
-- FortiGate UTM (filename + SHA256)
index=botsv1 sourcetype=fgt_utm srcip="x.x.x.x" filename=*.exe
| table _time, filename, file_hash

-- Sysmon (process creation + MD5)
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine="filename.exe"
| table _time, MD5, SHA256, CommandLine, ParentProcessId
```

**DNS queries from a host — filter out noise:**
```
index=botsv1 sourcetype=stream:dns src_ip="x.x.x.x"
| search NOT (query="*.microsoft.com" OR query="*.windows.com"
             OR query="*.local" OR query="*.arpa" OR query="*.in-addr.arpa")
| table _time, query
| sort _time
```

**SMB lateral movement check:**
```
index=botsv1 sourcetype=stream:smb src_ip="x.x.x.x"
| stats count by src_ip, dest_ip
| sort -count
```

**Windows authentication events around a time window:**
```
index=botsv1 sourcetype=wineventlog:security EventCode=4624
| eval hour=strftime(_time,"%H") | where hour>=21 AND hour<=23
| table _time, EventCode, Account_Name, IpAddress, Logon_Type
| sort _time
```

---

## Field mapping quick reference

Common field name differences across sourcetypes:

| Concept | stream:http | fgt_utm | Sysmon | wineventlog |
|---------|-------------|---------|--------|-------------|
| Source IP | src_ip | srcip | src_ip | IpAddress |
| Dest IP | dest_ip | dstip | dest_ip | — |
| HTTP Request | request / uri | — | CommandLine | — |
| HTTP Method | http_method | service | — | — |
| POST Body | form_data | — | — | — |
| Request Headers | src_headers | msg | — | — |
| Filename | — | filename | — | — |
| SHA256 | — | file_hash | SHA256 | — |
| MD5 | — | — | MD5 | — |
| Event Code | — | — | EventCode | EventCode |
