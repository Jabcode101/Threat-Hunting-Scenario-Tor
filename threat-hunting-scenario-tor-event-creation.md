# Threat Hunt: MySQL Database Compromise and Destructive Activity

**Investigated asset:** `corp-wdds-f332a`  
**Investigation type:** MySQL service compromise, unauthorized database access, and destructive activity  
**Status:** MySQL compromise confirmed; underlying Windows host compromise not established by available telemetry.

> **Portfolio note:** This case study documents findings from an earlier investigation. Replace each evidence placeholder with your original KQL screenshot and matching results. Exact event timestamps, original query text, database names, and record counts should be copied from the retained evidence rather than reconstructed.

---

## Threat Event

The investigation identified unauthorized access to a MySQL service associated with `corp-wdds-f332a`. Activity attributed to source IP `64.89.163.139` included suspicious root authentication, access to database contents, creation of a ransom-related database, destructive SQL commands, privilege changes, and a MySQL shutdown. The available evidence confirmed compromise of the **database service**; it did **not** independently establish that the attacker obtained control of the underlying Windows operating system.

## Investigation Objectives

1. Establish the sequence of suspicious MySQL authentication and query activity.
2. Identify the source IPs, accounts, database operations, and destructive actions involved.
3. Correlate database evidence with Windows logon, process, and network telemetry.
4. Determine what was confirmed, what remained unverified, and the resulting confidentiality, integrity, and availability concerns.

---

## Observed Attacker Activity and Investigation Timeline

The following is a **sequence of observed activity**, not a timestamped reconstruction. Insert exact UTC timestamps from the original logs when adding evidence.

| Sequence | Observed activity | Investigative significance |
| --- | --- | --- |
| 1 | Suspicious MySQL root authentication associated with `64.89.163.139` | Establishes the database access path under investigation. |
| 2 | Queries accessing database contents | Supports unauthorized access to data; the exact data accessed must be established from query logs. |
| 3 | Creation of a ransom-related database | Indicates an extortion-related action in the database service. |
| 4 | `DROP DATABASE` | Confirms destructive database activity. |
| 5 | `RESET MASTER` and/or `PURGE` log operations | Indicates attempts to alter or remove MySQL log history. |
| 6 | Privilege modifications | Shows changes to database access or authorization. |
| 7 | MySQL shutdown | Establishes an availability-impacting action against the service. |

### Evidence 1 — MySQL authentication and initial access

**Add screenshot:** Original query showing the suspicious root authentication, plus its results with timestamp, source IP, account, and outcome visible.

`![Evidence 1 - MySQL authentication](images/01-mysql-authentication.png)`

**Finding:** Suspicious database authentication was associated with `64.89.163.139`. Preserve the original event timestamp and log fields in the screenshot.

### Evidence 2 — Database access and query activity

**Add screenshot:** Query and results showing the database read operations before the destructive activity.

`![Evidence 2 - Database query activity](images/02-database-access.png)`

**Finding:** Database contents were queried. Do not claim confirmed exfiltration unless separate transfer evidence supports it.

### Evidence 3 — Ransom-related and destructive SQL activity

**Add screenshot:** Query/results showing the ransom-related database creation and `DROP DATABASE` events, with their chronological ordering visible.

`![Evidence 3 - Destructive SQL](images/03-destructive-sql.png)`

**Finding:** The database service was used to perform destructive operations.

### Evidence 4 — Log manipulation, privileges, and shutdown

**Add screenshot:** Query/results showing `RESET MASTER` / `PURGE`, privilege modifications, and the MySQL shutdown. Use multiple screenshots if one is too crowded.

`![Evidence 4 - Log and service changes](images/04-log-privilege-shutdown.png)`

**Finding:** These events document changes to logging, access permissions, and service availability.

---

## Tables Used to Investigate Indicators of Compromise

| Data source | Purpose |
| --- | --- |
| MySQL authentication logs | Review source IPs, accounts, authentication attempts, and outcomes. |
| MySQL query/audit logs | Reconstruct database reads, ransom-related activity, destructive statements, privilege changes, and shutdown. |
| `DeviceLogonEvents` | Check Windows authentication activity on the investigated host. |
| `DeviceProcessEvents` | Look for suspicious process execution and possible host-level follow-on activity. |
| `DeviceNetworkEvents` | Look for relevant network connections and correlate them with the database investigation. |

*Use the actual table names and field names from your original lab/workspace when inserting the retained queries; the MySQL log schema is not reproduced here.*

---

## Related KQL Queries and Evidence

The original query text is not reproduced here because it is not available in the current source material. Paste the **actual queries you ran** into the sections below, then insert the matching screenshot(s). This keeps the portfolio reproducible without presenting illustrative queries as historical evidence.

### Query 1 — MySQL authentication: suspicious source and root account

```kql
// PASTE ORIGINAL MYSQL AUTHENTICATION QUERY HERE
```

**Screenshot:** `images/01-mysql-authentication.png`  
**What to show:** Query, timestamp, source IP `64.89.163.139`, account, and authentication result.

### Query 2 — MySQL query history: access to database contents

```kql
// PASTE ORIGINAL DATABASE READ / QUERY HISTORY QUERY HERE
```

**Screenshot:** `images/02-database-access.png`  
**What to show:** The actual SQL operations and their timestamps.

### Query 3 — Destructive SQL and ransom-related activity

```kql
// PASTE ORIGINAL QUERY FOR RANSOM-RELATED DATABASE CREATION AND DROP DATABASE HERE
```

**Screenshot:** `images/03-destructive-sql.png`  
**What to show:** SQL statement, database target (if visible), source/account context, and timestamp.

### Query 4 — MySQL log operations, privileges, and shutdown

```kql
// PASTE ORIGINAL QUERY FOR RESET MASTER / PURGE, PRIVILEGE CHANGES, AND SHUTDOWN HERE
```

**Screenshot:** `images/04-log-privilege-shutdown.png`  
**What to show:** Individual operations and chronological order.

### Query 5 — Windows logon correlation

```kql
// PASTE ORIGINAL DEVICELOGONEVENTS QUERY HERE
```

**Screenshot:** `images/05-windows-logons.png`  
**What to show:** Host `corp-wdds-f332a`, relevant source IPs, success/failure results, and timestamps.

**Separate finding:** `201.187.98.150` appeared in suspicious Windows authentication telemetry with failures and one success, but the evidence reviewed did not establish that it was connected to the MySQL attack.

### Query 6 — Windows process and network correlation

```kql
// PASTE ORIGINAL DEVICEPROCESSEVENTS AND/OR DEVICENETWORKEVENTS QUERIES HERE
```

**Screenshot:** `images/06-host-correlation.png`  
**What to show:** Query and results, including any relevant process/network events or a clearly visible absence of matching events for the search window.

**Finding:** The available Defender telemetry did not establish a Windows host compromise. An absence of matching events in these queries is not proof that no host activity occurred.

---

## Indicators and Investigative Leads

| Indicator | Type | Interpretation |
| --- | --- | --- |
| `corp-wdds-f332a` | Investigated host | Windows system associated with the affected MySQL service. |
| `64.89.163.139` | Source IP | Associated with the suspicious MySQL activity investigated. |
| `201.187.98.150` | Source IP | Separate suspicious Windows authentication activity; not established as part of the MySQL incident. |
| `root` | MySQL account | Account involved in suspicious database authentication. |
| `DROP DATABASE` | SQL operation | Destructive database action. |
| `RESET MASTER` / `PURGE` | SQL operations | MySQL log-history alteration/removal operations. |

---

## Scope, Impact, and Assessment

| Security objective | Evidence-based assessment |
| --- | --- |
| **Confidentiality** | Unauthorized queries accessed database contents. The available summary does not establish a confirmed external data transfer. |
| **Integrity** | Destructive SQL and privilege changes affected database integrity and access controls. |
| **Availability** | Database deletion and MySQL shutdown affected service/data availability. |
| **Windows host compromise** | Not established by the available Defender evidence. |

**Conclusion:** The investigation confirmed compromise and misuse of the MySQL service associated with `corp-wdds-f332a`. The observed sequence included unauthorized database access, destructive commands, log-related operations, privilege changes, and service shutdown. The evidence does not justify describing the underlying Windows host as confirmed compromised, nor does it establish that the MySQL service was directly Internet-facing without separate firewall or network-configuration evidence.

## Recommended Response and Follow-Up

- Preserve MySQL authentication, query/audit, Windows logon, process, and network evidence.
- Review and rotate exposed database credentials and investigate how the root account was accessed.
- Restore affected data from verified backups where appropriate and validate database integrity.
- Review MySQL access controls, least privilege, remote access restrictions, and logging configuration.
- Investigate the separate Windows authentication activity without assuming it belongs to the same attack.
- Continue correlation with additional telemetry if host compromise or data exfiltration must be determined.

*These are recommended actions, not a claim that they were all performed during the lab.*

---

## Screenshot Checklist

Save the screenshots in an `images/` folder next to this `README.md`, then replace the literal placeholder lines above with the actual Markdown image embeds shown here:

```markdown
![Evidence 1 - MySQL authentication](images/01-mysql-authentication.png)
![Evidence 2 - Database query activity](images/02-database-access.png)
![Evidence 3 - Destructive SQL](images/03-destructive-sql.png)
![Evidence 4 - Log and service changes](images/04-log-privilege-shutdown.png)
![Evidence 5 - Windows logons](images/05-windows-logons.png)
![Evidence 6 - Host correlation](images/06-host-correlation.png)
```

For each screenshot, keep the query text, selected time range, table name, and relevant result columns legible. Redact real secrets, access tokens, or personal data before publishing.

---

## Created By

- **Author Name:** [Add your name]
- **Author Contact:** [Add your professional profile link]
- **Investigation Date:** [Add original investigation date]

## Validated By

- **Reviewer Name:** [If applicable]
- **Reviewer Contact:** [If applicable]
- **Validation Date:** [If applicable]

## Additional Notes

- This portfolio entry distinguishes confirmed database-service activity from unconfirmed host-level activity.
- Original query text, exact timestamps, and screenshots should be inserted from retained investigation evidence.

## Revision History

| Version | Changes | Date | Modified By |
| --- | --- | --- | --- |
| 1.0 | Initial GitHub case-study draft based on the prior investigation summary | [Add date] | [Add name] |
