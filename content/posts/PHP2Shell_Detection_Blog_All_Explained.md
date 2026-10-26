---
title: "PHP2Shell: Hunting Webshells with Microsoft Defender XDR on Windows and Linux"
date: 2026-10-26T00:00:00+05:30
draft: false
author: "Nirmal 🇮🇳"
description: "KQL detections for catching PHP webshell activity on Windows and Linux web servers using Microsoft Defender for Endpoint, no Sentinel required."
categories: ["Cybersecurity"]
tags: ["Threat Detection", "KQL", "Microsoft Defender", "Detection Engineering", "Blue Team"]
---


Last couple of days I was working on how to detect PHP2SHELL using Defender XDR Advance hunting query so here is my POV, I'll walk through a set of PHP webshell detections I built using Microsoft Defender for Endpoint (MDE) advanced hunting — no Sentinel involved. Before jumping into the queries, I want to cover some background on how PHP actually runs on a server, because understanding that makes the detections much easier to follow. I'll also call out where Windows and Linux differ, since a lot of PHP hosting runs on Linux and most public writeups only cover Windows/IIS.

Let's get into it.

## Why this matters

PHP runs a huge share of the web, so a PHP webshell is one of the most common footholds after a file-upload bug, an RCE flaw, or a vulnerable plugin. The attacker drops a small script, calls it over HTTP, and the web server starts running OS commands for them.

That moment is the weak point. A web-facing process (IIS, Apache, PHP-FPM) suddenly creates a shell or a download tool as a child. Normal websites almost never do that. Everything below is built on that parent-child relationship, plus two supporting signals: where PHP files get written, and which servers run exposed PHP.

All queries use standard Defender XDR Advanced Hunting tables (`DeviceProcessEvents`, `DeviceFileEvents`, `DeviceTvm*`, `DeviceInfo`).


## Step 1: How PHP Actually Runs on a Server

The basic flow is: browser → web server → PHP → script runs → response. PHP code runs under a low-privilege identity (an IIS app pool or a service account on Windows, `www-data`/`apache`/`nginx` on Linux). What matters for detection is **which process hosts PHP**, because that process name becomes the parent of anything the script launches.

| Model | Where | How PHP runs | Process you see in MDE |
|---|---|---|---|
| mod_php | Apache (Linux & Windows) | PHP loaded inside the Apache process | `apache2`/`httpd` (Linux), `httpd.exe` (Windows) |
| FastCGI on IIS | Windows | IIS FastCGI module starts PHP workers | `w3wp.exe` then `php-cgi.exe` |
| PHP-FPM | Linux (Nginx/Apache) | Separate pool of PHP workers behind a socket | `php-fpm`, often versioned like `php-fpm8.2` |
| CGI / LSAPI | Both / LiteSpeed | PHP launched per request or by LiteSpeed | `php-cgi`, `lsphp` |
| CLI | Both | Run from a terminal, cron, or scheduled task | `php`/`php.exe` |

I know, I know — Step 1 felt like a classroom lecture 😅 But now, let’s get our hands dirty. 
Two things that trip people up when writing these detections:

- **`php-fpm.exe` does not exist.** PHP-FPM is a Linux-only process model.
- **On Linux, FPM process names are often versioned** (`php-fpm8.2`), so match with `startswith` instead of an exact name.

## Step 2: Windows vs Linux — Know the Differences

| | Windows | Linux |
|---|---|---|
| PHP binaries | `C:\php`, `C:\Program Files\PHP`, `C:\xampp\php` | `/usr/bin/php`, `/usr/sbin/php-fpm` |
| Config | `php.ini` next to the PHP binaries | Per-SAPI: `/etc/php/<ver>/{cli,fpm,apache2}/php.ini` (Debian), `/etc/php.ini` + `/etc/php-fpm.d/www.conf` (RHEL) |
| Web roots | `C:\inetpub\wwwroot`, `C:\xampp\htdocs`, `C:\wamp64\www` | `/var/www/html`, `/var/www/<site>`, `/srv/www` |
| Runs as | `IIS APPPOOL\<pool>` or Apache service account | `www-data` (Debian/Ubuntu), `apache`/`nginx` (RHEL) |
| Temp / sessions | `C:\Windows\Temp` | `/tmp`, `/var/lib/php/sessions` |
| Shell PHP spawns | `cmd.exe /c <command>` | `/bin/sh -c <command>` |
| Process names | End in `.exe` | No extension; FPM names may be versioned |
| Typical post-exploit commands | `whoami`, `systeminfo`, `net user`, PowerShell, `certutil` | `id`, `uname -a`, `curl`/`wget`, `bash`, `python` |

Note: on Debian-style systems, `php.ini` differs per SAPI. Hardening the CLI config does nothing for the FPM or Apache config — a mistake I've seen more than once during assessments.

## Step 3: How a PHP Webshell Becomes a Shell

A webshell is just a PHP file that passes attacker input to something dangerous — `system()`, `exec()`, `shell_exec()`, `passthru()`, `popen()`, `proc_open()`, or backticks, often hidden behind `eval()` or `base64_decode()` to dodge file scanners.

When one of those functions runs, PHP asks the OS to create a child process. That child is what MDE records. The parent is whatever hosts PHP (`w3wp.exe`, `php-cgi.exe`, `httpd.exe`, `apache2`, `php-fpm`), and the child is `cmd.exe` or `sh`. Early commands are almost always recon (`whoami`, `id`, `systeminfo`, `uname`) followed by a download of a second-stage tool.

That gives us three angles to detect on:

1. **Process** — a web or PHP process spawning a shell or download tool
2. **File** — a web or PHP process writing new PHP files (the upload step) or executables/scripts (the staging step)
3. **Exposure** — where outdated or internet-facing PHP exists in the first place

## Step 4: Before You Run These

- Replace the placeholder device names in `WebServers` with your own web servers — or better, match on a device tag/group.
- The behavioural event queries include `DeviceId` and `ReportId` for investigation and potential custom-detection use. The baseline and exposure/inventory queries are primarily for hunting and prioritisation; they are not automatically suitable as custom detection rules without adapting them to the platform's requirements.
- Run each over 7–30 days first and tune before alerting. CMSs and frameworks legitimately write PHP files and sometimes call helper programs.
- `php.exe`/`php` is deliberately **not** treated as a web parent in the shell detections below, because CLI PHP under cron, Composer, and deployment scripts legitimately spawns shells. Hunt it separately if needed.

## Step 5: The Queries

### Baseline first (hunting, not an alert)

Before alerting on anything, learn what your web processes normally launch. Anything in the output you can't explain is either a tuning exclusion or a finding.

```sql
let WebServers = dynamic(['web-srv-01', 'web-srv-02']);
let WebProcs = dynamic(['w3wp.exe','php-cgi.exe','php-win.exe','httpd.exe','apache.exe','nginx.exe','apache2','httpd','nginx','php-cgi','lsphp','litespeed']);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where DeviceName has_any (WebServers)
| where InitiatingProcessFileName in~ (WebProcs) or InitiatingProcessFileName startswith 'php-fpm'
| summarize Executions = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by InitiatingProcessFileName, FileName
| order by Executions desc
```

#### What the baseline query tells you

This is a discovery query, not an alert. It groups process events by the initiating process and child filename, then reports the number of executions and the first and last timestamps seen during the 30-day window.

- `Executions` helps show which parent-child relationships are common.
- `FirstSeen` and `LastSeen` show the observed time span for each relationship.
- `order by Executions desc` puts the most frequently observed relationships first.

Use the output to learn what is normal on each server before deciding which relationships are suspicious. Because the summary groups only by parent and child process names, it does not show the command line, account, or individual event details. Pivot back to raw `DeviceProcessEvents` when a relationship needs investigation.

![Baseline query result showing w3wp.exe spawning php-cgi.exe](/images/step5.png)

Running this on my own environment, the top row was `w3wp.exe` → `php-cgi.exe` with a high execution count and a wide FirstSeen–LastSeen spread. That's expected and healthy — it's exactly the IIS + FastCGI chain described in Step 1 (IIS spins up `w3wp.exe`, which hands requests to `php-cgi.exe` to actually run the PHP). 

Seeing it here confirms two things:

1. The sensor is capturing this process chain correctly, so the shell detections downstream (Detection 1) will fire if something abnormal happens on top of it.

2. `php-cgi.exe` itself is not the thing to alert on — it runs constantly and legitimately. What you're watching for is `php-cgi.exe` spawning something it shouldn't, like `cmd.exe` or `powershell.exe`, which is what Detection 1 checks next.

### Detection 1: Windows web/PHP process spawns a shell or LOLBin

This is the core PHP-to-shell signal on Windows. On IIS with PHP, the process chain may look like `w3wp.exe` → `php-cgi.exe` → `cmd.exe`. This query looks for the final step: a web server or PHP-related process launching a command interpreter, download utility, discovery tool, or another potentially suspicious Windows utility.

It also catches cases where a web server process launches a suspicious child directly, without `php-cgi.exe` appearing as an intermediate process.

`DownloadIndicator` is a prioritisation hint. It flags command lines containing URL strings or common download-related terms. A `true` result does **not** prove that a download succeeded, and a `false` result does **not** mean the activity is safe.

```sql
let WebServers = dynamic(['win-web-01', 'win-web-02']);
let WebParents = dynamic(['w3wp.exe','php-cgi.exe','php-win.exe','httpd.exe','apache.exe','nginx.exe']);
let SuspiciousChildren = dynamic(['cmd.exe','powershell.exe','pwsh.exe','curl.exe','certutil.exe','bitsadmin.exe','whoami.exe','net.exe','net1.exe','nltest.exe','systeminfo.exe','mshta.exe','rundll32.exe','regsvr32.exe','wscript.exe','cscript.exe']);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName has_any (WebServers)
| where InitiatingProcessFileName in~ (WebParents)
| where FileName in~ (SuspiciousChildren)
| extend DownloadIndicator = ProcessCommandLine has_any ('http://', 'https://', 'Invoke-WebRequest', 'DownloadString', 'DownloadFile', 'Net.WebClient', '-urlcache', 'bitsadmin')
| project Timestamp, DeviceName, DeviceId, ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, FileName, ProcessCommandLine, AccountName, DownloadIndicator
| order by DownloadIndicator desc, Timestamp desc
```

#### How the query works

**1. Define the Windows web servers**

```sql
let WebServers = dynamic(['win-web-01', 'win-web-02']);
```

This list limits the hunt to the specified devices. Replace the example names with your own Windows web servers. `DeviceName has_any (WebServers)` uses term matching rather than strict whole-string equality; if you want exact device-name matching, use `DeviceName in~ (WebServers)` instead.

**2. Identify web server and PHP-related parent processes**

```sql
let WebParents = dynamic(['w3wp.exe','php-cgi.exe','php-win.exe','httpd.exe','apache.exe','nginx.exe']);
```

The list includes common Windows process names associated with IIS, PHP, Apache and Nginx:

- `w3wp.exe`: IIS worker process.
- `php-cgi.exe` and `php-win.exe`: PHP execution processes.
- `httpd.exe` and `apache.exe`: process names that may be used by Apache installations.
- `nginx.exe`: Nginx web server process.

The query checks `InitiatingProcessFileName`, which identifies the process that initiated the recorded process event. For example, an event where `php-cgi.exe` launches `cmd.exe` can match this condition.

These names are indicators, not proof of malicious activity. Confirm the actual process tree and expected application behaviour during triage.

**3. Define potentially suspicious child processes**

```sql
let SuspiciousChildren = dynamic(['cmd.exe','powershell.exe','pwsh.exe','curl.exe','certutil.exe','bitsadmin.exe','whoami.exe','net.exe','net1.exe','nltest.exe','systeminfo.exe','mshta.exe','rundll32.exe','regsvr32.exe','wscript.exe','cscript.exe']);
```

The list covers several types of activity:

- **Command execution:** `cmd.exe`, `powershell.exe`, `pwsh.exe`
- **Download or transfer utilities:** `curl.exe`, `certutil.exe`, `bitsadmin.exe`
- **Account and domain discovery:** `whoami.exe`, `net.exe`, `net1.exe`, `nltest.exe`
- **System discovery:** `systeminfo.exe`
- **Script execution or proxy execution:** `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `wscript.exe`, `cscript.exe`

These utilities also have legitimate administrative uses. The detection is interested in their execution from a web-related parent process, which may be unusual for a production web server.

**4. Search process events from the last seven days**

```sql
DeviceProcessEvents
| where Timestamp > ago(7d)
```

`DeviceProcessEvents` provides process telemetry collected by Defender for Endpoint. The time filter limits the hunt to the previous seven days. Adjust the window to suit your investigation and telemetry-retention requirements.

**5. Filter by device, parent and child process**

```sql
| where DeviceName has_any (WebServers)
| where InitiatingProcessFileName in~ (WebParents)
| where FileName in~ (SuspiciousChildren)
```

Together, these filters look for a listed child process running on a monitored server where the initiating process matches one of the listed web/PHP processes. The `in~` operator performs case-insensitive matching.

For example, `php-cgi.exe` launching `powershell.exe` can match. A PowerShell process launched by an unrelated parent process will not match this particular parent-child filter.

**6. Add a download-related indicator**

```sql
| extend DownloadIndicator = ProcessCommandLine has_any ('http://', 'https://', 'Invoke-WebRequest', 'DownloadString', 'DownloadFile', 'Net.WebClient', '-urlcache', 'bitsadmin')
```

This creates a Boolean field called `DownloadIndicator`. It checks the child process command line for URL strings and terms commonly associated with download activity.

Treat it as a prioritisation clue only. The query does not validate whether a URL was contacted or whether a file was successfully downloaded. It can also miss downloads that use other tools, APIs or command-line syntax.

**7. Select the fields needed for investigation**

```sql
| project Timestamp, DeviceName, DeviceId, ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, FileName, ProcessCommandLine, AccountName, DownloadIndicator
```

These columns help an analyst understand when and where the process ran, what launched it, which account was involved, and what command was executed. `DeviceId` and `ReportId` are useful identifiers when pivoting into the event in Defender.

**8. Sort likely download-related events first**

```sql
| order by DownloadIndicator desc, Timestamp desc
```

Rows where `DownloadIndicator` is `true` appear first, with the newest events at the top of each group. This is not a severity score: a row marked `false` may still be malicious, and a row marked `true` may be legitimate.

#### What to investigate when it matches

1. Review `InitiatingProcessCommandLine` and `ProcessCommandLine` to understand the process relationship and the command's purpose.
2. Inspect the process tree and verify whether the child process is expected for that application or server.
3. Check `InitiatingProcessAccountName` and `AccountName`, including whether the process ran as an application-pool identity or service account.
4. Pivot to nearby process, file and network events on the device. Review any URLs, file paths, hashes or outbound connections involved.
5. Determine whether the activity is legitimate, suspicious or confirmed malicious before taking containment action.

**Tuning:** Baseline normal behaviour first. Exclude known maintenance activity only with narrow conditions such as the expected parent process plus a specific command line or path. Avoid excluding an entire parent process, such as `w3wp.exe` or `php-cgi.exe`, because that could hide the behaviour this detection is intended to find.

**Limitations:** This is a process-based hunting query, not a detection for a particular PHP CVE. It may miss activity involving unlisted parent or child processes, renamed binaries, or webshells that read files or access data without spawning a child process. Combine it with web-server logs, WAF telemetry, file-write detections and vulnerability management for broader coverage.

---

### Detection 2: Linux web/PHP process spawns a shell or download tool

Apache, Nginx, LiteSpeed, or PHP-FPM should not be starting `sh`, `bash`, `curl`, `wget`, or interpreters. PHP's `system()` commonly results in a shell such as `sh -c <command>`, so the shell may be the first child process visible in Defender telemetry.

This is the Linux counterpart to Detection 1, but the process names and exclusion are different. Linux process names usually do not have a `.exe` extension, and PHP-FPM workers can have versioned names such as `php-fpm8.2`.


```sql
let WebServers = dynamic(['lnx-web-01', 'lnx-web-02']);
let WebParents = dynamic(['apache2','httpd','nginx','php-cgi','lsphp','litespeed']);
let SuspiciousChildren = dynamic(['sh','bash','dash','zsh','curl','wget','nc','ncat','socat','perl','whoami','id','uname']);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName has_any (WebServers)
| where InitiatingProcessFileName in~ (WebParents) or InitiatingProcessFileName startswith 'php-fpm'
| where FileName in~ (SuspiciousChildren) or FileName startswith 'python'
| where not(ProcessCommandLine has '/usr/sbin/sendmail -t')
| extend DownloadIndicator = ProcessCommandLine has_any ('http://', 'https://', 'curl ', 'wget ')
| project Timestamp, DeviceName, DeviceId, ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, FileName, ProcessCommandLine, DownloadIndicator
| order by DownloadIndicator desc, Timestamp desc
```

#### What is different in this query?

- **Linux parent matching:** `InitiatingProcessFileName in~ (WebParents) or InitiatingProcessFileName startswith 'php-fpm'` matches the listed Linux web processes and also allows versioned PHP-FPM process names.
- **Python child processes:** `FileName startswith 'python'` catches names such as `python`, `python3`, or versioned Python executables that are not individually listed in `SuspiciousChildren`.
- **Sendmail exclusion:** `where not(ProcessCommandLine has '/usr/sbin/sendmail -t')` removes matching command lines associated with a common PHP mail path. This is a broad text-based exclusion, not proof that the event is benign; validate it against your environment and narrow it if possible.
- **Download hint:** The `DownloadIndicator` checks for URL strings and the literal terms `curl ` or `wget `. It may miss alternate syntax, other tools, or downloads performed without these strings.

#### What to investigate

Review the parent and child command lines, service account, process tree, and nearby file/network events. For a Linux match, look for unexpected shells, reverse-connection utilities such as `nc`/`ncat`/`socat`, reconnaissance commands, and unexpected interpreter execution.

**Tuning:** PHP's `mail()` legitimately runs `sh -c /usr/sbin/sendmail -t -i` on many systems, so the query excludes command lines containing that text. Keep exclusions narrow: an attacker may be able to reproduce the same text, and the exclusion alone should not be treated as a security boundary.


### Detection 3: PHP file written by a web or PHP process

This detection looks for PHP-related files created, modified, or renamed by a web/PHP process. It targets the file-drop stage: an attacker may upload a webshell or write a PHP payload to a web-accessible location, then request it over HTTP.

The query covers both Windows and Linux process names in one hunt, but its effectiveness depends on Defender collecting the relevant file events and on the parent process being represented as expected.


```sql
let WebServers = dynamic(['web-srv-01', 'web-srv-02']);
let WebProcs = dynamic(['w3wp.exe','php-cgi.exe','php-win.exe','httpd.exe','apache.exe','nginx.exe','apache2','httpd','nginx','php-cgi','lsphp','litespeed']);
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName has_any (WebServers)
| where ActionType in ('FileCreated', 'FileModified', 'FileRenamed')
| where InitiatingProcessFileName in~ (WebProcs) or InitiatingProcessFileName startswith 'php-fpm'
| where FileName matches regex @'(?i)\.(php[0-9]?|phtml|phar)$'
| extend UserWritablePath = FolderPath has_any ('upload', 'uploads', 'images', 'media', 'files', 'tmp', 'temp')
| project Timestamp, DeviceName, DeviceId, ReportId, FolderPath, FileName, ActionType, UserWritablePath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by UserWritablePath desc, Timestamp desc
```

#### What is new in this query?

- **File events instead of process events:** `DeviceFileEvents` is used to hunt file activity rather than child-process creation.
- **Relevant file operations:** `ActionType in ('FileCreated', 'FileModified', 'FileRenamed')` looks for files that were created, changed, or renamed. Including modifications can reveal an existing PHP file being altered, not just a newly uploaded one.
- **PHP-related extensions:** The regular expression matches filenames ending in `.php`, `.php` plus one digit (for example `.php5`), `.phtml`, or `.phar`, without case sensitivity.
- **Potentially writable paths:** `UserWritablePath` marks paths containing terms such as `uploads`, `images`, `media`, `tmp`, or `temp`. This is only a path-based heuristic. `has_any` performs term matching, so review the actual `FolderPath` rather than assuming every `true` result is a writable upload directory.

**How to triage:** Review `FolderPath`, `FileName`, `ActionType`, the initiating process, and the account. Check whether the file is expected for the application and whether it is followed by a request or suspicious process execution.

**Prioritise** rows where `UserWritablePath` is `true`, especially when the file is in a user-uploaded content directory. However, do not assume every PHP file in such a directory is executable; confirm the web-server configuration and application behaviour.

**Tuning:** CMS updates, deployment tooling, Composer, and frameworks can legitimately write PHP files. Baseline first, then use narrow exclusions based on known paths and expected processes. Do not exclude all PHP writes from a web server.


### Detection 4: Executable or script dropped by a web or PHP process

This detection looks for a web/PHP process creating or renaming a file with an executable, library, or script extension. It targets possible staging activity after initial command execution, when an attacker may place a payload or supporting tool on the server.

Unlike Detection 3, which focuses on PHP-related extensions, this query looks for other file types that may be used to run code or load additional functionality.


```sql
let WebServers = dynamic(['web-srv-01', 'web-srv-02']);
let WebProcs = dynamic(['w3wp.exe','php-cgi.exe','php-win.exe','httpd.exe','apache.exe','nginx.exe','apache2','httpd','nginx','php-cgi','lsphp','litespeed']);
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName has_any (WebServers)
| where ActionType in ('FileCreated', 'FileRenamed')
| where InitiatingProcessFileName in~ (WebProcs) or InitiatingProcessFileName startswith 'php-fpm'
| where FileName matches regex @'(?i)\.(exe|dll|ps1|bat|cmd|vbs|hta|sh|pl|py|so)$'
| project Timestamp, DeviceName, DeviceId, ReportId, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

#### What is different in this query?

- **File operations:** `ActionType in ('FileCreated', 'FileRenamed')` focuses on file creation and rename events. Unlike Detection 3, it does not include `FileModified`.
- **Broader extension list:** The regular expression looks for `.exe`, `.dll`, PowerShell and command scripts, common scripting extensions, Python files, and Linux shared objects (`.so`).
- **Hash for follow-up:** `SHA256` can help correlate the file with other events or reputation/intelligence sources when the value is available.

This is an extension-based hunt, not a verdict that a file is malicious. Attackers can use extensions outside this list, while legitimate applications may create these file types.

**How to triage:** Review the full path, hash, initiating process and account. Validate the file's origin and signature where applicable, then pivot to process execution and network events involving the same device or file.

**Tuning:** Baseline legitimate deployment and update workflows. Focus on unexpected file types and locations, and use narrow exceptions for known-good activity rather than excluding a whole web-server process.

### Exposure 1: Where is PHP installed, and is the device internet-facing?

This query shifts from behaviour to asset discovery. It uses Defender Vulnerability Management software inventory to find software whose name contains `php`, then joins the latest available `DeviceInfo` record per device to add the `IsInternetFacing` value.

Use this output to prioritise the behavioural detections: a PHP installation on an internet-facing server may deserve earlier review than the same software on an isolated development machine. Internet-facing status is a prioritisation factor, not proof that the server is vulnerable or directly reachable from every network.

```sql
DeviceTvmSoftwareInventory
| where SoftwareName contains 'php'
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, *) by DeviceId
    | project DeviceId, IsInternetFacing
  ) on DeviceId
| project DeviceName, OSPlatform, SoftwareName, SoftwareVersion, IsInternetFacing
| order by IsInternetFacing desc, DeviceName asc
```

#### How to read the results

- `SoftwareName` and `SoftwareVersion` show the PHP inventory entries Defender reports.
- `IsInternetFacing` adds the internet-facing indicator from the latest `DeviceInfo` record available for each device.
- The `leftouter` join keeps inventory rows even when no matching device-info row is found. In that case, the internet-facing field may be empty.
- `arg_max(Timestamp, *) by DeviceId` selects the latest `DeviceInfo` row per device before the join.

**Limitations:** Inventory depends on Defender's discovery and reporting. A software name containing `php` may not capture every deployment or bundled runtime, and the internet-facing flag should be validated against your actual network exposure and asset records.

### Exposure 2: Known-vulnerable PHP

This query looks for PHP entries in Defender Vulnerability Management's software-vulnerability data and retains findings rated `High` or `Critical`. It then groups the results by device, operating system, software name, and version, counting distinct CVEs and collecting up to 20 CVE IDs for each group.


```sql
DeviceTvmSoftwareVulnerabilities
| where SoftwareName contains 'php'
| where VulnerabilitySeverityLevel in ('Critical', 'High')
| summarize CveCount = dcount(CveId), CVEs = make_set(CveId, 20) by DeviceName, OSPlatform, SoftwareName, SoftwareVersion
| order by CveCount desc
```

#### How to read the results

- `VulnerabilitySeverityLevel` limits the hunt to findings rated `High` or `Critical`.
- `dcount(CveId)` counts distinct CVEs in each device/software/version group.
- `make_set(CveId, 20)` returns up to 20 distinct CVE IDs for quick review; it is not guaranteed to list every CVE when a group has more than 20.
- Grouping by device and software version helps identify where the same vulnerable version appears across the estate.

Use this alongside Exposure 1 to prioritise remediation, especially for internet-facing systems. Confirm the affected version and vendor advisory before patching: vulnerability inventory can lag, and applicability may depend on packaging, backported fixes, or how the software was installed.

## Step 6: Test, Tune, Harden

**Test in a lab, not production.** Drop a one-line script in a test web root, for example `<?php system('whoami'); ?>`, and browse to it. You should see Detection 3 fire for the file creation and Detection 1 or 2 fire for the child process. If neither fires, check sensor health before assuming the server is clean.

**Tune by parent + command line, not by whole process.** Excluding `php-fpm` or `w3wp.exe` entirely defeats the point.

**Know the limits.** MDE sees processes, files, and network activity — not HTTP requests or PHP source. A webshell that only reads files or dumps a database without spawning a process won't trigger the process detections. Web server logs, a WAF, and file integrity monitoring fill that gap.

**Hardening that makes these detections quieter and the attacker's life harder:**

- Set `disable_functions` in `php.ini` for `system`, `exec`, `shell_exec`, `passthru`, `popen`, and `proc_open` if the application doesn't need them.
- Block PHP execution in uploads and media directories at the web server level.
- Run PHP under a dedicated low-privilege account with a restrictive `open_basedir`.
- Keep PHP patched and on a supported version.

## Takeaway

A web-facing process starting a shell, writing PHP into a folder it shouldn't, or dropping executables is a high-signal pattern — and Defender for Endpoint gives you that telemetry on both Windows and Linux. Baseline first, tune narrowly, and alert on the rest.

Thanks for reading!

I'm sharing these queries as a practical starting point for detection engineering, not as a plug-and-play rule for every environment. Please test them in a lab, validate the telemetry available in your Defender environment, and tune against normal application behaviour before creating production alerts.

Suggestions and improvements are welcome. If you've tested these detections, found a useful improvement, or spotted an edge case, feel free to share your feedback.



