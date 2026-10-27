---
title: "PHP2Shell: Detecting PHP Webshell Activity with Microsoft Defender"
date: 2026-10-26T00:00:00+05:30
draft: false
author: "Nirmal 🇮🇳"
description: "KQL detections for catching PHP webshell activity on Windows and Linux web servers using Microsoft Defender for Endpoint, no Sentinel required."
categories: ["Cybersecurity"]
tags: ["Threat Detection", "KQL", "Microsoft Defender", "Detection Engineering", "Blue Team"]
---

Last couple of days I was working on how to detect PHP2Shell using Defender XDR Advanced Hunting, so here is my POV. I'll walk through a set of PHP webshell detections I built using Microsoft Defender for Endpoint (MDE) advanced hunting — no Sentinel involved. Before the queries, I want to cover some background on how PHP runs on a server, because that makes the detections much easier to follow — and I'll call out where **Windows and Linux differ**, since a lot of PHP hosting runs on Linux and most public writeups only cover Windows/IIS.

Let's get into it.

## Why this matters

PHP runs a huge share of the web, so a PHP webshell is one of the most common footholds after a file-upload bug, an RCE flaw, or a vulnerable plugin. The attacker drops a small script, calls it over HTTP, and the web server starts running OS commands for them.

That moment is the weak point. A web-facing process (IIS, Apache, PHP-FPM) suddenly creates a shell or a download tool as a child. Normal websites almost never do that. Everything below is built on that parent-child relationship, plus two supporting signals: where PHP files get written, and which servers run exposed PHP.

All queries use standard Defender XDR Advanced Hunting tables (`DeviceProcessEvents`, `DeviceFileEvents`, `DeviceTvm*`, `DeviceInfo`).

## How PHP Actually Runs on a Server

The basic flow is: browser → web server → PHP → script runs → response. What matters for detection is **which process hosts PHP**, because that process name becomes the parent of anything the script launches.

| Model | Where | How PHP runs | Process you see in MDE |
|---|---|---|---|
| mod_php | Apache (Linux & Windows) | PHP loaded inside the Apache process | `apache2`/`httpd` (Linux), `httpd.exe` (Windows) |
| FastCGI on IIS | **Windows** | IIS FastCGI module starts PHP workers | `w3wp.exe` then `php-cgi.exe` |
| PHP-FPM | **Linux** (Nginx/Apache) | Separate pool of PHP workers behind a socket | `php-fpm`, often versioned like `php-fpm8.2` |
| CGI / LSAPI | Both / LiteSpeed | PHP launched per request or by LiteSpeed | `php-cgi`, `lsphp` |
| CLI | Both | Run from a terminal, cron, or scheduled task | `php`/`php.exe` |

Two things that trip people up when writing these detections:

- **`php-fpm.exe` does not exist.** PHP-FPM is a Linux-only process model.
- **On Linux, FPM process names are often versioned** (`php-fpm8.2`), so match with `startswith` instead of an exact name.

Ops I know Step 1 was boring 😅 but now let's focus more on what actually matters 🔥

## Windows vs Linux 

This is the part that matters most for writing accurate detections — mix up a path or a process name between the two and your query silently misses everything.

| |  Windows |  Linux |
|---|---|---|
| PHP binaries | `C:\php`, `C:\Program Files\PHP`, `C:\xampp\php` | `/usr/bin/php`, `/usr/sbin/php-fpm` |
| Config | `php.ini` next to the PHP binaries | Per-SAPI: `/etc/php/<ver>/{cli,fpm,apache2}/php.ini` (Debian), `/etc/php.ini` + `/etc/php-fpm.d/www.conf` (RHEL) |
| Web roots | `C:\inetpub\wwwroot`, `C:\xampp\htdocs`, `C:\wamp64\www` | `/var/www/html`, `/var/www/<site>`, `/srv/www` |
| Runs as | `IIS APPPOOL\<pool>` or Apache service account | `www-data` (Debian/Ubuntu), `apache`/`nginx` (RHEL) |
| Temp / sessions | `C:\Windows\Temp` | `/tmp`, `/var/lib/php/sessions` |
| Shell PHP spawns | `cmd.exe /c <command>` | `/bin/sh -c <command>` |
| Process names | End in `.exe` | No extension; FPM names may be versioned |
| Typical post-exploit commands | `whoami`, `systeminfo`, `net user`, PowerShell, `certutil` | `id`, `uname -a`, `curl`/`wget`, `bash`, `python` |

On Debian-style systems, `php.ini` differs per SAPI — hardening the CLI config does nothing for the FPM or Apache config. A mistake I've seen more than once during assessments.

## How a PHP Webshell Becomes a Shell

A webshell is just a PHP file that passes attacker input to something dangerous — `system()`, `exec()`, `shell_exec()`, `passthru()`, `popen()`, `proc_open()`, or backticks, often hidden behind `eval()` or `base64_decode()` to dodge scanners.

When one of those functions runs, PHP asks the OS to create a child process. That child is what MDE records. The parent is whatever hosts PHP (`w3wp.exe`, `php-cgi.exe`, `httpd.exe`, `apache2`, `php-fpm`), and the child is `cmd.exe` on Windows or `sh` on Linux. Early commands are almost always recon (`whoami`, `id`, `systeminfo`, `uname`) followed by a download of a second-stage tool.

That gives us three angles to detect on:

1. **Process** — a web or PHP process spawning a shell or download tool
2. **File** — a web or PHP process writing new PHP files (the upload step) or executables/scripts (the staging step)
3. **Exposure** — where outdated or internet-facing PHP exists in the first place

## Before You Run These

- Replace the placeholder device names in `WebServers` with your own web servers — or match on a device tag/group instead.
- Run each over 7–30 days first and tune before alerting. CMSs and frameworks legitimately write PHP files and sometimes call helper programs.
- `php.exe`/`php` is deliberately **not** treated as a web parent in the shell detections, because CLI PHP under cron, Composer, and deployment scripts legitimately spawns shells. Hunt it separately if needed.

## KQL Queries 

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

{{< figure src="/images/php-to-shell/baseline-result.webp" alt="Baseline query result showing w3wp.exe spawning php-cgi.exe" class="text-center" >}}

Running this in my own environment, the top row was `w3wp.exe` → `php-cgi.exe` — exactly the Windows IIS + FastCGI chain from Step 1. That confirms telemetry is healthy, and tells you `php-cgi.exe` itself isn't the alert — it runs constantly and legitimately. What you're watching for is `php-cgi.exe` spawning something it shouldn't, like `cmd.exe` or `powershell.exe`, which is exactly what Detection 1 checks next.

### Detection 1: Windows PHP process spawns a shell 

This is the core signal on Windows. On IIS with PHP, the chain looks like `w3wp.exe` → `php-cgi.exe` → `cmd.exe`. This query catches the final step — a web/PHP process launching a shell, download utility, discovery tool, or other LOLBin — and also catches a web server spawning a suspicious child directly, with no `php-cgi.exe` in between.

`DownloadIndicator` is a prioritisation hint, flagging command lines with URL strings or download-related terms. A `true` doesn't prove a download succeeded, and `false` doesn't mean the activity is safe.

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

`SuspiciousChildren` covers command execution (`cmd.exe`, `powershell.exe`), download/transfer tools (`curl.exe`, `certutil.exe`, `bitsadmin.exe`), account/domain discovery (`whoami.exe`, `net.exe`, `nltest.exe`), and script/proxy execution (`mshta.exe`, `rundll32.exe`, `regsvr32.exe`). These all have legitimate admin uses too — what's unusual is seeing them launched *by a web process*.

**How I would investigate:** check `InitiatingProcessCommandLine` and `ProcessCommandLine`, confirm the process tree, then check which account ran it (app-pool identity vs something unexpected). Pivot to nearby file and network events on the same device before deciding.

**Tuning:** baseline first, exclude known maintenance activity with narrow conditions (parent + specific command line), never exclude a whole parent like `w3wp.exe`.

**Limitations:** process-based, so it misses webshells that only read/exfiltrate data without spawning a child, or renamed binaries. Pair with web-server logs, WAF telemetry and the file-write detections below.

---

### Detection 2: Linux web/PHP process spawns a shell or download tool

The Linux counterpart to Detection 1. Apache, Nginx, LiteSpeed, or PHP-FPM shouldn't be starting `sh`, `bash`, `curl`, `wget`, or interpreters — PHP's `system()` commonly results in `sh -c <command>`, so the shell is often the first child process you'll see. Linux process names have no `.exe`, and PHP-FPM workers can be versioned (`php-fpm8.2`), which the query accounts for.

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

**How I would investigate:** review parent/child command lines, the service account, and the process tree. On Linux, pay close attention to reverse-connection tools (`nc`, `ncat`, `socat`) and unexpected interpreter execution.

**Tuning:** PHP's `mail()` legitimately runs `sh -c /usr/sbin/sendmail -t -i` on many systems — that's why it's excluded above. Keep exclusions narrow; an attacker can reproduce the same text in a command line.

### Detection 3: PHP file written by a web or PHP process

Catches the upload/drop step — a web process creating, modifying, or renaming a PHP-related file. Covers both Windows and Linux process names in one query.

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

`UserWritablePath` is a path-based heuristic (`uploads`, `images`, `tmp`, etc.) — prioritise those rows, but confirm the actual folder rather than trusting the flag blindly. A site has no legitimate reason to execute PHP from an uploads directory.

**Tuning:** CMS updates, Composer, and framework-compiled views all legitimately write PHP files. Baseline first, then exclude by known path — not by whole process.

### Detection 4: Executable or script dropped by a web or PHP process

Catches the staging step, once an attacker already has a shell and brings tooling. A web/PHP process creating or renaming an `.exe`, `.dll`, `.ps1`, `.sh`, `.py`, or similar is almost never legitimate, on either OS.

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

**How I would investigate:** check the full file path, SHA256 hash, initiating process and account. Validate the file's origin/signature where possible, then pivot to process and network events on the same device.

**Tuning:** baseline legitimate deployment/update workflows first, and use narrow exceptions rather than excluding a whole web-server process.

### Exposure 1: Where is PHP installed, and is the device internet-facing?

Shifts from behaviour to asset discovery — inventories PHP across the estate and flags internet-facing devices, so you know where the detections above matter most.

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

Internet-facing status here is a prioritisation factor, not proof a server is reachable or vulnerable — validate `IsInternetFacing` against your own network records, since inventory depends on Defender's discovery and reporting.

### Exposure 2: Known-vulnerable PHP

Lists High/Critical CVEs against installed PHP, per device — pair with Exposure 1 to patch internet-facing servers first.

```sql
DeviceTvmSoftwareVulnerabilities
| where SoftwareName contains 'php'
| where VulnerabilitySeverityLevel in ('Critical', 'High')
| summarize CveCount = dcount(CveId), CVEs = make_set(CveId, 20) by DeviceName, OSPlatform, SoftwareName, SoftwareVersion
| order by CveCount desc
```

`make_set(CveId, 20)` caps the list at 20 CVEs per group, so don't treat it as exhaustive when `CveCount` is higher. Confirm the affected version against the vendor advisory before recommending a patch — inventory can lag, and applicability depends on how PHP was packaged or installed.

## Step 6: Test, Tune, Harden

**Test in a lab, not production.** Drop a one-liner like `<?php system('whoami'); ?>` in a test web root and browse to it. You should see Detection 3 fire for the file creation and Detection 1 or 2 fire for the child process. If neither fires, check sensor health before assuming the server is clean.

**Tune by parent + command line, not by whole process.** Excluding `php-fpm` or `w3wp.exe` entirely defeats the point.

**Know the limits.** MDE sees processes, files, and network activity — not HTTP requests or PHP source. A webshell that only reads files or dumps a database without spawning a process won't trigger the process detections. Web server logs, a WAF, and file integrity monitoring fill that gap.

**Hardening that makes these detections quieter and the attacker's life harder:**

- Set `disable_functions` in `php.ini` for `system`, `exec`, `shell_exec`, `passthru`, `popen`, and `proc_open` if the app doesn't need them.
- Block PHP execution in uploads/media directories at the web server level.
- Run PHP under a dedicated low-privilege account with a restrictive `open_basedir`.
- Keep PHP patched and on a supported version.

## Takeaway

A web-facing process starting a shell, writing PHP into a folder it shouldn't, or dropping executables is a high-signal pattern — and Defender for Endpoint gives you that telemetry on **both Windows and Linux**. Baseline first, tune narrowly, and alert on the rest.

Thanks for reading!

I'm sharing these queries as a practical starting point for detection engineering, not a plug-and-play rule for every environment. Test them in a lab, validate the telemetry available in your Defender environment, and tune against normal application behaviour before creating production alerts.

**Suggestions and improvements are welcome.** If you've tested these, found a useful improvement, or spotted an edge case — feel free to share your feedback.
