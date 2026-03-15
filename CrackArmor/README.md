# CrackArmor: Critical AppArmor Vulnerabilities in Linux

## Overview

CrackArmor is the name given by Qualys to a set of nine critical vulnerabilities in AppArmor, the Mandatory Access Control (MAC) framework built into the Linux kernel. These flaws allow local attackers to escalate privileges to root, bypass confinement policies, escape containers, and in some cases trigger kernel-level denial of service on affected systems.

The issues affect all Linux kernels from version 4.11 onwards when AppArmor is enabled, which includes most supported releases of Ubuntu, Debian, and SUSE, among others. In contrast, SELinux-centric distributions such as Red Hat Enterprise Linux (RHEL), Fedora, and Amazon Linux are not affected in their default configuration.

This README summarizes the impact, affected software and distributions, patch status, and provides ready-to-use KQL queries for threat hunting in Microsoft Defender for Endpoint / Sentinel.

---

## What is AppArmor?

AppArmor (Application Armor) is a Linux kernel security module that enforces Mandatory Access Control policies per application through profiles. Instead of relying solely on Unix Discretionary Access Control (user/group/other permissions), AppArmor restricts what each process can do (files, network, capabilities, inter-process communication, etc.) based on a predefined profile.

Key characteristics:

- **Path-based**: Applications are identified by their filesystem path, which often makes AppArmor simpler to configure than label-based systems like SELinux.
- **Two main modes**:
  - **Enforce**: Violations are blocked and logged.
  - **Complain**: Violations are logged but not blocked, useful for profile tuning.

AppArmor is enabled by default in Ubuntu, Debian, and SUSE/openSUSE and used to confine many core services (web servers, databases, printing subsystems, etc.).

CrackArmor targets this layer: if AppArmor can be subverted, an attacker may turn a hardening mechanism into a vector for full system compromise.

---

## Affected Kernels and Distributions

### Vulnerable Kernel Versions

Public analysis and vendor advisories agree that CrackArmor affects **all Linux kernels from 4.11 onwards** when AppArmor is enabled as a Linux Security Module (LSM). This covers a wide range of still-deployed LTS branches, including 5.15 and 6.1.

Upstream and stable trees have released fixes for at least these branches:

| Kernel Branch | Status vs. CrackArmor    |
|---------------|--------------------------|
| 6.8.x         | Fixed in stable releases |
| 6.6.x (LTS)   | Fixed                    |
| 6.1.x (LTS)   | Fixed                    |
| 5.15.x (LTS)  | Fixed                    |

Kernels predating 4.11 do not contain the vulnerable AppArmor code paths but are generally out of support in modern distributions.

### Distributions Affected

Distributions are impacted if they:

1. Build the kernel with AppArmor support, and
2. Enable and use AppArmor in production.

Under this definition, the main affected families are:

- **Ubuntu** (all supported releases): AppArmor enabled and widely used to confine system services.
- **Debian**: AppArmor integrated and enabled by default on many installations.
- **SUSE Linux Enterprise** and **openSUSE**: AppArmor is a core part of the default security stack.
- Derivatives of these distributions (e.g., Linux Mint, Pop!\_OS, Kali Linux, etc.).

### Popular Distributions Likely *Not* Affected

Some widely used distributions are **not affected** in their default configuration because they use SELinux instead of AppArmor, or ship without AppArmor enabled:

| Distribution        | LSM Default | Affected by CrackArmor |
|---------------------|-------------|------------------------|
| RHEL / CentOS       | SELinux     | ❌ No                  |
| Fedora              | SELinux     | ❌ No                  |
| Amazon Linux        | SELinux     | ❌ No                  |
| Arch Linux          | None/opt-in | ❌ No (unless AppArmor manually enabled) |
| Ubuntu              | AppArmor    | ✅ Yes                 |
| Debian              | AppArmor    | ✅ Yes                 |
| SUSE / openSUSE     | AppArmor    | ✅ Yes                 |

> In typical enterprise RHEL/Fedora/Amazon Linux environments with SELinux in enforcing mode and no AppArmor, CrackArmor does not apply.

---

## Patch Availability and Timelines

### Discovery and Coordinated Disclosure

Qualys' Threat Research Unit (TRU) discovered the nine vulnerabilities and reported them privately under coordinated disclosure to Linux kernel maintainers and major distribution vendors. Public disclosure occurred around **11–13 March 2026**, at which point Ubuntu, Debian, and SUSE started publishing their own advisories and updates.

### CVE Status

At the time of initial disclosure, CrackArmor vulnerabilities did not yet have CVE identifiers assigned, as the Linux kernel team must finalize them once patches are stable. **Vendors emphasize that the lack of CVE IDs must not delay patching.**

### Per-Distribution Patch Status

| Distribution | Advisory | Available Since |
|---|---|---|
| **Ubuntu** 24.04 / 22.04 / 20.04 LTS | Canonical Vulnerability KB + Blog post | 11 March 2026 |
| **Debian** stable (trixie) | DSA-6162-1 / DSA-6163-1 | 12–13 March 2026 |
| **SUSE** SLES / openSUSE | SUSE-SU kernel advisories (*important*) | March 2026 |

---

## Remediation and Mitigation

Across vendors and researchers, the core message is consistent: treat CrackArmor as a **high-priority patching event** due to its ability to achieve root escalation, bypass confinement, and enable container escapes.

### General Approach

1. **Upgrade the kernel** to a fixed version on all systems using AppArmor.
2. **Reboot** affected machines so the new kernel is active.
3. Deploy **user-space mitigations** where vendors provide them (not a substitute for kernel patching).

### Ubuntu

```bash
# Full system and kernel update + reboot (recommended)
sudo apt update && sudo apt upgrade
sudo reboot
```

If an immediate reboot is not yet possible, install the user-space mitigations first:

```bash
# Harden sudo and su chain (no reboot required)
sudo apt update
sudo apt install sudo util-linux
```

> These updates harden `sudo` and `su` against an exploit chain using `sudo`, `su`, and Postfix, but do **not** replace the kernel patch.

### Debian

```bash
sudo apt update
sudo apt full-upgrade
sudo reboot
```

Verify that the `linux-image-*` metapackage has been upgraded to the version specified in DSA-6162-1 / DSA-6163-1 for your release.

### SUSE

```bash
sudo zypper refresh
sudo zypper patch
sudo reboot
```

Even in environments with live patching capabilities, SUSE advises moving to the fully patched kernel for these AppArmor flaws.

### Additional Compensating Controls

While patching is in progress:

- Limit local and SSH access to strictly necessary users.
- Review and harden `sudoers`; reduce the number of privileged accounts.
- Avoid running untrusted container images on nodes where AppArmor is active.
- Monitor for suspicious AppArmor profile changes and unexpected reboots or kernel panics.

---

## Detection with Microsoft Defender (KQL)

The following KQL queries can be used in **Microsoft Defender for Endpoint** or **Microsoft Sentinel** to hunt for behaviors associated with CrackArmor exploitation on Linux endpoints.

> **Prerequisites**: Linux endpoints must be onboarded to Microsoft Defender for Endpoint (MDE) or their logs ingested into Sentinel so that `DeviceFileEvents`, `DeviceProcessEvents`, and `DeviceEvents` tables are populated.

---

### 1. Suspicious Writes to AppArmor Control Pseudo-Files

CrackArmor manipulates AppArmor by writing to pseudo-files under `/sys/kernel/security/apparmor/` (`.load`, `.replace`, `.remove`) to load or replace security profiles.

```kusto
DeviceFileEvents
| where FolderPath startswith "/sys/kernel/security/apparmor"
| where FileName in (".load", ".replace", ".remove")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FolderPath, FileName
| order by Timestamp desc
```

---

### 2. Abuse of sudo and MAIL_CONFIG for Root Escalation

One documented exploit chain abuses the `MAIL_CONFIG` environment variable alongside `sudo` and Postfix (`sendmail`) to gain root.

```kusto
DeviceProcessEvents
| where FileName == "sudo" or FileName == "sendmail"
| where ProcessCommandLine has_any ("MAIL_CONFIG", "sendmail", "postfix")
| where InitiatingProcessAccountName != "root"
| where AccountName == "root" or ProcessTokenElevation == "TokenElevationTypeFull"
| project Timestamp, DeviceName, AccountName, InitiatingProcessAccountName,
          ProcessCommandLine, InitiatingProcessCommandLine, FileName
| order by Timestamp desc
```

---

### 3. Anomalous User Namespace Creation (Container Escape)

CrackArmor can help attackers escape containers by creating user namespaces from unprivileged contexts.

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("unshare", "clone", "--user", "userns")
| where InitiatingProcessAccountName !in ("root", "system")
| project Timestamp, DeviceName, AccountName, InitiatingProcessAccountName,
          ProcessCommandLine, FileName, FolderPath
| order by Timestamp desc
```

---

### 4. Suspicious Modifications to /etc/passwd

Some exploitation paths involve modifying `/etc/passwd` after gaining kernel-level control.

```kusto
DeviceFileEvents
| where FolderPath == "/etc" and FileName == "passwd"
| where ActionType in ("FileModified", "FileCreated")
| where InitiatingProcessAccountName != "root"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType
| order by Timestamp desc
```

---

### 5. Consolidated Hunting Query

Single-query view combining all the CrackArmor behavioral patterns:

```kusto
let AppArmorWrite = DeviceFileEvents
    | where FolderPath startswith "/sys/kernel/security/apparmor"
    | extend AlertType = "AppArmor pseudofile write";
let SudoAbuse = DeviceProcessEvents
    | where ProcessCommandLine has_any ("MAIL_CONFIG", "sendmail")
      and FileName == "sudo"
    | extend AlertType = "Sudo MAIL_CONFIG abuse";
let PasswdModify = DeviceFileEvents
    | where FolderPath == "/etc" and FileName == "passwd"
      and InitiatingProcessAccountName != "root"
    | extend AlertType = "Passwd modified by non-root";
let NamespaceEscape = DeviceProcessEvents
    | where ProcessCommandLine has_any ("unshare --user", "userns")
    | extend AlertType = "User namespace creation";
union AppArmorWrite, SudoAbuse, PasswdModify, NamespaceEscape
| project Timestamp, AlertType, DeviceName, AccountName,
          InitiatingProcessAccountName, ProcessCommandLine, FolderPath, FileName
| order by Timestamp desc
```

---

## References

- [Qualys TRU: CrackArmor — Critical AppArmor Flaws Enable Local Privilege Escalation](https://blog.qualys.com/vulnerabilities-threat-research/2026/03/12/crackarmor-critical-apparmor-flaws-enable-local-privilege-esc)
- [Canonical: AppArmor vulnerability fixes available (11 March 2026)](https://ubuntu.com/blog/apparmor-vulnerability-fixes-available)
- [Ubuntu Vulnerability Knowledge Base: CrackArmor](https://ubuntu.com/security/vulnerabilities/crackarmor)
- [The Hacker News: Nine CrackArmor Flaws in Linux AppArmor](https://thehackernews.com/2026/03/nine-crackarmor-flaws-in-linux-apparmor.html)
- [Debian DSA-6162-1](https://lists.debian.org/debian-security-announce/2026/msg00072.html)
- [SUSE Security Update for the Linux Kernel](https://www.suse.com/support/update/announcement/2026/suse-su-20260369-1/)

---

## License

This repository contains defensive guidance and detection queries. Adapt them to your environment and security policies as needed.
