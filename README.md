# Sigma Detection Engineering

A comprehensive collection of Sigma rules for threat detection engineering, covering the most impactful Windows attack techniques across the MITRE ATT&CK framework.

## Overview

This repository contains production-quality Sigma rules authored by Nilesh Dhage, organized by MITRE ATT&CK tactic. Each rule is validated against the Sigma specification and includes platform-specific conversion notes for Splunk and Elastic.

## Repository Structure

```
sigma-detection-engineering/
README.md
rules/
  powershell/
    proc_creation_win_powershell_encoded_command.yml
    proc_creation_win_powershell_download_cradle.yml
    proc_creation_win_powershell_suspicious_flags.yml
  credential_access/
    proc_creation_win_mimikatz_command_line.yml
    proc_access_win_lsass_memory_dump.yml
  lateral_movement/
    system_win_psexec_service_creation.yml
    proc_creation_win_wmi_process_spawn.yml
  persistence/
    registry_event_win_run_key_persistence.yml
```

## Rules Summary

### PowerShell Execution (T1059.001)

| Rule | Severity | Technique |
|------|----------|-----------|
| Suspicious PowerShell Encoded Command Execution | Medium | T1059.001, T1027 |
| PowerShell Download Cradle | Medium | T1059.001, T1105 |
| Suspicious PowerShell Execution Flag Combination | High | T1059.001, T1564.003 |

### Credential Access (T1003)

| Rule | Severity | Technique |
|------|----------|-----------|
| Mimikatz Command Line Patterns | Critical | T1003.001 |
| Suspicious LSASS Memory Access | High | T1003.001 |

### Lateral Movement (T1021, T1047)

| Rule | Severity | Technique |
|------|----------|-----------|
| PsExec Service Installation | High | T1021.002, T1569.002 |
| WMI Provider Spawning Command Interpreter | High | T1047 |

### Persistence (T1547)

| Rule | Severity | Technique |
|------|----------|-----------|
| Suspicious Run Key Registry Persistence | Medium | T1547.001 |

## MITRE ATT&CK Coverage

- **Execution**: T1059.001 (PowerShell), T1047 (WMI), T1569.002 (Service Execution)
- **Persistence**: T1547.001 (Registry Run Keys)
- **Defense Evasion**: T1027 (Obfuscated Files), T1564.003 (Hidden Window)
- **Credential Access**: T1003.001 (LSASS Memory)
- **Lateral Movement**: T1021.002 (SMB/PsExec), T1047 (WMI)

## Platform Conversion

These rules can be converted to target SIEM platforms using [sigma-cli](https://github.com/SigmaHQ/sigma-cli) or [pySigma](https://github.com/SigmaHQ/pySigma).

### Splunk
```bash
sigma convert -t splunk rules/powershell/proc_creation_win_powershell_encoded_command.yml
```

Example Splunk SPL output:
```
EventCode=4688 (NewProcessName="*\\powershell.exe" OR NewProcessName="*\\pwsh.exe") (CommandLine="* -enc *" OR CommandLine="* -encodedcommand *" OR CommandLine="* -ec *" OR CommandLine="* -e *")
```

### Elastic (Lucene/ES|QL)
```bash
sigma convert -t elasticsearch rules/powershell/proc_creation_win_powershell_encoded_command.yml
```

Example Elastic query output:
```
(process.executable:(*\\powershell.exe OR *\\pwsh.exe)) AND (process.command_line:(* -enc * OR * -encodedcommand * OR * -ec * OR * -e *))
```

## Log Source Requirements

| Rule Category | Required Log Source |
|--------------|--------------------|
| PowerShell rules | Windows Event ID 4688 (Process Creation) or Sysmon Event ID 1 |
| LSASS access | Sysmon Event ID 10 (Process Access) |
| PsExec detection | Windows System Event ID 7045 (Service Install) |
| WMI lateral movement | Windows Event ID 4688 or Sysmon Event ID 1 |
| Registry persistence | Sysmon Event ID 12/13 (Registry Events) |

## False Positive Tuning

Each rule includes documented false positive scenarios. Key tuning recommendations:

- **PowerShell rules**: Allowlist signed management binaries (SCCM, Intune, vendor agents)
- **LSASS rule**: Add known EDR/AV agent binaries to the filter_known_good list
- **PsExec rule**: Restrict alerts to unexpected source hosts and non-admin accounts
- **WMI rule**: Baseline expected WMI parent-child pairs in your environment
- **Registry rule**: Allowlist known installers (msiexec, vendor setup utilities)

## Author

**Nilesh Dhage**  
Date: 2026-07-16  
Status: Experimental

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rule Format](https://github.com/SigmaHQ/sigma/wiki/Specification)
- [pySigma Documentation](https://sigmahq-pysigma.readthedocs.io/)
- [Sigma Community Rules](https://github.com/SigmaHQ/sigma)
