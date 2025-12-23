# WN11-CC-000037 – Apply UAC Restrictions to Local Accounts on Domain Systems

Author: Christopher Ham

---

## Overview
This repository documents remediation and validation for **STIG ID WN11-CC-000037 (V-253357)**.

This control ensures that **local administrator accounts** have their **privileged tokens filtered** when accessing systems over the network, reducing the risk of lateral movement in domain environments.

---

## STIG Details
- STIG ID: WN11-CC-000037
- Vulnerability ID: V-253357
- Severity: CAT II (Medium)
- SRG: SRG-OS-000134-GPOS-00068
- CCI: CCI-001084
- Registry Hive: HKEY_LOCAL_MACHINE
- Registry Path: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
- Registry Value: LocalAccountTokenFilterPolicy
- Required Value: 0 (REG_DWORD)

---

## Security Rationale
Without User Account Control token filtering, compromised local administrator credentials can be used to move laterally across domain systems using elevated privileges. Enabling this control enforces least privilege for remote access and limits the impact of credential compromise.

---

## Applicability
- If the system is not domain-joined, this control is **Not Applicable (NA)**.
- If the system is domain-joined, this setting must be explicitly configured.

---

## Finding Condition
A system is **non-compliant** if:
- The system is domain-joined AND
- LocalAccountTokenFilterPolicy does not exist OR
- LocalAccountTokenFilterPolicy is not set to 0 (REG_DWORD)

---

## Manual Check (PowerShell)

Get-ItemProperty `
  -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name LocalAccountTokenFilterPolicy
  ## Expected Compliant Output

When the system is configured correctly, the following PowerShell command:

Get-ItemProperty `
  -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name LocalAccountTokenFilterPolicy

  will return:

  LocalAccountTokenFilterPolicy : 0
PSPath                   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
PSParentPath             : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies
PSChildName              : System
PSDrive                  : HKLM
PSProvider               : Microsoft.PowerShell.Core\Registry

This output confirms that LocalAccountTokenFilterPolicy exists and is explicitly set to the required value of 0 (REG_DWORD), indicating the system is compliant with STIG WN11-CC-000037.
