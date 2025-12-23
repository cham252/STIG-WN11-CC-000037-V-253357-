# WN11-CC-000037 – Apply UAC Restrictions to Local Accounts on Domain Systems

## Overview
This repository documents remediation and validation for **STIG ID WN11-CC-000037 (V-253357)**.

This control ensures that **local administrator accounts** have their **privileged tokens filtered** when accessing systems over the network, reducing the risk of lateral movement in domain environments.

## STIG Details
- **STIG ID:** WN11-CC-000037
- **Vulnerability ID:** V-253357
- **Severity:** CAT II (Medium)
- **SRG:** SRG-OS-000134-GPOS-00068
- **CCI:** CCI-001084
- **Registry Path:**  
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
- **Registry Value:**  
  `LocalAccountTokenFilterPolicy`
- **Required Value:** `0` (REG_DWORD)

## Security Rationale
Without UAC token filtering, compromised local administrator credentials can be used to move laterally across domain systems using elevated privileges. Enabling this control enforces least privilege during remote access.

## Finding Condition
A system is **non-compliant** if:
- The system is domain-joined **and**
- `LocalAccountTokenFilterPolicy` does not exist **or**
- The value is not set to `0`

Standalone (non-domain) systems are **Not Applicable (NA)**.

---

## Manual Check
```powershell
Get-ItemProperty `
  -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name LocalAccountTokenFilterPolicy
