# Cybersecurity Portfolio

Welcome to my cybersecurity portfolio. This repository contains hands-on labs, projects, and writeups focused on **Security Operations**, **Detection Engineering**, and **Blue Team** practices.

## About Me

- Graduate Computer Engineer
- CompTIA **Security+** certified
- Interested in **SOC operations**, **SIEM**, and **threat detection**

## Portfolio Structure

### 🔍 SIEM - Wazuh Labs

Practical labs focused on building and tuning detection rules with Wazuh.

- **[RDP Brute-Force Detection](siem-wazuh-labs/brute-force-lab/rdp-bruteforce-detection.md)**  
  Simulated RDP brute-force attack and detection with Wazuh. Configured custom correlation rules to detect repeated failed logons.

- **[Suspicious PowerShell Detection](siem-wazuh-labs/powershell-detection-lab/suspicious-powershell-detection.md)**  
  Simulated encoded PowerShell execution with Atomic Red Team, analyzed Sysmon and PowerShell logs in Wazuh, decoded the payload with CyberChef, and created a custom detection rule mapped to MITRE ATT&CK `T1059.001`.

### 🔧 Technical Skills

- **SIEM & Logging**: Wazuh, Windows Event Logs, Sysmon, PowerShell Script Block Logging
- **Attack Simulation**: Kali Linux, Hydra, Atomic Red Team
- **Detection Engineering**: Custom rules, correlation logic, alert tuning, MITRE ATT&CK mapping
- **Operating Systems**: Windows, Linux

## Contact

- **GitHub**: [https://github.com/dph862]
- **LinkedIn**: [https://linkedin.com/in/daniel-penco-hernandez]

---

> All labs and testing were performed in isolated, authorized environments for educational purposes.