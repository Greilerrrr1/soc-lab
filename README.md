# 🛡️ Azure SOC Home Lab – Microsoft Sentinel Attack Detection

## Overview

This project is a hands-on **Security Operations Center (SOC) home lab** built in **Microsoft Azure** using **Microsoft Sentinel**. The lab simulates real-world attack activity against a Windows virtual machine and demonstrates how a SOC analyst detects, investigates, and visualizes malicious behavior using log data and KQL.

The primary focus of this lab is detecting **brute-force login attempts (Event ID 4625)**, enriching attack data with geolocation information, and visualizing attacker activity on a global map inside Sentinel.

---

## Architecture

<img width="934" height="509" alt="Screenshot 2025-12-29 142533" src="https://github.com/user-attachments/assets/b8ae6fb0-c5df-4ee9-9510-070d213c2fb5" />


### Components Used
- Azure Virtual Machine (Windows 10 Enterprise)
- Network Security Group (NSG)
- Log Analytics Workspace
- Microsoft Sentinel (SIEM)
- Windows Security Events (`SecurityEvent` table)
<img width="1125" height="657" alt="Screenshot 2025-12-29 145354" src="https://github.com/user-attachments/assets/88276b9d-e96b-44d8-a61d-dcefd1ffb968" />

---

## Lab Environment

- **Cloud Platform:** Microsoft Azure  
- **Operating System:** Windows 10 Enterprise  
- **SIEM:** Microsoft Sentinel  
- **Log Source:** Windows Security Event Logs  
- **Attack Simulated:** Brute-force RDP login attempts  
- **Key Event ID:** `4625` – An account failed to log on  

<img width="1212" height="675" alt="Screenshot 2025-12-29 145750" src="https://github.com/user-attachments/assets/dca66671-f60a-41cf-a64c-1a02e95c89e0" />

---

## Detection & Analysis

### Failed Login Detection (Event ID 4625)

Failed login attempts were queried using **KQL (Kusto Query Language)** to identify:
- Targeted user accounts
- Attacking IP addresses
- Timestamp and frequency of attempts
<img width="1037" height="541" alt="Screenshot 2025-12-29 151526" src="https://github.com/user-attachments/assets/cbbb665f-1301-4ea2-bad8-0f3d0ab5d020" />

```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, Computer, IpAddress, Activity
```
<img width="1029" height="535" alt="Screenshot 2025-12-29 152451" src="https://github.com/user-attachments/assets/bf6e78c0-dab8-499c-b858-4577df8d4ac8" />

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
SecurityEvent
| where EventID == 4625
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| project TimeGenerated, IpAddress, cityname, countryname, latitude, longitude
```
<img width="1036" height="520" alt="Screenshot 2025-12-29 152734" src="https://github.com/user-attachments/assets/163f43b6-9c1e-4081-b573-85dce3773f51" />


  

