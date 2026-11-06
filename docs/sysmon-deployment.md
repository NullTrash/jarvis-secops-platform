# Endpoint Telemetry: Windows Sysmon & Shipper Deployment Guide

This guide walks you through deploying **Microsoft Sysmon** (System Monitor) with a security-focused configuration on Windows endpoints (such as your Workstation) and forwarding logs to the Proxmox SIEM.

---

## 1. Install Sysmon on Windows

1. Download **Sysmon** from Microsoft Sysinternals:
   [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Download a high-fidelity configuration file (such as SwiftOnSecurity's modular config):
   * SwiftOnSecurity Config: `https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml`
3. Open an Administrator PowerShell prompt and install Sysmon:
   ```powershell
   .\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
   ```
4. Verify Sysmon is running:
   ```powershell
   Get-Service -Name "Sysmon64"
   ```

---

## 2. Forward Endpoint Logs to Proxmox SIEM

### Option A: Winlogbeat (Lightweight & Fast)

1. Download Winlogbeat from Elastic:
   `https://www.elastic.co/downloads/beats/winlogbeat`
2. Extract to `C:\Program Files\Winlogbeat`.
3. Edit `winlogbeat.yml`:
   ```yaml
   winlogbeat.event_logs:
     - name: Microsoft-Windows-Sysmon/Operational
       level: information
     - name: Security
       event_id: 4624, 4625, 4672, 4688, 4720, 4728, 4732
     - name: Microsoft-Windows-PowerShell/Operational
       event_id: 4104

   output.logstash:
     hosts: ["<PROXMOX_SIEM_IP>:5044"]
   ```
4. Install and start the service:
   ```powershell
   cd "C:\Program Files\Winlogbeat"
   PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1
   Start-Service winlogbeat
   ```

### Option B: Elastic Agent (Managed via Fleet Server)
1. In Kibana, go to **Management** $\rightarrow$ **Fleet** $\rightarrow$ **Add Agent**.
2. Copy the enrollment command and run in Administrator PowerShell on the Windows host.

---

## 3. Telemetry Verification

In Kibana (`http://<pve-siem-ip>:5601`), open **Discover** $\rightarrow$ query `logs-endpoint.sysmon-*` or `winlogbeat-*`.
You will see detailed process creations, network socket connections, and DNS lookups in near real-time.
