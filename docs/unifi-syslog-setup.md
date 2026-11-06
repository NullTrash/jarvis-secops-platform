# UniFi Dream Router (UDR) Syslog Configuration Guide

This guide walks you through configuring your **UniFi Dream Router (UDR)** to stream firewall drops, threat detection events (IPS/IDS), and DNS logs to the **Jarvis Elastic SIEM** on Proxmox.

---

## 1. Network Requirements

* **Proxmox SIEM VM IP**: Note the local IP address of VM 1 (e.g. `10.0.0.20`).
* **Syslog Port**: `514` (UDP/TCP).

---

## 2. Configure Syslog in UniFi Network Application

1. Open your **UniFi Network Application** web interface (`https://unifi.ui.com` or `https://10.0.0.1`).
2. Go to **Settings** (Gear icon in the lower-left sidebar).
3. Navigate to **System** $\rightarrow$ **Advanced** (or **Application Logs / Remote Logging** depending on UniFi OS version).
4. Under **Remote Logging / Syslog**:
   * Toggle **Enable Syslog** (or **Remote Syslog Server**).
   * **Server IP**: Enter the IP address of your Proxmox SIEM VM (e.g., `10.0.0.20`).
   * **Port**: `514`
   * **Protocol**: `UDP` (or `TCP`).
5. Select log levels and categories:
   * Check **Network Application Logs**.
   * Check **Device Logs** (Access Points, Switches, UDR Gateway).
   * Check **Firewall Logs** / **Security Detections (IPS/IDS)**.
   * **Log Level**: Select `Debug` or `Normal / Info`.
6. Click **Apply Changes**.

---

## 3. Enable Firewall Logging on Specific Rules (Optional but Recommended)

To ensure dropped packets are logged:
1. In UniFi Network, go to **Settings** $\rightarrow$ **Security** $\rightarrow$ **Firewall Rules**.
2. Select your WAN / LAN Drop rules (e.g. `WAN In - Drop Invalid State`, `WAN Local - Drop All`).
3. Ensure **Logging** is checked for each rule you want visible in the SIEM.

---

## 4. Ingestion Verification

Once configured, verify traffic is reaching Logstash:

1. On the Proxmox SIEM VM:
   ```bash
   docker logs -f jarvis-logstash
   ```
2. In **Kibana** (`http://<pve-siem-ip>:5601`):
   * Go to **Discover**.
   * Select the index pattern: `logs-network.unifi-*`.
   * You should see real-time inbound firewall drops and router connection events!
