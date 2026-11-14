# 🛡️ Jarvis Curated Detection Rules Catalog (Deployed to Elastic SIEM)

- **Last Synced**: `2026-11-14 19:16:31 UTC`
- **Total Rules Deployed**: **25 / 25**
- **Target Data Streams**: `winlogbeat-*`, `logs-endpoint.sysmon-*`, `logs-network.unifi-default`

| # | Rule Name | Severity | Urgency | Language | MITRE Tactics | 30d Dry-Run Hits | Kibana Status |
| :---: | :--- | :---: | :---: | :---: | :--- | :---: | :---: |
| 1 | **Attempt to Establish VScode Remote Tunnel** (`command_and_control_tunnel_vscode.toml`) | `MEDIUM` | **72/100** | `EQL` | Command and Control | 1 | ✅ Active |
| 2 | **High Number of Process and/or Service Terminations** (`impact_stop_process_service_threshold.toml`) | `MEDIUM` | **72/100** | `KUERY` | Impact, Defense Evasion | 6 | ✅ Active |
| 3 | **First Time Seen Removable Device** (`initial_access_exfiltration_first_time_seen_usb.toml`) | `LOW` | **46/100** | `KUERY` | Initial Access, Exfiltration | 1 | ✅ Active |
| 4 | **Potential Invoke-Mimikatz PowerShell Script** (`credential_access_mimikatz_powershell_module.toml`) | `CRITICAL` | **100/100** | `KUERY` | Credential Access, Defense Evasion | 0 | ✅ Active |
| 5 | **Browser Process Spawned from an Unusual Parent** (`credential_access_browsers_unusual_parent.toml`) | `HIGH` | **88/100** | `EQL` | Credential Access, Collection | 0 | ✅ Active |
| 6 | **Potential Credential Access via Windows Utilities** (`credential_access_cmdline_dump_tool.toml`) | `HIGH` | **88/100** | `EQL` | Credential Access, Defense Evasion | 0 | ✅ Active |
| 7 | **NTDS or SAM Database File Copied** (`credential_access_copy_ntds_sam_volshadowcp_cmdline.toml`) | `HIGH` | **88/100** | `EQL` | Credential Access | 0 | ✅ Active |
| 8 | **Potential Credential Access via Trusted Developer Utility** (`credential_access_credential_dumping_msbuild.toml`) | `HIGH` | **88/100** | `EQL` | Credential Access, Defense Evasion | 0 | ✅ Active |
| 9 | **Outlook Home Page Registry Modification** (`command_and_control_outlook_home_page.toml`) | `HIGH` | **88/100** | `EQL` | Command and Control, Persistence | 0 | ✅ Active |
| 10 | **Potential REMCOS Trojan Execution** (`command_and_control_remcos_rat_iocs.toml`) | `HIGH` | **88/100** | `EQL` | Command and Control, Defense Evasion | 0 | ✅ Active |
| 11 | **Mimikatz Memssp Log File Detected** (`credential_access_mimikatz_memssp_default_logs.toml`) | `HIGH` | **88/100** | `EQL` | Credential Access, Persistence | 0 | ✅ Active |
| 12 | **Microsoft Exchange Worker Spawning Suspicious Processes** (`initial_access_suspicious_ms_exchange_worker_child_process.toml`) | `HIGH` | **88/100** | `EQL` | Initial Access, Execution | 0 | ✅ Active |
| 13 | **PowerShell Suspicious Script with Audio Capture Capabilities** (`collection_posh_audio_capture.toml`) | `HIGH` | **88/100** | `KUERY` | Collection, Execution | 0 | ✅ Active |
| 14 | **PowerShell Keylogging Script** (`collection_posh_keylogger.toml`) | `HIGH` | **88/100** | `KUERY` | Collection, Execution | 0 | ✅ Active |
| 15 | **PowerShell Suspicious Script with Screenshot Capabilities** (`collection_posh_screen_grabber.toml`) | `HIGH` | **88/100** | `KUERY` | Collection, Execution | 0 | ✅ Active |
| 16 | **PowerShell Invoke-NinjaCopy script** (`credential_access_posh_invoke_ninjacopy.toml`) | `HIGH` | **88/100** | `KUERY` | Credential Access, Execution | 0 | ✅ Active |
| 17 | **Network Activity to a Suspicious Top Level Domain** (`command_and_control_dns_susp_tld.toml`) | `HIGH` | **88/100** | `EQL` | Command and Control, Defense Evasion | 0 | ✅ Active |
| 18 | **Untrusted DLL Loaded by Azure AD Connect Authentication Agent** (`credential_access_imageload_azureadconnectauthsvc.toml`) | `HIGH` | **88/100** | `EQL` | Credential Access, Defense Evasion | 0 | ✅ Active |
| 19 | **Modification of WDigest Security Provider** (`credential_access_mod_wdigest_security_provider.toml`) | `HIGH` | **88/100** | `EQL` | Credential Access, Defense Evasion | 0 | ✅ Active |
| 20 | **Potential Local NTLM Relay via HTTP** (`credential_access_relay_ntlm_auth_via_http_spoolss.toml`) | `HIGH` | **88/100** | `EQL` | Credential Access, Defense Evasion | 0 | ✅ Active |
| 21 | **Potential File Download via a Headless Browser** (`command_and_control_headless_browser.toml`) | `HIGH` | **88/100** | `EQL` | Command and Control | 0 | ✅ Active |
| 22 | **Potential Remote Desktop Tunneling Detected** (`command_and_control_rdp_tunnel_plink.toml`) | `HIGH` | **88/100** | `EQL` | Command and Control, Lateral Movement | 0 | ✅ Active |
| 23 | **NetSupport Manager Execution from an Unusual Path** (`command_and_control_rmm_netsupport_susp_path.toml`) | `HIGH` | **88/100** | `EQL` | Command and Control | 0 | ✅ Active |
| 24 | **Unusual Executable File Creation by a System Critical Process** (`defense_evasion_system_critical_proc_abnormal_file_activity.toml`) | `HIGH` | **88/100** | `EQL` | Defense Evasion, Execution | 0 | ✅ Active |
| 25 | **Conhost Spawned By Suspicious Parent Process** (`execution_via_hidden_shell_conhost.toml`) | `HIGH` | **88/100** | `EQL` | Execution, Defense Evasion | 0 | ✅ Active |
