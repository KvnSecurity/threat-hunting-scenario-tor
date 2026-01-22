# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/KvnSecurity/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that has the string “tor” in it and discovered what looks like the user “employee” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop. These events began at: 
Jan 19, 2026 4:39:39 PM


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "kavin-threat-hu"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "kavin"
| order by Timestamp desc
| where Timestamp >= datetime(Jan 19, 2026 4:39:39)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, account = InitiatingProcessAccountName
```
<img width="1129" height="711" alt="Screenshot 2026-01-21 at 10 42 58 PM" src="https://github.com/user-attachments/assets/39cf64d8-7927-41d6-abf9-e0577c044ef0" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProccesEvents table for ANY ProcessComandLine that contained the string “tor-browser”. Based on the logs returned, On January 19, 2026 at 4:54 PM, the computer named kavin-threat-hu recorded that Kavin opened a newly downloaded program called Tor Browser, launching it directly from the Downloads folder on his computer.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "kavin-threat-hu"
| where ProcessCommandLine contains "tor-browser"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1152" height="292" alt="image" src="https://github.com/user-attachments/assets/f0d0c250-069d-4d7d-9cb2-672548b72fe4" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for ANY indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `Jan 19, 2026 4:55:09 PM`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "kavin-threat-hu"
| where FileName has_any ("tor.exe", "firefox.exe" "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1167" height="226" alt="image" src="https://github.com/user-attachments/assets/cef636eb-7b7a-4277-a199-55e9ea7913da" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish connection using any of the known ports. At Jan 19, 2026 4:56:17 PM, the computer named kavin-threat-hu, using the account kavin, successfully made a network connection from the Tor program (tor.exe) to an external server at 217.154.76.96 on port 9001, associated with the website 2fyfcabmg76s.com. There were several other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "kavin-threat-hu"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9050", "9150")
| project Timestamp, DeviceName,InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc

```
<img width="1166" height="590" alt="image" src="https://github.com/user-attachments/assets/8fd4d8c6-9454-48cb-bf45-6d1854c6ccd0" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `Jan 19, 2026 4:39 PM`
- **Event:** The user "kavin" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `Jan 19, 2026 4:54 PM`
- **Event:** The user "kavin" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `Jan 19, 2026 4:55 PM`
- **Event:** User "kavin" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `Jan 19, 2026 4:55 PM`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `Jan 19, 2026 8:55 PM` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `Jan 19, 2026 9:01 PM`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `kavin-threat-hu` by the user `kavin`. The device was isolated, and the user's direct manager was notified.

---
