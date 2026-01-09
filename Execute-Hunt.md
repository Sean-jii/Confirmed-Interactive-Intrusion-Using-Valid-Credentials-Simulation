# Confirmed-Interactive-Intrusion-Using-Valid-Credentials-Simulation
This project simulates a post-compromise intrusion against a Windows 10 Azure VM. Using only built-in Windows tools and valid credentials, the attacker progresses from access to persistence and data staging. Defender telemetry is correlated to identify ten behavioral flags, mirroring real SOC threat-hunting workflows.


Threat Hunt Findings

Device Name: seanji-threathu
Administrator Account: Seanji
Standard User (Compromised): jsmith
This section documents the results of a structured threat hunt conducted using Microsoft Defender for Endpoint in an Azure Windows 10 environment. Each flag represents a distinct attacker behavior observed during a simulated intrusion using the compromised user account jsmith on the host seanji-threathu.

Flag 1 – Successful Logon from a Rare External IP Address

A successful interactive logon was observed on seanji-threathu using the account jsmith from an external IP address that is rarely associated with this device. 

KQL Query Used:

DeviceLogonEvents

| where DeviceName == "seanji-threathu"

| where ActionType == "LogonSuccess"

| where AccountName == "jsmith"

| summarize LogonCount = count() by RemoteIP

| where LogonCount < 5

The IP address that was found was 174.237.12.168


<img width="936" height="166" alt="1" src="https://github.com/user-attachments/assets/03f89aa5-6924-4b4c-9143-d8851fdfac7b" />


----------


Flag 2 – Logon Outside Normal Business Hours

The same user account, jsmith, authenticated to seanji-threathu during non operating hours. This behavior increases confidence that the access was unauthorized and malicious in nature.

DeviceLogonEvents

KQL Query Used:

| where DeviceName == "seanji-threathu"

| where ActionType == "LogonSuccess"

| where AccountName == "jsmith"

| extend Hour = datetime_part("hour", Timestamp)

| where Hour < 6 or Hour > 20

| where RemoteIP == “74.237.12.168”


<img width="1468" height="229" alt="2" src="https://github.com/user-attachments/assets/6254f96d-2b1a-4d1d-a855-9467a030f7c0" />



----------


Flag 3 – PowerShell Executed by a Non-Administrative User

Shortly after the anomalous logon, PowerShell was executed by the standard user jsmith on seanji-threathu.

KQL Query Used:

DeviceProcessEvents

| where DeviceName == "seanji-threathu"

| where FileName =~ "powershell.exe"

| where AccountName == "jsmith"


<img width="1489" height="264" alt="3" src="https://github.com/user-attachments/assets/cbe407a8-22d0-4cc9-b865-77131178500a" />


----------


Flag 4 – Obfuscated PowerShell Execution

PowerShell was executed with encoded command-line parameters by jsmith, indicating an attempt to obscure the command’s true functionality.

This behavior strongly suggests malicious intent rather than administrative activity

KQL Query Used:

DeviceProcessEvents

| where DeviceName == "seanji-threathu"

| where FileName =~ "powershell.exe"

| where AccountName == "jsmith"

| where ProcessCommandLine has_any ("-enc", "-encodedcommand")

<img width="1421" height="82" alt="4" src="https://github.com/user-attachments/assets/74a79e19-025b-44bf-a907-013c729ca342" />


----------


Flag 5 – System and Network Discovery Commands

Multiple reconnaissance commands were executed on seanji-threathu by jsmith, including enumeration of user accounts, system configuration, and network details.

KQL Query Used:

DeviceProcessEvents

| where DeviceName == "seanji-threathu"

| where AccountName == "jsmith"

| where ProcessCommandLine has_any (

    "net user",
    
    "net localgroup",
    
    "systeminfo",
    
    "ipconfig",
    
    "whoami"
)

<img width="1464" height="178" alt="5" src="https://github.com/user-attachments/assets/aa8944c6-2cd5-4590-a67e-4bff7a514a2b" />


----------


Flag 6 – Credential Access Reconnaissance

Commands referencing the LSASS process and protected registry hives were observed being executed by jsmith on seanji-threathu. 

KQL Query Used:

DeviceProcessEvents

| where DeviceName == "seanji-threathu"

| where AccountName == "jsmith"

| where ProcessCommandLine has_any (

    "lsass",
    
    "HKLM\\SAM",
    
    "HKLM\\SECURITY"
)

<img width="1478" height="89" alt="6" src="https://github.com/user-attachments/assets/f011f886-4867-49e3-a6fc-1e6cb964ffd5" />


----------


Flag 7 – Local Account Creation and Administrative Privilege Assignment

A new local account, svc-backup, was created on seanji-threathu and subsequently added to the local Administrators group by the administrative account Seanji. Unauthorized account creation is a high-confidence indicator of compromise.

KQL Query Used:

DeviceEvents

| where DeviceName == "seanji-threathu"

| where InitiatingProcessAccountName == "Seanji"

| where ActionType in (

    "UserAccountCreated",
    

    "UserAccountAddedToLocalGroup"
)

<img width="1457" height="40" alt="7" src="https://github.com/user-attachments/assets/222e4248-44ca-432a-8054-59c755c23578" />


----------


Flag 8 – Scheduled Task Created for SYSTEM-Level Persistence

A scheduled task was created on seanji-threathu to execute a command under the SYSTEM account. 

KQL Query Used:

DeviceProcessEvents

| where DeviceName == "seanji-threathu"

| where ProcessCommandLine has_all ("schtasks", "create")

<img width="1463" height="75" alt="8" src="https://github.com/user-attachments/assets/36bec503-b096-4c3e-8864-efc94e9f37b5" />


----------


Flag 9 – Outbound Network Connections to Public IP Addresses

An outbound network connection was initiated from seanji-threathu to external public IP addresses using PowerShell. Outbound PowerShell network activity is particularly suspicious in post-compromise scenarios.

KQL Query Used:

DeviceNetworkEvents

| where DeviceName == "seanji-threathu"

| where InitiatingProcessFileName =~ "powershell.exe"

| where RemoteIPType == "Public"

<img width="1440" height="80" alt="9" src="https://github.com/user-attachments/assets/16195503-12ae-421a-abad-128b1304de1d" />


----------


Flag 10 – Local Data Staging via Compression

Files were compressed into a local archive on seanji-threathu, consistent with data staging behavior commonly observed prior to exfiltration. This is a strong sign of data theft 

KQL Query Used:

DeviceFileEvents

| where DeviceName == "seanji-threathu"

| where FileName endswith ".zip"

| order by Timestamp desc

<img width="2048" height="105" alt="10" src="https://github.com/user-attachments/assets/ad70468f-152a-4f13-bdbb-4f56346abd9a" />


----------


Analysis Summary

While some of the individual behaviors observed on seanji-threathu could appear benign in isolation, correlating authentication anomalies, PowerShell abuse, credential access intent, persistence mechanisms, and outbound network activity provides strong evidence of a post-compromise intrusion using valid credentials.
This hunt demonstrates the effectiveness of behavior-based detection and cross-table correlation within Microsoft Defender for Endpoint.


----------


Recommendations:

Enforce multi-factor authentication and conditional access for RDP

Monitor and restrict PowerShell usage where feasible

Alert on local account creation and administrator group changes

Create detections for encoded PowerShell execution

Establish baseline monitoring for outbound PowerShell network activity


----------


MITRE ATT&CK:

T1078 – Valid Accounts

T1021.001 – Remote Services: RDP

T1059.001 – Command and Scripting Interpreter: PowerShell

T1027 – Obfuscated Files or Information

T1082 – System Information Discovery

T1016 – Network Discovery

T1033 – Account Discovery

T1003.001 – OS Credential Dumping: LSASS Memory

T1003.002 – OS Credential Dumping: SAM

T1136.001 – Create Account: Local Account

T1098 – Account Manipulation

T1053.005 – Scheduled Task

T1071.001 – Application Layer Protocol: Web Protocols

T1041 – Exfiltration Over C2 Channel

T1560.001 – Archive via Utility

T1074.001 – Local Data Staging












