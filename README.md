# BOTSv3 Incident Analysis and SOC Investigation Report

**Course:** COMP5002 Security Operations & Incident Management  
**Assessment:** Coursework 2 – BOTSv3 Incident Analysis  
**Student:** Olusanya Jolaoluwa  
**Dataset:** Splunk Boss of the SOC v3 (BOTSv3)  
**Tools:** Splunk Enterprise, Ubuntu Linux, SPL  

---

## 1. Introduction

Security Operations Centres (SOCs) are responsible for the continuous monitoring, detection, and analysis of security events across modern enterprise environments (Fortinet, 2023). As organisations increasingly depend on cloud services, distributed endpoints, and complex networks, SOC teams must rely on structured investigation processes and security monitoring platforms to detect and respond to sophisticated cyber threats.

This report presents an end-to-end security incident investigation using the Boss of the SOC version 3 (BOTSv3) dataset. BOTSv3 is a publicly available security training dataset and Capture The Flag (CTF) exercise developed by Splunk, designed to simulate a realistic multi-stage cyberattack against a fictional organisation named Frothly. The dataset supports SOC-style investigations by providing diverse log sources representative of real enterprise environments (Cybersecurity Center, 2025).

The BOTSv3 dataset includes network traffic, endpoint telemetry, email artefacts, authentication logs, and cloud service activity. These data sources allow analysts to investigate attacker behaviour across the cyber kill chain using Splunk’s Search Processing Language (SPL).


### Objectives

The objectives of this investigation are to:
- Analyse security events within the BOTSv3 dataset using Splunk SPL
- Identify indicators of compromise and correlate events across multiple log sources
- Answer BOTSv3 300-level investigative questions with supporting evidence
- Demonstrate practical SOC workflows, including detection, triage, and escalation
- Reflect on SOC incident handling processes and investigative effectiveness

### Scope and Assumptions

This investigation is limited to post-incident detection and analysis using the logs provided within the BOTSv3 dataset as ingested into a locally deployed Splunk Enterprise environment. It assumes that the dataset accurately represents the simulated attack scenario, that no external threat intelligence is used beyond the provided data, and that the SOC operates under a tiered analyst model consistent with industry best practices.

---

## 2. SOC Roles & Incident Handling Reflection

### 2.1 SOC Tiered Structure and Responsibilities

Security Operations Centres (SOCs) typically operate using a tiered analyst model consisting of Tier 1 (Monitoring and Triage), Tier 2 (Investigation and Analysis), and Tier 3 (Advanced Threat Response) (Assaf, 2025).

The BOTSv3 exercise reflects this structure through progressively complex investigative tasks. 
- Tier 1 activities align with identifying basic anomalies using simple SPL searches, such as suspicious authentication or network behaviour. 
- Tier 2 responsibilities are strongly represented through correlation across network, endpoint, email, and cloud logs to confirm malicious activity. 
- Tier 3 activities are reflected through kill chain reconstruction, persistence analysis, and assessment of organisational impact.

This model demonstrates how SOCs scale expertise and manage alert volume by escalating validated threats to higher tiers.

---

### 2.2 Incident Handling Methodology in BOTSv3

The BOTSv3 dataset aligns closely with established incident response frameworks such as the NIST Incident Response Lifecycle, with a primary focus on the detection and analysis phase. Analysts are required to identify indicators of compromise, correlate events across multiple log sources, and distinguish malicious activity from benign behaviour using SPL (EC-Council, 2022).

Although containment and eradication actions are not directly performed within BOTSv3, the investigation requires analysts to infer appropriate response actions based on their findings.

---

### 2.3 Prevention, Detection, Response, and Recovery Mapping

BOTSv3 demonstrates how SOC activities map across the incident lifecycle:
- **Prevention:** Analysis reveals security gaps that could have been mitigated through stronger controls, such as improved email filtering or endpoint hardening.
- **Detection:** Detection is the primary focus of BOTSv3, with analysts relying on SPL queries to uncover command-and-control traffic, malicious scripting activity, and anomalous cloud behaviour.
- **Response:** Response is analytical rather than operational, with findings implying actions such as escalation and incident notification.
- **Recovery:** Recovery is indirectly addressed through post-incident reflection on system restoration, credential rotation, and improved monitoring.

---

### 2.4 Critical Reflection on SOC Effectiveness

A key lesson from BOTSv3 is that effective detection depends on log visibility and correlation across multiple data sources. No single telemetry source provides sufficient context on its own.

The exercise also highlights common SOC challenges, including alert fatigue, delayed detection, and skill gaps in SPL proficiency. To improve SOC effectiveness, organisations should prioritise behaviour-based detection, continuous analyst training, and clearly defined escalation paths.

Overall, BOTSv3 provides a realistic simulation of SOC pressures and reinforces the importance of structured incident handling methodologies in managing complex security incidents.

---

## 3. Installation & Data Preparation

### 3.1 Splunk Installation Environment

Splunk Enterprise was deployed on a **64-bit Ubuntu Linux virtual machine** to support SOC-style security analysis. The platform was installed locally to allow full control over configuration, data ingestion, and investigation, reflecting a typical on-premise SIEM deployment.

---

### 3.2 Splunk Installation and Validation

Splunk Enterprise was installed from the official Splunk distribution using the command line. During initial startup, the license agreement was accepted, and an administrator account was created.
Access to the Splunk web interface on port 8000 confirmed that the platform was operational and ready for dataset ingestion and analysis.

---

### 3.3 BOTSv3 Dataset Ingestion

After validating the Splunk installation, the Boss of the SOC v3 (BOTSv3) dataset was ingested to support SOC-style investigation. The dataset was obtained from Splunk’s official GitHub repository as a pre-indexed archive (`botsv3_data_set.tgz`).

The extracted dataset was copied into `/opt/splunk/etc/apps/`, allowing Splunk to automatically load the required indexes, lookups, and configurations. Splunk was then restarted to apply the dataset and make the data available for analysis.


---

### 3.4 Data Validation and SOC Readiness

Data ingestion was validated using the **Search & Reporting** application by running baseline SPL queries against the `botsv3` index to confirm event availability across the dataset timeline.

The presence of multiple hosts, sourcetypes, and timestamps verified that ingestion was successful and the environment was ready for investigation. From a SOC perspective, this validation ensures SIEM reliability prior to detection and analysis activities.

---

## 4. Guided Questions – BOTSv3 Investigation

This section presents the analysis and responses to the BOTSv3 300-level guided questions using Splunk Enterprise. Each question is investigated using targeted SPL queries aligned with standard Security Operations Centre (SOC) investigative workflows.

Multiple telemetry sources—including Office 365 logs, email (SMTP) traffic, endpoint telemetry (Sysmon), Windows Security events, and Osquery logs—are correlated to identify and validate malicious activity. For each question, findings are briefly explained and their SOC relevance is highlighted to demonstrate detection, analysis, and escalation within a real-world SOC context.

---

### 4.1 User Agent Responsible for Malicious OneDrive Upload

Office 365 management logs were analysed using the `ms:o365:management` sourcetype to identify the user agent responsible for a malicious OneDrive upload. The investigation focused on the OneDrive workload and the `FileUploaded` operation, using the known `.lnk` file extension to narrow the search.

The following SPL query was used:

```spl
index=botsv3 sourcetype=ms:o365:management Workload=OneDrive Operation=FileUploaded
| table _time UserAgent user src_ip Operation object
| sort by +_time
```

### Findings 

The query revealed the upload of the file BRUCE BIRTHDAY HAPPY HOUR PICS.lnk to OneDrive. The associated user agent responsible for the upload was:

```
Mozilla/5.0 (X11; Linux i686; rv:19.1br) Gecko/20130508 Fedora/1.9.1-2.5.r3.0 NaenaraBrowser/3.5b4
```

### Why the File Is Malicious

.lnk files are Windows shortcut files that are frequently abused by attackers to execute hidden commands or malicious payloads while appearing benign. The deceptive filename suggests social engineering intent, and the use of an uncommon Linux-based browser for a OneDrive upload further strengthens the indication of malicious activity (Mitre, 2020).

### SOC Relevance

Identifying the user agent provides valuable context about attacker tooling and behaviour. From a SOC perspective, this supports anomaly detection in cloud environments, assists in threat profiling, and enables the development of detection rules for suspicious OneDrive file uploads.

---

### 4.2 Identification of Macro-Enabled Malicious Email Attachment

SMTP email traffic was analysed using the `stream:smtp` sourcetype to identify a macro-enabled document delivered via email. Since macro-enabled Office files such as `.xlsm` are commonly abused in phishing attacks, the investigation focused on email events flagged by antivirus alerts.

The following SPL query was used to locate relevant events:

```spl
index=botsv3 sourcetype=stream:smtp *alert*
```

To extract additional email and attachment details, the search was refined as follows:

```spl
index=botsv3 sourcetype=stream:smtp *alert* subject=*
| table _time subject attach_transfer_encoding{} content{} attach_content_decoded_md5_hash{}
```

#### Findings

Analysis of the returned events showed that the email body contained a Base64-encoded alert message generated by Microsoft’s email security controls. The encoded content was extracted and decoded using CyberChef.
The decoded output confirmed that a macro-enabled Excel file was identified as malware and removed:
Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm Detection: W97M.Empstage

#### SOC Relevance

Macro-enabled Office documents are a common initial access vector in phishing attacks. From a SOC perspective, this investigation demonstrates how SMTP telemetry, antivirus alerting, and content decoding can be used to quickly identify and confirm malicious email attachments, supporting early detection and prevention of compromise.

---

### 4.3 Executable Launched by the Malicious Macro

After identifying the malicious macro-enabled Excel attachment, Sysmon process creation logs were analysed to determine the executable launched by the malware. Macro-enabled documents often abuse trusted system binaries to execute malicious code, making Sysmon telemetry an appropriate data source for this investigation.

The following SPL query was used to identify relevant Sysmon events:

```spl
index=botsv3 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational *xlsm*
| sort by +_time
```

#### Findings

Analysis of the returned Sysmon events revealed that the macro embedded within the malicious Excel document executed the following binary:

```
HxTsr.exe
```

HxTsr.exe is a legitimate Microsoft Outlook component. Its execution in this context indicates that the malicious macro abused a trusted system binary to carry out its activity (Glasswire, 2025).

#### SOC Relevance

Abuse of trusted binaries is a common evasion technique used to blend malicious activity with legitimate processes. From a SOC perspective, monitoring abnormal process execution chains involving Office documents is critical for detecting stealthy, fileless attacks and enabling timely escalation and containment.

---

### 4.4 Root-Created User Account on Linux Host

In Linux environments, user accounts are commonly created using the `adduser` or `useradd` commands (Debian, 2022). As Osquery records command execution activity on the Linux host hoth, the investigation focused on identifying account creation actions initiated by the root user.

The following SPL query was used:

```spl
index=botsv3 host=hoth (adduser OR useradd)
```

#### Findings

The results show that the root user created a new account using the useradd command. Osquery logs revealed that the password was supplied directly within the command-line arguments:

```
useradd -p ilovedavidverve tomcat7
```

Password identified: ilovedavidverve

#### SOC Relevance

Root-level account creation is a strong indicator of attacker persistence following compromise. From a SOC perspective, Osquery command execution logs enable detection of privilege abuse and post-compromise activity, warranting immediate escalation, credential rotation, and containment.

---

### 4.5 Post-Compromise User Account Creation on Windows Endpoint

Following confirmation of endpoint compromise, Windows Security logs were analysed to identify post-compromise user account creation. Windows Security Event ID 4720, which records new user account creation, was used for this investigation (vinaypamnani-msft, 2021).

The following SPL query was executed:

```spl
index=botsv3 sourcetype=WinEventLog:Security EventCode=4720
```

#### Findings

The results showed that a new user account named svcvnc was created shortly after the compromise. Event details confirm that this activity was logged under the Windows Security auditing framework.

User account created: svcvnc

#### SOC Relevance

Unauthorized user creation is a high-confidence indicator of persistence. From a SOC perspective, Event ID 4720 enables reliable detection of post-exploitation activity and would typically trigger immediate escalation, account disabling, and credential review.

---

### 4.6 Privilege Escalation via Group Membership Assignment

After identifying the malicious user account `svcvnc`, Windows Security logs were analysed to determine its assigned privilege level. Windows Security Event ID 4732, which records when a user is added to a local security group, was used to identify privilege escalation.

The following SPL query was executed:

```spl
index=botsv3 svcvnc EventCode=4732
| table Group_Name
```

#### Findings

The query results show that the user account svcvnc was added to the following security groups:

- Administrators
- Users

Group membership (alphabetical, comma-separated):
administrators, users

#### SOC Relevance

Membership in the Administrators group confirms successful privilege escalation. When correlated with prior unauthorized account creation (Event ID 4720), this provides high-confidence evidence of attacker persistence and post-exploitation behaviour, requiring immediate escalation and containment.

---

### 4.7 Process Listening on a “Leet” Port

The term “leet” refers to port 1337, historically linked to attacker backdoors. As the compromised system was a Linux host (hoth), Osquery logs were analysed to identify processes listening on this suspicious port.

The following SPL query was used:

```spl
index=botsv3 sourcetype=osquery:results host=hoth 1337
```

#### Findings

The results showed a process actively listening on TCP port 1337, along with its associated process ID.

Process ID identified:
14356

#### SOC Relevance

A service listening on port 1337 is a strong indicator of backdoor activity. Identifying the associated process ID enables further investigation into the binary, persistence mechanisms, and potential command-and-control activity, supporting Tier 2 SOC escalation and response.

---

### 4.8 MD5 of Network Scanner Downloaded to Fyodor’s Endpoint

#### Investigation Approach

Sysmon telemetry was analysed on Fyodor’s endpoint (FYODOR-L) to identify the executable used to scan Frothly’s network. Sysmon process creation events (Event ID 1) were reviewed, as they include executable paths and cryptographic hash values such as MD5.

The following SPL query was used to isolate the suspicious binary:

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host="FYODOR-L"
("<EventID>1</EventID>" OR EventCode=1 OR EventID=1)
| rex field=_raw "Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Data Name='Hashes'>(?<Hashes>[^<]+)"
| search Image="*hdoor.exe*"
| rex field=Hashes "MD5=(?<MD5>[A-Fa-f0-9]{32})"
| table _time Image MD5 Hashes
```

#### Findings

The Sysmon process execution event showed the scanner binary executed from:
C:\Windows\Temp\hdoor.exe
Sysmon recorded the following MD5 value for the file:
MD5: 586EF56F4D8963DD546163AC31C865D7

#### SOC Relevance

Identifying the MD5 hash allows SOC analysts to confirm the exact binary used by the attacker, perform threat intelligence lookups, and hunt for the same file across other endpoints. This supports rapid scoping, detection tuning, and incident containment.

## 5. Conclusion

This investigation demonstrated a structured SOC-style analysis of a multi-stage attack using the BOTSv3 dataset and Splunk Enterprise. By correlating email, cloud, endpoint, and host-based telemetry, key attacker actions were identified, including malicious file delivery, living-off-the-land execution, account creation, privilege escalation, and backdoor activity.

The findings highlight the importance of comprehensive logging, cross-source correlation, and analyst proficiency in SPL for effective detection and response. Overall, the investigation reflects real-world SOC workflows and reinforces the value of layered security monitoring in identifying and containing advanced threats.

