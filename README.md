# BOTSv3 Incident Analysis and SOC Investigation Report

**Course:** COMP5002 Security Operations & Incident Management  
**Assessment:** Coursework 2 – BOTSv3 Incident Analysis  
**Student:** Olusanya Jolaoluwa  
**Dataset:** Splunk Boss of the SOC v3 (BOTSv3)  
**Tools:** Splunk Enterprise, Ubuntu Linux, SPL  

---

## 1. Introduction

Security Operations Centres (SOCs) are responsible for the continuous monitoring, detection, and analysis of security events across modern enterprise environments. As organisations increasingly depend on cloud services, distributed endpoints, and complex networks, SOC teams must rely on structured investigation processes and security monitoring platforms to detect and respond to sophisticated cyber threats.

This report presents an end-to-end security incident investigation using the **Boss of the SOC version 3 (BOTSv3)** dataset. BOTSv3 is a publicly available security training dataset and Capture The Flag (CTF) exercise developed by Splunk, designed to simulate a realistic multi-stage cyberattack against a fictional organisation named *Frothly*. The dataset supports SOC-style investigations by providing diverse log sources representative of real enterprise environments.

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

Security Operations Centres (SOCs) typically operate using a **tiered analyst model** consisting of Tier 1 (Monitoring and Triage), Tier 2 (Investigation and Analysis), and Tier 3 (Advanced Threat Response).

The BOTSv3 exercise reflects this structure through progressively complex investigative tasks. 
- Tier 1 activities align with identifying basic anomalies using simple SPL searches, such as suspicious authentication or network behaviour. 
- Tier 2 responsibilities are strongly represented through correlation across network, endpoint, email, and cloud logs to confirm malicious activity. 
- Tier 3 activities are reflected through kill chain reconstruction, persistence analysis, and assessment of organisational impact.

This model demonstrates how SOCs scale expertise and manage alert volume by escalating validated threats to higher tiers.

---

### 2.2 Incident Handling Methodology in BOTSv3

The BOTSv3 dataset aligns closely with established incident response frameworks such as the **NIST Incident Response Lifecycle**, with a primary focus on the *detection and analysis* phase. Analysts are required to identify indicators of compromise, correlate events across multiple log sources, and distinguish malicious activity from benign behaviour using SPL.

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

A key lesson from BOTSv3 is that **effective detection depends on log visibility and correlation across multiple data sources**. No single telemetry source provides sufficient context on its own.

The exercise also highlights common SOC challenges, including alert fatigue, delayed detection, and skill gaps in SPL proficiency. To improve SOC effectiveness, organisations should prioritise behaviour-based detection, continuous analyst training, and clearly defined escalation paths.

Overall, BOTSv3 provides a realistic simulation of SOC pressures and reinforces the importance of structured incident handling methodologies in managing complex security incidents.

---

## 3. Installation & Data Preparation

### 3.1 Splunk Installation Environment

Splunk Enterprise was deployed on a **64-bit Ubuntu Linux virtual machine** to support SOC-style security analysis. The platform was installed locally to allow full control over configuration, data ingestion, and investigation, reflecting a typical on-premise SIEM deployment.

---

### 3.2 Splunk Installation and Validation

Splunk Enterprise was installed from the official Splunk distribution using the command line. During initial startup, the license agreement was accepted and an administrator account was created.

Access to the Splunk web interface on **port 8000** confirmed that the platform was operational and ready for dataset ingestion and analysis.

---

### 3.3 BOTSv3 Dataset Ingestion

After validating the Splunk installation, the **Boss of the SOC v3 (BOTSv3)** dataset was ingested to support SOC-style investigation. The dataset was obtained from Splunk’s official GitHub repository as a pre-indexed archive (`botsv3_data_set.tgz`).

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

.lnk files are Windows shortcut files that are frequently abused by attackers to execute hidden commands or malicious payloads while appearing benign. The deceptive filename suggests social engineering intent, and the use of an uncommon Linux-based browser for a OneDrive upload further strengthens the indication of malicious activity.

### SOC Relevance

Identifying the user agent provides valuable context about attacker tooling and behaviour. From a SOC perspective, this supports anomaly detection in cloud environments, assists in threat profiling, and enables the development of detection rules for suspicious OneDrive file uploads.

---

### 4.2 Identification of Macro-Enabled Malicious Email Attachment

SMTP email traffic was analysed using the `stream:smtp` sourcetype to identify a macro-enabled document delivered via email. Macro-enabled Office documents, particularly `.xlsm` files, are commonly abused by attackers to deliver malicious VBA macros and are a frequent initial access vector in phishing attacks.

The investigation began by searching for antivirus alerts within email traffic to identify messages flagged as malicious.

The following SPL query was used:

```spl
index=botsv3 sourcetype=stream:smtp *alert*
```

This search returned events containing an attachment named Malware Alert Text.txt, indicating that a malicious attachment had been detected and handled by email security controls. To extract further details, the query was refined to display relevant email and attachment fields.

The refined SPL query was:

```spl
index=botsv3 sourcetype=stream:smtp *alert* subject=*
| table _time subject attach_transfer_encoding{} content{} attach_content_decoded_md5_hash{}
```

#### Findings

Analysis of the returned events showed that the email body contained a Base64-encoded alert message generated by Microsoft’s email security controls. The encoded content was extracted and decoded using CyberChef.

The decoded output confirmed that a macro-enabled Excel file was identified as malware and removed:

Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm
Detection: W97M.Empstage


#### SOC Relevance

Macro-enabled Office documents are a common phishing-based malware delivery mechanism. From a SOC perspective, this investigation demonstrates the effective use of SMTP telemetry, antivirus alerting, and content decoding to confirm malware delivery. It highlights the importance of layered email security controls and continuous monitoring of email logs to detect and prevent early-stage intrusion attempts.

---

### 4.3 Executable Launched by the Malicious Macro

After identifying the malicious macro-enabled Excel attachment, Sysmon process creation logs were analysed to determine the executable launched by the malware. Macro-enabled documents frequently abuse trusted system binaries to execute malicious code while blending into normal system activity, making Sysmon telemetry an appropriate data source for this investigation.

The following SPL query was executed to identify Sysmon events associated with the malicious `.xlsm` file:

```spl
index=botsv3 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational *xlsm*
| sort by +_time
```

#### Findings

Analysis of the returned Sysmon events revealed that the macro embedded within the malicious Excel document executed the following binary:

```
HxTsr.exe
```

HxTsr.exe is a legitimate Microsoft Outlook component. Its execution in this context indicates that the malicious macro abused a trusted system binary to carry out its activity.

#### SOC Relevance

Abuse of trusted binaries such as HxTsr.exe demonstrates advanced attacker tradecraft and highlights the need for SOC teams to monitor abnormal process execution chains involving Office applications. From a SOC perspective, detecting unexpected parent-child process relationships enables early identification of stealthy, fileless attacks and supports rapid escalation, investigation, and containment.

---

### 4.4 Root-Created User Account on Linux Host

In Linux environments, user accounts are typically created using the `adduser` or `useradd` commands. As Osquery records command execution activity on the Linux host `hoth`, the investigation focused on identifying account creation actions initiated by the `root` user.

The following SPL query was used to locate relevant events:

```spl
index=botsv3 host=hoth (adduser OR useradd)
```

This query searches across all available logs for the host hoth without restricting the sourcetype, ensuring visibility into Osquery command execution logs and privileged user actions.

#### Findings

The results show that the root user successfully created a new account using the useradd command. Osquery logs revealed that the password was supplied directly within the command-line arguments:

```
useradd -p ilovedavidverve tomcat7
```

Password identified: ilovedavidverve

The presence of a plaintext password within the command-line arguments confirms credential exposure and improper account creation practices.

#### SOC Relevance

From a SOC perspective, account creation by the root user represents a high-severity security event and is commonly associated with attacker persistence following a compromise. Osquery’s ability to log command execution enables detection of privilege abuse and post-compromise activity. Such an event would typically require immediate escalation, credential rotation, and containment to prevent further unauthorized access.

---

### 4.5 Post-Compromise User Account Creation on Windows Endpoint

Following confirmation of endpoint compromise, the investigation focused on identifying post-compromise user account creation, a common persistence technique used by attackers. As the operating system was not initially known, Windows Security logs were analysed due to their reliable auditing of account management activity.

Windows Security **Event ID 4720** indicates that a new user account has been created. Using this knowledge, the following Splunk query was executed to isolate relevant events:

```spl
index=botsv3 sourcetype=WinEventLog:Security EventCode=4720
```

This query filters Windows Security logs to return only user account creation events across the BOTSv3 dataset.

#### Findings

The results returned a user creation event showing that a new account named svcvnc was created shortly after the endpoint compromise. Event details confirm that this activity was logged under the Windows Security auditing framework, indicating successful account creation on the system.

User account created: svcvnc

#### SOC Relevance

From a SOC and incident response perspective, this activity represents high-confidence malicious persistence:

- Event ID 4720 is a critical indicator of unauthorized account creation
- Attackers commonly create service-like accounts (e.g., svcvnc) to blend in and avoid suspicion
- Such activity warrants immediate escalation, account disabling, and credential review
- Correlating endpoint compromise with account creation strengthens attribution and incident severity

This finding highlights the importance of Windows Security logging and demonstrates how SOC analysts detect attacker persistence during post-exploitation.

---

### 4.6 Privilege Escalation via Group Membership Assignment

After identifying the malicious user account `svcvnc`, Windows Security logs were analysed to determine the privilege level assigned to the account. Windows **Event ID 4732** records when a user is added to a local security group, making it an appropriate indicator for identifying privilege escalation.

The following Splunk query was executed to isolate group membership changes associated with the compromised account:

```spl
index=botsv3 svcvnc EventCode=4732
| table Group_Name
```

#### Findings

The query results show that the user account svcvnc was added to the following security groups:

- Administrators
- Users

Group membership (alphabetical, comma-separated):
Administrators,Users

#### SOC Relevance

Membership in the Administrators group confirms successful privilege escalation and represents a critical security incident. When correlated with prior unauthorized account creation (Event ID 4720), this provides high-confidence evidence of attacker persistence and post-exploitation behaviour.

From a SOC perspective, such activity would require immediate escalation, removal of the malicious account, and containment actions to prevent further compromise or lateral movement.

---

### 4.7 Process Listening on a “Leet” Port

The term **“leet”** refers to the numerical value **1337**, which is historically associated with attacker backdoors and malicious services. Given that the compromised endpoint was a Linux system (`host: hoth`), Osquery logs were analysed to identify processes listening on suspicious ports.

The following Splunk query was used to locate relevant events:

```spl
index=botsv3 sourcetype=osquery:results host=hoth 1337
```

This query isolates Osquery results related to port 1337, reducing noise and highlighting potentially malicious services.

#### Findings

The results showed a process actively listening on TCP port 1337, along with its associated process ID.

Process ID identified:
14356

#### SOC Relevance

Services listening on port 1337 are commonly associated with attacker backdoors and command-and-control infrastructure. Identifying the process ID allows SOC analysts to pivot into deeper investigation, including binary identification, parent process analysis, and persistence assessment.

This activity reflects Tier 2 SOC investigation, where endpoint telemetry is correlated with known attacker tradecraft to assess compromise severity and guide escalation decisions.

---

### 4.8 MD5 of Network Scanner Downloaded to Fyodor’s Endpoint

#### Investigation Approach

To identify the file used to scan Frothly’s network, Sysmon telemetry was analysed on Fyodor’s endpoint (**FYODOR-L**). Sysmon records process execution events and includes file hash values (including MD5) in the `Hashes` field. The investigation focused on process creation events and pivoted on the unusual executable observed on the host.

#### SPL Query Used

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

