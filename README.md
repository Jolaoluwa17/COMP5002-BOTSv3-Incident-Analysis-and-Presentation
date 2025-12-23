# BOTSv3 Incident Analysis and SOC Investigation Report

**Course:** COMP5002 Security Operations & Incident Management  
**Assessment:** Coursework 2 – BOTSv3 Incident Analysis  
**Student:** Olusanya Jolaoluwa  
**Dataset:** Splunk Boss of the SOC v3 (BOTSv3)  
**Tools:** Splunk Enterprise, Ubuntu Linux, SPL  

---

## 1. Introduction

Security Operations Centres (SOCs) play a critical role in modern organisations by providing continuous monitoring, threat detection, incident analysis, and coordinated response to cybersecurity threats. As enterprise environments increasingly rely on complex networks, cloud services, and distributed endpoints, SOC teams must be capable of responding to sophisticated attacks using structured processes and advanced security monitoring tools.

This report presents an end-to-end security incident investigation using the **Boss of the SOC version 3 (BOTSv3)** dataset. BOTSv3 is a publicly available security training dataset and Capture The Flag (CTF) exercise developed by Splunk to simulate a realistic cyberattack scenario. The dataset is based on a fictional brewing company named *Frothly* and is designed to support realistic SOC-style security investigations.

The BOTSv3 dataset provides a diverse collection of log data, including network traffic, endpoint activity, email artefacts, authentication events, and cloud service logs. These data sources enable analysts to investigate a simulated multi-stage attack and apply real-world threat hunting and incident analysis techniques using Splunk’s Search Processing Language (SPL).

### Objectives

The objectives of this investigation are to:
- Analyse security events within the BOTSv3 dataset using SPL
- Identify indicators of compromise and correlate events across multiple log sources
- Answer BOTSv3 300-level investigative questions with supporting evidence
- Demonstrate practical SOC workflows including detection, triage, escalation, and analysis
- Critically reflect on incident handling methodologies and SOC effectiveness

### Scope and Assumptions

The scope of this investigation is limited to post-incident detection and analysis using the logs provided within the BOTSv3 dataset as ingested into a locally deployed Splunk Enterprise environment. The investigation assumes that:
- The dataset accurately represents the simulated attack scenario
- No external threat intelligence sources are used beyond the provided data
- The SOC operates under a tiered analyst model consistent with industry best practices

These assumptions allow the investigation to focus on analytical accuracy, incident reconstruction, and evaluation of SOC workflows.

---

## 2. SOC Roles & Incident Handling Reflection

### 2.1 SOC Tiered Structure and Responsibilities

Modern Security Operations Centres (SOCs) commonly operate using a **tiered analyst model** to efficiently manage alerts and incidents. This structure typically consists of Tier 1 (Monitoring and Triage), Tier 2 (Investigation and Analysis), and Tier 3 (Advanced Threat Response).

The BOTSv3 exercise implicitly reflects this model through the increasing complexity of investigative tasks:
- **Tier 1 analysts** focus on monitoring and initial triage. In BOTSv3, this aligns with identifying anomalies such as unusual DNS activity, failed authentication attempts, or suspicious processes using basic SPL searches.
- **Tier 2 analysts** perform deeper investigation and correlation across multiple data sources. BOTSv3 strongly represents Tier 2 work, requiring analysts to pivot between network, endpoint, email, and cloud logs to confirm malicious activity.
- **Tier 3 analysts** handle advanced threat analysis and strategic response. Within BOTSv3, this is reflected through reconstructing the attacker kill chain, identifying persistence mechanisms, and assessing organisational impact.

This tiered approach demonstrates how SOCs scale expertise and reduce analyst overload by filtering false positives at lower tiers.

---

### 2.2 Incident Handling Methodology in BOTSv3

The BOTSv3 dataset closely aligns with established incident response frameworks such as the **NIST Incident Response Lifecycle**, particularly the *detection and analysis* phase. Analysts are required to identify indicators of compromise (IOCs), correlate events, and distinguish malicious activity from benign noise using SPL.

While containment and eradication actions are not directly executed within the dataset, analysts are expected to infer appropriate responses, such as isolating affected hosts or revoking compromised credentials, based on investigative findings.

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

Splunk Enterprise was deployed on a **64-bit Ubuntu Linux virtual machine** to simulate a realistic Security Operations Centre (SOC) analysis environment. Ubuntu was selected due to its stability, security focus, and widespread adoption in SOC and SIEM deployments.

The Splunk instance was installed **locally (on-premise style)** to provide full control over system configuration, data ingestion, and analysis. This setup reflects real-world SOC environments where SIEM platforms are centrally managed and tightly controlled.

---

### 3.2 Splunk Installation and Validation

Splunk Enterprise was downloaded from the official Splunk website and installed via the command line using the recommended Linux installation path. During the initial startup, the license agreement was accepted and an administrator account was created to manage system configuration and data ingestion.

Following installation, the Splunk web interface was accessed locally via **port 8000**. Successful authentication and access to the Splunk Enterprise dashboard confirmed that the SIEM platform was operational and ready for dataset ingestion and analysis.

---

### 3.3 BOTSv3 Dataset Ingestion

After validating the Splunk installation, the **Boss of the SOC version 3 (BOTSv3)** dataset was ingested to support SOC-style investigation. The dataset was obtained from Splunk’s official GitHub repository as a **pre-indexed archive (`botsv3_data_set.tgz`)**, designed to simulate a realistic enterprise security incident.

The extracted `botsv3_data_set` directory was copied into: /opt/splunk/etc/apps/

This directory is the standard location for Splunk applications and datasets, allowing Splunk to automatically recognise and load the data. The directory structure was verified to confirm the presence of required configuration files, lookup tables, and indexed data. Splunk was then restarted to apply the dataset configuration.

---

### 3.4 Data Validation and SOC Readiness

Data ingestion was validated using the **Search & Reporting** application. A baseline SPL query against the `botsv3` index confirmed that events were searchable across the full dataset timeline.

The high event volume, combined with the presence of multiple hosts, sourcetypes, and timestamps, verified that the dataset had been ingested successfully and was ready for investigation.

From a SOC perspective, this validation step is critical to ensure SIEM reliability before incident analysis begins. Confirming data availability and index integrity mirrors real-world SOC workflows, where ingestion and health checks are performed prior to detection, triage, and threat-hunting activities.

At this stage, the Splunk environment was fully prepared to support the BOTSv3 guided investigation.

---

## 4. Guided Questions – BOTSv3 Investigation

This section presents the analysis and responses to the Boss of the SOC v3 (BOTSv3) 300-level guided questions. Each question is investigated using Splunk Enterprise and structured according to standard Security Operations Centre (SOC) investigative workflows.

Targeted Splunk Search Processing Language (SPL) queries are used to identify, correlate, and validate malicious activity across multiple telemetry sources, including Office 365 logs, email (SMTP) traffic, endpoint telemetry (Sysmon), Windows Security events, and Osquery logs. Supporting evidence such as query outputs and screenshots is provided where appropriate.

For each question, findings are explained in context and their SOC relevance is discussed to demonstrate how the activity would be detected, analysed, and escalated within a real-world SOC environment.

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

```Mozilla/5.0 (X11; Linux i686; rv:19.1br) Gecko/20130508 Fedora/1.9.1-2.5.r3.0 NaenaraBrowser/3.5b4
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

### Findings

Analysis of the returned events showed that the email body contained a Base64-encoded alert message generated by Microsoft’s email security controls. The encoded content was extracted and decoded using CyberChef.

The decoded output confirmed that a macro-enabled Excel file was identified as malware and removed:

Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm
Detection: W97M.Empstage


### SOC Relevance

Macro-enabled Office documents are a common phishing-based malware delivery mechanism. From a SOC perspective, this investigation demonstrates the effective use of SMTP telemetry, antivirus alerting, and content decoding to confirm malware delivery. It highlights the importance of layered email security controls and continuous monitoring of email logs to detect and prevent early-stage intrusion attempts.


