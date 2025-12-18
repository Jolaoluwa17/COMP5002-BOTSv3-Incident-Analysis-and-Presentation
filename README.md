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


