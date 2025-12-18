# BOTSv3 Incident Analysis and SOC Investigation Report

**Course:** COMP5002 Security Operations & Incident Management  
**Assessment:** Coursework 2 – BOTSv3 Incident Analysis  
**Student:** Olusanya Jolaoluwa  
**Dataset:** Splunk Boss of the SOC v3 (BOTSv3)  
**Tools:** Splunk Enterprise, Ubuntu Linux, SPL  

---

## 1. Introduction

Security Operations Centres (SOCs) play a critical role in detecting, analysing, and responding to cyber threats in modern enterprise environments. This report presents an end-to-end incident investigation using the **Boss of the SOC v3 (BOTSv3)** dataset, a realistic simulated security incident developed by Splunk.

The BOTSv3 scenario is set within a fictional brewing company, *Frothly*, and contains diverse log sources including endpoint telemetry, network traffic, email logs, and cloud service activity. The dataset emulates a multi-stage attack aligned with the **cyber kill chain**, requiring analysts to identify malicious activity, understand attacker behaviour, and assess organisational impact.

### Objectives
The objectives of this investigation are to:
- Analyse security events using Splunk’s Search Processing Language (SPL)
- Answer BOTSv3 300-level investigative questions with supporting evidence
- Demonstrate practical SOC workflows including detection, triage, and escalation
- Critically reflect on SOC operations, tooling, and incident response strategies

### Scope and Assumptions
This investigation focuses exclusively on the BOTSv3 dataset provided by Splunk. It assumes:
- Logs are complete and accurately represent the simulated environment
- No additional threat intelligence beyond what is available in the dataset
- The SOC operates under a tiered incident response model (Tier 1–3)

---

## 2. SOC Roles & Incident Handling Reflection

Modern SOCs operate using tiered analyst roles to ensure efficient detection and response...

