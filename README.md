# endpoint-security-monitoring-lab
Endpoint Security Monitoring and Threat Analysis Lab using Metasploit, Process Explorer, TCPView, and Wireshark.
# Endpoint Security Monitoring and Threat Analysis Lab

## Project Overview

This project demonstrates a controlled endpoint security investigation conducted within a virtualized lab environment. The objective was to simulate malicious activity, monitor endpoint behavior, analyze network communications, and investigate indicators of compromise (IOCs) using industry-standard security tools.

The project provides hands-on experience with endpoint monitoring, process analysis, network traffic inspection, and threat investigation methodologies commonly used by SOC analysts and blue-team professionals.

---

## Objectives

* Build an isolated cybersecurity lab environment.
* Simulate a compromise using a controlled payload.
* Monitor endpoint behavior during attack execution.
* Analyze active network connections.
* Capture and inspect network traffic.
* Identify indicators of compromise (IOCs).
* Understand the fundamentals of threat hunting and incident investigation.

---

## Lab Environment

### Virtual Machines

| Machine       | Purpose         |
| ------------- | --------------- |
| Windows VM    | Target Endpoint |
| Kali Linux VM | Attacker System |

### Virtualization Platform

* VMware Workstation

---

## Tools Used

| Tool                 | Purpose                             |
| -------------------- | ----------------------------------- |
| VMware Workstation   | Virtual Lab Environment             |
| Kali Linux           | Security Testing Platform           |
| Metasploit Framework | Attack Simulation                   |
| Process Explorer     | Process Monitoring                  |
| TCPView              | Network Connection Analysis         |
| Wireshark            | Packet Capture and Traffic Analysis |

---

## Project Workflow

### Phase 1 – Lab Setup

* Created isolated Windows and Kali Linux virtual machines.
* Configured communication between both systems.

### Phase 2 – Attack Simulation

* Generated a controlled payload using Metasploit Framework.
* Executed the payload on the Windows endpoint.
* Established a Meterpreter session.

### Phase 3 – Endpoint Investigation

Using Process Explorer:

* Monitored running processes.
* Analyzed process hierarchies.
* Investigated suspicious process activity.

### Phase 4 – Network Investigation

Using TCPView:

* Examined active TCP connections.
* Identified suspicious outbound communications.
* Correlated network activity with running processes.

### Phase 5 – Traffic Analysis

Using Wireshark:

* Captured network traffic.
* Analyzed packet communications.
* Investigated attacker-to-victim communication patterns.

### Phase 6 – Threat Investigation

* Correlated endpoint and network telemetry.
* Identified indicators of compromise (IOCs).
* Documented attack behavior and findings.

---

## Skills Demonstrated

* Endpoint Security Monitoring
* Threat Hunting Fundamentals
* Malware Behavior Analysis
* Process Analysis
* Network Forensics
* Packet Analysis
* Incident Investigation
* Security Monitoring
* Threat Detection

---

## Key Learnings

This project enhanced my understanding of how malicious activity can be identified through endpoint and network monitoring. It provided practical exposure to attack simulation, process investigation, network traffic analysis, and IOC identification in a controlled environment.

The project also reinforced the importance of correlating multiple sources of telemetry when investigating security incidents.

---

## Screenshots

### VMware Lab Environment

<img width="1919" height="910" alt="Screenshot 2026-04-07 175151" src="https://github.com/user-attachments/assets/03e0410a-49c1-4012-8c2e-02dab0c5f506" />

### Metasploit Session

<img width="1907" height="990" alt="Screenshot 2026-04-07 172234" src="https://github.com/user-attachments/assets/1ea933cf-6fb4-4585-8bc4-66890a7d75df" />

### TCPView Network Analysis

<img width="1904" height="991" alt="Screenshot 2026-04-07 190548" src="https://github.com/user-attachments/assets/361ece84-8e05-4a46-9674-2f28c057c051" />

### TCPView Network Analysis

<img width="1904" height="1023" alt="Screenshot 2026-04-07 162957" src="https://github.com/user-attachments/assets/48090740-e2ae-4cb1-93c1-63d9df470dee" />


---

## Future Improvements

* Sysmon Integration
* Wazuh Integration
* SIEM Log Collection
* MITRE ATT&CK Mapping
* Automated Detection Rules
* Advanced Threat Hunting Scenarios

---

## Author

Seshagiri Mallela

Cybersecurity | Endpoint Security | Threat Hunting | Cloud Security
