# Incident evidence and response summary — LAB

**Incident:** INC0010003 (ServiceNow ITSM, resolved as a training exercise)  
**Internal workstation:** 10.2.3.101  
**External FTP server:** 162.241.123.75  
**Classification:** Simulated credential-related and contact-data exfiltration  
**Impact / Urgency / Priority:** Medium / High / High (P2)

## Executive summary
Analysis of a historical malware-related training PCAP identified two outbound FTP transfers from 10.2.3.101 to 162.241.123.75. The transferred data included credential-related records and an email contact list. FTP control replies reported successful completion, and the capture contains associated FTP data packets. This presents possible credential-misuse and phishing risks in the hypothetical business scenario. Neither the initial access method nor the specific malware family can be confirmed from the available evidence. Follow-up endpoint and email telemetry would be needed.

## Evidence chain

- Frames 290–295: FTP authentication exchange, with 230 reporting success.
- Frame 312: first STOR upload request; frame 315: 754 bytes of FTP data; frame 321: 226 success.
- Frame 330: second STOR upload request; frame 333: 724 bytes of FTP data; frame 338: 226 success.
- Frames 280–282: hosting-field lookup and response `false`; purpose not determined.
- Frames 23–28: DNS/TCP/TLS sequence for Google-related content endpoint; application payload encrypted and not independently attributed to the FTP activity.

## Response planning and disposition

**Containment (proposed only):** preserve evidence, isolate the affected host, restrict FTP destination access, identify exposed accounts, rotate credentials and revoke sessions as appropriate.  
**Eradication (proposed only):** inspect endpoint/EDR logs, file artifacts, and persistence; remove confirmed malicious artifacts with approved tools.  
**Recovery (proposed only):** restore from a trustworthy image, validate security controls, and monitor for recurring abnormal traffic.  
**Disposition:** Lab IR documentation completed; ServiceNow ticket resolved for simulation. Actual remediation was **not** performed or verified.

## Open questions

- Which process performed the exfiltration?
- Was the workstation initially compromised, and by what mechanism?
- What was the exact credential protection state of each extracted value?
- Were any accounts subsequently accessed or contacts abused?

This report omits all credential values and contact-list contents.
