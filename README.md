[README_Wireshark_ServiceNow_Analysis.md](https://github.com/user-attachments/files/33469977/README_Wireshark_ServiceNow_Analysis.md)
# FTP Data Exfiltration Investigation and ServiceNow Incident Response

**Hands-on network forensics and simulated SOC incident lifecycle**  
**Tools:** Wireshark, ServiceNow ITSM Incident Management  
**Incident:** `INC0010003` (lab)  
**Dataset:** Public training PCAP, February 3, 2026, described as GuLoader / AgentTesla-style traffic

> **Scope and integrity:** This is a historical training scenario, not a production breach response. FTP data exfiltration was observed in the capture. Attribution to a particular malware family, the initial-access mechanism, and any real-world remediation were **not** established. ServiceNow response actions were **proposed/simulated**, not executed. The default ITSM Incident application was used, **not** ServiceNow Security Incident Response (SIR).

## Business problem

An organization can identify suspicious network activity but still fail to document evidence, prioritize risk, and track response actions. This project demonstrates a repeatable handoff: inspect network evidence in Wireshark, create an incident with defensible findings, document proposed response actions, and record the lab's resolution in ServiceNow.

## Investigation approach

Instead of using the sample's malware label as proof, I worked from general traffic reconnaissance toward specific evidence:

1. Reviewed **Protocol Hierarchy** to identify observed protocols (TCP/TLS, DNS, HTTP, FTP).
2. Used **IPv4 Endpoints** and **Conversations** to identify participants and data direction.
3. Examined a large TLS exchange and checked DNS resolution plus Client Hello SNI.
4. Investigated FTP control messages (`USER`, `PASS`, `230`, `PASV`, `STOR`, `150`, `226`).
5. Examined `ftp-data` packets and TCP streams to verify transferred data types, without republishing their sensitive contents.
6. Reconstructed the limited chronology before FTP, including an HTTP IP-information lookup.
7. Opened and resolved a **simulated** ServiceNow ITSM incident, preserving internal work notes for proposed containment, eradication, and recovery.

### Traffic overview

![Wireshark Protocol Hierarchy](screenshots/wireshark/01-protocol-hierarchy.png)

The training capture contains **353 packets** across **6 IPv4 endpoints**. These are findings from this sample, not a baseline for normal network behavior.

![Wireshark IPv4 Endpoints](screenshots/wireshark/02-ipv4-endpoints.png)

![Wireshark IPv4 Conversations](screenshots/wireshark/03-ipv4-conversations.png)

The private host `10.2.3.101` participated in all 5 IPv4 conversations. A large TLS conversation with `142.251.186.132` sent approximately 270 KB *toward* the workstation, but traffic volume alone did not establish a malicious download.

## Verified network findings

| Evidence | Observation | Interpretation / limit |
|---|---|---|
| Frames 23–28 | DNS resolved `drive.usercontent.google.com` to `142.251.186.132`, followed by TCP and TLS handshake with matching SNI | Hostname and encrypted connection observed; content/initial access not established |
| Frames 280, 282 | HTTP GET to `ip-api.com/line/?fields=hosting`; response `200 OK`, body `false` | Hosting-status query observed; an environment-check motive is only a hypothesis |
| Frames 290–295 | FTP `USER`/`PASS` exchange and `230` login success | FTP authentication succeeded; captured credentials intentionally omitted |
| Frames 312, 314–315, 321 | First FTP `STOR` operation, associated server acceptance, 754-byte FTP-DATA payload, `226` completion | File data traveled from private host to external FTP server and server reported successful completion |
| Frames 330, 332–333, 338 | Second FTP `STOR` operation, associated server acceptance, 724-byte FTP-DATA payload, `226` completion | Second outbound upload with server-reported success |

**Exfiltration flow:** `10.2.3.101` (FTP client) → `162.241.123.75` (external FTP server). The uploaded data contained **credential-related records** and an **email contact list**. Individual password values were not independently classified as plaintext or cryptographically protected. Filenames alone were not used as proof; FTP-DATA and stream inspection provided stronger evidence.

![FTP data packets, with no file contents displayed](screenshots/wireshark/04-ftp-data-uploads.png)

### Secondary lead: IP-information lookup

![HTTP response to hosting query](screenshots/wireshark/05-http-response.png)

The `false` response was returned for the `hosting` field. The capture does not prove which local process requested it or whether it was related to the subsequent uploads.

## Case timeline (capture order)

| Sequence | Event | Reference |
|---|---|---|
| 1 | Google-related DNS lookup and TLS session began | Frames 23–28 |
| 2 | IP-information lookup completed | Frames 280–282 |
| 3 | FTP name resolution and connection setup | Frames 284–289 |
| 4 | FTP login succeeded | Frames 290–295 |
| 5 | First outbound FTP upload | Frames 312–321 |
| 6 | Second outbound FTP upload | Frames 330–338 |

> Capture-relative timing is not the same as file-transfer duration. Chronology does not establish that separate network events were initiated by the same process.

## ServiceNow ITSM incident

A lab ticket was created in the **standard Incident Management** application using the available developer instance.

| Field | Value |
|---|---|
| Incident | `INC0010003` |
| Short description | `[LAB] Credential and Contact Data Exfiltration via FTP` |
| Category | Software |
| Impact | 2 – Medium |
| Urgency | 1 – High |
| Priority | 2 – High (calculated by instance) |
| Final state | Resolved **for training exercise only** |
| Assignment group | Unassigned (no appropriate group selected in lab) |

![ServiceNow incident fields](screenshots/servicenow/01-incident-details.png)

### Proposed response lifecycle

**Containment (proposed):** isolate the affected workstation after preserving evidence, restrict communication to the FTP destination, protect potentially exposed accounts, and notify responders.

![Internal containment work notes](screenshots/servicenow/02-containment-notes.png)

**Eradication and recovery (proposed):** acquire and analyze endpoint evidence; remove confirmed malicious artifacts; examine possible initial access; rebuild from a trusted source where appropriate; reset exposed credentials; verify system health; monitor for renewed exfiltration.

![Internal eradication and recovery notes](screenshots/servicenow/03-recovery-plan.png)

**Training disposition:** The investigation and response *planning* were completed. No live endpoint was isolated, repaired, or verified clean. ServiceNow incident `INC0010003` was marked Resolved to conclude the lab workflow, not to certify real-world remediation.

![Resolved lab incident](screenshots/servicenow/04-resolved-incident.png)

## Business value

- Linked a technical finding to a searchable, prioritized incident record.
- Preserved the evidence chain and distinguished observations from hypotheses.
- Documented response ownership gaps, containment recommendations, and recovery prerequisites.
- Demonstrated how ITSM incident tracking can support a **simulated** SOC workflow, even without the dedicated SIR module.

## Limitations and next evidence requests

- TLS application data was not decrypted; no particular payload download was confirmed.
- The specific GuLoader/AgentTesla malware attribution remains unverified from this network-only investigation.
- Initial access and the identity of the responsible executable/process were not established.
- Endpoint/EDR records, Windows process execution logs, browser history, and email security logs would be needed to test infection hypotheses.
- The training case does **not** demonstrate actual containment or verified restoration.

## Lessons learned

The largest conversation is not automatically the malicious one. A command (`STOR`) shows an intended action; data packets and completion replies provide stronger evidence that an upload occurred. Carefully scoped conclusions and reproducible packet references are more valuable than naming a malware family without proof.

## Source and safe sharing

Training capture: [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/2026/index.html) (February 3, 2026 scenario). Credit belongs to the original dataset publisher. **The PCAP is deliberately excluded** because it includes credential-related fields and a contact list. Screenshots showing plaintext credentials or contact addresses are deliberately excluded. Never publish live secrets, full email contact lists, or captured passwords.
