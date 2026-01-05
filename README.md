## Log4Shell Remote Code Execution Assessment, HTB Unified 

### Project Overview
This repository documents a hands on security assessment of the Log4Shell vulnerability, CVE 2021 44228, against the UniFi Network Application on the Hack The Box Unified machine. The assessment validates remote code execution, achieves initial access, and escalates privileges to root following a real world attacker workflow.

### Scope
* Authorized Hack The Box lab environment only.

### Target Environment
* Platform. Hack The Box
* Machine. Unified
* Application. UniFi Network Application
* Version. 6.4.54
* Vulnerability. Log4Shell CVE 2021 44228
* Impact. Remote code execution and full system compromise

### Tools Used
* Nmap
* Burp Suite
* Rogue JNDI
* Wireshark
* tcpdump
* Netcat
* MongoDB client utilities

### Attack Workflow
* Reconnaissance
* Identified exposed services using network scanning.
* Confirmed UniFi web interface on port 8443.
* Validated application version to assess Log4Shell exposure.

### Exploitation and Initial Access
* Intercepted UniFi API login requests using Burp Suite.
* Injected a crafted JNDI payload into the remember parameter.
* Observed outbound LDAP traffic confirming payload execution.
* Obtained a reverse shell as the unifi user.

### Post Exploitation and Privilege Escalation
* Enumerated local services and running processes.
* Identified internal MongoDB access.
* Extracted application data and escalated privileges.
* Achieved root access and verified full compromise.

### Screenshots and Evidence
#### The following screenshots are included to validate each stage of the attack.
#### Reconnaissance:
#### This shows open ports and attack surface discovery.
<img src="https://github.com/bikasha49/htb_unified_log4shell_rce/blob/3dd87d3cf0d1026a1eba49f0ceef97e2b946ce88/screenshot/recon_nmap_open_ports.png.png" width="590" align="left">
<br clear="left"/>

#### Application Identification:
#### This proves the vulnerable UniFi application and version.
<img src="https://github.com/bikasha49/htb_unified_log4shell_rce/blob/3dd87d3cf0d1026a1eba49f0ceef97e2b946ce88/screenshot/unifi_version_6_4_54.png.png" width="590" align="left">
<br clear="left"/>

#### Request Interception:
#### This shows you intercepted the API login request in Burp Suite.
<img src="https://github.com/bikasha49/htb_unified_log4shell_rce/blob/3dd87d3cf0d1026a1eba49f0ceef97e2b946ce88/screenshot/burp_captured_api_login_request.png.png" width="590" align="left">
<br clear="left"/>

#### Payload Injection:
#### This shows the Log4Shell payload placed in the remember parameter.
<img src="https://github.com/bikasha49/htb_unified_log4shell_rce/blob/3dd87d3cf0d1026a1eba49f0ceef97e2b946ce88/screenshot/burp_log4shell_payload_remember_field.png.png" width="590" align="left">
<br clear="left"/>

#### Exploit Validation:
#### This proves the target made an outbound LDAP connection, confirming execution.
<img src="https://github.com/bikasha49/htb_unified_log4shell_rce/blob/3dd87d3cf0d1026a1eba49f0ceef97e2b946ce88/screenshot/ldap_callback_proof_port_389.png.png" width="590" align="left">
<br clear="left"/>

#### Initial Access:
#### This shows you received a shell and confirmed the unifi user.
<img src="https://github.com/bikasha49/htb_unified_log4shell_rce/blob/3dd87d3cf0d1026a1eba49f0ceef97e2b946ce88/screenshot/reverse_shell_proof_whoami_unifi.png.png" width="590" align="left">
<br clear="left"/>

#### Post Exploitation:
#### This proves continued access after exploitation.
<img src="https://github.com/bikasha49/htb_unified_log4shell_rce/blob/3dd87d3cf0d1026a1eba49f0ceef97e2b946ce88/screenshot/user_flag_user_txt.png.png" width="590" align="left">
<br clear="left"/>

#### Impact Proof:
#### This proves full compromise with root access.
<img src="https://github.com/bikasha49/htb_unified_log4shell_rce/blob/3dd87d3cf0d1026a1eba49f0ceef97e2b946ce88/screenshot/root_flag_root_txt.png.png" width="590" align="left">
<br clear="left"/>

### Impact
* Remote code execution confirmed.
* Interactive shell access obtained.
* Privilege escalation to root achieved.

### Remediation Recommendations
* Upgrade UniFi Network Application to a patched version.
* Disable JNDI lookups where possible.
* Restrict outbound network access from application servers.
* Enforce authentication and least privilege for internal services.
* Monitor for suspicious JNDI patterns and unexpected outbound LDAP traffic.

### What I Gained From This Project
* Hands on experience exploiting a critical real world vulnerability.
* Understanding of Log4Shell behavior at both application and network levels.
* Practical use of Burp Suite for manual request interception and exploitation.
* Experience validating exploits through packet level evidence using tcpdump and Wireshark.
* Confidence documenting offensive security work in a clear and professional manner.
### 🌐 Let's Connect
<a href="https://www.linkedin.com/in/bikasha-gurung">
  <img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white" alt="Connect on LinkedIn" />
</a>

