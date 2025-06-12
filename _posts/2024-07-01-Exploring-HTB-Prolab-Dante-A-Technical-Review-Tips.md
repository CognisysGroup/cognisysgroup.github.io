---
title: Exploring HTB Prolab Dante - A Technical Review + Tips
author: Soham
date: 2024-07-01 10:45:00 +0100
categories: [HTB, Prolab, Dante]
tags: [HTB, Prolab, Dante, Review]
image:
  path: https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/6ec93821-f6bf-4534-9489-858cd7428591
  alt: 
render_with_liquid: false
---


**Introduction**

Hack The Box (HTB) Prolab - _Dante_ offers a challenging and immersive environment for improving penetration testing skills. This is a Red Team Operator Level 1 lab. This lab demands expertise in pivoting, web application attacks, lateral movement, buffer overflow and exploiting various vulnerabilities. In this review, I'll share my experience, what I learned, the indispensable tools, and some aspects that I found less favourable.

As per Hack The Box, the description of Dante is as follows.

_Dante Pro Lab is a captivating environment with Linux and Windows Operating Systems. You will level up your skills in information gathering and situational awareness, be able to exploit Windows and Linux buffer overflows, gain familiarity with the Metasploit Framework, and much more! Completion of this lab will demonstrate your skills in network penetration testing, including:_

- _Enumeration_
- _Exploit Development_
- _Lateral Movement_
- _Privilege Escalation_
- _Web Application Attacks_

The portal's lab description will provide the entry point subnet. As a first step in pwning the Dante labs, you can start scanning and enumerating all the live hosts from this subnet. The lab contains hosts in multiple subnets and requires pivoting to reach those hosts from the initial subnet. You need to capture 14 machines and 27 flags scattered across the network to complete this lab.

**Registration**

HTB now offers a single subscription with access to all six active Prolabs on the platform, with difficulties ranging from Intermediate to Insane. This can be billed monthly or annually. I took a monthly subscription and solved Dante labs in the same period.

**Difficulty Level**

HTB advertises the difficulty level as intermediate, and it is justifiable. This network is not for the faint-hearted, as it involves pivoting, privilege escalation, extensive post-enumeration activities, and some active directory scenarios to exploit. After solving this lab, you will become a better penetration tester with improved skill sets. 

**What I Learned**

**Pivoting Techniques**

Pivoting is essential for any penetration tester, and Dante excels at it. Nearly every target necessitated at least one layer of pivoting, with many requiring multiple hops. Establishing and managing intricate network tunnels can be accomplished using various methods and tools. Tools such as Sshuttle, proxy chains, chisel, and Metasploit's routing capabilities can be utilised in the lab. Mastering the ability to create dynamic and static SSH tunnels and skillfully using them for port forwarding was a pivotal skill honed in this lab.

**Ligolo-ng for Tunneling**

One tool that stood out as a lifesaver was [Ligolo-ng](https://github.com/nicocha30/ligolo-ng). Its ease of use and efficiency in building robust tunnelling connections made many pivoting tasks much more manageable. This was heavily used while solving the Dante labs. This tool follows a client-server architecture like Chisel. It creates a TUN interface on the server side(threat actor) but eliminates the need to utilise the SOCKS proxy to interact with the internal hosts. This significantly improves the speed of tunnelled traffic without the need for proxy chains to slow down the connections. Check out this fantastic tool to explore its capabilities for managing tunnels and pivots.

**Leveraging Netexec**

Netexec is the new and actively maintained open-source tool that originated from a better-known tool called Crackmapexec. Netexec is now pre-installed in Kali and can be utilised to its fullest while solving the Dante labs or other internal penetration testing engagements. It is a tool that helps automate assessing the security of large networks. Multiple protocols, like SMB, SSH, RDP, FTP, LDAP, WMI, etc., are supported and commonly present in enterprise networks.

**Buffer Overflow Exploits**

Leveraging vulnerabilities such as the classic stack overflow on Windows and Linux targets reinforces one's understanding of memory management and exploitation techniques. These exercises not only refreshed my skills but also taught me new methods of payload delivery and execution.​

**Tools That Made a Difference**

- **WinPEAS and LinEnum**: These scripts efficiently automate the collection of crucial system information for Windows and Linux systems, saving significant time.​
- **Metasploit**: Essential for managing multiple pivots and routing traffic through compromised hosts, Metasploit's flexibility and power were indispensable in the Dante lab​
- **Ligolo-ng**: One of the best tools for pivoting, easy to set up and efficient.
- **Crackmapexec/netexec:** Netexec is crucial for validating all the identified credentials when conducting network penetration tests. This tool is like a Swiss army knife and does an exceptional job. Netexec has even more impressive capabilities, including support for inbuilt modules.
- **Pspy:** This tool helps identify all the running on a Linux machine without root permissions. It lets you see commands run by other users, cron jobs, etc., as they execute. Great for the enumeration of Linux systems

**Challenges and Drawbacks**

**Network Complexity and Documentation**

The complex network topology was a fantastic learning experience but also a significant challenge. To avoid getting lost, it was paramount to document every step and connection meticulously. However, correctly setting up the multi-hop pivot connections was a substantial task.​

**Flag Locations**

The placement of the flags was a matter of debate. While most were easy to find, some were hidden, causing frustration. Providing clear instructions for all flag locations made the experience less tedious without compromising the main objectives. This makes it more of a CTF than a real environment.

**Lab Redeployment**

Although the lab is redeployed daily, resetting a single machine can be difficult if the reason provided is not convincing. Additionally, it's not easy to tell if a machine has been reset after a request, as there's no visual indicator on the platform. One way to check is to create a simple file on the machine. If the file is deleted, it indicates that the machine has been reset from the backend.

**Hidden Gems: Using Flags as Hints**

Within Dante, the flags can sometimes act as breadcrumbs that guide you through the network. You can often identify the next logical target or pivot point in the network through careful analysis of the information and clues provided by some of the captured flags. This lab component facilitates heightened engagement and meticulous analysis, enriching the learning experience by establishing connections between various network segments and vulnerabilities.

**Tips**

- The re-use of credentials in Dante is widespread, so collect credentials from each compromised host.
- After you have compromised a machine, search for the "DANTE{"flag to ensure none are left behind.
- Read the flags carefully. They could be a hint to the next pivot point.
- If the services on the machine are not responding, ensure you submit a lab reset on the portal.
- Sometimes, essential tools won't work, so ensure you can craft simple bash scripts/PowerShell scripts for simple tasks such as scanning the live hosts in the network.
- Ensure you save all the artefacts once you have completed the post-exploitation process, as that will come in handy for exploiting other hosts in the network.
- Never give up. Keep trying different techniques and tools. When you run a command, try analysing simple error messages and giving them to ChatGPT when you don't understand them.
- Taking good notes is one of the most important things you can do. This will save you a ton of time when you take a break or return to solve the labs at the end of the day.
- For efficient pivoting in the labs, ligolo-ng stands out as the top tool for the job.
- Basics of Active Directory exploits and attacks will be helpful, as the lab includes some AD attack scenarios.
- Before spraying credentials across the network, ensure you are aware of the implemented account lockout policy.
- If you're stuck, you can seek help from other users in the Discord channel. It is a supportive community, and it will give you little nudges to solve the labs without spoiling the fun.
- Suppose you believe that certain services on the machines are not functioning correctly. In that case, you can request a redeployment on the platform. Sometimes, switching the VPN server can resolve most of the issues.
- Occasionally, you may find unintended ways to access certain sensitive information or exploits; be sure to exploit and document these.

**Conclusion**

The HTB Prolab Dante provides excellent training for penetration testers who want to enhance their skills in pivoting, network tunnelling, and exploiting various vulnerabilities. The challenges in the lab facilitate significant growth and prepare participants for real-world scenarios. Despite some drawbacks, such as the complexity of subnet discovery and the hidden flag locations, the lab offers immense value. Tools like Ligolo-ng, WinPEAS, LinEnum, and Metasploit are essential for success in this environment. Dante is a demanding yet rewarding experience for anyone serious about advancing their penetration testing capabilities.

This is the excellent certificate you get from Hack The Box after completing 100% of the Dante labs!

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/0b788675-b767-4b17-aed2-c756b4775178)

![Cert_1](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/6ec93821-f6bf-4534-9489-858cd7428591)


**References**

For those interested in owning the Dante Prolab, here are some valuable resources:

- [PayloadsAlltheThings Github Repo](https://github.com/swisskyrepo/PayloadsAllTheThings/)
- [Hack The Box Academy](https://academy.hackthebox.com/)
- [HackTricks](https://book.hacktricks.xyz/)
