---
title: Certified Red Team Operator Certificate Review
author: Soham
date: 2025-07-10 12:45:00 +0100
categories: [Certificate, Review]
tags: [CRTO, Review]
image:
  path: <img width="1280" height="720" alt="White Pink Grid Feminine Cover Of Tumbnail (2)" src="https://github.com/user-attachments/assets/34907578-cd6c-4f0b-9a88-a9ea6f024512" />
  alt: 
render_with_liquid: false
---

**Certified Red Team Operator (CRTO 1) – Review and Tips**

Soham is an experienced Security Consultant specialising in network penetration testing, active directory exploitation, and red teaming. He excels at identifying vulnerabilities and simulating advanced attack scenarios to strengthen organisational security defences. This blog will provide a comprehensive overview of the preparation process required to obtain this certification, along with valuable insights and recommendations for aspiring candidates.

The **Red Team Operations 1,** offered by Zero-Point Security, is a CREST Practitioner-level hands-on course that emphasises adversary simulation and red team operations within Windows Active Directory environments. This is developed and maintained by Daniel Duggan, also known as Rasta Mouse, and provides comprehensive coverage of the entire attack lifecycle, encompassing initial access and domain enumeration, lateral movement, privilege escalation, as well as domain takeover, cross-forest attacks and persistence techniques. The certification primarily utilises the Cobalt Strike C2 framework and other red team tools. Those who enrol in this course will gain Certified Red Team Operator (CRTO) certification upon passing the rigorous 48-hour practical exam.

**CRTO Course Review**

The Certified Red Team Operator (CRTO) course offers well-structured, clear, and concise content, often updated with current techniques. It provides lifetime access to materials and an integrated lab environment powered by Skillable, allowing students hands-on experience with real-world attack scenarios and C2 frameworks. The 48-hour practical exam, spread over seven days, requires completing operational objectives while being stealthy and evading security solutions without detection (Windows Defender). Similar to the old exam format, no report submission is needed, and retakes are free, making it a flexible and highly recommended pathway for transitioning into red teaming or understanding adversary tactics.

The course is ideal for:

1. **Penetration testers** who want to transition into the more specialised Red Teaming field
2. **SOC teams and security analysts** who wish to gain a thorough understanding of actual adversary tactics
3. **Future Red Team members** who are keen to learn evasion techniques, operational security (OPSEC), and the Cobalt Strike C2 framework

*While the specific vulnerabilities from the exam are not discussed, this account focuses on the overall experience of the CRTO. Soham recounts his experience with the exam in this blog*.

**The Exam**

I took the exam about 6 months ago, in December 2024. The exam is not proctored, unlike other exams, especially the Offsec exams, so you are not continuously monitored. The course materials and labs (before the May 2025 update) were incredibly well-designed, providing hands-on, practical insights into red team operations. The old labs powered by SnapLabs faced issues from time to time, but they were manageable. They did not significantly reduce the purchased lab time.

I started my exam at 11 am. The exam was a thrilling challenge, requiring the submission of 8 flags within 48 hours, with a passing threshold set at six flags. I had successfully achieved the passing requirement of 6 flags within the first 8 hours and completed all eight flags in under 15 hours. Since this is an assumed breach scenario, we are given a Windows foothold machine and the attacker machine with Cobalt Strike installed. I had to spend the first few hours bypassing the local Windows Defender, as the payload that bypassed Windows Defender in the labs did not work during the exam. After bypassing it and gaining local administrator privileges on the first foothold machine, the subsequent steps proceeded smoothly, with Cobalt Strike serving as the primary C2 server. I conducted further enumeration of Active Directory and analysed users, groups, computers, OUs, domain trusts, GPOs, Local Admins via GPOs and child/parent domains present in the Active Directory environment as part of the initial enumeration phase. Following this, I had the first three flags in about 5 hours.

The fourth flag required about 2.5 hours, as I encountered multiple difficulties troubleshooting my commands. While these commands were functional in the lab environment, they failed to produce the desired output during the examination. Consequently, I had to conduct a more thorough examination of the commands and perform additional troubleshooting to resolve the issues.

The fifth flag was also time-consuming, as I had missed a small detail while enumerating. I went back to my notes, fixed the commands, set up some persistence methods, and obtained the 5th flag. I was taking frequent small breaks in between, and to calm my mind, I went for a walk around my house while listening to music. The sixth flag didn't take long, and by this point, I had the keys to the kingdom and knew I had passed the exam. After about 8 hours of testing, I had enough flags to succeed, and then I went for dinner with a relaxed mind.

After dinner, I went out with my friends for a night stroll to feel even more at ease. After returning, I decided to capture the last two remaining flags as well. However, the seventh flag proved the hardest to capture, requiring some pivoting and additional troubleshooting of the commands. It took me about five hours to capture it, and the eighth flag was straightforward, bringing the total exam time to approximately 15 hours. Everything you need to pass the exam is thoroughly covered in the course materials. Around 2 am, I took a screenshot of the flag submission dashboard and went to sleep.

**Course Update (May 2025)**

As of May 19, 2025, Daniel Duggan has completely rewritten the Red Team Ops 1 course and launched the new site at this [address](https://www.zeropointsecurity.co.uk/start). The latest training platform now integrates labs and exams directly into courses, eliminating the need for a separate login. A transition to Skillable facilitates this, along with their new lab provider, LearnWorlds, which is the new Learning Management Platform being utilised.

A significant advantage of this shift is the elimination of lab expiry dates, removing time pressure on students to complete their practical exercises. This is a massive update! It offers on-demand exams directly within individual courses, eliminating the need for independent bookings or coupons. Students can take tests at any time they're ready. For a complete list of changes, please refer to the new blog post [here](https://www.zeropointsecurity.co.uk/blog/new-site-launch).

**Updated Exam scoring**

The maximum score attainable is **100**, and the minimum score required for passing is **85**.

Achieving the operational objective is worth 50 points, implying that it is not possible to obtain a passing score without accomplishing the presented objective. There are no flags to submit in the new exam, unlike in the old exam format.

OPSEC (Operational Security) discipline determines the remaining 50 points of the score, with perfect OPSEC earning full points and failures resulting in deductions. OPSEC' failures,' such as detection by antivirus software, will reduce your overall OPSEC score.

**Tips & Things to keep in mind**

1. The exam is an assume-breach scenario; you will not have a C2 beacon pre-running, but you will have access to the victim machine to run one manually. This might need bypassing Windows Defender to run a beacon successfully.
2. The exams are now graded based on **outcomes** and **performance** rather than merely reviewing a set of flags.
3. If your OPSEC score falls below a certain threshold, failing the exam is inevitable, irrespective of objective completion.
4. Additionally, you will fail the exam if you trigger an alert on a restricted host, even if you accomplish the operational objective.
5. In addition to this, there is a 72-hour cooldown before you can attempt the exam again. This is solely to prevent individuals from spamming consecutive exam lab launches.
6. Don't forget to join the CRTO Discord server. After verifying your details, you can join the students' channel (Private). Many of your doubts can be cleared in that channel, as even the author is actively answering the queries along with channel moderators.
7. Thoroughly document each topic covered in the course materials, ensuring that comprehensive and detailed notes are taken. Gain a deep understanding of the underlying mechanisms of the attacks, including their prerequisites for exploitation. Additionally, acquire knowledge of effective mitigations to prevent these attacks. This knowledge will be invaluable in real-world engagements, where you will be responsible for communicating it to clients.
8. While practising in the labs, note down the Windows Defender signature versions, as this might come in handy during the exams. That's all I can say.
9. You may need to adjust the C2 profile according to the given operational objective. Ensure that the base profile bypasses the defender while practising in the labs, and you can modify it in the exam if necessary.
10. While taking the exam, ensure you set up a proper persistence mechanism to avoid redoing all the attack steps if the exam VMs encounter any issues. It's better to be safe than sorry.

<img width="1686" height="1238" alt="image" src="https://github.com/user-attachments/assets/108410f2-a96d-4d4f-ab6e-4da83f87e2a9" />

<img width="1280" height="2054" alt="image" src="https://github.com/user-attachments/assets/70b27356-c3c1-45bc-8f23-4e2a7d601494" />

