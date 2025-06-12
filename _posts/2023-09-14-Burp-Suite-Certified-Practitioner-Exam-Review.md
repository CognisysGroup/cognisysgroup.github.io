---
title: Burp Suite Certified Practitioner Exam (BSCP) Review
author: Cognisys
date: 2023-09-14 5:00:00 +0100
categories: [Web Application Pentesting, Application Security, BSCP]
tags: [BSCP, Application Security, Web Pentesting]
image:
  path: https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/f49d9b83-d318-401d-a7fc-c99ea48c87d6
  alt: 
render_with_liquid: false
---

At Cognisys, we are driven by experts in cybersecurity. Our team comprises individuals with extensive skills and a deep understanding of the field, always ready to secure your business.

In the ever-evolving landscape of cybersecurity, staying ahead of the curve is not an option; it's a necessity. As businesses around the world seek to fortify their digital defences, the role of a penetration tester has never been more critical. To validate their skills and expertise, two of our company's finest pentesters recently embarked on a journey to become Burp Suite Certified Practitioners. In this blog, we will provide you with an in-depth review of the Burp Suite Certified Practitioner (BSCP) exam, as well as insights from our successful pentesters who passed this challenging certification.

## The Certification Overview

The Burp Suite Certified Practitioner (BSCP) is an official certification designed specifically for web security professionals. This certification is offered by the creators of Burp Suite, a renowned web vulnerability scanner and security testing tool widely used by cybersecurity experts and organisations.

Achieving the BSCP certification is a testament to an individual's expertise in web security, and it signifies a comprehensive understanding of various web security vulnerabilities. This certification is highly regarded in the cybersecurity field and is an indicator of a practitioner's proficiency in identifying, exploiting, and mitigating web application security risks.

## Exam Format and Structure

The exam consists of 2 applications with 3 challenges each, in total 6 challenges. Candidates are required to successfully solve both applications within a time frame of **four hours**.

In order to successfully navigate and resolve the challenges presented in the applications, candidates must follow a specific sequence of steps:

1. **Access Low-Level Users**: At the initial stage, candidates need to gain access to low-level user accounts within the applications. This often entails identifying vulnerabilities or weaknesses in the system's security measures, which may include exploiting common web application vulnerabilities like cross-site scripting (XSS) or insecure authentication mechanisms.

2. **Elevate to Administrator User**: Building upon the access gained to low-level user accounts, candidates must then proceed to elevate their privileges to that of an administrator user. This step demands a deeper understanding of the application's architecture and security configurations. The objective here is to attain the highest level of access rights within the application, often associated with administrator privileges.

3. **Retrieve User Secret**: The ultimate goal of the challenge is to extract or read confidential information or secrets associated with a specific user account. This could be done by Remote code execution, SSRF, Java deserialisation, etc. Successfully retrieving the user secret will lead to solving the application.

## How to Prepare?

The preparation should be around web application vulnerabilities. It would be beneficial if you're already familiar with OWASP's Top 10 vulnerabilities. Ultimately, You can refer to Portswigger Academy labs specifically practitioner-level labs which all are free of cost. Refer to [Portswigger](https://portswigger.net/web-security/certification/how-to-prepare)

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/524ee5e6-1628-4170-a9ac-b420e84ded08)

Give a try to the practice exam before taking the BSCP exam. However, the practice exam is easy compared to an actual exam. 

## Difficulty Level?

The Burp Suite Certified Practitioner exam is not for the faint of heart. It falls within the moderate range. Candidates are expected to have a comprehensive understanding of web application security concepts and techniques, and the ability to apply this knowledge effectively in practical situations. Most candidates make multiple attempts to pass this certification. 

## Interview with Our Pentesters

We've asked a few questions to our pen testers  [Punit](https://www.linkedin.com/in/0xanuj/) and [Rajveer](https://www.linkedin.com/in/rajveer67/) who shared their experience with the BSCP examination. 

**Q: Can you share your motivation behind pursuing the Burp Suite Certified Practitioner certification?**

*Rajveer*: Certifications ensure credibility and validate your skills and that was the real motivation behind pursuing BSCP.

*Punit*: Agreed. The certification validates the skillset. It's a great way to demonstrate your expertise to clients and employers. I like challenges and this certificate was challenging so that was the motivation for me.

**Q: How did you prepare for the exam? Any recommended resources?**

*Punit*: I started by reading reviews of other people first and it was evident that most people found it challenging. Then, I explored various online labs and videos. The PortSwigger Academy has some excellent material, including labs that mimic real-world scenarios.

*Rajveer*: Yes, the PortSwigger Academy is a goldmine for anyone preparing for this certification. But I would say mindset building to make any vulnerability exploitable will help people a lot.

**Q: Can you describe the exam format and the level of difficulty?**

*Punit*: The exam consists of 2 applications with 6 challenges, 3 for each application. You have to demonstrate your ability to exploit web vulnerabilities. It's challenging but fair.

*Rajveer*: I'd say the difficulty level is moderate. You need to understand web security inside out and be prepared to tackle real-world scenarios.

**Q: Any tips for those aspiring to take the Burp Suite Certified Practitioner exam?**

*Punit*: Don't rush the preparation. Take your time to understand web application security flaws. Practice in all practitioner Portswigger labs before attempting the exam.

*Rajveer*: And don't miss the hacker mindset-building, focus on that because the actual exam will test that too.

**Q: How do you describe the overall exam experience?**

*Punit*: The experience was good but I faced an issue while starting the exam as it does verification using examity and my verification got stuck on my second attempt however the Portswigger support helped me with this.  During my first attempt, I was let down by my performance as I underestimated it and the actual exam was challenging. Also during the second attempt, I got confused with one of the vulnerabilities which took me around half an hour to make it exploitable. It was great fun in the end to achieve success as you get to prove your capabilities which you would eventually apply during a client engagement.

*Rajveer*: The exam experience for me was smooth, I didn't encounter any technical glitches during the exam. During my first attempt, I was able to solve 4 out of 6 challenges, and I had one and a half hours left. However, the remaining 2 challenges were quite difficult, and I couldn't solve them. In my second attempt, I was well-prepared and had enough practice with PortSwigger labs, which helped me solve all the challenges within two hours.

## Conclusion

Becoming a Burp Suite Certified Practitioner is a testament to one's dedication to web application security testing. Our successful pentester's have shown that with the right motivation, resources, and preparation, this certification is within reach.

So, if you're looking to upskill in the world of cybersecurity, consider following in their footsteps. Start your journey to becoming a Burp Suite Certified Practitioner, and unlock a world of opportunities to protect and secure digital assets. Good luck!
## References

For those interested in pursuing the Burp Suite Certified Practitioner certification, here are some valuable resources:

- [PortSwigger Academy](https://portswigger.net/web-security)
- [How to prepare](https://portswigger.net/web-security/certification/how-to-prepare)
- [BSCP Guide - Github](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

With the right guidance and dedication, you can enhance your skills and become a certified expert in web application security testing.
