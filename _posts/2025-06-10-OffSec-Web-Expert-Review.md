---
title: OffSec Web Expert (OSWE) - Review
author: Punit
date: 2025-06-10 10:45:00 +0100
categories: [Application Security, Code Review, Review]
tags: [OSWE, Review]
image:
  path: https://github.com/user-attachments/assets/ca0caede-1627-4321-8608-589c05929efb
  alt: 
render_with_liquid: false
---

## Overview 

Punit is a Managing Consultant at Cognisys Group, specialising in application security with a strong focus on offensive security and secure coding practices. With experience spanning multiple industry sectors, he brings a practical, hands-on perspective to his work. In this blog, he shares a detailed review of his preparation for the OSWE certification and insights from the exam experience.

The **Offensive Security Web Expert (OSWE)** certification is widely regarded as one of the most challenging and prestigious web application security certifications available today. It’s part of OffSec’s level-300 certification series, focusing heavily on white-box testing, manual code review, and deep vulnerability exploitation techniques. Unlike black-box exams, where you test apps blindly, the OSWE exam is designed to evaluate your ability to find and exploit vulnerabilities in custom-built applications by reviewing their source code.
## The OffSec Course and Review

This course is best suited for those with a solid foundation in application security, as it covers advanced-level material. If you're just beginning your journey, you might find it challenging, but once you’ve built up your skills, it’s a fantastic certification to aim for. For those already confident in understanding, it’s an excellent opportunity to deepen your expertise and put your knowledge to the test.

The course content is well-structured and informative, though the voiceover in the videos may not be particularly engaging for all learners. Those who prefer reading may find it more effective to go through the material independently, as the narration can feel somewhat lacking. While the course does not outline a formal methodology for the exam, it does offer valuable walkthroughs of vulnerabilities across several applications. Overall, it serves as a useful foundation for developing a personalised approach to code review.

### For Exam Preparation

It's important to focus on key aspects such as using a debugger and setting up remote debugging. For those with prior experience in testing environments, this may be straightforward. However, for anyone unfamiliar with debugging, it's essential to dedicate time to learning it thoroughly.

The challenge labs are where most of the effort should be concentrated. Attempting the exam without completing these labs is not advisable. While not every lab requires remote debugging, it is a skill that may be necessary during the actual exam, so it's wise to be well-prepared.

The difficulty of the labs can vary; some are relatively simple, while others pose significant challenges. Creating custom scripts, testing them thoroughly, and maintaining detailed notes is highly recommended. Each lab offers valuable lessons, and even those reminiscent of older black-box testing scenarios can provide meaningful insights.

In general, the initial vulnerabilities in each lab tend to be accessible, but achieving full code execution often involves subtle complexities that require careful attention.

### Make Notes – Seriously

Taking notes while studying is strongly recommended. For those who don’t typically enjoy journaling, the process might feel tedious, but it often proves invaluable during the exam. A tool like **Obsidian** is particularly effective for offline note-taking, especially since the use of AI tools is not permitted in the OSWE exam. Alternatively, platforms such as **Notion** can also be used, provided that AI features are disabled.

### Dig and Learn Deeper

While the course provides a solid foundation, candidates preparing for the exam are strongly advised to delve well beyond the basics. As this is a Level-300 certification, it does not focus on straightforward vulnerabilities. Success requires a deep, technical understanding of each concept.

When studying a vulnerability, it's important not to stop at simply understanding what it is. Instead, focus on how it works, why it exists, and how it might be exploited in various scenarios. Practical experience is crucial, resources such as *Hack The Box* labs and *PortSwigger Web Security Academy* exercises offer valuable hands-on exposure.

For applied learning, *TJNull’s HTB Boxes Prep playlist* on YouTube is a particularly useful resource. It demonstrates how vulnerabilities are leveraged in real-world situations and can significantly enhance exam readiness. The playlist is available [here](https://www.youtube.com/watch?v=NMGsnPSm8iw&list=PLidcsTyj9JXKTnpphkJ310PVVGF-GuZA0).

Take *SQL Injection* as an illustrative example. While many beginners may grasp the basics, a Level-300 exam requires a significantly more advanced understanding. This includes familiarity with various SQL databases such as *PostgreSQL*, *MySQL*, and *MSSQL*, as well as a comprehensive grasp of second-order SQL injections, blind injections, time-based techniques, and error-based attacks. Building small, intentionally vulnerable applications can be an effective way to observe how these attack vectors behave under different configurations.

To deepen technical proficiency, it is highly beneficial to *read RFCs and official documentation* related to the protocols and technologies under assessment. This not only reinforces core fundamentals but also highlights how systems are designed to function, and where those assumptions may fail. Additionally, studying *exploitation chains* provides insight into how multiple vulnerabilities can be linked to escalate access or impact, reflecting the strategies commonly used in real-world attacks.

Manual practice remains essential throughout the preparation process. Since automated tools and browser extensions are not permitted during the exam, it is important to develop confidence in *identifying and exploiting vulnerabilities manually*. Minimal tool usage sharpens instincts and strengthens technical problem-solving. Finally, adopting a *developer’s perspective*, understanding how coding errors are introduced, can greatly improve the ability to detect flaws during application security reviews.
## The Exam Day

*While the specific vulnerabilities are not discussed, this account focuses on the overall experience of OSWE. Punit recollects his attempt at the exam in this blog* 

I scheduled my exam for 4:30 PM and joined the session about 15 minutes early to complete all the required proctoring verifications and checks.

As soon as the exam started, I managed to get a foothold on the first box fairly quickly, identifying the initial vulnerability within the first four hours. After that, I turned my attention to a second vulnerability on the same machine and worked late into the night, right up until midnight, before deciding to get some rest. The next morning, after a bit of breakfast and a fresh start, I jumped back in. I was able to pinpoint the root cause of the issue, but I hit a roadblock when it came to exploitation—I was missing a crucial piece of the puzzle.

After spending a few more hours trying to piece it together without success, I decided it was time to move on to the second machine. With about three to four hours of deep focus, I uncovered the first vulnerability there. Thankfully, the second vulnerability on that box didn’t take nearly as long to identify and exploit. At that point, I had already scripted some basic automation to exploit parts of the vulnerabilities and felt confident I had around 85 points—enough to pass the exam.

Still, my mind kept drifting back to the second vulnerability on the first machine. Despite being mentally drained, I pushed myself to revisit it. After a long stretch of trial-and-error and sheer mental effort, I finally managed to exploit it—late into the night. That moment was pure joy. Not only had I secured enough to pass, but now I had everything needed for a perfect 100!

By then, it was already 3 AM. My brain was crying out for rest, but I forced myself to stay awake just a bit longer to write the first exploit script properly. I finally went to sleep around 5:30 AM and woke again at 11. Skipping the usual morning routine, I jumped straight into scripting for the second box. I completed it, ran it to make sure it worked flawlessly, and then carefully reviewed all my screenshots and notes.

That review step was critical. It was during this check that I noticed a few key screenshots were missing. Catching those gaps in time allowed me to complete my documentation thoroughly and avoid any last-minute surprises.

At last, the 48 hours were over. It had been intense, exhausting, and at times overwhelming—but absolutely amazing.

## The Challenges I faced during the exam

One of the most frustrating aspects of the exam was the lag on the debugging machines. Honestly, it made for a pretty rough experience throughout the attempt. I strongly feel that OffSec needs to improve this area. At times, one of the boxes would lag so badly that it was nearly impossible to make any meaningful progress. Reconnecting to the machine occasionally helped, but not always. From my experience, I would highly recommend using a **Kali box** for everything, even when connecting to the debug machines, as it made things slightly more manageable.

Another real challenge was dealing with distractions and emotional dips during the exam. This test isn’t just about technical skills—it also puts your patience and mental resilience to the test. There were moments when I felt completely stuck for hours, unable to move forward, and it was easy to feel demotivated. What helped me in those moments was music, specifically Qawwali. That kind of music really lifted my mood and helped me channel my frustration into focus. It was a personal remedy, but I believe everyone should have a strategy to reset their mindset during those inevitable low points.

Sleep was another major hurdle. When I get into deep focus, I tend to lose track of time and forget basic self-care. While that might sound like dedication, it’s actually not great for your health. Even when I tried to sleep, my mind kept drifting back to the vulnerabilities I had been working on. Strangely enough, that obsessive thinking helped, keeping the problem-solving process alive in the background. It was draining, but in its own way, it pushed me closer to the solutions I needed.
## Is it worth it?

If you’re focused on building your career and need to showcase certifications, the OSWE can definitely be a valuable credential. It sends a strong signal to employers, especially those who rely on certifications as a way to filter candidates, rather than investing time in evaluating technical skills more deeply.

That said, it’s important to recognise the broader context. Certifications like OSWE are often shaped more by industry expectations and hiring frameworks than by a genuine reflection of deep expertise. While the OSWE does require you to demonstrate solid skills in web application exploitation, holding the certificate doesn’t automatically make someone an expert. I’ve come across individuals who had the certification but still lacked critical practical skills.

At the end of the day, it’s a great challenge if you want to push yourself, provided you’re comfortable with the cost. With that kind of money, you might even be tempted to create your own learning path. But the reality is that, in today’s job market, certifications still carry weight in the eyes of many organisations, and that’s something worth acknowledging.

## Conclusion

The OSWE certification is not just a test of technical ability, it’s a test of perseverance, problem-solving, and mental resilience. It’s one of the few certifications where the journey itself transforms you, helping you think like a real-world attacker and assess applications with surgical precision.

If you’re someone who enjoys white-box testing, source code analysis, and solving deeply embedded logic flaws, OSWE is a fantastic milestone to pursue. 

Just remember: it’s not about ticking a box or adding a line on your CV. It’s about what you learn in the process, how you push your boundaries, and how you emerge with not just a certificate, but with sharpened instincts as a security professional.

If you’re on the path, best of luck. You’re going to love it.

<img width="1055" alt="Screenshot 2025-04-18 at 3 19 35 AM" src="https://github.com/user-attachments/assets/34c47ca1-bfd2-4d16-b6bd-c2c0aba429fc" />

