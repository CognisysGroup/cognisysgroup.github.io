---
title: An Interesting XSS-Bypassing WAF
author: Punit
date: 2023-07-26 11:04:00 +0100
categories: [Web Application Pentesting, Case Study, XSS]
tags: [application security, bypass, waf, XSS, web pentesting, javascript]
image:
  path: https://user-images.githubusercontent.com/46415431/256192029-9d650314-0e93-4a0d-bd9d-3517300b47b4.png
  alt: 
render_with_liquid: false
---

### Overview

Greetings, everyone! I'm [Punit](https://www.linkedin.com/in/0xanuj/), an Application Security Specialist working with [Cognisys Group](https://cognisys.co.uk). My primary role involves being a Pentester with expertise in testing the security of Web, Mobile, and APIs. 

In this blog, I'd like to present a case study that involves a recent application testing assessment, where we encountered a Cross-Site Scripting (XSS) vulnerability. Interestingly, during our investigation, we discovered that the Web Application Firewall (WAF) initially appeared to safeguard the application against malicious inputs, but we eventually identified a WAF bypass.

Whether you're a cybersecurity enthusiast seeking a comprehensive understanding of the basics to tactics for bypassing WAFs, this blog is tailored for you. Our topics of exploration will include:

* Understanding Cross-Site Scripting (XSS)
* The Role of Web Application Firewalls (WAF)
* Vulnerability Scenario
* WAF Analysis
* Crafting the Custom Payload 
* Mitigation and Recommendations
* Conclusion

We'll start with laying a solid foundation with essential basics. Let's dive right in!

### Understanding Cross-Site Scripting (XSS)

Cross-Site Scripting (XSS) is a common web application vulnerability that occurs when a threat actor injects malicious scripts into web pages viewed by other users. This can happen when the application does not properly validate or sanitise user inputs, allowing malicious actors to execute arbitrary javascript code in the context of the victim's browser.

#### Anatomy of XSS

XSS attacks can be classified into three main types:

1. **Stored XSS:** The malicious script is permanently stored on the server and served to users who access the affected page.
2. **Reflected XSS:** The malicious script is reflected from a web server's response, typically through a URL parameter, and executed in the victim's browser.
3. **DOM-based XSS:** The malicious script manipulates the Document Object Model (DOM) of a web page on the client side, leading to javascript code execution.

### The Role of Web Application Firewalls (WAF)

Web Application Firewalls play a crucial role in safeguarding web applications against various attacks, including XSS. They inspect incoming requests, analyse the payloads, and apply predefined rule sets to identify and block malicious traffic.

WAFs can protect web applications from both known and unknown threats by leveraging various techniques such as signature-based pattern matching, behaviour analysis, and anomaly detection. They help bridge the gap between application vulnerabilities and the time it takes for developers to address them.

### Vulnerability Scenario

During one of our assessments of the application, we stumbled upon a parameter named `redirect` in one of the URLs. 

![Pasted image 20230725122924](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/46415431/0fe469bb-deec-45ad-844c-2feab155385a)

The `redirect` parameters commonly facilitate the navigation of the web application to the `/home/dashboard` web page upon successful user authentication. As a penetration tester, I decided to test the `redirect` feature by inserting a simple URL (`http://google.com`) as its value. The purpose was to confirm whether it would indeed redirect users to the intended destination. To my discovery, the parameter successfully redirected me to `google.com`, exposing an open redirection vulnerability. 

> The web application is built using Next.js, a popular framework for server-side rendering and building modern applications. Next.js provides a seamless development experience and offers several performance benefits. One essential component of a Next.js application is the `__NEXT_DATA__` JSON object. This object contains critical data used by the Next.js framework to handle server-side rendering, initial data population, and client-side navigation. It acts as a communication bridge between the server and the client, ensuring a smooth transition between pages.

![Screenshot 2023-07-25 at 3 43 32 PM](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/46415431/52d9734c-c628-4481-825a-bee15252f32e)

Afterwards, we determined that the redirection was initiated by a client-side script. This script utilised the value of the `redirect` parameter to redirect the user to the intended destination URL. 

Curiously, I tried to insert a basic XSS payload by setting the `redirect` parameter to `javascript:alert(1)`. Surprisingly, the WAF responded with a 403 Forbidden error, indicating that it successfully detected and blocked our attack attempt.

![Screenshot 2023-07-25 at 12 43 51 PM](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/46415431/b1658e65-64c8-48e0-bc38-1e8ab2f4c743)

Most people step back from here as they think there is a WAF which is preventing the insertion of any malicious payloads but we at Cognisys step forward and try to carry out WAF bypass techniques

### WAF Analysis

To bypass the WAF's protection, we need to understand how it was detecting and filtering malicious input. A typical WAF employs signature-based detection, pattern matching, and anomaly detection techniques. In this scenario, it was evident that the WAF was using keyword matching to recognise and block our XSS payloads.  Let's understand how did we approach the target: 

**Step 1: Understanding what type of WAF might be in the place.**

In the initial stages of our investigation, I decided to URL encode the payload to test its effectiveness in potential bypass attempts. However, it turned out that this approach didn't yield the desired results. Surprisingly, In our above open redirect issue, the web application did not produce any 403 responses. This led us to suspect the presence of a word filtering WAF, which might be screening for specific keywords such as `javascript` or `alert` etc. 

**Step 2: Find out Filtered Words**

In our testing, whenever we attempted to insert the below characters or words into the value of the `redirect` parameter, the application responded with a 403 forbidden error code.

```
( ) - parenthesis
[ ] - Square Brackets
' or " - Single/double quotes
, - Comma
. - Dot
document
window
```

**Step 3: Find out the Allowed Keywords**

Having identified the blocked elements, we can now consider exploring unblocked alternatives to bypass the WAF. One promising option is to utilise backticks (\`) as an alternative to parentheses ( ) in the `redirect` parameter's value. Additionally, it appears that certain JavaScript keywords such as `alert`, `prompt`, `confirm` etc were not blocked, suggesting there may be numerous other unblocked JavaScript keywords we can leverage. Let's craft a simple payload with `alert` and backticks (\`) :

```
javascript:alert`XSS Cognisys`
```

![Pasted image 20230725133234](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/46415431/0c2649cf-51a8-4022-adb6-4ad9c285a0fb)

Now we are able to execute the alert pop-up but still, we are aware it is not a impactful XSS that WAF is blocking some essential keywords such as `document` or `window` which can be used to leverage the impact of XSS. We'll explore the potential of obfuscating the XSS payload. One of the techniques we can use is the `atob` function for Base64 decoding. The `atob` function is a built-in JavaScript function that decodes a Base64 encoded string into its original form.

To achieve this, we need to encode our payload in Base64 format to make it more challenging for the WAF to detect.  Let's craft our payload now

## Crafting the Custom Payload

Here, for example, I want to execute the below malicious payload:

```
?redirect=javascript:document.write("<h1>This is test</h1>")
```

Using `document.write("` within the `redirect` parameter will trigger a 403 error as the WAF blocks these keywords. A more effective approach involves crafting a Base64 encoded payload and then decoding it using the `atob` function. The idea behind using the base64 approach is to make the payload look benign while it gets interpreted as a malicious payload after decoding. 

```
?redirect=javascript:atob`ZG9jdW1lbnQud3JpdGUoIjxoMT5UaGlzIGlzIHRlc3Q8L2gxPiIp`
```

The above payload will exclusively display the decoded base64 string on the webpage. This happens due to client-side handling using `window.location.href` to render the decoded content. This can be illustrated as follows: 

```
windows.location.href = "<Redirect Value>";
```

You can also verify this behaviour in the console. Nonetheless, it's worth noting that the payload renders HTML tags (H1 Tag within our payload), which can potentially be exploited for XSS purposes.

![Screenshot 2023-07-26 at 6 49 32 AM](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/46415431/18981fd8-11e5-47ea-9161-79597587ccba)

Now, let's craft it using HTML. We used a simple `onerror` event handler attribute on the image tag to demonstrate XSS. We encoded the payload in base64 and then passed it as a value for the `redirect` parameter in the URL.

```
Payload:
<img src=1 onerror=alert("Hello")>

Base64 encoded: 
'PGltZyBzcmM9MSBvbmVycm9yPWFsZXJ0KCJIZWxsbyIpPg=='

URL:
?redirect=javascript:atob`PGltZyBzcmM9MSBvbmVycm9yPWFsZXJ0KCJIZWxsbyIpPg==`

```

![Screenshot 2023-07-26 at 7 05 20 AM](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/46415431/5c280ee5-b063-43a3-a26e-46f43f4bbf99)

Similarly, we can utilise base64 to encode our blocked keywords such as `document`, `window` etc.

```
Payload:
<img src=1 onerror=alert(document.cookie)>

Base64 encoded:
'PGltZyBzcmM9MSBvbmVycm9yPWFsZXJ0KGRvY3VtZW50LmNvb2tpZSk+'
```

![MicrosoftTeams-image (30)](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/46415431/6c3be662-8410-4aee-a2dc-186e030e075a)

## Mitigation and Recommendations

Our journey instilled valuable insights, inspiring us to share these best practices for mitigating XSS vulnerabilities:

1. **Input Validation:** Employ strict input validation and sanitise user inputs using security libraries and frameworks to prevent the injection of malicious code.
2. **Output Encoding:** Implement context-aware output encoding to neutralise potential XSS payloads and ensure data is rendered safely on the client side.
4. **Regular WAF Updates:** Keep the WAF's signature and rule set up-to-date to address evolving threats effectively and maintain optimal protection.
   
## Conclusion

Our technical expedition into the world of XSS vulnerabilities and WAF bypass techniques underscores the critical need for comprehensive web application security. As defenders, we must stay vigilant, continuously analyse and secure code, and be prepared to adapt to emerging attack vectors.

Happy pentesting!, and may your applications stand strong against the relentless tide of cyber threats :)
