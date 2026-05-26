---
title: Breaking Tenant Boundaries, When Path Traversal Isn't About the Filesystem
author: Rajveer
date: 2026-05-25 15:50:00 +0100
categories: [Case Study, Web Application Pentesting]
tags: [Case Study, Web Application Pentesting]
image:
  path: https://github.com/user-attachments/assets/4ec5a34a-6197-408b-bfcd-b3104726ac86
render_with_liquid: false
---

Multi-tenant SaaS applications are a tricky beast. From the outside, they look like a single product, but underneath the surface, they're hosting data and configurations for dozens, hundreds, sometimes thousands of separate organisations. Every request that hits the backend has to know which tenant it belongs to and what data it should be allowed to touch. When that boundary is enforced cleanly, the platform works as advertised. When it isn't, the consequences can be severe. A single authenticated user in one organisation might be able to peek into the files of every other organisation on the platform.

In most engagements, when you spot a path traversal issue, you expect the usual outcome. Files from the underlying filesystem, an `/etc/passwd` here, a `web.config` there, maybe a deployment artefact if you're lucky. But not every path traversal touches the disk. Sometimes the "path" being traversed isn't a filesystem path at all. It's the URL of an internal API being called somewhere deep in the architecture, and the consequences end up looking very different from the textbook case.

This is a case study from a recent engagement where exactly that happened. What initially looked like a dead-end path traversal turned into a full cross-tenant data exposure, allowing an authenticated user in one organisation to enumerate and download every file in every other organisation's asset library on the platform.

## Engagement Context

The target was a multi-tenant social media monitoring and PR platform used by organisations to track, manage, and report on the social presence of their brands. Each organisation could have multiple users, with role-based access controls separating what those users could do within their own tenant.

One feature stood out during the early reconnaissance phase. The Asset Library was a shared workspace where users in an organisation could upload files (images, PDFs, brochures, marketing materials, internal documents) that other users in the same organisation could view and download. It was, by design, scoped to each tenant. A user in Organisation A should never see files belonging to Organisation B.

Anything that handles cross-user file storage in a multi-tenant context is worth poking at, so this was the first place we started.

## The Download Endpoint

The Asset Library exposed a file download endpoint that took two query parameters, `filename` and `folderPath`.

```text
GET https://api.target.com/api/clientpublicdoc?filename=try.svg&folderPath=
```

The response was a JSON document containing a base64-encoded string. Once decoded, this matched the content of the SVG file we had uploaded earlier as a test.

![image1](https://github.com/user-attachments/assets/bc1ade5e-cf3f-4bd5-9aea-4dca7636346b)

Two user-controlled parameters in a file download endpoint are a red flag in the best of times. The first instinct was the obvious one. Classic path traversal on the `filename`.

## The Path Traversal That Wasn't

We started with the usual payloads on the `filename` parameter.

```
filename=../try.svg                              → ""
filename=../../../../../etc/passwd               → ""
filename=../../../../../../boot.ini              → ""
filename=C:\Windows\win.ini                      → ""
```

Every variation came back as an empty string. The application wasn't biting on any of them. At this point, the easy assumption would be that there's nothing here and that input sanitisation is doing its job. But the existence of a second parameter, `folderPath`, was suspicious. Why expose a folder path at all if it isn't doing something interesting on the backend?

So we shifted focus and started fuzzing `folderPath` instead.

```text
GET /api/clientpublicdoc?filename=boot.ini&folderPath=../../../../../../
```

This time, the response wasn't empty. It came back as a long base64 string. After decoding, we were looking at an HTML page. Not a system file, but a generic ASP.NET-style landing page with the title "AI REDACTED DMS API".

![image2](https://github.com/user-attachments/assets/c82b52ef-036e-4950-be5d-fa137d06a8da)

That was unexpected. The same request with `folderPath=` empty returned the original empty response. So whatever was happening, it was the `folderPath` parameter, not the `filename`, that controlled the response. We had been fuzzing the wrong parameter the entire time.

## Mapping What's Behind the Scenes

To narrow things down further, the `filename` value was dropped altogether, and we varied just the depth of the traversal in `folderPath`.

```text
GET /api/clientpublicdoc?filename=&folderPath=../
Response → "W10="   (base64 for: [])
```

A literal empty JSON array. Now things were getting interesting.

```text
GET /api/clientpublicdoc?filename=&folderPath=../../
Response → base64 decoded:
{"message":"No HTTP resource was found that matches the request URI 'https://internal-dms-api.target.com/api/doc/Public/'."}
```

![image3](https://github.com/user-attachments/assets/6a9e1f44-8161-417e-b909-fd85774a5cc4)

There it was. The application wasn't reading from a filesystem at all. The public-facing API was making an HTTP call to an internal API to fetch files, and the `folderPath` parameter was being concatenated directly into that internal URL. By going up a couple of levels with `../`, we were effectively rewriting the URL the backend was requesting against the internal service.

The mental model now looked like this:

```
User
  → https://api.target.com/api/clientpublicdoc
     → internal HTTP request
        → https://internal-dms-api.target.com/api/doc/Public/{folderPath}/{filename}
```

The error message gave us the base path: `/api/doc/Public/`. By using `folderPath=../../`, we had traversed back to the `/api/` root of the internal service, where no such resource existed (hence the 404). What we needed was the next segment after `Public/`. The segment that selected which tenant's files were being retrieved.

## The Dead End

This is the part where we almost gave up.

The structure was clearly `Public/{something}/{filename}`. But what was `{something}`? A few hypotheses came to mind:

- The organisation ID, a numeric identifier visible in various API responses
- The user ID, also numeric
- A UUID assigned to each tenant or each user
- A custom folder name derived from the tenant's slug or company name

Every reasonable guess was tried. Our own user ID and organisation ID were pulled from JWT tokens and API responses and thrown into `folderPath`.

```
folderPath=../../92030                                    (user ID)
folderPath=../../5645                                     (organisation ID)
folderPath=../../ac489995-cf90-4a6e-834b-608d6360c4ae     (random UUID)
```

Every single one came back empty. We were completely blind to the naming convention the internal service used. Without that, there was no way to construct a valid path. We couldn't even validate what our own tenant's directory was called.

It genuinely felt like a wall.

## Going Back to the Application

When you hit a dead end, the best move is usually to step back and re-read what the application has already been telling you. So we went back through the proxy history and looked at every endpoint the Asset Library feature touched. Maybe somewhere in those responses, the application was already leaking the identifier we needed.

It turned up on the asset listing endpoint.

```text
GET https://api.target.com/api/clientpublicdoc/list
```

This is the endpoint the UI calls when rendering the list of files in the user's own Asset Library. The response was a JSON array of file objects, and one field in particular stood out.

```text
[
  {
    "sourceKey": "clientpublicdoc_clientid-5645_5645",
    "fileName": "Test Image.jpg",
    "publicUrl": "https://cdn.target.com/publicitem/6b9b06dc-b9ed-49ca-b2e8-...",
    ...
  },
  ...
]
```

![image4](https://github.com/user-attachments/assets/7200baea-2331-490f-8c8b-880e78556996)

`sourceKey`. The format `clientpublicdoc_clientid-5645_5645` had the unmistakable shape of an internal directory identifier, with a numeric client ID embedded inside it. This was almost certainly the name of the folder sitting just after `Public/` on the internal service.

## Confirming the Theory

To validate this, a request was crafted using our own `sourceKey` in `folderPath`.

```text
GET /api/clientpublicdoc?filename=try.svg&folderPath=../../clientpublicdoc_clientid-5645_5645
Response → base64 content of try.svg
```

![image5](https://github.com/user-attachments/assets/830c23bb-d484-42c1-b3b2-88d25ad9c797)

Identical to what we got with the original empty `folderPath`. That confirmed it. The default `folderPath` value was effectively a shorthand for "current tenant's sourceKey". When the same value was supplied explicitly via path traversal, the application happily routed the internal call there.

Just to be thorough, the same request with one fewer `../`.

```text
GET /api/clientpublicdoc?filename=try.svg&folderPath=../clientpublicdoc_clientid-5645_5645
Response → ""
```

![image6](https://github.com/user-attachments/assets/ab35d24f-9b77-4e84-a1b6-b52b567e03fd)

Empty. Good. That confirmed the exact depth of traversal needed to escape one level and land on a sibling tenant's folder.

Next, the `filename` was removed entirely, leaving `folderPath` pointed at our own `sourceKey`.

```text
GET /api/clientpublicdoc?filename=&folderPath=../../clientpublicdoc_clientid-5645_5645
```

The response was a base64-encoded JSON array, byte-for-byte identical to what `/clientpublicdoc/list` had returned. With no specific filename, the internal service was returning a directory listing for that folder.

![image7](https://github.com/user-attachments/assets/fba9b7db-52a7-4467-8ae6-14732994940e)

Two primitives were now in hand:

- List all files in any folder where the `sourceKey` is known
- Download any individual file from that folder by supplying its filename

## Cross-Tenant Exposure

The final question was whether `sourceKey` values were predictable across tenants. Looking at our own, `clientpublicdoc_clientid-5645_5645`, the structure was hardly opaque. A static prefix of `clientpublicdoc_clientid-`, followed by what looked like a sequentially assigned numeric client ID, duplicated after an underscore.

If client IDs were assigned incrementally, then guessing other tenants' `sourceKey` values was trivial.

Incrementing the client ID by one:

```text
GET /api/clientpublicdoc?filename=&folderPath=../../clientpublicdoc_clientid-5646_5646
```

The response decoded to:

```text
[
  {
    "sourceKey": "clientpublicdoc_clientid-5646_5646",
    "fileName": "banner.jpeg",
    "publicUrl": "https://cdn.target.com/publicitem/8caecb23-24c3-4dc5-...",
    ...
  },
  {
    "sourceKey": "clientpublicdoc_clientid-5646_5646",
    "fileName": "brochure_new.pdf",
    "publicUrl": "https://cdn.target.com/publicitem/c5d897cc-a1ff-4897-...",
    ...
  }
]
```

![image8](https://github.com/user-attachments/assets/1e84e0f5-0ad4-4dcb-970c-b761b46b8178)

That was the asset library of a completely different organisation.

It got worse. The `publicUrl` field in each entry pointed at a CDN-hosted version of the file that was directly accessible with no authentication check at all. The platform had wrapped its actual file storage behind public URLs that relied entirely on the obscurity of a randomly generated UUID. Once those UUIDs leaked through the listing endpoint, the files were effectively in the open.

From here, the same trick could be repeated against any client ID in the platform's range. Every organisation's asset library, with every file's name, size, metadata, and direct download URL, was reachable from an authenticated session in a single tenant account.

## Impact

What started as a quirky variant of path traversal turned out to be a serious breach of the platform's multi-tenant isolation model. A user authenticated against any organisation could:

- Enumerate every other organisation's Asset Library on the platform
- Retrieve filenames, sizes, upload timestamps, and any other metadata associated with those assets
- Download the underlying files via the CDN public URLs, regardless of which tenant originally owned them

For a platform whose customer base includes PR agencies, brand teams, and communications consultancies, the contents of those asset libraries are not idle clip art. They typically include unreleased press materials, embargoed campaign content, internal brand documents, client-specific brochures, and similar sensitive material. Disclosure of any of this between tenants would constitute a serious confidentiality breach, with knock-on consequences for the affected organisations' regulatory commitments, NDAs, and reputational exposure.

## Remediation

There are several layers at which this issue should be addressed, and ideally, all of them should be in place rather than relying on a single control.

- **Enforce tenant boundaries on the internal API, not just the public one.** The internal file service was trusting whatever path the public API forwarded to it. The internal service should be authenticating each call, knowing the identity of the requesting tenant, and refusing to serve content from a `sourceKey` that doesn't belong to that tenant. Internal services in a multi-tenant platform should not assume their upstream callers are doing access control correctly.

- **Sanitise input that flows into upstream URLs.** The `folderPath` parameter was being concatenated into an internal URL without any normalisation. Any sequence of `..`, slashes, or other URL-meaningful characters should be stripped or rejected before the value is used as part of a path segment. Where possible, the public API should not accept a folder path from the user at all. It already knows which tenant the session belongs to and can derive the path server-side.

- **Replace predictable identifiers with unguessable ones.** The use of an incrementing client ID inside `sourceKey` made enumeration trivial. Switching to UUIDs or HMAC-signed identifiers would significantly raise the bar even if the underlying access-control bug were still present. Predictable IDs should not be relied on as a security boundary, but in a defence-in-depth, they help.

- **Audit similar patterns across the codebase.** When one endpoint demonstrates this pattern, a public API forwarding user input into an internal HTTP request, there are usually others. Every endpoint that proxies internally should be reviewed for the same class of issue.

- **Don't rely on URL obscurity for file confidentiality.** The CDN `publicUrl` values were treated as effectively secret, even though they were returned to any user who could list assets. A breach of the listing endpoint immediately broke the entire file confidentiality model. Files in a tenant-isolated asset library should sit behind authenticated requests, not public URLs whose security depends on the secrecy of a UUID.

## Key Takeaways

A few things from this engagement are worth holding onto.

Path traversal isn't always about the filesystem. The class of bug here was structurally identical to a classic LFI, but the "path" being traversed was an internal HTTP route, not a directory tree. The same instinct (can I get out of the intended scope by going up?) applied, but the indicators and the consequences looked different. When `../` produces a 404 instead of a file, that's not necessarily a dead end. It might just mean the path is being interpreted somewhere unusual.

Read every response, not just the ones you expect to be useful. The `sourceKey` field on the listing endpoint was the single piece of information that turned a stalled exercise into a confirmed cross-tenant exposure. It wasn't hidden. The application was sending it back to its own UI every time someone opened the Asset Library page. The only thing it took was going back and reading what the application had already been telling us.

And the boring one. Predictable identifiers in multi-tenant systems are an attack accelerator. Even if access control had been broken without them, having to brute-force UUIDs to find another tenant's directory is a meaningfully higher bar than incrementing 5645 to 5646.

## References

- [OWASP Testing Guide for Path Traversal](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include)
- [OWASP Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [PortSwigger Path Traversal](https://portswigger.net/web-security/file-path-traversal)
