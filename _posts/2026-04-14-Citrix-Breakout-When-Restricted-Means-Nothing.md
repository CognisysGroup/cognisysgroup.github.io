---
title: Citrix Breakout When Restricted Means Nothing
author: Pratik
date: 2026-04-14 15:10:00 +0100
categories: [Case Study, Citrix]
tags: [Case Study, Citrix]
image:
  path: https://github.com/user-attachments/assets/0908123d-f8be-4e2f-aa60-3e6f6abbc170
render_with_liquid: false
---

Cognisys was presented with a challenge: A locked-down Citrix environment. After logging into the machine, Cognisys was dropped onto a standard Windows desktop, but with significant restrictions. The goal was simple: Open the Command Prompt. The result? A flat denial. Similarly, attempting to launch PowerShell yielded the same result, the application was blocked. Cognisys was tasked with determining whether command execution was still possible in an environment where Cmd.exe and PowerShell.exe were explicitly restricted.  
  
This blog explains the approach taken for this challenge and ultimately how Cognisys outmaneuvered the restricted desktop by turning its own trusted components against it, bypassing every user‑mode control to gain full, unfettered access to a PowerShell instance.

## The Initial Restriction: An Illusion of Security

Upon logging in to the provided Citrix environment, Cognisys was greeted with a heavily restricted desktop. Access to system binaries, the command prompt, and even PowerShell was blocked. Application whitelisting was in place, and web filtering prevented the downloading of unauthorised tools. On the surface, it appeared to be a textbook example of a locked-down workspace.  
  
The goal of such an environment is to provide just enough access for a role such as a system administrator, help desk technician, or IT support staff while preventing any exploration of the wider network.

## The First Cracks: The Power of a .bat File

Cognisys's initial reconnaissance focused on what was allowed. The file system permissions were tested, and it was discovered that although many executables were blocked, it was still possible to roam the C:\ drive. The key finding was that the file extension filters were not comprehensive.

Despite the restrictions, the environment allowed executing files with the  `.bat` extension. This is a fundamental, and surprisingly common, oversight. While `.exe` files may be locked down, batch files are often overlooked as "legacy" or "administrative" tools. This provided the initial foothold.

Using a simple batch file, Cognisys could run ad hoc commands and pipe the output to a text file for review. This allowed the team to begin enumerating the local system and the domain, gathering valuable intelligence about their position within the network.

<img width="1888" height="1190" alt="Pasted image 20260324132753" src="https://github.com/user-attachments/assets/99eba8b5-9d05-49c2-87ee-3ff31d99c3aa" />

This initial step confirmed that while interactive access was limited, the underlying command engine was still very much alive. It proved that commands could run, and the next step was to upgrade and open a fully interactive terminal.

## The Breakout: Abusing Trusted System Components

With the ability to execute batch files confirmed, the next logical step was to escalate the available interactive capabilities. The objective was not to find a novel exploit, but to determine if the system's own trusted components could be chained together to circumvent the blocking policies. Specifically, Cognisys aimed to invoke a full PowerShell environment, the very utility the restrictions were designed to conceal.

The approach was based on the principle that application whitelisting may block direct execution of binaries like `PowerShell.exe`, but can still be bypassed through indirect execution using scripting hosts. Windows includes several native executables designed to run scripts, such as `wscript.exe`, which are generally trusted by the operating system and by extension poorly configured security software.

Cognisys's approach was to create a lightweight, two-stage process. First, a batch file was used to dynamically generate a VBScript in the user's temporary directory. This script contained a single instruction to create an instance of the Windows Shell object and use it to launch PowerShell. Once the script was written to disk, the same batch file called `wscript.exe`, the legitimate Windows Script Host, was used to execute it.

```
@echo off
echo Set objShell = CreateObject("WScript.Shell") > %temp%\shell.vbs
echo objShell.Run "powershell.exe -NoExit", 1, False >> %temp%\shell.vbs
wscript.exe %temp%\shell.vbs
```

To better understand the system's behaviour and confirm the bypass, Cognisys needed a way to inspect running processes and their relationships. However, the environment imposed strict internet restrictions. Access to websites such as YouTube and gambling platforms was restricted, and direct downloads of executable (.exe) files were blocked. Surprisingly, downloading a zip archive remained permitted. Cognisys leveraged this gap by downloading a tool called Process Hacker, a powerful process analysis tool packaged as a zip file, extracting it locally, and running the portable executable without installation.

<img width="1600" height="366" alt="Pasted image 20260324132813" src="https://github.com/user-attachments/assets/280027ec-9705-4df4-9ea2-4079f2d13bce" />


This technique succeeded because the security policy was configured to block the _target_ (`powershell.exe`) but not the _method_ (spawning it as a child process of `wscript.exe`). By using `wscript.exe` as a trusted proxy, the request to start PowerShell originated from an allowed process, bypassing the static block on the executable itself. The result was a fully interactive PowerShell console, effectively rendering the desktop restrictions obsolete once the `.bat` file was executed. The environment had failed to recognise that blocking a binary is ineffective if its execution can be brokered by a trusted system component.

<img width="996" height="504" alt="Pasted image 20260324132839" src="https://github.com/user-attachments/assets/5bf3cc3b-cd74-4294-9404-b704bf769674" />

## The Fallout: Why This Matters

This breakout is significant for several reasons. It demonstrates that user-level restrictions are not a "set and forget" solution. An authenticated user, even with low privileges, can leverage seemingly benign tools like batch files and VBScript to circumvent poorly implemented policies.

From this PowerShell terminal, a threat actor could:

- Run advanced reconnaissance tools like PowerView.

- Dump credentials from memory if the administrator role is achieved.

- Move laterally across the network.

- Install persistent backdoors.

- Ultimately, escalate privileges and compromise the entire domain.

The environment's security was not defeated by a zero-day exploit, but by a simple script and a failure to apply the principle of least functionality to all file types and scripting engines.
## Recommendations: Building a Robust Defence

To prevent this class of breakout, organisations must move beyond blocking just the most obvious executables. A defence-in-depth approach is required, with a focus on application whitelisting.

1. **Implement Default-Deny Application Whitelisting:** Instead of blocking a list of "bad" applications, adopt a model where only explicitly approved applications are allowed to run. This includes controlling the execution of scripting engines like `wscript.exe`, `cscript.exe`, and `mshta.exe`. If a user has no business need to run a VBScript, it should be blocked.

2. **Harden Windows Configurations:** Adhere to industry-standard security baselines, such as the CIS Benchmarks for Microsoft Windows Desktop. These benchmarks provide detailed, prescriptive guidance on disabling unnecessary features, restricting PowerShell in constrained language mode, and enforcing strong access controls.

3. **Understand Your Attack Surface:** Every allowed application and script host increases the attack surface. The client in this engagement allowed a `.bat` file without a clear business requirement. A thorough audit of what is permitted and why is crucial.
## Conclusion

This Citrix breakout underscores a fundamental truth that configuration is security. The platform provided the tools to build a secure space, but the policies failed to lock the door. By chaining a permitted file extension with a trusted system binary, Cognisys dismantled the entire security model. For defenders, the lesson is clear if a perimeter can be bypassed with a simple VBScript, it was never a perimeter at all.
# References:

- https://www.cisecurity.org/benchmark/microsoft_windows_desktop
- https://web.archive.org/web/20160324163123/https:/www.nsa.gov/ia/_files/os/win2k/application_whitelisting_using_srp.pdf
- https://attack.mitre.org/techniques/T1059/005/
