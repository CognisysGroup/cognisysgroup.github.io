---
title: How to Decompile a Hermes React Native Binary (Android Pentest)
author: Punit
date: 2024-05-22 04:04:00 +0100
categories: [Android Pentesting, Application Security]
tags: [Android Pentesting, Application Security]
image:
  path: https://github.com/CognisysGroup/cognisysgroup.github.io/assets/46415431/784fcc49-109c-41a5-99f8-9d0835acfde8
  alt: 
render_with_liquid: false
---

## Overview

At Cognisys, our days are filled with uncovering the intricacies of various applications, but some projects stand out due to their complexity and the insights they provide. Recently, we tackled an Android React Native application using the Hermes JavaScript engine, which presented unique challenges and learning opportunities.

Today, we will walk through the detailed process of decompiling a React Native application, focusing on using Hermes-dec to handle Hermes bytecode. This guide is aimed at security researchers eager to delve deep into mobile application internals, uncover potential vulnerabilities, and enhance their penetration testing skills.

## Understanding React Native and Hermes

React Native is a widely used framework for building mobile applications using JavaScript. To optimise performance, many developers choose Hermes, a JavaScript engine designed to improve startup times and runtime efficiency of React Native apps.
### Why do Devs Use Hermes?

Hermes offers several key benefits:

* **Improved Startup Time**: By precompiling JavaScript to bytecode, Hermes reduces the time for an app to start.
* **Reduced Memory Usage**: Hermes is optimised to use memory efficiently, which is crucial for mobile devices.
* **Smaller App Size**: Hermes applications can be smaller, as the engine is designed to be lightweight.
* **Better Performance**: Hermes enhances the runtime performance of JavaScript code, making applications more responsive.

For more details, check out the [official React Native documentation on Hermes](https://reactnative.dev/docs/hermes).

## Step-by-Step Guide to Decompiling an Android React Native Application
#### Step 1: Extract the APK

 **Extract the APK**: If you don't already have the APK file, extract it from your device using adb:

```bash
$ adb shell pm list packages
$ adb shell pm path com.example.app 
$ adb pull /path/to/your.apk
```
#### Step 2: Decompile the APK

 **Decompile the APK**: Use APKTool to convert the APK into readable resources and smali code:

```bash
$ apktool d your.apk -o decompiled_folder
```
   
This command generates a `decompiled_folder` containing the resources and smali files.

#### Step 3: Extract the Binary Bundle

 **Locate the Binary Bundle**: Navigate to the `assets` directory within the decompiled APK folder. Look for `index.android.bundle`. In most cases, you'll find a JavaScript instead of a bytecode, which is great for testing purposes, but if you find a bytecode ready for the adventure to reverse engineer the binary to get the pseudocode in JavaScript. In this case it was binary as seen below:

![Pasted image 20240522130047](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/46415431/2551e214-ee6a-4dd0-9f4c-258e53708223)

#### Step 4: Detecting Hermes in a React Native Application

To determine if an app uses Hermes, you can perform the following steps:

*  **Inspect the APK Contents**: After decompiling the APK with APKTool, navigate to the `assets` directory and look for Hermes-specific files, such as `index.android.hermes` or `index.android.bundle`.

* **File Inspection**: Use the `file` command to inspect the JavaScript bundle:

```bash
$ file index.android.bundle
index.android.bundle: Hermes JavaScript bytecode, version 94
```
   
   If the output indicates `Hermes JavaScript bytecode, version 94`, it confirms the use of Hermes. 
##### Why Does the Version Matter?

The version number (e.g., version 94) is crucial because it signifies the specific version of the Hermes engine used to compile the bytecode. Each version of Hermes might have different features, optimisations, or bug fixes. Knowing the version can help in:

- **Choosing the Right Tools**: Some decompilation tools, like `hermes-dec` by [@P1sec](https://github.com/P1sec/hermes-dec), must support specific Hermes versions to decompile the bytecode correctly. This tool might not support older versions, but for example, `hbctool` by [@bongtrop ](https://github.com/bongtrop/hbctool) supports versions 59, 62, 74, and 76.
- **Understanding Bytecode Changes**: Different versions of Hermes can introduce changes in the bytecode format, which can affect how you analyse and interpret the decompiled code.

#### Step 5: Install Hermes decompile tool

4. **Decompile Hermes Bytecode**: Use `hermes-dec` to convert the Hermes bytecode back to JavaScript. Let's first set the `hermes-dec`

```bash
$ git clone git@github.com:P1sec/hermes-dec.git
$ cd hermes-dec/
$ python3 setup.py install
```

#### Step 6: Try to Disassemble and Decompile the Hermes Binary 

5. While decompiling React Native applications typically involves extracting and analysing JavaScript code, applications using the Hermes engine require an additional step to handle the Hermes bytecode. Here's how you can disassemble and decompile the Hermes bytecode using **hermes-dec**:

```bash
$ python3 hbc_disassembler.py ../index.android.bundle disassemreact 
[+] Disassembly output wrote to "disassemreact"
```

   6. Lets Decompile and get the pseudocode 
  
```bash
$ hbc_decompiler.py ../index.android.bundle decompiledreact
[+] Decompiled output wrote to "decompiledreact"
```

![Pasted image 20240522130655](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/46415431/a0d674db-623e-403c-8a46-3b218efdaa21)


For further deobfuscation, use tools like JavaScript Deobfuscator if your JavaScript code is still obfuscated and not easily readable. https://github.com/ben-sb/obfuscator-io-deobfuscator

## Conclusion:

Decompiling an Android React Native application using the Hermes engine involves detailed and technically challenging steps. By leveraging tools such as `adb`, `APKTool`, `hermes-dec`, and Deobfuscation tools, security researchers can gain deep insights into the app's structure and functionality, aiding in vulnerability discovery and security assessments.
