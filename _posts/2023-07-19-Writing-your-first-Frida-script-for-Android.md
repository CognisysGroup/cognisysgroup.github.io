---
title: Writing your first Frida script for Android
author: Rajveer
date: 2023-07-19 9:45:00 +0100
categories: [Android Pentesting, Frida]
tags: [mobile application pentest, android, frida, pentesting, root detection, reverse engineering]
image:
  path: https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/1defdfc7-fc6b-446b-a3c2-b0ae3578a14e
  alt: 
render_with_liquid: false
---

## Overview

Hi everyone, I wish you all are doing amazing. My name is Rajveersinh Parmar and I'm an Application Security Consultant at [Cognisys](https://cognisys.co.uk/), specialised in Web, Mobile and API Pentesting. In this blog, I aim to make you aware of using Frida and guide you in writing your first Frida script for Android. 

We will focus on using Frida for bypassing restrictions within an Android application. You can follow along with this blog if you're a complete beginner or someone who has used pre-built Frida scripts but want to learn about creating their own scripts. I'll give you walk through for the topics mentioned below.

- What is Frida?
- How does Frida work?
- Setting up Frida
- Installing and decompiling the application
- Analysing the code to identify the key functions
- Frida script writing to bypass restrictions
- Conclusion
- References

## What is Frida?

Starting with the basic question, what is Frida? According to their official website, Frida is a "dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers". Basically, it allows you to hook and inject your own scripts into processes running on the system.

It means you can overwrite the application's code runtime. For example, if an application is relying upon a function which checks whether you're an admin user or not, and depending upon the result, it returns true or false. Since you can modify the code runtime, you can make the function return true every time making the application believe you are the admin user. Similarly, you can bypass lots of such restrictions using Frida and Frida Scripts. Here, you'll get an idea of how you can write your own Frida scripts to do the same. But before proceeding further, let's have a look at the basics.

## How Frida Works?

If you're coming from an old-school hacker background, you would be aware of Metasploit, so you can assume it's similar to installing your MSF payload on the Android and commanding it to perform certain tasks and return certain data. Even if you're not aware of any of this, you can assume it is like installing our agent into the operating system with root-level privileges and communicating to it back and forth to hook any process and modify the behaviour of the code. It will start making more sense as we go further and start playing with it.

## Setting up Frida

#### 1. Host Machine

Frida supports all the major operating systems including Windows, Linux and MacOS. The only prerequisite you need is having python3 installed on your system. You can install Frida by running `pip install frida-tools`, and to verify the installation, you can use `frida --version` or `frida-ps` command. If you get the successful output of the above command, Frida is all set on your host machine. Now it's time to install it on the Android device.

#### 2. Android

You need to have a rooted Android device or emulator, most of the emulators provide root privileges. For Windows and Linux, you can use Genymotion and for MacOS, I would suggest using Android Studio's emulators. I personally prefer using emulators for pentesting as you can change its configuration anytime if the application is not working correctly, this can be considered an advantage of using emulators. There were rare scenarios where I had to use a physical device to test the applications. Moving ahead, you would also need to have ADB set up on your host machine. If Android Studio is installed on your system, then SDK tools including ADB would be already there in its defined directory. If that's not the case then you can download and setup ADB from [here.](https://developer.android.com/tools/adb)

Once your device is connected with ADB, you would need to know the architecture type of your device in order to download the Frida Server, it is another half of Frida which you will install on the Android. To identify the architecture type, use `adb shell getprop ro.product.cpu.abi` command:

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/faddd03f-4f05-4eb2-ad15-659ecf9bed01)

Look for `frida-server-{version}-android-{architecture}` in the [releases](https://github.com/frida/frida/releases) section of the Frida GitHub repository and download the corresponding Frida Server with the latest version. Unzip the downloaded archive and push the Frida Server to the device. For that, use the command `adb push <Firda-Server> /data/local/tmp`. By doing this, it will move the Firda Server to `/data/local/tmp` directory of the Android device.

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/57502600-642e-40bd-8519-177bb75479e1)

Further you need to modify the Frida-Server permissions to run it. To do so, follow the below commands:

1. `adb root`
2. `adb shell`
3. `chmod +x /data/local/tmp/<Frida-Server>`
4. `./data/local/tmp/<Frida-Server>`

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/0ec84891-aacc-450f-ba6d-ba9af237ed00)

To verify Frida-server is running correctly on Android, open a new terminal and enter `frida-ps -Uai` command. It will list the installed applications along with their package names on the Android device.

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/709c71b5-7761-4e7a-b2cb-0ee2ccddcb41)

With this confirmation, the setup is done. For further demonstration, I've developed a vulnerable application [FridaMe](https://github.com/CognisysGroup/FridaMe). You can download the APK from the releases section of the GitHub repository.  

## Installing and decompiling the application

To install the application, you can either drag and drop the APK into the emulator or can use the command `adb install <application_name>.apk` Let's have a look at the installed application.

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/4c8f9837-6e1d-4b2b-834e-a380d0eaf748)

As seen above, there are two functionalities, but both of them are inaccessible due to the restrictions.

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/8d2c07fd-bc92-4bd9-b1de-e0bf8d1e41b2)

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/21dc8c3c-4ef7-4d17-bec6-b7c2208b1e95)

Let's decompile the APK and have a look at its code to write a Frida script in order to bypass these restrictions.

#### Decompiling the APK

There is a traditional way to decompile the APK and reach its source code where you extract the APK using [Apktool](https://github.com/iBotPeaches/Apktool) then use [dex2jar](https://github.com/pxb1988/dex2jar) to convert `classes.dex` to `classes.jar` and lastly use [jd-gui](https://github.com/java-decompiler/jd-gui) to view the java class files. But there are some tools such as [jadx-gui](https://github.com/skylot/jadx), [JEB]( https://www.pnfsoftware.com/), etc. which automate this process and provide additional features such as bytecode viewer, deobfuscator, debugger, etc. Here, we will use Jadx-gui to decompile the application. Open the Jadx-gui and drag & drop the APK into it. It will take a little time and you would be presented with this screen.

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/6b8e09c7-43bc-4696-ae9f-d06d43a787d5)

## Analysing the code to identify the key functions

#### What to look into the source code?

`Androidmanifest.xml` contains the blueprint of the Android application. You can always start analysing the source code from here. It can be found under the Resources directory. Here, we want to find the code responsible for those restrictions and for that, we need to start analysing the code from `MainActivity` as it's the first activity rendered by the application. You can identify the `MainAcitvity` by confirming the `MAIN` and `LAUNCHER` intent filter within it. 

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/15840906-d36c-482e-bf5e-16f0b702449f)

Since we got the path of the `MainActivity` which is `group.cognisys.fridame.MainActivity`, we can expand the directory structure and open the `MainActivity`.

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/caf4edb9-8605-4f4a-8a63-2cc25221a21c)

The initial logic for checking the user privilege is written inside the `onClick()` listener of the `adminButton`. If we look closer, there is an `if` condition initiating a call to `isAdmin()`.

`isAdmin()` is defined in the same activity and it is a boolean function meaning it can either return `true` or `false`. As seen in the code, it just returns the value of the `isAdmin` variable, and the assigned value of the `isAdmin` variable is `false`, therefore `isAdmin()` will always return `false` in this case. To satisfy the initial `if` condition, we would need to make `isAdmin()` return `true` so it can take us to the `AdminArea` activity or else it will just result in an error `"Only admin can access this area"`.

## Writing a Frida script

Let's start writing a Frida script to bypass this restriction. Frida provides [JavaScript API](https://frida.re/docs/javascript-api/) to write our own code which can be further used to hook the process and to analyse and manipulate the actual code. Writing a Frida script for this scenario is easy since we only need to provide a reference of the `MainActivity` in order to change the implementation of the `isAdmin()` to return `true`. Open your favourite code editor, paste the below script and save it with the `.js` extension.

```javascript
Java.perform(() => {
  const MainActivity = Java.use('group.cognisys.fridame.MainActivity');
  MainActivity.isAdmin.implementation = function () {
    console.log("Hooking isAdmin Method...");
    return true;
  };
});
```

`Java.perform()` is a callback function provided by Frida's JavaScript API. It ensures that our script is executed in the context of the target application once all the Java classes have been loaded.

Then we have defined a constant variable named `MainAcitivity` assigning `Java.use()` to it. `Java.use()` is also provided by Frida's JavaScript API, it takes a parameter as a reference of the `MainActivity` class within the target application. It allows you to access and modify the properties and methods of the `MainActivity` class.

In the next line, we have changed the implementation of the `isAdmin()` with our own function which will overwrite the actual code runtime. `Console.log()` is just there to print a message on our terminal to confirm we have successfully hooked the `isAdmin()`. At the last, we have made our function return `true` in order to satisfy the initial `if` condition so it can lead us to the `AdminArea` activity.

Let's run and test our script against the application. Make sure the Frida server on Android is up and running. Use the command `frida -U -l yourscript.js -f group.cognisys.fridame` to attach the script with the vulnerable application. The `-l` flag is used to provide the Frida script and the `-f` flag accepts the package name of the application.

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/220953f6-9df4-4a0d-a2f0-1f05c9bb4a4e)

This will start the application with our Frida script attached to it. If you click the `ADMIN AREA` button, you would be able to bypass the restriction and access `AdminArea` activity as seen below.

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/d604489d-9da6-4423-b699-2abe6009ddbf)

Now, let's try to bypass root detection. For that, we would need to identify the code responsible for detecting root access. We can again start with the `MainActivity` as the `USER LOGIN `button is defined within it.

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/153b8ec5-eafb-4e25-9cca-4914bc5a3707)

The above code is responsible for root detection check. Let's understand the flow. There is an `onclick()` listener for the `userLogin` button which calls `Utils.isDeviceRooted()` method and stores its value in the `status` variable. Then there is an `if` condition which compares the values of the `status` variable with `"Device is safe."`. If the condition satisfies then it will take us to another activity or else it will display the error `"Device is rooted, can't proceed further!"`.

Let's look at the implementation of `Utils.isDeviceRooted()` method. Double-click on a method to open its definition. Jadx-gui will open its class in a new tab.

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/68cb3b0e-9af2-497c-9c44-c0efff9e4b50)

As seen above, there is an `isDeviceRooted()` method within the `Utils` class which returns a string. Here, the [RootBeer](https://github.com/scottyab/rootbeer) library is used to detect root access on Android. The `isRooted` variable stores the value of RootBeer's `rootBeer.isRooted()` method which returns `true` or `false` depending upon whether the device is rooted or not. And lastly, there is an `if` condition which checks the value of the `isRooted` variable and returns a string accordingly.

To bypass this check, we would need to change the implementation of the `isDeviceRooted()` method to always return `"Device is safe."` string so the initial `if` condition in `MainAcitivity` gets satisfied and let us access the `UserLogin` activity. You can append the below code snippet within your existing Frida script.

```javascript
const Utils = Java.use('group.cognisys.fridame.Utils');
Utils.isDeviceRooted.implementation = function () {
  console.log("Hooking isDeviceRooted Method...");
  return "Device is safe.";
};
```

Here, we have just passed the reference of the `Utils` class to `Java.use()` function. Then we changed the implementation of `isDeviceRooted()` to return the expected string and console log the message. So our final script would look like below.

```javascript
Java.perform(() => {
  const MainActivity = Java.use('group.cognisys.fridame.MainActivity');
  MainActivity.isAdmin.implementation = function () {
    console.log("Hooking isAdmin Method...");
    return true;
  };

  const Utils = Java.use('group.cognisys.fridame.Utils');
  Utils.isDeviceRooted.implementation = function () {
    console.log("Hooking isDeviceRooted Method...");
    return "Device is safe.";
  };
});
```

Let's run it against the application. Use the same command as above to run the application by attaching the script. You can click on the `USER LOGIN` button to confirm the bypass for the root detection, as seen below.

![image](https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/65b41355-190b-4720-9691-9192715b1f19)

## Conclusion 

In this blog, we have explored the capabilities of Frida, a really powerful tool allowing us to analyse and manipulate the code runtime. It is important to note that Frida should always be used responsibly and ethically, adhering to applicable laws and regulations. Additionally, we have learned about the easiest way to decompile the APK and look into the source code to identify key logic functions. Lastly, most importantly we've learned about writing a Frida script to bypass the restrictions. Since now you know, writing a Frida script is easy, you can explore and dive deep into it to bypass complex restrictions and scenarios. I wish you all the best :). I will create the next part of this blog, where we will bypass more complex restrictions in complex scenarios.

Thank you for taking the time to read this blog. If you have any queries, ideas of complex scenarios to share or just feedback, please feel free to reach out to me on [Twitter](https://twitter.com/R4JVE3R).

## References

- [https://developer.android.com/tools/adb](https://developer.android.com/tools/adb)
- [https://frida.re/docs/android/](https://frida.re/docs/android/)
- [https://github.com/skylot/jadx](https://github.com/skylot/jadx)
- [https://developer.android.com/guide/topics/manifest/manifest-intro](https://developer.android.com/guide/topics/manifest/manifest-intro)
- [https://frida.re/docs/javascript-api/](https://frida.re/docs/javascript-api/)
