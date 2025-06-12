---
title: Combining Indirect Dynamic Syscalls and API Hashing
author: saad_ahla
date: 2023-07-13 11:40:00 +0800
categories: [Blogging, Tutorial]
tags: [red team]
image:
  path: https://github.com/CognisysGroup/cognisysgroup.github.io/assets/25560539/3ad69455-f694-4a9c-a186-59100dd51868
  alt: 
render_with_liquid: false
---


# Overview

This blog will talk about in depth analysis and implementation of :

- API hashing, how to resolve module's base address and API's base address from `PEB` using C & WinDbg.
- Indirect Dynamic Syscall, by resolving the SSN and the address pointing to a backed syscall instruction dynamically.

**The code** for this article is part of a Shellcode Loader implementing Indirect Dynamic Syscall & API Hashing and Fileless Shellcode using WinSock2 can be found on this **[Github](https://github.com/CognisysGroup/HadesLdr)** Repository.

The author of this blog post is [Saad Ahla](https://www.linkedin.com/in/saad-ahla/), known as [@D1rkMtr](https://twitter.com/D1rkMtr), and he is passionate about Purple Team tooling.

# x64 calling convention

We will explore an essential aspect of function handling in programming languages: function arguments and return values. When calling a function, the initial four arguments are typically passed via registers, while any additional arguments are arranged on the stack. 

The specific registers used for the initial arguments depend on their position and type. Arguments in the leftmost four positions are passed in left-to-right order, utilising `RCX`, `RDX`, `R8`, and `R9`, respectively. For the fifth argument and beyond, they are placed on the stack as previously described. 

Finally, the return value of a function is stored in the `RAX` register. Understanding these principles is crucial for effectively working with function parameters and return values in programming. 

Let’s take a classic example, a process that allocates one page of memory within the main function :
```c

#include <Windows.h>
#include <stdio.h>

int main() {

	// MEM_COMMIT | MEM_RESERVE = 0x00003000
	// PAGE_EXECUTE_READWRITE = 0x40

	LPVOID mem = VirtualAlloc(NULL, 0x1000, 0x00003000, 0x40);
	if (!mem) {
		printf("[-] Failed in allocating memory (%u)\n", GetLastError());
		return -1;
	}
	printf("[+] Memory Allocated Successfully %p\n", mem);
	getchar();

	return 0;
}


```

We will use the [x64dbg](https://x64dbg.com/) debugger created by [Duncan Ogilvie](https://twitter.com/mrexodia), run the executable under x64dbg debugger and put a breakpoint on `VirtualAlloc` using `bp VirtuaAlloc` . Upon successful execution of the binary, we will hit the breakpoint as seen:

![callingx64](https://github.com/CognisysGroup/HadesLdr/assets/123980007/52ec800d-0c68-4b7d-8ff8-da9c0c3fc23f)

We can see the calling convention in action in x64 process, the 1st [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) argument which is NULL or 0 gets passed to `RCX` , the 2nd argument which is NULL or 0 gets passed to `RDX`, the 3rd argument which is 0x3000 gets passed to `R8` and the 4th argument which is 0x40 get passed to `R9` .

Let's step into `VirtualAlloc` `jmp` instruction. And to get the return address stored in `rax` , Let's step over all the instructions until we get into the `ret` instruction inside `VirtualAlloc` :


![retrax](https://github.com/CognisysGroup/HadesLdr/assets/123980007/a2a72adf-a0f4-480c-aae6-dda0c3be811d)


And we hit the `ret` instruction, and we can see the allocated memory stored in `RAX`. To confirm this, let's click on run to continue the process execution flow, and if will hit `getchar()` . It will print the allocated memory, and we can compare it with the value we got from `RAX` :

![virtualAllocRet](https://github.com/CognisysGroup/HadesLdr/assets/123980007/4a4c423e-1aa4-4ba7-a5de-416e7fe5d7e6)


We can see it's the same, and the return value of an API is in fact stored in `RAX`.

After understanding the x64 calling convention, let's dig deeper into the System Call, and how `VirtualAlloc` & `Zw/NtAllocateVirtualMemory` behave like wrappers that prepare the arguments for the syscall.

# System Calls

Software programs need to carry out a range of tasks beyond simple calculations, like memory allocating, process creating, and thread creating. These tasks, at their core, can only be enacted by code operating in a kernel mode. Thus, the query arises: how can code functioning in user mode carry out these kinds of tasks?

Talking about the last main function, the documented Windows API [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) is called, which is implemented in `kernel32.dll`, it's one of the Windows subsystem DLLs, we can confirm that by looking at the IAT (Import Address Table) for our binary to see the functions imported by `kernel32.dll` module, and we can see in fact `VirtualAlloc` is present :

![virtualAlloc](https://github.com/CognisysGroup/HadesLdr/assets/123980007/3ab2c067-b2b0-491c-9023-3bab13fa8662)


Or by checking the EAT (Export Address Table) of `Kernel32.dll` using x64dbg :

![EATkernel32](https://github.com/CognisysGroup/HadesLdr/assets/123980007/a5da4ec4-406b-428d-8661-362a27b3913c)


This function is running in user mode, and it's actually a wrapper that prepares the arguments to another undocumented Native API called `NtAllocateVirtualMemory` or `ZwAllocateVirtualMemory` it is, in fact, the lowest layer of code which is still in user mode which is implemented in `ntdll.dll`. We can confirm this by looking at the EAT (Export Address Table) of `ntdll.dll` using x64dbg :

![EATntdll](https://github.com/CognisysGroup/HadesLdr/assets/123980007/409c85bd-a15a-4ff0-8ad5-89b9934f5910)


this function is also running on user mode, and it's also a wrapper that prepares the arguments to the `syscall`, and that we can both dispense with.

Let's use  [x64dbg](https://x64dbg.com/) again and put a breakpoint on `VirtualAlloc` using `bp VirtuaAlloc`, and click run to hit the breakpoint :

![virtualAllocBP](https://github.com/CognisysGroup/HadesLdr/assets/123980007/52039f3b-f2b5-43a6-8f32-76b06db82c8f)


Let's step into the `jmp` to get into the `VirtualAlloc` code, we can see inside that `VirtualAlloc` is doing some error check , then prepare the arguments for `ZwAllocateVirtualMemory` to be called after , it's on address `0x7FFEA79A4261` :

![VirtualAllocCode](https://github.com/CognisysGroup/HadesLdr/assets/123980007/755a1aca-290e-4dd2-87de-5ca0d45b275a)


So the conclusion here is that `VirtualAlloc` doesn't allocate memory but prepare the argument for `ZwAllocateVirtualMemory`.
Let's step over until we get into `ZwAllocateVirtualMemory` calling instruction, then step into to take a look at the code for `ZwAllocateVirtualMemory` :

![ZwAllocateVirtualMemory](https://github.com/CognisysGroup/HadesLdr/assets/123980007/6238aac0-4afa-4948-bdfe-82d795d3a3bb)


This (officially undocumented) API is the one that makes the transition to kernel mode.
Before the actual transition, a value known as the `System Service Number` (`SSN`) or `Syscall Number` is loaded into a CPU register `EAX` . Each Native API has its unique `SSN`, and it can be differ from windows version to another, you can take a look at `SSNs` for different versions [here](https://j00ru.vexillium.org/syscalls/nt/64/) reversed by [@j00ru](https://twitter.com/j00ru?lang=en). Following this, a specific CPU instruction is executed `syscall`, which facilitates the transition to kernel mode. Simultaneously, the processor jumps to a predetermined routine known as the system service dispatcher.

Subsequently, the system service dispatcher utilises the value stored in the EAX register as an index within a `System Service Dispatch Table (SSDT)`. By leveraging this table, the code performs a jump to access the actual system service (system call). In the case of our previous process, the entry in the `SSDT` would point to the I/O manager’s `Zw/NtAllocateVirtualMemory` function. It is worth noting that this function shares the same name and arguments as the one found in `ntdll.dll`. Once the system service is complete, the thread returns to user mode and proceeds to execute the instruction immediately following the `syscall`.

![systemService](https://github.com/CognisysGroup/HadesLdr/assets/123980007/d5216352-3795-42b3-8668-8f849f40fe31)


So the conclusion is that we can dispense with WIN API and Native API and create our own syscall stub that simulates a Native API Execution and that does the transition to kernel mode through the `syscall`, which will allow us to bypass User land EDR Hooks.
And the syscall stub will look like this :

![syscallStub](https://github.com/CognisysGroup/HadesLdr/assets/123980007/a5e35b0a-daae-426a-958c-c981f951d22f)


We will be using this stub later in the `Indirect Dynamic Syscalls` part, so before seeing we need to retrieve dynamically the `SSN` and jump to an address containing the `syscall` instruction inside `ntdll.dll` so that the `syscall` should be done from a legit module, otherwise, it would be suspicious.

Before digging deeper into that, we need to retrieve the `Native APIs` addresses and the `ntdll.dll` address, the good way to do this is by getting them from the `Process Environment Block (PEB)` of the current process and not rely on `LdrGetDllHandle` and `LdrGetProcedureAddress` in `ntdll.dll` or `GetModuleHandle` and `GetProcAddress` in `kernel32.dll` as it will be shown on the `Import Address Table (IAT)` of the current process, and it could also be monitored by the EDR Hooks.

Below we see the `Import Address Table (IAT)` of our binary that uses `GetModuleHandleA` and `GetProcAddress` to retrieve the address of `NtAllocateVirtualMemory` :

![GetModuleHandleA](https://github.com/CognisysGroup/HadesLdr/assets/123980007/e60d3272-ccea-433b-b146-6f6cb28b98bc)


# API Hashing

## Retrieving Module's Base Address

We are using this hash algorithm for hashing our strings that will be compared later with Module names or API names :

- A variable named `hash` is initialised with the value `0x99`.
- A loop is executed for each character in the `data` string, it obtains its ASCII value using the `ord` function, and it is added to the `hash` variable. Additionally, the `hash` value is left-shifted by 1 and then added to itself.
- After the loop completes, the final value of the `hash` is printed.

```python
import sys

def myHash(data):
    hash = 0x99
    for i in range(0, len(data)):
        hash += ord(data[i]) + (hash << 1)
    print (hash)
    return hash

myHash(sys.argv[1])
```

Using this script, we will calculate the hashes for the `Module name` and `Symbol (API) name`, and it will be compared later with the `Module name` and the `API name` we're looking for, starting from the `PEB`. Now let's just focus on retrieving `Module base addresses` and `API base addresses` from the `PEB` using [Windbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/) .

the `PEB` (Process Environment Block - one of the system structures that is created by the Operating System at process runtime).

In a 64-bit process, the `Process Environment Block (PEB)` is located at an offset of 0x60 from the `Thread Environment Block (TEB)`. The `TEB` is a structure that holds information specific to the currently executing thread. this `TEB` structure is pointed by the `GS segment` register.

So the PEB address is located at GS:\[0x60\].

Let's see in depth how we could resolve a module's base address using windbg, let's run cmd under windbg.

By executing the command "_**lm**_", the system will output a list of all the loaded modules within the process.

![lm](https://github.com/CognisysGroup/HadesLdr/assets/123980007/0355d70a-d0e0-4a80-bdab-262466df8113)


Upon examining the loaded modules in the process, it is evident that both `ntdll.dll` and `kernel32.dll` are automatically loaded into the process memory. The base address of `ntdll.dll` is `0x7ff9e3190000`, while the base address of `kernel32.dll` is `0x7ff9e2490000`.

To examine the `TEB (Thread Environment Block)` structure and its attributes at its current address, you can use the "**dt**" command.

![teb](https://github.com/CognisysGroup/HadesLdr/assets/123980007/bc90df4b-fb9d-4861-b4ac-283d3a9f94d8)


From the information provided, it is observed that the `PEB (Process Environment Block)` structure is positioned at an offset of 0x60 from the `TEB (Thread Environment Block)` structure. The specific address of the `PEB` structure is stated as `0xf0f51b8000`.

Now let's take a look at the `PEB` structure and discover some of its internals :

![peb](https://github.com/CognisysGroup/HadesLdr/assets/123980007/7e4daa87-b04a-4a66-bdcd-5a30fea5c7e5)


Let's focus our attention on the `PEB_LDR_DATA` structure located at an offset of 0x18 within the `PEB` , let's check its attributes :

![ldr](https://github.com/CognisysGroup/HadesLdr/assets/123980007/128362f8-b243-46c7-a365-61abc78e0df7)


![list_entry](https://github.com/CognisysGroup/HadesLdr/assets/123980007/ffde6633-e29c-45a7-814f-d836420880d9)


Within this structure, our focus lies on three linked lists of type "_**LIST_ENTRY**_" that share a common purpose: revealing all the loaded modules mapped into the process memory space. These linked lists are as follows:

1. _**InLoadOrderModuleList**_: This linked list consists of pointers to the previous (Blink) and next (Flink) _**LDR_DATA_TABLE_ENTRY**_ in load order. It provides the modules in the order they were loaded into the process.
    
2. _**InMemoryOrderModuleList**_: Similarly, this linked list contains pointers to the previous (Blink) and next (Flink) _**LDR_DATA_TABLE_ENTRY**_ in memory placement order. It represents the modules based on their memory placement within the process.
    
3. _**InInitializationOrderModuleList**_: This linked list maintains pointers to the previous (Blink) and next (Flink) _**LDR_DATA_TABLE_ENTRY**_ in initialization order. It reflects the modules according to their initialization sequence.

Our focus will be on the `InLoadOrderModuleList` structure. To begin, we will examine the `first LDR_DATA_TABLE_ENTRY` associated with the `initial loaded module` located at the memory address `0x274c3c230f0`.

![inLoadOrder](https://github.com/CognisysGroup/HadesLdr/assets/123980007/352bd2f6-a12f-46ab-a108-10c3b50a80b4)


Upon inspecting the structure, we observe that it contains valuable information, such as the `base address of the module` at the specified address and `the module name "cmd.exe"`. Now, let's proceed to examine the next `LDR_DATA_TABLE_ENTRY` in `load order`.

![NextModule](https://github.com/CognisysGroup/HadesLdr/assets/123980007/354919a8-ba97-43f3-be2f-000ab264bfb1)


The next `LDR_DATA_TABLE_ENTRY` `in load order` corresponds to the `"ntdll.dll"`  module, which is located at the address `0x7ff9e3190000`. Now, let's proceed to inspect the `subsequent LDR_DATA_TABLE_ENTRY` in `load order`.

![kernel32Module](https://github.com/CognisysGroup/HadesLdr/assets/123980007/8616b484-67d7-4338-84e4-d705bcbed33b)


The following `LDR_DATA_TABLE_ENTRY` in the `InLoadOrderModuleList` pertains to the `"kernel32.dll" module`, positioned at the address `0x7ff9e2490000`. By utilizing the next entry in the `InLoadOrderModuleList`, we can iterate through all the loaded modules and obtain their respective addresses.

To consolidate our knowledge, we will now implement our understanding in a C language project. In this project, we will redefine the necessary structures, focusing solely on the attributes relevant to our needs.

By leveraging the insights gained earlier, we will construct a C function that will get the hash for the module name as an input and return the base address of this module.

```c
HMODULE RetrieveModuleBaseAddr(DWORD hashInput) {
    HMODULE ModuleBaseAddr;
    INT_PTR PEB = __readgsqword(0x60);
    INT_PTR Ldr = 0x18;
    INT_PTR FlinkOffset = 0x10;

    INT_PTR PEB_LDR_DATA = *(INT_PTR*)(PEB + Ldr);
    INT_PTR FistFlink = *(INT_PTR*)(PEB_LDR_DATA + FlinkOffset); // InLoadOrderModuleList
    LDR_MODULE* LDR_DATA_TABLE_ENTRY = (LDR_MODULE*)FistFlink;
    do {
        LDR_DATA_TABLE_ENTRY = (LDR_MODULE*)LDR_DATA_TABLE_ENTRY->InLoadOrderLinks.Flink;
        if (LDR_DATA_TABLE_ENTRY->DllBase != NULL) {

            if (CalculateModuleHash(LDR_DATA_TABLE_ENTRY) == hashInput) {
                break;
            }
        }
    } while (FistFlink != (INT_PTR)LDR_DATA_TABLE_ENTRY);

    ModuleBaseAddr = (HMODULE)LDR_DATA_TABLE_ENTRY->DllBase;
    return ModuleBaseAddr;
}
```

The `CalculateModuleHash` function calculates a hash value for the module name stored in the `BaseDllName` field of an `LDR_MODULE` structure. It retrieves each character of the module name from the `BaseDllName.Buffer` field and stores them in the `moduleName` character array. The loop continues until it encounters a null-terminator or reaches the maximum size of the `moduleName` array. After ensuring the `moduleName` string is null-terminated, it calls `CalculateHash` function which calculates the hash of a string the same way the previous Python script does, passing `moduleName` after converting it to lowercase using `CharLowerA` function. The resulting hash value is returned.

```c
DWORD CalculateHash(char* inputData) {
    DWORD hashValue = 0x99;
    for (int index = 0; index < strlen(inputData); index++) {
        hashValue += inputData[index] + (hashValue << 1);
    }
    return hashValue;
}


DWORD CalculateModuleHash(LDR_MODULE* moduleLinkList) {
    char moduleName[64];
    size_t index = 0;

    while (moduleLinkList->BaseDllName.Buffer[index] && index < sizeof(moduleName) - 1) {
        moduleName[index] = (char)moduleLinkList->BaseDllName.Buffer[index];
        index++;
    }
    moduleName[index] = 0;
    return CalculateHash((char*)CharLowerA(moduleName));
}
```

And if the hash of the module name corresponding to the current `LDR_DATA_TABLE_ENTRY` equals the submitted module name hash, it will return the base address of that module.

```c
if (CalculateModuleHash(LDR_DATA_TABLE_ENTRY) == hashInput) {
                break;
}
```


## Retrieving API's Base Address

After retrieving the Module's Base Address, let's see in depth how we could resolve an API's base address using windbg.

All we need now is to access the `Export Directory Table` of this module, a data structure known as _**_IMAGE_EXPORT_DIRECTORY**_. This data structure contains vital information about symbols, such as:

- NumberOfFunctions: the total count of exported functions.
- AddressOfFunctions: a Relative Virtual Address (RVA) pointing to the list of exported functions.
- AddressOfNames: a RVA pointing to the list of exported symbol names.
- AddressOfNameOrdinals: a RVA pointing to the list of ordinals.

![imageExDir](https://github.com/CognisysGroup/HadesLdr/assets/123980007/f0069784-cd2e-48e3-bbf3-886cfdf9f513)


Let's parse the `Export Directory Table` of `ntdll.dll` module :

![lm2](https://github.com/CognisysGroup/HadesLdr/assets/123980007/9cb8465c-48bb-4592-a476-ee0f50e00361)


Ntdll is loaded at address `0x7ff9e3190000`, let's go through its `DOS HEADER` :

![DosHeader](https://github.com/CognisysGroup/HadesLdr/assets/123980007/4e250f75-7728-4bd1-baea-331222733b94)


Next, we proceed to examine the NT HEADER. The base address of the NT HEADER can be obtained by adding the base address of the module to the hexadecimal value of "e_lfanew" in the `DOS HEADER`.

![NtHeader](https://github.com/CognisysGroup/HadesLdr/assets/123980007/4efd5008-b6cd-4610-b9c7-c7be5feca7d2)


##### Then we go through the `OPTIONAL HEADER`  at offset 0x18 :

```shell
0:000> dt _IMAGE_OPTIONAL_HEADER64 00007ff9`e3190000+0xe8+0x18
combase!_IMAGE_OPTIONAL_HEADER64
   ...
   +0x068 LoaderFlags      : 0
   +0x06c NumberOfRvaAndSizes : 0x10
   +0x070 DataDirectory    : [16] _IMAGE_DATA_DIRECTORY
```

Located at offset 0x70, there is a pointer pointing to the first [IMAGE_DATA_DIRECTORY](https://learn.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-image_data_directory) structure within the data directory. This structure holds important information about the Export Directory, such as the RVA (Relative Virtual Address) of the Export Directory Table.

![imageDirEntryExport](https://github.com/CognisysGroup/HadesLdr/assets/123980007/5b257bc9-8cf9-46f4-afd4-53f4d923dfe4)


##### At that pointer we can see the RVA of the Export Directory Table , which is 0x1521c0 :

![ImageDataDir](https://github.com/CognisysGroup/HadesLdr/assets/123980007/8015f37b-88c4-411e-9fae-349835a10368)


Subsequently, we can utilize the obtained RVA to access the Export Directory Table within the ntdll module, which was previously mentioned.

![imageExDir](https://github.com/CognisysGroup/HadesLdr/assets/123980007/7dc6644d-b89b-4b91-b0fe-4a4ba3617cc3)


The `AddressOfNames` field contains the `RVA (Relative Virtual Address)` of the function names, which are stored in alphabetical order. To determine the base address of each function name, we add the base address of `ntdll` to the `RVA` of each function name in the `AddressOfNames` array.

![AddressOfNames](https://github.com/CognisysGroup/HadesLdr/assets/123980007/0c9436cf-6af2-4555-9c67-04781fe4c74e)


AddressOfFunctions holds the RVA of the function addresses :

![AddressOfFunctions](https://github.com/CognisysGroup/HadesLdr/assets/123980007/b1277ec2-acdf-4fbf-bcc3-867808a1fb8b)


AddressOfNameOrdinals holds a WORD (16-bit) ordinal

![AddressOfOrdinals](https://github.com/CognisysGroup/HadesLdr/assets/123980007/1538d953-7cd9-45f7-b3f2-21910652ee24)


to calculate the RVA (Relative Virtual Address) of a function, we obtain the value pointed by (Module base address + RVA of AddressOfFunctions) and add the ordinal corresponding to that function multiplied by 4 bytes. The size of 4 bytes is used because it represents the size of an RVA.

To retrieve the Base Address of a symbol based on its name, a search is conducted in the export-names array. If a matching name is found at index 'i', the 'i-th' entry in the export-ordinals array contains the ordinal associated with the function. This ordinal can be used to obtain the function's RVA from the export-functions array. By adding the base address of the DLL module to the RVA, we can convert it into a functional symbol Base Address.

![AddressOfFunctions](https://github.com/CognisysGroup/HadesLdr/assets/123980007/b1277ec2-acdf-4fbf-bcc3-867808a1fb8b)

By leveraging the insights gained earlier, we will construct a C function that will get the base address of the module and the hash for the symbol name as input and return the base address of this symbol (API).

```c
LPVOID getAPIAddr(HMODULE module, DWORD myHash) {

    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((LPBYTE)module + DOSheader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY EXdir = (PIMAGE_EXPORT_DIRECTORY)(
        (LPBYTE)module + NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD fAddr = (PDWORD)((LPBYTE)module + EXdir->AddressOfFunctions);
    PDWORD fNames = (PDWORD)((LPBYTE)module + EXdir->AddressOfNames);
    PWORD  fOrdinals = (PWORD)((LPBYTE)module + EXdir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < EXdir->AddressOfFunctions; i++) {
        LPSTR pFuncName = (LPSTR)((LPBYTE)module + fNames[i]);
        DWORD hash = CalculateHash(pFuncName);
        if (hash == myHash) {
            //printf("functionName : %s\n", pFuncName);
            return (LPVOID)((LPBYTE)module + fAddr[fOrdinals[i]]);
        }
    }
    return NULL;
}
```


# Indirect Dynamic Syscalls

In our code, our intention is to indirectly invoke system calls using assembly language. To facilitate this, we can enable assembly code support within Visual Studio by adding the `masm` build dependency. This enables us to include `.asm` files and incorporate assembly code into our project seamlessly. you can get information on how to set up that from [that blog](https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs#setting-up-project-environment) from [ired.team](https://www.ired.team/) .

![Asm](https://github.com/CognisysGroup/HadesLdr/assets/123980007/71893894-248e-42b0-a1c2-9b5e71ecc4f6)


In our `.asm` file, we defined some procedures like `GetSyscall` & `GetSyscallAddr`  that will keep updating the `SSN number` and the address of the syscall instruction within `ntdll` of the current customised Native API Procedure that we are calling.

![TheLoader](https://github.com/CognisysGroup/HadesLdr/assets/123980007/16385d13-c79c-453a-be48-2b4ba68ceaa7)


the `SSN` and the `Syscall Address` within `ntdll` are retrieved dynamically using the [Hell’s Gate](https://github.com/am0nsec/HellsGate/blob/1d860c0734c0e35a2f026d9a04856ded19dfdf31/HellsGate/main.c#L146)  technique by [@am0nsec](https://twitter.com/am0nsec) & [@smelly_vx](https://twitter.com/smelly_vx)  improved to [Halo’s Gate](https://blog.sektor7.net/#!res/2021/halosgate.md) by [@SEKTOR7net](https://twitter.com/SEKTOR7net) in case of the syscall stub is hooked, this is done by the `GetSSN` & `GetsyscallInstr` functions respecively.

in case of the Native API is not hooked :

![NativeNotHooked](https://github.com/CognisysGroup/HadesLdr/assets/123980007/059008ea-fb03-4a6e-85cb-3d877dd6380c)


`GetSSN` function will check for the presence of :

```c
	mov r10,rcx   // 0x4c 0x8b 0xd1
	mov eax, SSN  // 0xb8 0xNN 0xNN 0x00 0x00
```

if found it will return `WORD SSN` at offset `0x5` from the beginning of the Native API base address :

```c
WORD syscall = NULL;

    if (*((PBYTE)addr) == 0x4c
        && *((PBYTE)addr + 1) == 0x8b
        && *((PBYTE)addr + 2) == 0xd1
        && *((PBYTE)addr + 3) == 0xb8
        && *((PBYTE)addr + 6) == 0x00
        && *((PBYTE)addr + 7) == 0x00) {

        BYTE high = *((PBYTE)addr + 5);
        BYTE low = *((PBYTE)addr + 4);
        syscall = (high << 8) | low;

        return syscall;

    }
```

Same for `GetsyscallInstr` it will return the address pointing to the `syscall instruction`   :

```c
 WORD syscall = NULL;

    if (*((PBYTE)addr) == 0x4c
        && *((PBYTE)addr + 1) == 0x8b
        && *((PBYTE)addr + 2) == 0xd1
        && *((PBYTE)addr + 3) == 0xb8
        && *((PBYTE)addr + 6) == 0x00
        && *((PBYTE)addr + 7) == 0x00) {

        return (INT_PTR)addr + 0x12;    // syscall

    }
```

the `GetSSN` & `GetsyscallInstr`  check for any hook presented by the `JMP` instruction with the opcode `0xe9` at many probable positions where this opcode can be found within the Native API assembly

![NativeHooked](https://github.com/CognisysGroup/HadesLdr/assets/123980007/79036bc8-7e22-4d29-903e-b1fc6ea5716c)


and if this `0xe9` opcode is found, it will go DOWN or UP 32 Bytes  to the next or previous Native API stub, because each Native API is sized 32 bytes, then the `GetSSN` & `GetsyscallInstr` will make sure if it's not hooked, then it will calculate the `SSN` of the `Native API` we're looking for based on that not hooked `SSN` plus or minus the number of iteration we did (number of `DOWNs` or `UPs`)

![Sized32B](https://github.com/CognisysGroup/HadesLdr/assets/123980007/3a283e10-b8b5-4c01-a4a3-7a150c585933)


![HookedSSN](https://github.com/CognisysGroup/HadesLdr/assets/123980007/51330982-1f3c-4d72-a992-9d5e18ab45a6)


Same logic is applied to the `GetsyscallInstr` with retrieving the address pointing to the `syscall instruction` of a none hooked Native API starting UP or DOWN from a hooked one.

![HookedSyscall](https://github.com/CognisysGroup/HadesLdr/assets/123980007/cc893af2-039f-4864-b590-e1f83a77b68b)


Then after retrieving dynamically the `SSN` and the `syscall instruction` within ntdll memory for the Native API that we're interested in, we gonna let `GetSyscall` & `GetSyscallAddr` update `SSN number` and `the address of the syscall instruction within ntdll` that the jump is made in order to do the `syscall` for our custom procedure.

In this way, we will bypass EDR hooks, and the EDR is no more monitor our User land API.

**The code** for this article is part of a Shellcode Loader implementing Indirect Dynamic Syscall & API Hashing and Fileless Shellcode using WinSock2 can be found on this **[Github](https://github.com/CognisysGroup/HadesLdr)** Repository.

### References :

[https://www.amazon.co.uk/Windows-Kernel-Programming-Pavel-Yosifovich/dp/1977593372](https://www.amazon.co.uk/Windows-Kernel-Programming-Pavel-Yosifovich/dp/1977593372)
[https://github.com/am0nsec/HellsGate/tree/master](https://github.com/am0nsec/HellsGate/tree/master)  
[https://cocomelonc.github.io/tutorial/2022/04/02/malware-injection-18.html](https://cocomelonc.github.io/tutorial/2022/04/02/malware-injection-18.html)    
[https://blog.sektor7.net/#!res/2021/halosgate.md](https://blog.sektor7.net/#!res/2021/halosgate.md)  
[https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs#setting-up-project-environment](https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs#setting-up-project-environment)  
