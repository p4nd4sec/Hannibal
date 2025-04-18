+++
title = "Hannibal"
chapter = true
weight = 100
+++

## `execute_bof`: Execute Beacon Object File from Hannibal agents

This command are developed for executing Beacon Object File in the Hannibal agents, with a flexible additional arguments, or additional payloads. 

### Beacon Object File (BOF)

Beacon Object File (BOF), at its core, is in the format of an object file. This file is created during the *compilation* process when C/C++ compiler convert source code into executable binaries. 

![Object Link Process](./attachments/images/obj-link-process.png)

These object files contains information about functions in the binaries, imports/exports, and also implementations of those functions. Object files in general are not supposed to run as a program, but as inputs for linker to create an executable file. Therefore, the file size of an object file is relatively much smaller comparing to final executable.

```
PS .\hannibal.o                                                                                                     
    Directory: ...

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---            4/7/2025 11:19 PM          36652 hannibal.o

PS ls ..\hannibal.exe                                                                                                           
    Directory: ...

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---           4/17/2025 11:04 AM        1064378 hannibal.exe

```
When an object file is weaponized to include implementations of malicious functions, it becomes Beacon Object Files. When we say "run a BOF", that means we are doing the job of a linker. Our implementation of `execute_bof` in Hannibal is doing the exact same thing: parsing the defined functions, link the import tables to the correct function at runtime, etc.; and finally, execute it with the functions defined inside. 

### Why BOF? 

As you may noticed, there is one another function in Hannibal agent: `execute_hbin`, which receives shellcode to achieve the same thing: running some fileless payload. Here is a quick comparison between Beacon Object File and shellcode. 

| Functions          | Strengths                                                                                                                                                                                                  | Weaknesses                                                                                                                                                                              |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`execute_bof`**  | + Quick development, directly derived from normal C/C++ compilation.<br>+ A lot of open source BOFs are ready to test & modify.<br>+ Easy change the structs/parameters/etc. as we need during operations. | + Need a COFF loader.<br>+ May drop more signatures for detection.                                                                                                                      |
| **`execute_hbin`** | + Full control to what we can do, as it is shellcode.<br>+ Smaller payload than BOFs<br>+ No COFF parser needed.<br>+ Porting BOFs to shellcode is relatively easy.                                        | + There are open-source BOFs already, require more work to port.<br>+ Very sensitive to struct changes during development of future Hannibal build.<br>+ Limitation of PIC shellcode 🫠 |

So, in general, the quick development, easy to use and build of BOF will trade-off with somewhat more complexity in implementation of agent, which will increase the size of the Hannibal agent shellcode. However, we think that in some cases, we need complex operations, running a BOF will reduce our headache 🤯. 

## How to use 

To start, you can try with this [example BOF file](./attachments/sample_bof). The source code is in [main.c](./attachments/main.c). If this object file to be built as an executable, it will run like:

```powershell
main.exe <a_number> <a_string> <a_wstring> <file>
``` 

### Run the command

This is how you run the `execute_bof`. 

1. Get a callback from a victim :)
2. Next, you can run the `execute_bof` in the interaction with the callback. A GUI will display. 

![](./attachments/images/example.png)

There are 03 parameters: 

+ `bof` (Required): The BOF will be sent and executed. 
+ `Arguments`: Additional arguments. You can have as many arguments as you want (of course longer payload!), and at the moment there are 03 types that the `execute_bof` server side can host: 
  + `int32`: A signed 32-bit integer. 
  + `string`: A normal C-style string. 
  + `wchar`: A `wchar_t` string. 
+ `Additional File`: Additional file, could be served as the second stage payload. 

`Arguments` and `Additional File` are not required. However, for `Additional File`, due to some restriction in the mechanism of Hannibal shellcode agent to not having `NULL` payload, a random 16-byte gibberish will be added as a decoy. 

Next, just task it :D

### During the task 

Periodically, the victim's Hannibal agent will load new task. The task for `execute_bof` are loaded as this struct: 

```c
typedef struct _CMD_EXECUTE_BOF {
    PBYTE args;
    int argc;
    PBYTE bof;
    int bof_size;
    PBYTE file_content;
    int file_size;
} CMD_EXECUTE_BOF;
```

+ `PBYTE args`: the encoded arguments, in the order that you added. With the above example, the value of `args` will look like this (in bytes): 

```
|     int32      |       string       |        wchar         |
|\x39\x05\x00\x00|\x74\x65\x73\x74\x00|..............\x00\x00|   
```
+ `int argc`: the length of `args`, in bytes. 
+ `PBYTE bof`: the BOF file. 
+ `int bof_size`: size of the BOF file.
+ `PBYTE file_content`: the additional file. 
+ `int file_size`: the additional file's size.

Under the hood, the lifecycle of `execute_bof` could be summarized in this diagram: 

```mermaid
flowchart TD
    A@{ shape: manual-file, label: Input Bof file} --> B[BOF file loader];
    B --> C{Is it loadable?}; 
    C -- Yes --> D[Execute BOF file]; 
    C -- No --> E[Quit];
    D --> F[Sending log to C2];
    E --> F[Sending log to C2];
```

For the above test BOF, with above parameters, here is the response you get back: 

![](./attachments/images/output.png)

## Development & Debugging 

> I have discovered a truly marvelous documentation of this, which this margin is too narrow to contain. (h114mx001)

TODO: continue this hehe