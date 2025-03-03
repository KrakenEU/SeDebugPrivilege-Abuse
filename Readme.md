## SeDebugPrivilege Abuse Tool

This tool demonstrates how the SeDebugPrivilege privilege in Windows can be abused to manipulate processes running as SYSTEM. It is intended for educational purposes, security research, and authorized penetration testing.

It's built in rust because why not

#### What is SeDebugPrivilege?

SeDebugPrivilege is a powerful privilege in Windows that allows a process to debug another process, including the ability to read and write to the memory of other processes. By default, this privilege is granted to administrators and can be abused to escalate privileges if not properly secured.

#### How the Tool Works

The tool leverages SeDebugPrivilege to:
- Enable SeDebugPrivilege: The tool enables SeDebugPrivilege for the current process using the Windows API.
- Open a Target Process: It opens a handle to a target process running as SYSTEM (e.g., lsass.exe or services.exe).
- Manipulate the Target Process: Once a handle to the target process is obtained, the tool injects the loaded shellcode and Creates a Remote Thread using the VirtualAllocEx injection technique.

#### Usage

Running the tool:

```
git clone https://github.com/yourusername/SeDebugPrivilege-Abuse-Tool.git
cd SeDebugPrivilege-Abuse-Tool
```

1. On the helper/xoring.py script, change your input shellcode that is going to be injected, and its output path:

![image](https://github.com/user-attachments/assets/9decbcc4-d01c-419c-a63a-825da0f421a4)

2. Get the shellcode bytes in a printable format:

```
xxd -i xored.bin > xored.rs
```

3. Replace the shellcode in shellcode.rs

![image](https://github.com/user-attachments/assets/4cd8cfa8-1131-4f11-95c3-be78ed845200)

```
cargo build --release
```

4. Spot a process running as system and logon type > 0

![image](https://github.com/user-attachments/assets/e915674d-2f68-4eda-9b7a-4eb8cc0b3a09)

5. Run the tool

```
.\SeDebugPrivilege.exe vm3dservice.exe
```

Example:

![image](https://github.com/user-attachments/assets/94d92028-142f-4c47-a6be-013f88c0fed0)

![image](https://github.com/user-attachments/assets/658386cc-3d76-44f5-b74a-8697ab72a7bf)

## Special thanks

This wouldn't be possible without the inspiration of some big geniuses:

- xct adopt tool: https://github.com/xct/adopt
- bruno 1337 SeDebugPrivilege-Exploit: https://github.com/bruno-1337/SeDebugPrivilege-Exploit




