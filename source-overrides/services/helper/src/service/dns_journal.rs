use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

static FAILED: AtomicBool = AtomicBool::new(false);
static LAST_OS_ERROR: AtomicI32 = AtomicI32::new(0);

pub fn failed() -> bool {
    FAILED.load(Ordering::Relaxed)
}

pub fn last_os_error() -> Option<i32> {
    match LAST_OS_ERROR.load(Ordering::Relaxed) {
        0 => None,
        code => Some(code),
    }
}

pub fn record(event: &str, result: &str, session: &str, os_error: Option<i32>) {
    #[cfg(windows)]
    match native::record(event, result, session, os_error) {
        Ok(()) => {
            FAILED.store(false, Ordering::Relaxed);
            LAST_OS_ERROR.store(0, Ordering::Relaxed);
        }
        Err(error) => {
            LAST_OS_ERROR.store(error.raw_os_error().unwrap_or(-1), Ordering::Relaxed);
            if !FAILED.swap(true, Ordering::Relaxed) {
                eprintln!("DNS journal write failed: {}", error);
            }
        }
    }
    #[cfg(not(windows))]
    let _ = (event, result, session, os_error);
}

#[cfg(windows)]
mod native {
    use once_cell::sync::Lazy;
    use std::fs::{self, OpenOptions};
    use std::io::{self, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::ptr::null_mut;
    use std::sync::Mutex;
    use windows_sys::Win32::Foundation::{
        GetLastError, LocalFree, ERROR_ALREADY_EXISTS, SYSTEMTIME,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
        SetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, IsWellKnownSid,
        WinBuiltinAdministratorsSid, WinLocalSystemSid, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
    };
    use windows_sys::Win32::System::SystemInformation::GetSystemTime;

    static LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn directory() -> io::Result<PathBuf> {
        let root = std::env::var_os("ProgramData")
            .ok_or_else(|| io::Error::other("ProgramData unavailable"))?;
        let path = PathBuf::from(root).join("FlClashDnsProtection");
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let sddl: Vec<u16> = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)\0"
            .encode_utf16()
            .collect();
        unsafe {
            let mut descriptor = null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let created = CreateDirectoryW(wide.as_ptr(), &attributes);
            let error = GetLastError();
            if created == 0 && error != ERROR_ALREADY_EXISTS {
                LocalFree(descriptor);
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            let flags = GetFileAttributesW(wide.as_ptr());
            if flags == INVALID_FILE_ATTRIBUTES || flags & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                LocalFree(descriptor);
                return Err(io::Error::other("Unsafe journal directory"));
            }
            let mut owner = null_mut();
            let mut security = null_mut();
            let code = GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut security,
            );
            if code != 0 {
                LocalFree(descriptor);
                return Err(io::Error::from_raw_os_error(code as i32));
            }
            let trusted = IsWellKnownSid(owner, WinLocalSystemSid) != 0;
            let repairable = IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0;
            LocalFree(security);
            if !trusted && repairable {
                let mut system_owner = null_mut();
                let mut defaulted = 0;
                let mut dacl = null_mut();
                let mut present = 0;
                if GetSecurityDescriptorOwner(descriptor, &mut system_owner, &mut defaulted) == 0
                    || GetSecurityDescriptorDacl(
                        descriptor,
                        &mut present,
                        &mut dacl,
                        &mut defaulted,
                    ) == 0
                    || present == 0
                {
                    let error = io::Error::last_os_error();
                    LocalFree(descriptor);
                    return Err(error);
                }
                let code = SetNamedSecurityInfoW(
                    wide.as_ptr(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION
                        | PROTECTED_DACL_SECURITY_INFORMATION,
                    system_owner,
                    null_mut(),
                    dacl,
                    null_mut(),
                );
                LocalFree(descriptor);
                if code != 0 {
                    return Err(io::Error::from_raw_os_error(code as i32));
                }
                return Ok(path);
            }
            LocalFree(descriptor);
            if !trusted {
                return Err(io::Error::other("Journal directory is not SYSTEM-owned"));
            }
        }
        Ok(path)
    }

    pub fn record(
        event: &str,
        result: &str,
        session: &str,
        os_error: Option<i32>,
    ) -> io::Result<()> {
        let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = directory()?.join("guard.jsonl");
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let flags = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if flags != INVALID_FILE_ATTRIBUTES && flags & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::other("Unsafe journal file"));
        }
        if fs::metadata(&path).is_ok_and(|m| m.len() > 5 * 1024 * 1024) {
            let _ = fs::remove_file(path.with_extension("jsonl.2"));
            let _ = fs::rename(
                path.with_extension("jsonl.1"),
                path.with_extension("jsonl.2"),
            );
            fs::rename(&path, path.with_extension("jsonl.1"))?;
        }
        let mut clock: SYSTEMTIME = unsafe { std::mem::zeroed() };
        unsafe {
            GetSystemTime(&mut clock);
        }
        let ts = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            clock.wYear,
            clock.wMonth,
            clock.wDay,
            clock.wHour,
            clock.wMinute,
            clock.wSecond,
            clock.wMilliseconds
        );
        let data = serde_json::json!({"schema_version":1,"ts":ts,"module":"guard","level":if os_error.is_some(){"error"}else{"info"},"event":event,"result":result,"session_id":session,"os_error":os_error,"build_id":"0.9.2-dns2.1"});
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "{}", data)?;
        file.flush()
    }
}
