#![allow(non_snake_case)]
pub mod proc {
    use std::mem::{size_of, zeroed};

    use windows::{
        core::PCSTR,
        Win32::{
            Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LUID},
            Security::{
                AdjustTokenPrivileges, LookupPrivilegeValueA, SE_PRIVILEGE_ENABLED,
                TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES,
                TOKEN_QUERY,
            },
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        }, s,
    };

    // enable or disable token privilege
    pub unsafe fn set_privilege(
        token: HANDLE,
        privilege_name: PCSTR,
        enabled: bool,
    ) -> Result<(), windows::core::Error> {
        // 获取权限id
        let mut luid = zeroed::<LUID>();
        LookupPrivilegeValueA(None, privilege_name, &mut luid).ok()?;

        // 设置token权限
        let mut tp = zeroed::<TOKEN_PRIVILEGES>();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = if enabled {
            SE_PRIVILEGE_ENABLED
        } else {
            TOKEN_PRIVILEGES_ATTRIBUTES(0x0)
        };

        AdjustTokenPrivileges(
            token,
            false,
            Some(&tp),
            size_of::<TOKEN_PRIVILEGES>() as _,
            None,
            None,
        )
        .ok()?;

        Ok(())
    }

    // enable current process debug privilege
    pub unsafe fn enable_debug_priv() -> Result<(), windows::core::Error> {
        let mut proc_handle = INVALID_HANDLE_VALUE;
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut proc_handle,
        )
        .ok()?;
        set_privilege(proc_handle, s!("SeDebugPrivilege"), true)?;
        CloseHandle(proc_handle);

        Ok(())
    }
}
