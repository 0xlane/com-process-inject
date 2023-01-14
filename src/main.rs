#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]
pub mod combase;
use combase::*;
use windows::{
    w,
    Win32::{
        System::{
            Com::{
                CoInitializeEx, CoUninitialize, IStream, COINIT_MULTITHREADED, MSHCTX_INPROC,
                STREAM_SEEK_SET, StringFromIID,
            },
            LibraryLoader::GetModuleHandleW, Diagnostics::{Debug::ReadProcessMemory, ToolHelp::{PROCESSENTRY32, CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, Process32First, Process32Next}}, Threading::{OpenProcess, PROCESS_VM_READ, PROCESS_QUERY_LIMITED_INFORMATION, GetCurrentProcessId}, Registry::{RegGetValueA, HKEY_CLASSES_ROOT, RRF_RT_REG_SZ, RegGetValueW},
        },
        UI::Shell::SHCreateMemStream, Foundation::{HANDLE, CloseHandle},
    }, core::{PCSTR, PWSTR, PCWSTR}, s,
};

use std::{
    ffi::c_void,
    mem::{size_of, zeroed},
    ptr::null_mut
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct tagPageEntry {
    pub pNext: *mut tagPageEntry,
    pub dwFlag: *mut u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CInternalPageAllocator {
    pub _cPages: u64,
    pub _pPageListStart: *mut *mut tagPageEntry,
    pub _pPageListEnd: *mut *mut tagPageEntry,
    pub _dwFlags: u32,
    pub _ListHead: tagPageEntry,
    pub _cEntries: u32,
    pub _cbPerEntry: u64,
    pub _cEntriesPerPage: u16,
    pub _pLock: *mut c_void,
}

// CPageAllocator CIPIDTable::_palloc structure in combase.dll
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CPageAllocator {
    pub _pgalloc: CInternalPageAllocator,
    pub _hHeap: *mut c_void,
    pub _cbPerEntry: u64,
    pub _lNumEntries: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct tagIPIDEntry {
    pub pNextIPID: *mut tagIPIDEntry, // next IPIDEntry for same object
    pub dwFlags: IPIDFlags,           // flags (see IPIDFLAGS)
    pub cStrongRefs: u32,             // strong reference count
    pub cWeakRefs: u32,               // weak reference count
    pub cPrivateRefs: u32,            // private reference count
    pub pv: *mut c_void,              // real interface pointer
    pub pStub: *mut windows::core::IUnknown, // proxy or stub pointer
    pub pOXIDEntry: *mut c_void,      // ptr to OXIDEntry in OXID Table
    pub ipid: IPID,                   // interface pointer identifier
    pub iid: windows::core::GUID,     // interface iid
    pub pChnl: *mut c_void,           // channel pointer
    pub pIRCEntry: *mut c_void,       // reference cache line
    pub pInterfaceName: *mut windows::core::HSTRING,
    pub pOIDFLink: *mut tagIPIDEntry, // In use OID list
    pub pOIDBLink: *mut tagIPIDEntry,
}
pub type IPIDEntry = tagIPIDEntry;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct tagCTXVERSION {
    pub ThisVersion: u16,
    pub MinVersion: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct tagCTXCOMMONHDR {
    pub ContextId: windows::core::GUID,
    pub Flags: u32,
    pub Reserved: u32,
    pub dwNumExtents: u32,
    pub cbExtents: u32,
    pub MshlFlags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct tagBYREFHDR {
    pub Reserved: u32,
    pub ProcessId: u32,
    pub guidProcessSecret: windows::core::GUID,
    pub pServerCtx: *mut c_void, // CObjectContext
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct tagBYVALHDR {
    pub Count: u32,
    pub Frozen: windows::Win32::Foundation::BOOL,
}
pub type CTXBYVALHDR = tagBYVALHDR;

#[repr(C)]
#[derive(Clone, Copy)]
pub union CtxHdrUnion {
    pub ByRefHdr: tagBYREFHDR,
    pub ByValHdr: tagBYVALHDR,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct tagCONTEXTHEADER {
    pub Version: tagCTXVERSION,
    pub CmnHdr: tagCTXCOMMONHDR,
    pub uCtxHdr: CtxHdrUnion,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct tagSTRINGBINDING {
    pub wTowerId: u16,
    pub aNetworkAddr: u16,
}
pub type STRINGBINDING = tagSTRINGBINDING;

pub const COM_C_AUTHZ_NONE: u16 = 0xffff;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct tagSECURITYBINDING {
    pub wAuthnSvc: u16,
    pub wAuthzSvc: u16,
    pub aPrincName: u16,
}
pub type SECURITYBINDING = tagSECURITYBINDING;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct tagDUALSTRINGARRAY {
    pub wNumEntries: u16,
    pub wSecurityOffset: u16,
    pub aStringArray: [u8; 1],
}
pub type DUALSTRINGARRAY = tagDUALSTRINGARRAY;

pub const OBJREF_SIGNATURE: u32 = 0x574f454d;
pub const OBJREF_STANDARD: u32 = 0x1;
pub const OBJREF_HANDLER: u32 = 0x2;
pub const OBJREF_CUSTOM: u32 = 0x4;
pub const OBJREF_EXTENDED: u32 = 0x8;

pub const SORF_OXRES1: u32 = 0x1;
pub const SORF_OXRES2: u32 = 0x20;
pub const SORF_OXRES3: u32 = 0x40;
pub const SORF_OXRES4: u32 = 0x80;
pub const SORF_OXRES5: u32 = 0x100;
pub const SORF_OXRES6: u32 = 0x200;
pub const SORF_OXRES7: u32 = 0x400;
pub const SORF_OXRES8: u32 = 0x800;
pub const SORF_NULL: u32 = 0x0;
pub const SORF_NOPING: u32 = 0x1000;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct tagDATAELEMENT {
    pub dataID: windows::core::GUID,
    pub cbSize: u32,
    pub cbRounded: u32,
    pub Data: [u8; 1],
}
pub type DATAELEMENT = tagDATAELEMENT;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct tagOBJREFDATA {
    pub nElms: u32,
    pub ppElmArray: *mut *mut DATAELEMENT,
}
pub type OBJREFDATA = tagOBJREFDATA;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OBJREFSTD {
    pub std: STDOBJREF,
    pub saResAddr: DUALSTRINGARRAY,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OBJREFHANDLER {
    pub std: STDOBJREF,
    pub clsid: windows::core::GUID,
    pub saResAddr: DUALSTRINGARRAY,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OBJREFCUSTOM {
    pub clsid: windows::core::GUID,
    pub cbExtension: u32,
    pub size: u32,
    pub pData: *mut u8,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OBJREFEXTENDED {
    pub std: STDOBJREF,
    pub pORData: OBJREFDATA,
    pub saResAddr: DUALSTRINGARRAY,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union ObjRefUnion {
    pub u_standard: OBJREFSTD,
    pub u_handler: OBJREFHANDLER,
    pub u_custom: OBJREFCUSTOM,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct tagOBJREF {
    pub signature: u32,
    pub flags: u32,
    pub iid: windows::core::GUID,
    pub u_objref: ObjRefUnion,
}
pub type OBJREF = tagOBJREF;

// 利用 IRundown::DoCallback() 完成注入需要的信息
pub struct _COM_CONTEXT {
    pub pid: u32,     // 进程 ID
    pub name: String, // 进程名

    pub path: String,     // dll 路径或者 shellcode 路径
    pub inject_pic: bool, // 注入 shellcode
    pub inject_dll: bool, // 注入 dll
    pub list_ipid: bool,  // 列出 IRundown 实例
    pub verbose: bool,    // 是否包含其他接口实例
    pub use_objref: bool, // 是否使用 CoGetObject() 绑定 IRundown 实例

    pub base: usize,     // GetModuleHandle("combase"); or GetModuleHandle("ole32");
    pub data: u32,       // VirtualAddress of .data segment
    pub size: u32,       // VirtualSize
    pub secret: u32,     // CProcessSecret::s_guidOle32Secret
    pub server_ctx: u32, // g_pMTAEmptyCtx
    pub ipid_tbl: u32,   // CIPIDTable::_palloc
    pub oxid: u32,       // offsetof(tagOXIDEntry, OXID)
}
impl ::core::default::Default for _COM_CONTEXT {
    fn default() -> Self {
        Self {
            pid: Default::default(),
            name: Default::default(),
            path: Default::default(),
            inject_pic: Default::default(),
            inject_dll: Default::default(),
            list_ipid: Default::default(),
            verbose: Default::default(),
            use_objref: Default::default(),
            base: Default::default(),
            data: Default::default(),
            size: Default::default(),
            secret: Default::default(),
            server_ctx: Default::default(),
            ipid_tbl: Default::default(),
            oxid: Default::default(),
        }
    }
}
pub type COM_CONTEXT = _COM_CONTEXT;
pub type PCOM_CONTEXT = *mut COM_CONTEXT;

// 从远程 COM 进程中获取到的 IRundown 接口信息
#[derive(Clone, Copy)]
pub struct _IPID_ENTRY {
    pub iid: windows::core::GUID,
    pub ipid: IPID, // 要绑定的IPID
    pub oxid: OXID, // Object Exporter ID
    pub oid: OID,   // Object Identifier
}
pub type IPID_ENTRY = _IPID_ENTRY;
pub type PIPID_ENTRY = *mut IPID_ENTRY;

// 从远程 COM 进程中获取到的 IRundown 实例信息和调用 DoCallback 方法要求的信息
#[derive(Clone, Copy)]
pub struct _RUNDOWN_CONTEXT {
    pub pfnCallback: *mut c_void, // 执行的回调函数
    pub pParam: *mut c_void,      // 回调函数的参数

    pub pServerCtx: *mut c_void,                // DoCallback 验证要求
    pub guidProcessSecret: windows::core::GUID, // DoCallback 验证要求

    pub ipid: IPID, // 要绑定的IPID
    pub oxid: OXID, // Object Exporter ID
    pub oid: OID,   // Object Identifier
}
pub type RUNDOWN_CONTEXT = _RUNDOWN_CONTEXT;
pub type PRUNDOWN_CONTEXT = *mut RUNDOWN_CONTEXT;

// Microsoft removed this prototype from oleacc.h, but the function still exists and works fine.
pub type GetProcessHandleFromHwnd_T =
    unsafe extern "system" fn(
        hwnd: windows::Win32::Foundation::HWND,
    ) -> windows::Win32::Foundation::HANDLE;

pub type KAFFINITY = ULONG_PTR;
pub type KPRIORITY = std::ffi::c_long;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct _THREAD_BASIC_INFORMATION {
    pub ExitStatus: windows::Win32::Foundation::NTSTATUS,
    pub TebBaseAddress: *mut c_void,
    pub ClientId: windows::Win32::System::WindowsProgramming::CLIENT_ID,
    pub AffinityMask: KAFFINITY,
    pub Priority: KPRIORITY,
    pub BasePriority: KPRIORITY,
}
pub type THREAD_BASIC_INFORMATION = _THREAD_BASIC_INFORMATION;
pub type PTHREAD_BASIC_INFORMATION = *mut THREAD_BASIC_INFORMATION;

// 获取 combase.dll 或 ole32.dll 的 .data 段地址和大小
unsafe fn get_com_data(ctx: *mut COM_CONTEXT) -> Result<(), ::windows::core::Error> {
    type PIMAGE_DOS_HEADERS = *mut windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
    #[cfg(target_pointer_width = "64")]
    type IMAGE_NT_HEADERS = ::windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
    #[cfg(target_pointer_width = "32")]
    type IMAGE_NT_HEADERS = ::windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
    type PIMAGE_NT_HEADERS = *mut IMAGE_NT_HEADERS;
    
    // old systems use ole32
    let m: *mut u8 = ::core::mem::transmute(GetModuleHandleW(w!("combase")).or_else(|_| GetModuleHandleW(w!("ole32")))?);
    let dos: PIMAGE_DOS_HEADERS = m.offset(0) as _;
    let nt: PIMAGE_NT_HEADERS = m.offset((*dos).e_lfanew as _) as _;
    let sec_count = (*nt).FileHeader.NumberOfSections;
    let sections: &[windows::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER] = ::core::slice::from_raw_parts(
        m.offset((*dos).e_lfanew as _).offset(size_of::<IMAGE_NT_HEADERS>() as _) as *mut _,
        sec_count as _
    );

    for i in 0..sec_count {
        let cur_sec = sections[usize::from(i)];
        let name = String::from_utf8(cur_sec.Name.to_vec())?;
        if name.trim_matches(char::from(0)) == ".data" {
            (*ctx).base = m as _;
            (*ctx).data = cur_sec.VirtualAddress as _;
            (*ctx).size = cur_sec.Misc.VirtualSize as _;
            break;
        }
    }

    Ok(())
}

unsafe fn find_com_data(cc: *mut COM_CONTEXT, inbuf: *mut u8, inlen: usize) -> Result<u32, ::windows::core::Error> {
    let mut rva = 0;

    let db = (*cc).base + (*cc).data as usize;


    for i in 0..(*cc).size - inlen as u32 {
        let x: &[u8] = ::core::slice::from_raw_parts((db + i as usize) as *mut _, inlen);
        let y: &[u8] = ::core::slice::from_raw_parts(inbuf, inlen);
        
        if x == y {
            rva = (db + i as usize - (*cc).base) as _;
            return Ok(rva);
        }
    }

    return Err(::windows::core::Error::from(windows::Win32::Foundation::E_INVALIDARG));
}

// 搜索 CIPIDTable::_palloc 偏移
unsafe fn find_ipid_table(cc: *mut COM_CONTEXT) -> Result<(), ::windows::core::Error> {
    let db = ((*cc).base + (*cc).data as usize) as *mut ULONG_PTR;
    let cnt = ((*cc).size as usize - size_of::<CPageAllocator>()) / size_of::<ULONG_PTR>();

    for i in 0..cnt {
        let cpage = db.offset(i as _) as *mut _ as *mut CPageAllocator;

        // Legacy systems use 0x70, current is 0x78，找的不对会导致后面步骤访问到无效地址
        if (*cpage)._pgalloc._cbPerEntry>= 0x70 {
            if (*cpage)._pgalloc._cEntriesPerPage != 0x32 {
                continue;
            }
            if (*cpage)._pgalloc._pPageListEnd <= (*cpage)._pgalloc._pPageListStart {
                continue;
            }
            // 相比原项目，这里添加了这两个条件解决因找到错误的 ipid_tbl 导致程序崩溃的问题
            if (*cpage)._pgalloc._cPages <= 0 || (*cpage)._pgalloc._cEntries <= 0 {
                continue;
            }

            // (com_inject::CPageAllocator) *cpage = {
            //   _pgalloc = {
            //     _cPages = 1
            //     _pPageListStart = 0x0000028c1d5085f0
            //     _pPageListEnd = 0x0000028c1d5085f8
            //     _dwFlags = 0
            //     _ListHead = {
            //       pNext = 0x0000028c1d509bb0
            //       dwFlag = 0x0000000000000000
            //     }
            //     _cEntries = 2
            //     _cbPerEntry = 120
            //     _cEntriesPerPage = 50
            //     _pLock = 0x0000000000000000
            //   }
            //   _hHeap = 0x0000000000000000
            //   _cbPerEntry = 0
            //   _lNumEntries = 0
            // }

            (*cc).ipid_tbl = (cpage as usize - (*cc).base) as _;
            return Ok(());
        }
    }

    Err(::windows::core::Error::from(windows::Win32::Foundation::E_INVALIDARG))
}

// 搜索 OXIDEntry._moxid 偏移
unsafe fn find_oxid_offset(cc: *mut COM_CONTEXT) -> Result<(), ::windows::core::Error> {
    const IPID_OFFSET_LEGACY: u32 = 0x30;
    const MOXID_OFFSET_LEGACY: u32 = 0x18;
    const IPID_OFFSET_CURRENT: u32 = 0xb8;
    const MOXID_OFFSET_CURRENT: u32 = 0xc8;

    let cpage = ((*cc).base + (*cc).ipid_tbl as usize) as *mut CPageAllocator;
    let entry: *mut tagIPIDEntry = *(*cpage)._pgalloc._pPageListStart.offset(0) as *mut _;
    let buf: *mut u8 = (*entry).pOXIDEntry as *mut _;

    for ofs in 0..256u32 {
        let x: &[u8] = ::core::slice::from_raw_parts(buf.offset(ofs as _), size_of::<IPID>());
        let y: &[u8] = ::core::slice::from_raw_parts(::core::mem::transmute(&(*entry).ipid), size_of::<IPID>());

        if x == y {
            if ofs == IPID_OFFSET_LEGACY {
                (*cc).oxid = MOXID_OFFSET_LEGACY;
            } else if ofs == IPID_OFFSET_CURRENT {
                (*cc).oxid = MOXID_OFFSET_CURRENT;
            } else {
                return Err(::windows::core::Error::from(windows::Win32::Foundation::E_INVALIDARG));
            }
            return Ok(());
        }
    }

    Err(::windows::core::Error::from(windows::Win32::Foundation::E_INVALIDARG))
}

// 从 combase.dll 或者 ole32.dll 中读取在远程进程中执行 IRundown::DoCallback 所需要的一切信息
unsafe fn init_cc(cc: *mut COM_CONTEXT) -> Result<(), windows::core::Error> {
    // 得到 IMarshalEnvoy 接口的指针
    let e: IMarshalEnvoy = CoGetObjectContext(&<IMarshalEnvoy as ::windows::core::Interface>::IID)?;

    // 封装context header，他应该包含server context的堆地址和secret GUID
    let stream: IStream = SHCreateMemStream(None).ok_or(windows::core::Error::from_win32())?;
    e.MarshalEnvoy(stream.clone(), MSHCTX_INPROC.0 as _)?;

    // 读取上下文头到本地
    let mut hdr: tagCONTEXTHEADER = zeroed();
    stream.Seek(0, STREAM_SEEK_SET)?;
    stream
        .Read(
            &mut hdr as *mut _ as *mut _,
            size_of::<tagCONTEXTHEADER>() as _,
            None,
        )
        .ok()?;

    // 读取 combase.dll 或 ole32.dll 的 .data 段
    get_com_data(cc)?;

    // 找到 g_pMTAEmptyCtx
    (*cc).server_ctx = find_com_data(cc, ::core::mem::transmute(&hdr.uCtxHdr.ByRefHdr.pServerCtx), size_of::<ULONG_PTR>())?;

    // 找到 CProcessSecret::s_guidOle32Secret
    (*cc).secret = find_com_data(cc, ::core::mem::transmute(&hdr.uCtxHdr.ByRefHdr.guidProcessSecret), size_of::<::windows::core::GUID>())?;

     // 找到 CIPIDTable::_palloc
    find_ipid_table(cc)?;

    // 找到 OXIDEntry._moxid
    find_oxid_offset(cc)?;

    Ok(())
}

unsafe fn get_ipid_entries(cc: *mut COM_CONTEXT, hp: HANDLE) -> Option<Vec<IPID_ENTRY>> {
    let mut entries: Vec<IPID_ENTRY> = vec![];

    let ipid_tbl = (*cc).base + (*cc).ipid_tbl as usize;

    // 读取 CPageAllocator，如果报错意味着远程进程没有 COM
    let mut cpage: CPageAllocator = zeroed();
    if !ReadProcessMemory(hp, ipid_tbl as *const _, &mut cpage as *mut _ as *mut _, size_of::<CPageAllocator>(), None).as_bool() {
        return None;
    }

    // 读取所有 page 地址
    let page_cnt = cpage._pgalloc._cPages as usize;
    let mut pages: Vec<ULONG_PTR> = Vec::with_capacity(page_cnt);
    if !ReadProcessMemory(hp, cpage._pgalloc._pPageListStart as *mut _ as *mut _, pages.as_mut_ptr() as *mut _ as *mut _, page_cnt * size_of::<ULONG_PTR>(), None).as_bool() {
        return None;
    }
    pages.set_len(page_cnt);

    // 循环 page
    let ipid_cnt = cpage._pgalloc._cEntriesPerPage as usize;    // 每页的 IPIDEntry 数量
    for page in pages {
        let mut page_entries: Vec<IPIDEntry> = Vec::with_capacity(ipid_cnt);

        if !ReadProcessMemory(hp, page as *const _, page_entries.as_mut_ptr() as *mut _ as *mut _, ipid_cnt * size_of::<IPIDEntry>(), None).as_bool() {
            return None;
        }
        page_entries.set_len(ipid_cnt);

        // 解析每一个 entry
        for e in page_entries {
            // 跳过 inactive entries
            if e.pOXIDEntry == null_mut() || e.dwFlags.0 == 0 {
                continue;
            }
            if (e.dwFlags & (IPIDF_DISCONNECTED | IPIDF_DEACTIVATED)).0 != 0 {
                continue;
            }

            // 是否只获取 IRundown
            if !(*cc).verbose && e.iid != <IRundown as ::windows::core::Interface>::IID {
                continue;
            }

            let mut item: IPID_ENTRY = zeroed();
            item.iid = e.iid;
            item.ipid = e.ipid;

            // 读取 _moxid (OXID and OID)
            let pOxidEntry = e.pOXIDEntry as *mut u8;
            let mut tmp: [u64; 2] = zeroed();
            if !ReadProcessMemory(hp, pOxidEntry.offset((*cc).oxid as _) as *const _, tmp.as_mut_ptr() as *mut _, tmp.len() * size_of::<u64>(), None).as_bool() {
                continue;
            }

            item.oxid = tmp[0];
            item.oid = tmp[1];

            if item.oxid == 0 || item.oid == 0 {
                continue;
            }
            entries.push(item);
        }
    }

    if entries.len() > 0 {
        Some(entries)
    } else {
        None
    }
}

// 列出一个进程中的 IPID
unsafe fn dump_ipid(cc: *mut COM_CONTEXT, pe: &mut PROCESSENTRY32) -> Result<(), ::windows::core::Error> {
    // let ret = false;

    let hp = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
        false,
        pe.th32ProcessID
    )?;

    let ret = loop {
        match get_ipid_entries(cc, hp) {
            Some(entries) => {
                println!("\n**************************************");
                println!("Process: {} [{}]", PCSTR::from_raw(pe.szExeFile.as_ptr() as *mut _).to_string().unwrap_or(String::from("_")), pe.th32ProcessID);
                println!("");

                for e in entries {
                    let iid = StringFromIID(&e.iid)?.to_string().unwrap_or(String::from("N/A"));
                    let ipid = StringFromIID(&e.ipid as *const _ as *mut _)?.to_string().unwrap_or(String::from("N/A"));
                    let oxid = StringFromIID(&e.oxid as *const _ as *mut _)?.to_string().unwrap_or(String::from("N/A"));

                    let mut iname: [u16; 260] = zeroed();
                    let mut ipath: Vec<u16> = w!("Interface\\").as_wide().to_vec();
                    ipath.append(&mut iid.encode_utf16().collect());
                    ipath.push(0x0);

                    let mut len = iname.len() as u32;
                    if RegGetValueW(
                        HKEY_CLASSES_ROOT,
                        PCWSTR::from_raw(ipath.as_ptr()),
                        None,
                        RRF_RT_REG_SZ,
                        None,
                        Some(iname.as_mut_ptr() as *mut _),
                        Some(&mut len)
                    ).is_ok() {
                        println!("IPID:{}, OXID:{} : {}", ipid, oxid, PCWSTR::from_raw(iname.as_ptr()).to_string().unwrap_or(String::from("_")));
                    }
                }
            }
            None => break Err(::windows::core::Error::from_win32())
        }
        break Ok(());
    };
    CloseHandle(hp);

    ret
}

// 列出所有进程的 IPID，排除我们自己
unsafe fn list_ipid(cc: *mut COM_CONTEXT) -> Result<(), ::windows::core::Error> {
    let hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;

    let mut pe: PROCESSENTRY32 = zeroed();
    pe.dwSize = size_of::<PROCESSENTRY32>() as _;
    if Process32First(hsnapshot, &mut pe).as_bool() {
        loop {
            if pe.th32ProcessID > 4 && pe.th32ProcessID != GetCurrentProcessId() {
                if (*cc).pid == Default::default() || (*cc).pid == pe.th32ProcessID {
                    let _ = dump_ipid(cc, &mut pe);
                }
            }
            if !Process32Next(hsnapshot, &mut pe).as_bool() {
                break;
            }
        }
    }
    CloseHandle(hsnapshot);

    Ok(())
}

unsafe fn init_rundown_ctx(hp: HANDLE, cc: *mut COM_CONTEXT, rc: *mut RUNDOWN_CONTEXT) -> Result<(),::windows::core::Error> {
    // 只获取 IRundown 实例
    (*cc).verbose = false;
    let entries = get_ipid_entries(cc, hp).ok_or(::windows::core::Error::from_win32())?;



    // 保存第一个
    (*rc).ipid = entries[0].ipid;
    (*rc).oxid = entries[0].oxid;
    (*rc).oid = entries[0].oid;

    // 如果第一次读到 16 位 NULL，则需要调用 DoCallback 初始化
    for _ in 0..2 {
        // 尝试读取远程进程中的 GUID secret
        ReadProcessMemory(hp, ((*cc).base + (*cc).secret as usize) as *const _, &mut (*rc).guidProcessSecret as *const _ as *mut _, size_of::<windows::core::GUID>(), None).ok()?;

        println!("{:?}", (*rc).guidProcessSecret);
        break;
    }
    Ok(())
}

fn main() {
    unsafe {
        // 初始化 COM
        CoInitializeEx(None, COINIT_MULTITHREADED).unwrap();

        let mut cc: COM_CONTEXT = Default::default();
        cc.verbose = false;
        // cc.pid = 14196;

        init_cc(&mut cc).unwrap();

        list_ipid(&mut cc).unwrap();

        // let hp = OpenProcess(PROCESS_VM_READ, false, cc.pid).unwrap();

        // let mut rc: RUNDOWN_CONTEXT = zeroed();
        // init_rundown_ctx(hp, &mut cc, &mut rc).unwrap();

        // CloseHandle(hp);

        CoUninitialize();

        println!("Hello, world!");
    }
}