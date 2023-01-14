pub type ULONG_PTR = usize;

// !oledata
#[repr(C)]
pub struct tagSOleTlsData {
    pub pvThreadBase: *mut std::ffi::c_void,
    pub pSmAllocator: *mut std::ffi::c_void,
    pub dwApartmentID: u32,
    pub dwFlags: u32,
    pub TlsMapIndex: u32,
    pub ppTlsSlot: *mut *mut std::ffi::c_void,
    pub cComInits: u32,
    pub cOleInits: u32,
    pub cCalls: u32,
    pub pServerCall: *mut std::ffi::c_void,
    pub pCallObjectCache: *mut std::ffi::c_void,
    pub pContextStack: *mut std::ffi::c_void,
    pub pObjServer: *mut std::ffi::c_void,
    pub dwTIDCaller: u32,
    pub pCurrentCtxForNefariousReaders: *mut std::ffi::c_void,
    pub pCurrentContext: *mut std::ffi::c_void
}

#[repr(transparent)]
#[derive(core::cmp::PartialEq, core::cmp::Eq)]
pub struct PLM_TASKCOMPLETION_CATEGORY_FLAGS(pub u32);
pub const PT_TC_NONE: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x0);
pub const PT_TC_PBM: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x1);
pub const PT_TC_FILEOPENPICKER: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x2);
pub const PT_TC_SHARING: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x4);
pub const PT_TC_PRINTING: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x8);
pub const PT_TC_GENERIC: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x10);
pub const PT_TC_CAMERA_DCA: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x20);
pub const PT_TC_PRINTER_DCA: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x40);
pub const PT_TC_PLAYTO: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x80);
pub const PT_TC_FILESAVEPICKER: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x100);
pub const PT_TC_CONTACTPICKER: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x200);
pub const PT_TC_CACHEDFILEUPDATER_LOCAL: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x400);
pub const PT_TC_CACHEDFILEUPDATER_REMOTE: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x800);
pub const PT_TC_ERROR_REPORT: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x2000);
pub const PT_TC_DATA_PACKAGE: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x4000);
pub const PT_TC_CRASHDUMP: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x10000);
pub const PT_TC_STREAMEDFILE: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x20000);
pub const PT_TC_PBM_COMMUNICATION: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x80000);
pub const PT_TC_HOSTEDAPPLICATION: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x100000);
pub const PT_TC_MEDIA_CONTROLS_ACTIVE: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x200000);
pub const PT_TC_EMPTYHOST: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x400000);
pub const PT_TC_SCANNING: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x800000);
pub const PT_TC_ACTIONS: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x1000000);
pub const PT_TC_KERNEL_MODE: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x20000000);
pub const PT_TC_REALTIMECOMM: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x40000000);
pub const PT_TC_IGNORE_NAV_LEVEL_FOR_CS: PLM_TASKCOMPLETION_CATEGORY_FLAGS = PLM_TASKCOMPLETION_CATEGORY_FLAGS(0x80000000);
impl core::marker::Copy for PLM_TASKCOMPLETION_CATEGORY_FLAGS {}
impl core::clone::Clone for PLM_TASKCOMPLETION_CATEGORY_FLAGS {
    fn clone(&self) -> Self {
        *self
    }
}
impl core::default::Default for PLM_TASKCOMPLETION_CATEGORY_FLAGS {
    fn default() -> Self {
        Self(0)
    }
}
impl core::fmt::Debug for PLM_TASKCOMPLETION_CATEGORY_FLAGS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("_PLM_TASKCOMPLETION_CATEGORY_FLAGS").field(&self.0).finish()
    }
}

pub const CLSID_OSTaskCompletion: windows::core::GUID = windows::core::GUID::from_u128(0x07fc2b94_5285_417e_8ac3c2ce5240b0fa);
#[repr(transparent)]
pub struct ITaskCompletionCallback(windows::core::IUnknown);
unsafe impl windows::core::Interface for ITaskCompletionCallback {
    const IID: windows::core::GUID = windows::core::GUID::from_u128(0xe3a475cf_34ea_4e9a_9f3e_48ce5c6e4e57);
}
unsafe impl windows::core::Vtable for ITaskCompletionCallback {
    type Vtable = ITaskCompletionCallback_Vtbl;
}
#[repr(C)]
pub struct ITaskCompletionCallback_Vtbl {
    pub base__: windows::core::IUnknown_Vtbl,
    pub Proc3: unsafe extern "system" fn(p0: i32, p1: i32) -> windows::core::HRESULT
}

pub const CLSID_CoreShellComServerRegistrar: windows::core::GUID = windows::core::GUID::from_u128(0x54e14197_88b0_442f_b9a386837061e2fb);
#[repr(transparent)]
pub struct ICoreShellComServerRegistrar(windows::core::IUnknown);
unsafe impl windows::core::Interface for ICoreShellComServerRegistrar {
    const IID: windows::core::GUID = windows::core::GUID::from_u128(0x27eb33a5_77f9_4afe_ae056fdbbe720ee7);
}
unsafe impl windows::core::Vtable for ICoreShellComServerRegistrar {
    type Vtable = ICoreShellComServerRegistrar_Vtbl;
}
#[repr(C)]
pub struct ICoreShellComServerRegistrar_Vtbl {
    pub base__: windows::core::IUnknown_Vtbl,
    pub RegisterCOMServer: unsafe extern "system" fn(rclsid: *const windows::core::GUID, pUnk: *mut std::ffi::c_void, ServerTag: *mut u32) -> windows::core::HRESULT,
    pub UnregisterCOMServer: unsafe extern "system" fn(ServerTag: u32) -> windows::core::HRESULT,
    pub DuplicateHandle: unsafe extern "system" fn(dwSourceProcessId: u32, SourceHandle: windows::Win32::Foundation::HANDLE, dwTargetProcessId: u32, lpTargetHandle: *mut windows::Win32::Foundation::HANDLE, dwDesiredAccess: u32, bInheritHandle: windows::Win32::Foundation::BOOL, dwOptions: u32) -> windows::core::HRESULT,
    pub OpenProcess: unsafe extern "system" fn(dwDesiredAccess: u32, bInheritHandle: windows::Win32::Foundation::BOOL, SourceProcessId: u32, TargetProcessId: u32, lpTargetHandle: *mut windows::Win32::Foundation::HANDLE) -> windows::core::HRESULT,
    pub GetAppIdFromProcessId: unsafe extern "system" fn(dwProcessId: u32, AppId: *mut windows::core::HSTRING) -> windows::core::HRESULT,
    pub CoreQueryWindowService: unsafe extern "system" fn(hWindowHandle: windows::Win32::Foundation::HWND, GuidInfo: windows::core::GUID, IUnknownInterface: *mut *mut windows::core::IUnknown) -> windows::core::HRESULT,
    pub CoreQueryWindowServiceEx: unsafe extern "system" fn(hWindowHandle: windows::Win32::Foundation::HWND, hHandle: windows::Win32::Foundation::HWND, GuidInfo: windows::core::GUID, IUnknownInterface: *mut *mut windows::core::IUnknown) -> windows::core::HRESULT,
    pub GetUserContextForProcess: unsafe extern "system" fn(dwProcessId: u32, ContextId: *mut windows::Win32::Foundation::LUID) -> windows::core::HRESULT,
    pub BeginTaskCompletion: unsafe extern "system" fn(dwProcessId: u32, pTaskCompletionCallback: *mut ITaskCompletionCallback, Flags: PLM_TASKCOMPLETION_CATEGORY_FLAGS, TaskId: *mut u32) -> windows::core::HRESULT,
    pub EndTaskCompletion: unsafe extern "system" fn(TaskId: u32) -> windows::core::HRESULT
}

#[repr(transparent)]
#[derive(core::cmp::PartialEq, core::cmp::Eq)]
pub struct IPIDFlags(pub u32);
pub const IPIDF_CONNECTING: IPIDFlags = IPIDFlags(0x1);
pub const IPIDF_DISCONNECTED: IPIDFlags = IPIDFlags(0x2);
pub const IPIDF_SERVERENTRY: IPIDFlags = IPIDFlags(0x4);
pub const IPIDF_NOPING: IPIDFlags = IPIDFlags(0x8);
pub const IPIDF_COPY: IPIDFlags = IPIDFlags(0x10);
pub const IPIDF_VACANT: IPIDFlags = IPIDFlags(0x80);
pub const IPIDF_NONNDRSTUB: IPIDFlags = IPIDFlags(0x100);
pub const IPIDF_NONNDRPROXY: IPIDFlags = IPIDFlags(0x200);
pub const IPIDF_NOTIFYACT: IPIDFlags = IPIDFlags(0x400);
pub const IPIDF_TRIED_ASYNC: IPIDFlags = IPIDFlags(0x800);
pub const IPIDF_ASYNC_SERVER: IPIDFlags = IPIDFlags(0x1000);
pub const IPIDF_DEACTIVATED: IPIDFlags = IPIDFlags(0x2000);
pub const IPIDF_WEAKREFCACHE: IPIDFlags = IPIDFlags(0x4000);
pub const IPIDF_STRONGREFCACHE: IPIDFlags = IPIDFlags(0x8000);
pub const IPIDF_UNSECURECALLSALLOWED: IPIDFlags = IPIDFlags(0x10000);
impl core::marker::Copy for IPIDFlags {}
impl core::clone::Clone for IPIDFlags {
    fn clone(&self) -> Self {
        *self
    }
}
impl core::default::Default for IPIDFlags {
    fn default() -> Self {
        Self(0)
    }
}
impl core::fmt::Debug for IPIDFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("IPIDFlags").field(&self.0).finish()
    }
}
impl core::ops::BitOr for IPIDFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}
impl core::ops::BitAnd for IPIDFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MInterfacePointer {
    pub ulCntData: u32,
    pub abData: [u8; 1]
}
pub type PMInterfacePointer = *mut MInterfacePointer;

pub type OXID = u64;
pub type OID = u64;
pub type REFIPID = *const windows::core::GUID;
pub type REFGUID = *const windows::core::GUID;
pub type REFIID = *const windows::core::GUID;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IPID {
    pub offset: u16,
    pub page: u16,

    pub pid: u16,
    pub tid: u16,

    pub seq: [u8; 8]
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct tagSTDOBJREF {
    pub flags: u32,
    pub cPublicRefs: u32,
    pub oxid: OXID,
    pub oid: OID,
    pub ipid: IPID
}
pub type STDOBJREF = tagSTDOBJREF;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct tagREMQIRESULT {
    pub hResult: windows::core::HRESULT,
    pub std: STDOBJREF
}
pub type REMQIRESULT = tagREMQIRESULT;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct tagREMINTERFACEREF {
    pub ipid: IPID,
    pub cPublicRefs: u32,
    pub cPrivateRefs: u32
}
pub type REMINTERFACEREF = tagREMINTERFACEREF;

pub type PTRMEM = u64;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct tagXAptCallback {
    pub pfnCallback: PTRMEM,                    // what to execute. e.g. LoadLibraryA, EtwpCreateEtwThread
    pub pParam: PTRMEM,                         // parameter to callback.
    pub pServerCtx: PTRMEM,                     // combase!g_pMTAEmptyCtx
    pub pUnk: PTRMEM,                           // Not required
    pub iid: windows::core::GUID,               // Not required
    pub iMethod: i32,                           // Not required
    pub guidProcessSecret: windows::core::GUID  // combase!CProcessSecret::s_guidOle32Secret
}
pub type XAptCallback = tagXAptCallback;

// Used on most recent builds of Windows.
#[repr(transparent)]
pub struct IRundown(windows::core::IUnknown);
unsafe impl windows::core::Interface for IRundown {
    const IID: windows::core::GUID = windows::core::GUID::from_u128(0x00000134_0000_0000_c000_000000000046);
}
unsafe impl windows::core::Vtable for IRundown {
    type Vtable = IRundown_Vtbl;
}
#[repr(C)]
pub struct IRundown_Vtbl {
    pub base__: windows::core::IUnknown_Vtbl,
    pub RemQueryInterface: unsafe extern "system" fn(ripid: REFIPID, cRefs: u32, cIids: u16, iids: *mut windows::core::GUID, ppQIResults: *mut *mut REMQIRESULT) -> windows::core::HRESULT,
    pub RemAddRef: unsafe extern "system" fn(cInterfaceRefs: u16, InterfaceRefs: *mut REMINTERFACEREF, pResults: *mut windows::core::HRESULT) -> windows::core::HRESULT,
    pub RemRelease: unsafe extern "system" fn(cInterfaceRefs: u16, InterfaceRefs: *mut REMINTERFACEREF) -> windows::core::HRESULT,
    pub RemQueryInterface2: unsafe extern "system" fn(ripid: REFIPID, cIids: u32, piids: *mut windows::core::GUID, phr: *mut windows::core::HRESULT, ppMIFs: *mut *mut MInterfacePointer) -> windows::core::HRESULT,
    pub AcknowledgeMarshalingSets: unsafe extern "system" fn(cMarshalingSets: u16, pMarshalingSets: *mut ULONG_PTR) -> windows::core::HRESULT,
    pub RemChangeRef: unsafe extern "system" fn(flags: u32, cInterfaceRefs: u16, InterfaceRefs: *mut REMINTERFACEREF) -> windows::core::HRESULT,
    pub DoCallback: unsafe extern "system" fn(pParam: *mut XAptCallback) -> windows::core::HRESULT,
    pub DoNonreentrantCallback: unsafe extern "system" fn(pParam: *mut XAptCallback) -> windows::core::HRESULT,
    pub GetInterfaceNameFromIPID: unsafe extern "system" fn(ipid: *mut IPID, Name: *mut windows::core::HSTRING) -> windows::core::HRESULT,
    pub RundownOid: unsafe extern "system" fn(cOid: u32, aOid: *mut OID, aRundownStatus: *mut u8) -> windows::core::HRESULT
}

// Used on legacy systems (Vista, Windows 7, Windows 2008)
#[repr(transparent)]
pub struct IRundownLegacy(windows::core::IUnknown);
unsafe impl windows::core::Interface for IRundownLegacy {
    const IID: windows::core::GUID = windows::core::GUID::from_u128(0x00000134_0000_0000_c000_000000000046);
}
unsafe impl windows::core::Vtable for IRundownLegacy {
    type Vtable = IRundownLegacy_Vtbl;
}
#[repr(C)]
pub struct IRundownLegacy_Vtbl {
    pub base__: windows::core::IUnknown_Vtbl,
    pub RemQueryInterface: unsafe extern "system" fn(ripid: REFIPID, cRefs: u32, cIids: u16, iids: *mut windows::core::GUID, ppQIResults: *mut *mut REMQIRESULT) -> windows::core::HRESULT,
    pub RemAddRef: unsafe extern "system" fn(cInterfaceRefs: u16, InterfaceRefs: *mut REMINTERFACEREF, pResults: *mut windows::core::HRESULT) -> windows::core::HRESULT,
    pub RemRelease: unsafe extern "system" fn(cInterfaceRefs: u16, InterfaceRefs: *mut REMINTERFACEREF) -> windows::core::HRESULT,
    pub RemQueryInterface2: unsafe extern "system" fn(ripid: REFIPID, cIids: u32, piids: *mut windows::core::GUID, phr: *mut windows::core::HRESULT, ppMIFs: *mut *mut MInterfacePointer) -> windows::core::HRESULT,
    pub RemChangeRef: unsafe extern "system" fn(flags: u32, cInterfaceRefs: u16, InterfaceRefs: *mut REMINTERFACEREF) -> windows::core::HRESULT,
    pub DoCallback: unsafe extern "system" fn(pParam: *mut XAptCallback) -> windows::core::HRESULT,
    pub RundownOid: unsafe extern "system" fn(cOid: u32, aOid: *mut OID, aRundownStatus: *mut u8) -> windows::core::HRESULT
}
// use winapi::um::unknwnbase::*;
// use windows::Win32::System::Com::IStream;
// use windows::core::{HRESULT, GUID};
// use core::ffi::c_void;

// RIDL!{#[uuid(0x000001c8, 0x0000, 0x0000, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46)]
// interface IMarshalEnvoy(IMarshalEnvoyVtbl): IUnknown(IUnknownVtbl) {
//     fn GetEnvoyUnmarshalClass(
//         dwDestContext: u32,
//         pclsid: *mut windows::core::GUID,
//     ) -> windows::core::HRESULT,
//     fn GetEnvoySizeMax(
//         dwDestContext: u32,
//         pcb: *mut u32,
//     ) -> windows::core::HRESULT,
//     fn MarshalEnvoy(
//         pstm: *mut windows::Win32::System::Com::IStream,
//         dwDestContext: u32,
//     ) -> windows::core::HRESULT,
//     fn UnmarshalEnvoy(
//         pstm: *mut windows::Win32::System::Com::IStream,
//         riid: REFIID,
//         ppv: *mut *mut core::ffi::c_void,
//     ) -> windows::core::HRESULT,
// }}

// #[repr(C)]
// pub struct IMarshalEnvoy {
//     pub lpVtbl: *const IMarshalEnvoy_Vtbl
// }
// impl IMarshalEnvoy {
//     #[inline]
//     pub unsafe fn GetEnvoyUnmarshalClass(&self, dwDestContext: u32, pclsid: *mut windows::core::GUID) -> windows::core::HRESULT {
//         ((*self.lpVtbl).GetEnvoyUnmarshalClass)(self as *const _ as *mut _, dwDestContext, pclsid)
//     }
//     #[inline]
//     pub unsafe fn GetEnvoySizeMax(&self,  dwDestContext: u32, pcb: *mut u32) -> windows::core::HRESULT {
//         ((*self.lpVtbl).GetEnvoySizeMax)(self as *const _ as *mut _, dwDestContext, pcb)
//     }
//     #[inline]
//     pub unsafe fn MarshalEnvoy(&self, pstm: *mut windows::Win32::System::Com::IStream, dwDestContext: u32) -> windows::core::HRESULT {
//         ((*self.lpVtbl).MarshalEnvoy)(self as *const _ as *mut _, pstm, dwDestContext)
//     }
// }
#[repr(transparent)]
pub struct IMarshalEnvoy(windows::core::IUnknown);
impl IMarshalEnvoy {
    pub unsafe fn GetEnvoyUnmarshalClass(&self, dwDestContext: u32, pclsid: *mut windows::core::GUID) -> windows::core::Result<()> {
        (::windows::core::Vtable::vtable(self).GetEnvoyUnmarshalClass)(::windows::core::Vtable::as_raw(self), dwDestContext, ::core::mem::transmute(pclsid)).ok()
    }
    pub unsafe fn GetEnvoySizeMax(&self,  dwDestContext: u32, pcb: *mut u32) -> windows::core::Result<()> {
        (::windows::core::Vtable::vtable(self).GetEnvoySizeMax)(::windows::core::Vtable::as_raw(self), dwDestContext, ::core::mem::transmute(pcb)).ok()
    }
    pub unsafe fn MarshalEnvoy(&self, pstm: ::windows::Win32::System::Com::IStream, dwDestContext: u32) -> windows::core::Result<()> {
        (::windows::core::Vtable::vtable(self).MarshalEnvoy)(::windows::core::Vtable::as_raw(self), ::core::mem::transmute(pstm), dwDestContext).ok()
    }
    pub unsafe fn UnmarshalEnvoy(&self, pstm: windows::Win32::System::Com::IStream, riid: REFIID, ppv: *mut *mut ::core::ffi::c_void) -> windows::core::Result<()> {
        (::windows::core::Vtable::vtable(self).UnmarshalEnvoy)(::windows::core::Vtable::as_raw(self), ::core::mem::transmute(pstm), ::core::mem::transmute(riid), ::core::mem::transmute(ppv)).ok()
    }
}
impl ::core::clone::Clone for IMarshalEnvoy {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl ::core::cmp::PartialEq for IMarshalEnvoy {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
unsafe impl windows::core::Interface for IMarshalEnvoy {
    const IID: windows::core::GUID = windows::core::GUID::from_u128(0x000001c8_0000_0000_c000_000000000046);
}
unsafe impl windows::core::Vtable for IMarshalEnvoy {
    type Vtable = IMarshalEnvoy_Vtbl;
}
::windows::core::interface_hierarchy!(IMarshalEnvoy, windows::core::IUnknown);
#[repr(C)]
pub struct IMarshalEnvoy_Vtbl {
    pub base__: windows::core::IUnknown_Vtbl,
    pub GetEnvoyUnmarshalClass: unsafe extern "system" fn(this: *mut ::core::ffi::c_void, dwDestContext: u32, pclsid: *mut windows::core::GUID) -> windows::core::HRESULT,
    pub GetEnvoySizeMax: unsafe extern "system" fn(this: *mut ::core::ffi::c_void, dwDestContext: u32, pcb: *mut u32) -> windows::core::HRESULT,
    pub MarshalEnvoy: unsafe extern "system" fn(this: *mut ::core::ffi::c_void, pstm: windows::Win32::System::Com::IStream, dwDestContext: u32) -> windows::core::HRESULT,
    pub UnmarshalEnvoy: unsafe extern "system" fn(this: *mut ::core::ffi::c_void, pstm: windows::Win32::System::Com::IStream, riid: REFIID, ppv: *mut *mut ::core::ffi::c_void) -> windows::core::HRESULT
}

// pub trait IMarshalEnvoy_Impl: Sized {
//     fn GetEnvoyUnmarshalClass(&self, dwDestContext: u32, pclsid: *mut windows::core::GUID) -> windows::core::Result<()>;
//     fn GetEnvoySizeMax(&self,  dwDestContext: u32, pcb: *mut u32) -> windows::core::Result<()>;
//     fn MarshalEnvoy(&self, pstm: *mut windows::Win32::System::Com::IStream, dwDestContext: u32) -> windows::core::Result<()>;
//     fn UnmarshalEnvoy(&self, pstm: *mut windows::Win32::System::Com::IStream, riid: REFIID, ppv: *mut *mut ::core::ffi::c_void) -> windows::core::Result<()>;
// }
// impl ::windows::core::RuntimeName for IMarshalEnvoy {}
// impl IMarshalEnvoy_Vtbl {
//     pub const fn new<Identity: ::windows::core::IUnknownImpl<Impl = Impl>, Impl: IMarshalEnvoy_Impl, const OFFSET: isize>() -> IMarshalEnvoy_Vtbl {
//         unsafe extern "system" fn GetEnvoyUnmarshalClass<Identity: ::windows::core::IUnknownImpl<Impl = Impl>, Impl: IMarshalEnvoy_Impl, const OFFSET: isize>(this: *mut ::core::ffi::c_void, dwDestContext: u32, pclsid: *mut windows::core::GUID) -> windows::core::HRESULT {
//             let this = (this as *const *const ()).offset(OFFSET) as *const Identity;
//             let this = (*this).get_impl();
//             this.GetEnvoyUnmarshalClass(::core::mem::transmute_copy(&dwDestContext), ::core::mem::transmute_copy(&pclsid)).into()
//         }
//         unsafe extern "system" fn GetEnvoySizeMax<Identity: ::windows::core::IUnknownImpl<Impl = Impl>, Impl: IMarshalEnvoy_Impl, const OFFSET: isize>(this: *mut ::core::ffi::c_void, dwDestContext: u32, pcb: *mut u32) -> windows::core::HRESULT {
//             let this = (this as *const *const ()).offset(OFFSET) as *const Identity;
//             let this = (*this).get_impl();
//             this.GetEnvoySizeMax(::core::mem::transmute_copy(&dwDestContext), ::core::mem::transmute_copy(&pcb)).into()
//         }
//         unsafe extern "system" fn MarshalEnvoy<Identity: ::windows::core::IUnknownImpl<Impl = Impl>, Impl: IMarshalEnvoy_Impl, const OFFSET: isize>(this: *mut ::core::ffi::c_void, pstm: *mut windows::Win32::System::Com::IStream, dwDestContext: u32) -> windows::core::HRESULT {
//             let this = (this as *const *const ()).offset(OFFSET) as *const Identity;
//             let this = (*this).get_impl();
//             this.MarshalEnvoy(::core::mem::transmute(&pstm), ::core::mem::transmute_copy(&dwDestContext)).into()
//         }
//         unsafe extern "system" fn UnmarshalEnvoy<Identity: ::windows::core::IUnknownImpl<Impl = Impl>, Impl: IMarshalEnvoy_Impl, const OFFSET: isize>(this: *mut ::core::ffi::c_void, pstm: *mut windows::Win32::System::Com::IStream, riid: REFIID, ppv: *mut *mut ::core::ffi::c_void) -> windows::core::HRESULT {
//             let this = (this as *const *const ()).offset(OFFSET) as *const Identity;
//             let this = (*this).get_impl();
//             this.UnmarshalEnvoy(::core::mem::transmute(&pstm), ::core::mem::transmute_copy(&riid), ::core::mem::transmute(&ppv)).into()
//         }
//         Self {
//             base__: ::windows::core::IUnknown_Vtbl::new::<Identity, OFFSET>(),
//             GetEnvoyUnmarshalClass: GetEnvoyUnmarshalClass::<Identity, Impl, OFFSET>,
//             GetEnvoySizeMax: GetEnvoySizeMax::<Identity, Impl, OFFSET>,
//             MarshalEnvoy: MarshalEnvoy::<Identity, Impl, OFFSET>,
//             UnmarshalEnvoy: UnmarshalEnvoy::<Identity, Impl, OFFSET>,
//         }
//     }
//     pub fn matches(iid: &windows::core::GUID) -> bool {
//         iid == &<IMarshalEnvoy as ::windows::core::Interface>::IID
//     }
// }

pub unsafe fn CoGetObjectContext<T>(riid: *const ::windows::core::GUID) -> ::windows::core::Result<T>
where
    T: ::windows::core::Interface
{
    #[cfg_attr(windows, link(name = "windows"))]
    extern "system" {
        fn CoGetObjectContext(riid: *const ::windows::core::GUID, ppv: *mut *mut ::core::ffi::c_void) -> ::windows::core::HRESULT;
    }
    let mut result__ = ::core::option::Option::None;
    CoGetObjectContext(::core::mem::transmute(riid), &mut result__ as *mut _ as *mut _).and_some(result__)
}
