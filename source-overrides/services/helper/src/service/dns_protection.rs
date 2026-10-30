use once_cell::sync::Lazy;
use serde::Serialize;
use std::io;
use std::sync::{Mutex, Once};
use std::time::Duration;

#[derive(Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardStatus {
    pub armed: bool,
    pub bound: bool,
    pub session_id: String,
    pub interface_luid: Option<String>,
    pub error_code: Option<String>,
    pub diagnostic_error: bool,
    pub diagnostic_os_error: Option<i32>,
}

struct Guard {
    session_id: String,
    native: native::NativeGuard,
    error: Option<String>,
}

static GUARD: Lazy<Mutex<Option<Guard>>> = Lazy::new(|| Mutex::new(None));
static WATCHER: Once = Once::new();

pub fn configure(session_id: &str, enabled: bool) -> io::Result<GuardStatus> {
    let mut guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
    if !enabled {
        if guard.as_ref().is_some_and(|g| g.session_id != session_id) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "guard session mismatch",
            ));
        }
        *guard = None;
        super::dns_journal::record("guard_released", "success", session_id, None);
        return Ok(GuardStatus::default());
    }
    if let Some(current) = guard.as_mut() {
        current.native.refresh()?;
        current.session_id = session_id.to_owned();
        current.error = None;
    } else {
        *guard = Some(Guard {
            session_id: session_id.to_owned(),
            native: native::NativeGuard::new()?,
            error: None,
        });
    }
    WATCHER.call_once(|| {
        std::thread::spawn(|| loop {
            std::thread::sleep(Duration::from_millis(250));
            let mut guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(current) = guard.as_mut() {
                let previous = current.native.luid();
                if let Err(error) = current.native.refresh() {
                    if current.error.is_none() {
                        super::dns_journal::record(
                            "guard_update_failed",
                            "failed",
                            &current.session_id,
                            error.raw_os_error(),
                        );
                    }
                    current.error = Some(format!(
                        "DP_GUARD_FAILED:{}",
                        error.raw_os_error().unwrap_or(0)
                    ));
                } else {
                    if previous != current.native.luid() {
                        super::dns_journal::record(
                            if current.native.luid().is_some() {
                                "guard_bound"
                            } else {
                                "guard_waiting_tun"
                            },
                            "success",
                            &current.session_id,
                            None,
                        );
                    }
                    current.error = None;
                }
            }
        });
    });
    super::dns_journal::record("guard_armed", "success", session_id, None);
    Ok(snapshot(guard.as_ref()))
}

pub fn status() -> GuardStatus {
    let guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
    snapshot(guard.as_ref())
}

pub fn shutdown() {
    *GUARD.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

fn snapshot(guard: Option<&Guard>) -> GuardStatus {
    match guard {
        Some(g) => GuardStatus {
            armed: true,
            bound: g.native.luid().is_some() && g.error.is_none(),
            session_id: g.session_id.clone(),
            interface_luid: g.native.luid().map(|id| id.to_string()),
            error_code: g.error.clone(),
            diagnostic_error: super::dns_journal::failed(),
            diagnostic_os_error: super::dns_journal::last_os_error(),
        },
        None => GuardStatus::default(),
    }
}

#[cfg(not(windows))]
mod native {
    use std::io;
    pub struct NativeGuard;
    impl NativeGuard {
        pub fn new() -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows DNS Guard required",
            ))
        }
        pub fn refresh(&mut self) -> io::Result<()> {
            Ok(())
        }
        pub fn luid(&self) -> Option<u64> {
            None
        }
    }
}

#[cfg(windows)]
mod native {
    use std::io;
    use std::mem::zeroed;
    use std::ptr::{null, null_mut};
    use windows_sys::core::GUID;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, IF_TYPE_PROP_VIRTUAL, MIB_IF_TABLE2,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NdisMediumIP;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

    const SUBLAYER: GUID = GUID::from_u128(0x5b3b80a6_4e39_48e5_9f6c_2cc01ddb9821);

    pub struct NativeGuard {
        engine: isize,
        filters: Vec<u64>,
        luid: Option<u64>,
    }

    impl NativeGuard {
        pub fn new() -> io::Result<Self> {
            unsafe {
                let mut session: FWPM_SESSION0 = zeroed();
                session.flags = FWPM_SESSION_FLAG_DYNAMIC;
                let mut engine = 0;
                check(FwpmEngineOpen0(null(), 10, null(), &session, &mut engine))?;
                let mut guard = Self {
                    engine,
                    filters: Vec::new(),
                    luid: None,
                };
                let mut layer: FWPM_SUBLAYER0 = zeroed();
                let mut name: Vec<u16> = "FlClash DNS Protection\0".encode_utf16().collect();
                layer.subLayerKey = SUBLAYER;
                layer.displayData.name = name.as_mut_ptr();
                layer.weight = u16::MAX - 1;
                check(FwpmSubLayerAdd0(engine, &layer, null_mut()))?;
                guard.replace_filters(find_tun()?)?;
                Ok(guard)
            }
        }

        pub fn luid(&self) -> Option<u64> {
            self.luid
        }

        pub fn refresh(&mut self) -> io::Result<()> {
            let current = find_tun()?;
            if current != self.luid {
                unsafe {
                    self.replace_filters(current)?;
                }
            }
            Ok(())
        }

        unsafe fn replace_filters(&mut self, luid: Option<u64>) -> io::Result<()> {
            check(FwpmTransactionBegin0(self.engine, 0))?;
            let result = self.install_filters(luid);
            match result {
                Ok(ids) => {
                    if let Err(error) = check(FwpmTransactionCommit0(self.engine)) {
                        FwpmTransactionAbort0(self.engine);
                        return Err(error);
                    }
                    self.filters = ids;
                    self.luid = luid;
                    Ok(())
                }
                Err(error) => {
                    FwpmTransactionAbort0(self.engine);
                    Err(error)
                }
            }
        }

        unsafe fn install_filters(&self, luid: Option<u64>) -> io::Result<Vec<u64>> {
            for id in &self.filters {
                check(FwpmFilterDeleteById0(self.engine, *id))?;
            }
            let mut ids = Vec::new();
            let mut interface = luid.unwrap_or(0);
            for layer in [
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            ] {
                for port in [53_u16, 853] {
                    let mut conditions = vec![
                        not_loopback(),
                        integer_condition(FWPM_CONDITION_IP_REMOTE_PORT, port),
                    ];
                    if luid.is_some() {
                        let mut condition: FWPM_FILTER_CONDITION0 = zeroed();
                        condition.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
                        condition.matchType = FWP_MATCH_NOT_EQUAL;
                        condition.conditionValue.r#type = FWP_UINT64;
                        condition.conditionValue.Anonymous.uint64 = &mut interface;
                        conditions.push(condition);
                    }
                    ids.push(self.add_filter(layer, &mut conditions, FWP_ACTION_BLOCK, 10)?);
                }
            }
            let mut ipv6 = vec![not_loopback()];
            ids.push(self.add_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                &mut ipv6,
                FWP_ACTION_BLOCK,
                11,
            )?);
            for kind in [133_u16, 134, 135, 136] {
                let mut protocol: FWPM_FILTER_CONDITION0 = zeroed();
                protocol.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                protocol.matchType = FWP_MATCH_EQUAL;
                protocol.conditionValue.r#type = FWP_UINT8;
                protocol.conditionValue.Anonymous.uint8 = 58;
                let mut ndp = vec![
                    protocol,
                    integer_condition(FWPM_CONDITION_IP_LOCAL_PORT, kind),
                ];
                ids.push(self.add_filter(
                    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                    &mut ndp,
                    FWP_ACTION_PERMIT,
                    12,
                )?);
            }
            Ok(ids)
        }

        unsafe fn add_filter(
            &self,
            layer: GUID,
            conditions: &mut [FWPM_FILTER_CONDITION0],
            action: u32,
            weight: u8,
        ) -> io::Result<u64> {
            let mut filter: FWPM_FILTER0 = zeroed();
            let mut name: Vec<u16> = "FlClash DNS Protection\0".encode_utf16().collect();
            filter.displayData.name = name.as_mut_ptr();
            filter.layerKey = layer;
            filter.subLayerKey = SUBLAYER;
            filter.weight.r#type = FWP_UINT8;
            filter.weight.Anonymous.uint8 = weight;
            filter.action.r#type = action;
            filter.numFilterConditions = conditions.len() as u32;
            filter.filterCondition = conditions.as_mut_ptr();
            let mut id = 0;
            check(FwpmFilterAdd0(self.engine, &filter, null_mut(), &mut id))?;
            Ok(id)
        }
    }

    impl Drop for NativeGuard {
        fn drop(&mut self) {
            unsafe {
                FwpmEngineClose0(self.engine);
            }
        }
    }

    unsafe fn not_loopback() -> FWPM_FILTER_CONDITION0 {
        let mut condition: FWPM_FILTER_CONDITION0 = zeroed();
        condition.fieldKey = FWPM_CONDITION_FLAGS;
        condition.matchType = FWP_MATCH_FLAGS_NONE_SET;
        condition.conditionValue.r#type = FWP_UINT32;
        condition.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
        condition
    }

    unsafe fn integer_condition(field: GUID, value: u16) -> FWPM_FILTER_CONDITION0 {
        let mut condition: FWPM_FILTER_CONDITION0 = zeroed();
        condition.fieldKey = field;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.r#type = FWP_UINT16;
        condition.conditionValue.Anonymous.uint16 = value;
        condition
    }

    fn check(code: u32) -> io::Result<()> {
        if code == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(code as i32))
        }
    }

    fn find_tun() -> io::Result<Option<u64>> {
        unsafe {
            let mut table: *mut MIB_IF_TABLE2 = null_mut();
            check(GetIfTable2(&mut table))?;
            let rows =
                std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
            let mut found = None;
            for row in rows {
                let length = row
                    .Alias
                    .iter()
                    .position(|x| *x == 0)
                    .unwrap_or(row.Alias.len());
                if String::from_utf16_lossy(&row.Alias[..length]) == "FlClashDNS"
                    && row.OperStatus == 1
                    && row.Type == IF_TYPE_PROP_VIRTUAL
                    && row.MediaType == NdisMediumIP
                {
                    found = Some(row.InterfaceLuid.Value);
                    break;
                }
            }
            FreeMibTable(table.cast());
            Ok(found)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn idle_guard_does_not_claim_protection() {
        let status = snapshot(None);
        assert!(!status.armed);
        assert!(!status.bound);
        assert!(status.interface_luid.is_none());
    }
}
