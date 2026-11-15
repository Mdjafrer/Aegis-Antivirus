use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use sled::Db;
use std::sync::Mutex;
use lazy_static::lazy_static;
use std::io::Read;
use std::path::Path;

// YARA 和 Mmap
use yara_x::{Compiler, Rules};
use memmap2::Mmap;
use std::sync::OnceLock;

// Windows API 签名验证
use windows::core::{PCWSTR, GUID};
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO, 
    WTD_UI_NONE, WTD_REVOKE_NONE, WTD_CHOICE_FILE, 
    WTD_STATEACTION_VERIFY, WTD_STATEACTION_CLOSE
};
use windows::Win32::Foundation::HWND;

lazy_static! {
    static ref DB: Mutex<Option<Db>> = Mutex::new(None);
    static ref TRUST_DB: Mutex<Option<Db>> = Mutex::new(None);
    static ref BUILTIN_DB: Mutex<Option<Db>> = Mutex::new(None);
    static ref CLOUD_CACHE_DB: Mutex<Option<Db>> = Mutex::new(None);
}

static YARA_RULES: OnceLock<Rules> = OnceLock::new();

#[repr(C)]
pub struct AVScanResult {
    pub is_virus: i32,
    pub virus_name: [u8; 256],
    pub engine_name: [u8; 64],
    pub md5: [u8; 33],
    pub risk_score: i32,
}

// 终极签名验证（针对 windows 0.52 版本严格类型修复）
unsafe fn is_file_signed(file_path: &str) -> bool {
    let wide_path: Vec<u16> = file_path.encode_utf16().chain(std::iter::once(0)).collect();
    
    let file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide_path.as_ptr()),
        hFile: Default::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut trust_data: WINTRUST_DATA = std::mem::zeroed();
    trust_data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    
    trust_data.Anonymous.pFile = &file_info as *const _ as *mut _;

    let action_id = GUID::from_u128(0x00AAC56B_CD44_11d0_8CC2_00C04FC295EE);
    
    let ptr_data = &mut trust_data as *mut _ as *mut core::ffi::c_void;
    let ptr_action = &action_id as *const _ as *mut _;

    let result = WinVerifyTrust(HWND(0), ptr_action, ptr_data);
    
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(HWND(0), ptr_action, ptr_data);

    result == 0 
}

#[no_mangle]
pub unsafe extern "C" fn AV_Init(db_path: *const c_char, _clamav_path: *const c_char) -> i32 {
    let path_str = CStr::from_ptr(db_path).to_string_lossy().into_owned();
    
    if let Ok(db) = sled::open(&path_str) {
        *DB.lock().unwrap() = Some(db);
    } else { return 0; }

    if let Ok(trust_db) = sled::open(format!("{}_trust", path_str)) {
        *TRUST_DB.lock().unwrap() = Some(trust_db);
    } else { return 0; }

    if let Ok(builtin_db) = sled::open(format!("{}_builtin", path_str)) {
        *BUILTIN_DB.lock().unwrap() = Some(builtin_db);
    } else { return 0; }

    if let Ok(cache_db) = sled::open(format!("{}_cloudcache", path_str)) {
        *CLOUD_CACHE_DB.lock().unwrap() = Some(cache_db);
    } else { return 0; }

    // 加载 YARA 规则
    let db_path_obj = Path::new(&path_str);
    let yara_path = db_path_obj.parent().unwrap_or(Path::new(".")).join("sigbase_fixed.yar");
    
    if yara_path.exists() {
        let mut compiler = Compiler::new();
        if let Ok(yara_source) = std::fs::read_to_string(&yara_path) {
            if compiler.add_source(yara_source.as_str()).is_ok() {
                let _ = YARA_RULES.set(compiler.build());
                println!("[OK] YARA rules loaded successfully.");
            }
        }
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn AV_ScanFile(file_path: *const c_char, result: *mut AVScanResult) -> i32 {
    if file_path.is_null() || result.is_null() { return 0; }
    let path_str = match CStr::from_ptr(file_path).to_str() { Ok(s) => s, Err(_) => return 0 };
    
    (*result).is_virus = 0;
    (*result).risk_score = 0;

    let file_handle = match std::fs::File::open(path_str) { Ok(f) => f, Err(_) => return 0 };
    
    // 1. MD5 计算
    let mut file_md5 = file_handle.try_clone().unwrap();
    let mut context = md5::Context::new();
    let mut buffer = [0u8; 65536];
    while let Ok(n) = file_md5.read(&mut buffer) {
        if n == 0 { break; }
        context.consume(&buffer[..n]);
    }
    let md5_hex = format!("{:x}", context.compute());
    let md5_bytes = md5_hex.as_bytes();
    ptr::copy_nonoverlapping(md5_bytes.as_ptr(), (*result).md5.as_mut_ptr(), md5_bytes.len());

    // 2. 数字签名校验（放行合法系统文件）
    if is_file_signed(path_str) {
        return 0; 
    }

    // 3. 查内置白名单
    let builtin_lock = BUILTIN_DB.lock().unwrap();
    if let Some(db) = &*builtin_lock { if db.contains_key(md5_hex.as_bytes()).unwrap_or(false) { return 0; } }
    drop(builtin_lock);

    // 4. 查用户信任区
    let trust_lock = TRUST_DB.lock().unwrap();
    if let Some(db) = &*trust_lock { if db.contains_key(md5_hex.as_bytes()).unwrap_or(false) { return 0; } }
    drop(trust_lock);

    // 5. 查本地 MD5 病毒库
    let db_lock = DB.lock().unwrap();
    if let Some(db) = &*db_lock {
        if let Ok(Some(v_name)) = db.get(md5_hex.as_bytes()) {
            (*result).is_virus = 1;
            let name = v_name.to_vec();
            ptr::copy_nonoverlapping(name.as_ptr(), (*result).virus_name.as_mut_ptr(), name.len().min(255));
            let eng = b"Rust-MD5\0";
            ptr::copy_nonoverlapping(eng.as_ptr(), (*result).engine_name.as_mut_ptr(), eng.len());
            return 1;
        }
    }
    drop(db_lock);

    // 6. 启发式查杀
    let mut is_heuristic = false;
    let mut head_file = file_handle.try_clone().unwrap();
    let mut head_buffer = [0u8; 4096];
    if let Ok(n) = head_file.read(&mut head_buffer) {
        let head_data = String::from_utf8_lossy(&head_buffer[..n]).to_lowercase();
        if head_data.contains("powershell -enc") || (head_data.contains("cmd.exe /c") && head_data.contains("http")) {
            is_heuristic = true;
        }
    }

    // 7. YARA 扫描
    if let Some(rules) = YARA_RULES.get() {
        if let Ok(mmap) = unsafe { Mmap::map(&file_handle) } {
            let mut scanner = yara_x::Scanner::new(rules);
            if let Ok(scan_results) = scanner.scan(&mmap) {
                for rule in scan_results.matching_rules() {
                    (*result).is_virus = 1;
                    let name = format!("YARA.{}", rule.identifier());
                    let name_bytes = name.as_bytes();
                    ptr::copy_nonoverlapping(name_bytes.as_ptr(), (*result).virus_name.as_mut_ptr(), name_bytes.len().min(255));
                    let eng = b"YARA-Engine\0";
                    ptr::copy_nonoverlapping(eng.as_ptr(), (*result).engine_name.as_mut_ptr(), eng.len());
                    return 1;
                }
            }
        }
    }

    // 8. 启发式兜底
    if is_heuristic {
        (*result).is_virus = 1;
        let name = b"Heuristic.Suspicious\0";
        ptr::copy_nonoverlapping(name.as_ptr(), (*result).virus_name.as_mut_ptr(), name.len());
        let eng = b"Rust-Heuristic\0";
        ptr::copy_nonoverlapping(eng.as_ptr(), (*result).engine_name.as_mut_ptr(), eng.len());
        return 1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn AV_ScanCloudWithCache(md5_str: *const c_char, result: *mut AVScanResult) -> i32 {
    if md5_str.is_null() { return 0; }
    let md5 = match CStr::from_ptr(md5_str).to_str() { Ok(s) => s, Err(_) => return 0 };
    
    (*result).is_virus = 0;

    // 查缓存
    let cache_lock = CLOUD_CACHE_DB.lock().unwrap();
    if let Some(cache_db) = &*cache_lock {
        if let Ok(Some(v)) = cache_db.get(md5.as_bytes()) {
            if v.as_ref() == b"clean" { return 0; }
            if let Ok(name_str) = String::from_utf8(v.to_vec()) {
                (*result).is_virus = 1;
                let name_bytes = name_str.as_bytes();
                ptr::copy_nonoverlapping(name_bytes.as_ptr(), (*result).virus_name.as_mut_ptr(), name_bytes.len().min(255));
                let eng = b"Cloud-Cache\0";
                ptr::copy_nonoverlapping(eng.as_ptr(), (*result).engine_name.as_mut_ptr(), eng.len());
                return 1;
            }
        }
    }
    drop(cache_lock);

    // 获取环境变量中的 API Key
    let api_key = std::env::var("MALWAREBAZAAR_API_KEY").unwrap_or_else(|_| "YOUR_API_KEY_HERE".to_string());
    if api_key == "YOUR_API_KEY_HERE" || api_key.is_empty() { return 0; }

    let client = reqwest::blocking::Client::new();
    let res = client.post("https://mb-api.abuse.ch/api/v1/")
        .header("Auth-Key", &api_key)
        .form(&[("query", "get_info"), ("hash", md5)])
        .send();

    if let Ok(response) = res {
        if let Ok(json) = response.json::<serde_json::Value>() {
            let cache_lock = CLOUD_CACHE_DB.lock().unwrap();
            let cache_db = cache_lock.as_ref().unwrap();
            if json["query_status"] == "ok" {
                let _ = cache_db.insert(md5.as_bytes(), b"Cloud.MalwareBazaar.Malware".as_ref());
                let _ = cache_db.flush();
                (*result).is_virus = 1;
                let name = b"Cloud.MalwareBazaar.Malware\0";
                ptr::copy_nonoverlapping(name.as_ptr(), (*result).virus_name.as_mut_ptr(), name.len());
                let eng = b"Cloud-API\0";
                ptr::copy_nonoverlapping(eng.as_ptr(), (*result).engine_name.as_mut_ptr(), eng.len());
                return 1;
            } else {
                let _ = cache_db.insert(md5.as_bytes(), b"clean".as_ref());
                let _ = cache_db.flush();
                if cache_db.len() > 50000 {
                    let mut iter = cache_db.iter();
                    if let Some(Ok((old_key, _))) = iter.next() { let _ = cache_db.remove(old_key); }
                }
            }
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn AV_AddMD5(md5_str: *const c_char, virus_name: *const c_char) -> i32 {
    if md5_str.is_null() || virus_name.is_null() { return 0; }
    let md5 = match CStr::from_ptr(md5_str).to_str() { Ok(s) => s, Err(_) => return 0 };
    let name = match CStr::from_ptr(virus_name).to_str() { Ok(s) => s, Err(_) => return 0 };
    let db_lock = DB.lock().unwrap();
    if let Some(db) = &*db_lock {
        if db.insert(md5.as_bytes(), name.as_bytes()).is_ok() { let _ = db.flush(); return 1; }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn AV_AddTrust(md5_str: *const c_char) -> i32 {
    if md5_str.is_null() { return 0; }
    let md5 = match CStr::from_ptr(md5_str).to_str() { Ok(s) => s, Err(_) => return 0 };
    let trust_lock = TRUST_DB.lock().unwrap();
    if let Some(trust_db) = &*trust_lock {
        if trust_db.insert(md5.as_bytes(), b"trusted").is_ok() { let _ = trust_db.flush(); return 1; }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn AV_RemoveTrust(md5_str: *const c_char) -> i32 {
    if md5_str.is_null() { return 0; }
    let md5 = match CStr::from_ptr(md5_str).to_str() { Ok(s) => s, Err(_) => return 0 };
    let trust_lock = TRUST_DB.lock().unwrap();
    if let Some(trust_db) = &*trust_lock {
        if trust_db.remove(md5.as_bytes()).unwrap_or(None).is_some() { let _ = trust_db.flush(); return 1; }
    }
    0
}