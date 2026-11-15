use eframe::egui::{self, Color32, Rounding};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use walkdir::WalkDir;
use libloading::{Library, Symbol};
use std::ffi::CString;
use std::os::raw::c_char;

#[repr(C)]
struct AVScanResult { is_virus: i32, virus_name: [u8; 256], engine_name: [u8; 64], md5: [u8; 33], risk_score: i32 }

#[derive(Clone)]
struct ThreatInfo { file_path: String, virus_name: String, md5: String }

struct CppEngine { lib: Library }

impl CppEngine {
    fn load(dll_path: &str, db_path: &str) -> Option<Self> {
        unsafe {
            let lib = Library::new(dll_path).ok()?;
            let init: Symbol<unsafe extern "C" fn(*const c_char, *const c_char) -> i32> = lib.get(b"AV_Init").ok()?;
            let c_db = CString::new(db_path).unwrap();
            let clam_path = CString::new("").unwrap();
            if init(c_db.as_ptr(), clam_path.as_ptr()) == 1 { Some(Self { lib }) } else { None }
        }
    }

    fn scan(&self, path: &str) -> Option<(String, String)> {
        unsafe {
            let scan_func: Symbol<unsafe extern "C" fn(*const c_char, *mut AVScanResult) -> i32> = self.lib.get(b"AV_ScanFile").ok()?;
            let c_path = CString::new(path).unwrap();
            let mut result = std::mem::zeroed::<AVScanResult>();
            if scan_func(c_path.as_ptr(), &mut result) == 1 {
                let name_end = result.virus_name.iter().position(|&b| b == 0).unwrap_or(256);
                let name = String::from_utf8_lossy(&result.virus_name[..name_end]).to_string();
                let eng_end = result.engine_name.iter().position(|&b| b == 0).unwrap_or(64);
                let eng = String::from_utf8_lossy(&result.engine_name[..eng_end]).to_string();
                let md5_end = result.md5.iter().position(|&b| b == 0).unwrap_or(33);
                let md5 = String::from_utf8_lossy(&result.md5[..md5_end]).to_string();
                return Some((format!("{}.{}", eng, name), md5));
            }
            None
        }
    }

    fn scan_cloud_with_cache(&self, md5: &str) -> Option<String> {
        unsafe {
            if let Ok(func) = self.lib.get::<Symbol<unsafe extern "C" fn(*const c_char, *mut AVScanResult) -> i32>>(b"AV_ScanCloudWithCache") {
                let c_md5 = CString::new(md5).unwrap();
                let mut result = std::mem::zeroed::<AVScanResult>();
                if func(c_md5.as_ptr(), &mut result) == 1 {
                    let name_end = result.virus_name.iter().position(|&b| b == 0).unwrap_or(256);
                    let name = String::from_utf8_lossy(&result.virus_name[..name_end]).to_string();
                    let eng_end = result.engine_name.iter().position(|&b| b == 0).unwrap_or(64);
                    let eng = String::from_utf8_lossy(&result.engine_name[..eng_end]).to_string();
                    return Some(format!("{}.{}", eng, name));
                }
            }
            None
        }
    }

    fn add_trust(&self, md5: &str) -> bool {
        unsafe {
            if let Ok(func) = self.lib.get::<Symbol<unsafe extern "C" fn(*const c_char) -> i32>>(b"AV_AddTrust") {
                let c_md5 = CString::new(md5).unwrap();
                return func(c_md5.as_ptr()) == 1;
            }
            false
        }
    }

    fn remove_trust(&self, md5: &str) -> bool {
        unsafe {
            if let Ok(func) = self.lib.get::<Symbol<unsafe extern "C" fn(*const c_char) -> i32>>(b"AV_RemoveTrust") {
                let c_md5 = CString::new(md5).unwrap();
                return func(c_md5.as_ptr()) == 1;
            }
            false
        }
    }
}

struct ScanState {
    is_scanning: Arc<AtomicBool>,
    is_cleaning: Arc<AtomicBool>,
    cleaning_msg: Arc<Mutex<String>>,
    scanned_count: Arc<AtomicUsize>,
    total_count: Arc<AtomicUsize>,
    threats: Arc<Mutex<Vec<ThreatInfo>>>,
    engine: Arc<Option<CppEngine>>,
}

struct AntivirusApp {
    scan_path: String,
    state: ScanState,
    display_threats: Vec<ThreatInfo>,
    show_trust_view: bool,
    test_md5_input: String,
}

impl Default for AntivirusApp {
    fn default() -> Self {
        let exe_dir = std::env::current_exe().unwrap_or_else(|_| PathBuf::from(".")).parent().unwrap_or(Path::new(".")).to_path_buf();
        // 注意：这里改成了 aegis_engine.dll
        let dll_path = exe_dir.join("aegis_engine.dll"); 
        let db_path = exe_dir.join("aegis_db");
        let engine = CppEngine::load(dll_path.to_str().unwrap_or("aegis_engine.dll"), db_path.to_str().unwrap_or("aegis_db"));

        let state = ScanState {
            is_scanning: Arc::new(AtomicBool::new(false)),
            is_cleaning: Arc::new(AtomicBool::new(false)),
            cleaning_msg: Arc::new(Mutex::new(String::new())),
            scanned_count: Arc::new(AtomicUsize::new(0)),
            total_count: Arc::new(AtomicUsize::new(0)),
            threats: Arc::new(Mutex::new(Vec::new())),
            engine: Arc::new(engine),
        };

        Self { 
            scan_path: "C:\\Windows\\System32".to_string(), 
            state, 
            display_threats: Vec::new(), 
            show_trust_view: false, 
            test_md5_input: String::new() 
        }
    }
}

impl eframe::App for AntivirusApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = Color32::from_rgb(18, 18, 22); 
        visuals.window_fill = Color32::from_rgb(24, 24, 28);
        visuals.widgets.active.bg_fill = Color32::from_rgb(0, 120, 215); 
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(0, 90, 170);
        visuals.widgets.inactive.rounding = Rounding::same(6.0);
        ctx.set_visuals(visuals);

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("🛡️ Aegis Antivirus");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button(if self.show_trust_view { "返回主页" } else { "信任区管理" }).clicked() {
                        self.show_trust_view = !self.show_trust_view;
                    }
                });
            });
            ui.separator();

            if self.show_trust_view {
                self.draw_trust_view(ui);
            } else {
                self.draw_main_view(ui, ctx);
            }
        });
    }
}

impl AntivirusApp {
    fn draw_main_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label("扫描目录:");
            let text_edit = egui::TextEdit::singleline(&mut self.scan_path).desired_width(350.0);
            ui.add_enabled(!self.state.is_scanning.load(Ordering::Relaxed), text_edit);
            if ui.add_enabled(!self.state.is_scanning.load(Ordering::Relaxed), egui::Button::new("📁 浏览")).clicked() {
                if let Some(folder) = rfd::FileDialog::new().pick_folder() { self.scan_path = folder.display().to_string(); }
            }
        });

        ui.add_space(15.0);
        let is_scanning = self.state.is_scanning.load(Ordering::Relaxed);
        let is_cleaning = self.state.is_cleaning.load(Ordering::Relaxed);
        
        ui.horizontal(|ui| {
            if !is_scanning && !is_cleaning {
                if ui.add(egui::Button::new("▶ 开始扫描").fill(Color32::from_rgb(0, 150, 100))).clicked() { self.start_scan(ctx.clone()); }
            } else if is_cleaning {
                ui.spinner();
                ui.label(egui::RichText::new("正在后台云端洗白误报...").color(Color32::YELLOW));
            } else {
                if ui.add(egui::Button::new("⏹ 停止").fill(Color32::from_rgb(200, 50, 50))).clicked() { self.state.is_scanning.store(false, Ordering::Relaxed); }
            }
        });

        ui.add_space(20.0);
        let scanned = self.state.scanned_count.load(Ordering::Relaxed);
        let total = self.state.total_count.load(Ordering::Relaxed);
        if total > 0 { ui.add(egui::ProgressBar::new(scanned as f32 / total as f32).show_percentage()); }

        ui.add_space(20.0);
        ui.separator();
        ui.horizontal(|ui| {
            ui.heading("⚠ 风险项");
            if is_cleaning {
                ui.spinner();
                let msg = self.state.cleaning_msg.lock().unwrap().clone();
                ui.label(egui::RichText::new(msg).color(Color32::YELLOW).small());
            }
        });
        
        if !is_scanning && !is_cleaning { 
            self.display_threats = self.state.threats.lock().unwrap().clone(); 
        }

        egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
            let mut remove_indices = Vec::new();
            for (idx, threat) in self.display_threats.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(format!("❌ [{}] {}", threat.virus_name, threat.file_path)).color(Color32::from_rgb(255, 100, 100)));
                    if ui.button("加入信任区").clicked() { remove_indices.push(idx); }
                    if ui.button("直接删除").clicked() {
                        let _ = std::fs::remove_file(&threat.file_path);
                        remove_indices.push(idx);
                    }
                });
            }
            for idx in remove_indices.into_iter().rev() { self.display_threats.remove(idx); }
        });

        if is_scanning || is_cleaning { ctx.request_repaint(); }
    }

    fn draw_trust_view(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        ui.heading("🛡️ 信任区管理");
        ui.label("提示：系统自带的“内置白名单”写死在底层，此处展示的是“用户信任区”。");
        ui.separator();
        
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label("输入要移除的 MD5:");
            ui.text_edit_singleline(&mut self.test_md5_input);
            if ui.button("从用户信任区移除").clicked() && !self.test_md5_input.is_empty() {
                if let Some(eng) = &*self.state.engine {
                    eng.remove_trust(&self.test_md5_input);
                    println!("已从用户信任区移除: {}", self.test_md5_input);
                    self.test_md5_input.clear();
                }
            }
        });
    }

    fn start_scan(&mut self, ctx: egui::Context) {
        let path = self.scan_path.clone();
        if !Path::new(&path).exists() { return; }
        
        self.state.is_scanning.store(true, Ordering::Relaxed);
        self.state.is_cleaning.store(false, Ordering::Relaxed);
        self.state.scanned_count.store(0, Ordering::Relaxed);
        self.state.total_count.store(0, Ordering::Relaxed);
        self.state.threats.lock().unwrap().clear();
        self.display_threats.clear();

        let is_scanning = self.state.is_scanning.clone();
        let is_cleaning = self.state.is_cleaning.clone();
        let cleaning_msg = self.state.cleaning_msg.clone();
        let scanned_count = self.state.scanned_count.clone();
        let total_count = self.state.total_count.clone();
        let threats = self.state.threats.clone();
        let engine = self.state.engine.clone();
        
        let (tx, rx) = mpsc::channel::<()>();

        let ctx_clone = ctx.clone();
        let threats_shared = self.state.threats.clone();
        std::thread::spawn(move || {
            if rx.recv().is_ok() {
                is_cleaning.store(true, Ordering::Relaxed);
                let current_threats = threats_shared.lock().unwrap().clone();
                if !current_threats.is_empty() {
                    let client = reqwest::blocking::Client::new();
                    let mut cleaned_md5s = Vec::new();

                    for (i, t) in current_threats.iter().enumerate() {
                        if t.md5.len() == 32 {
                            *cleaning_msg.lock().unwrap() = format!("正在核对云端白名单 ({}/{})...", i + 1, current_threats.len());
                            let url = format!("https://hashlookup.circl.lu/lookup/md5/{}", t.md5);
                            if let Ok(res) = client.get(&url).send() {
                                if res.status().is_success() { cleaned_md5s.push(t.md5.clone()); }
                            }
                            std::thread::sleep(std::time::Duration::from_millis(20)); 
                        }
                    }

                    if !cleaned_md5s.is_empty() {
                        let mut threats_lock = threats_shared.lock().unwrap();
                        threats_lock.retain(|t| !cleaned_md5s.contains(&t.md5));
                    }
                }
                *cleaning_msg.lock().unwrap() = "云端比对完成".to_string();
                is_cleaning.store(false, Ordering::Relaxed);
                let _ = ctx_clone.request_repaint();
            }
        });

        std::thread::spawn(move || {
            let mut files = Vec::new();
            for entry in WalkDir::new(&path).into_iter().filter_map(|e| e.ok()) {
                if !is_scanning.load(Ordering::Relaxed) { return; }
                if entry.file_type().is_file() {
                    let p = entry.path().to_string_lossy().to_string();
                    if p.ends_with(".exe") || p.ends_with(".dll") || p.ends_with(".sys") { files.push(p); }
                }
            }
            total_count.store(files.len(), Ordering::Relaxed);

            files.par_iter().for_each(|file_path| {
                if !is_scanning.load(Ordering::Relaxed) { return; }
                if let Some(eng) = &*engine {
                    if let Some((v_name, md5)) = eng.scan(file_path) {
                        threats.lock().unwrap().push(ThreatInfo { file_path: file_path.clone(), virus_name: v_name, md5 });
                    }
                }
                scanned_count.fetch_add(1, Ordering::Relaxed);
            });

            is_scanning.store(false, Ordering::Relaxed);
            let _ = tx.send(());
        });
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([750.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native("Aegis Antivirus", options, Box::new(|cc| {
        let mut fonts = egui::FontDefinitions::default();
        let exe_dir = std::env::current_exe().unwrap_or_else(|_| PathBuf::from(".")).parent().unwrap_or(Path::new(".")).to_path_buf();
        if let Ok(font_data) = std::fs::read(exe_dir.join("font.ttf")) {
            fonts.font_data.insert("my_font".to_owned(), egui::FontData::from_owned(font_data));
            fonts.families.get_mut(&egui::FontFamily::Proportional).unwrap().insert(0, "my_font".to_owned());
            cc.egui_ctx.set_fonts(fonts);
        }
        Box::new(AntivirusApp::default())
    }))
}