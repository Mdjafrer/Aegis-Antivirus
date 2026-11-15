# Aegis Antivirus (神盾杀毒)

**English** | [简体中文](#简体中文)

A high-performance, purely native antivirus engine written entirely in Rust.

## 📝 Acknowledgements
The core architecture, Rust engine code, and project guidance were developed with the assistance of **DeepSeek AI**. We believe in the power of AI-assisted programming to build robust, secure, and high-performance systems.

## ✨ Features
- **Pure Rust Core**: Memory safety and zero-cost abstractions.
- **Multi-Engine Detection**: MD5 signature matching, YARA-X rule engine, and heuristic behavior analysis.
- **Windows Signature Validation**: Skips trusted, signed system files via `WinVerifyTrust` to minimize false positives.
- **Cloud Reputation**: Queries CIRCL Hash Lookup API asynchronously for secondary whitelist validation.
- **Native GUI**: Built with `eframe` / `egui` for a smooth, non-blocking UI.

## 🚀 Build & Run
1. `cd engine && cargo build --release`
2. `cd ui && cargo build --release`
3. Place the generated `aegis_engine.dll`, `font.ttf`, and YARA rules next to the UI executable.
4. Run `aegis-antivirus.exe`.

---

## 简体中文 (Simplified Chinese)

基于纯血 Rust 构建的高性能原生桌面杀毒引擎。**（当前软件 UI 为纯中文）**

## 📝 致谢
本项目的核心架构、Rust 引擎代码及开发指导，均在 **DeepSeek AI** 的辅助下完成。我们相信 AI 辅助编程在构建健壮、安全、高性能系统中的巨大潜力。

## ✨ 核心特性
- **纯血 Rust 核心**：内存安全，零成本抽象。
- **多引擎查杀**：极速 MD5 特征匹配、YARA-X 规则引擎、启发式行为分析。
- **数字签名校验**：通过 Windows API (`WinVerifyTrust`) 自动跳过受信任的系统文件，极大降低误报。
- **云端信誉与异步降噪**：异步查询 CIRCL Hash Lookup API，进行二次白名单验证。
- **原生 GUI**：基于 `eframe` / `egui` 构建，极致流畅，拒绝 WebView 卡顿。

## 🚀 编译与运行
1. `cd engine && cargo build --release`
2. `cd ui && cargo build --release`
3. 将生成的 `aegis_engine.dll`、`font.ttf` 以及 YARA 规则文件，与 UI 可执行文件放在同一目录。
4. 运行 `aegis-antivirus.exe`。

## ⚠️ 免责声明
本项目仅供学习与技术研究使用，请勿用于非法用途。
