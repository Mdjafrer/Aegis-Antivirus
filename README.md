\# Aegis Antivirus



A high-performance, purely native antivirus engine written entirely in Rust.



\## 📝 Acknowledgements

The core architecture, Rust engine code, and project guidance were developed with the assistance of \*\*DeepSeek AI\*\*. We believe in the power of AI-assisted programming to build robust, secure, and high-performance systems.



\## ✨ Features

\- \*\*Pure Rust Core\*\*: Memory safety and zero-cost abstractions.

\- \*\*Multi-Engine Detection\*\*: MD5 signature matching, YARA-X rule engine, and heuristic behavior analysis.

\- \*\*Windows Signature Validation\*\*: Skips trusted, signed system files via `WinVerifyTrust` to minimize false positives.

\- \*\*Cloud Reputation\*\*: Queries CIRCL Hash Lookup API asynchronously for secondary whitelist validation.

\- \*\*Native GUI\*\*: Built with `eframe` / `egui` for a smooth, non-blocking UI.



\## 🛠️ Tech Stack

\- \*\*Core Engine\*\*: Rust, `yara-x`, `sled` (Embedded KV Store), Windows API

\- \*\*UI\*\*: `eframe` / `egui`



\## 🚀 Build \& Run

1\. `cd engine \&\& cargo build --release`

2\. `cd ui \&\& cargo build --release`

3\. Place the generated `aegis\_engine.dll`, `font.ttf`, and YARA rules next to the UI executable.

4\. Run `aegis-antivirus.exe`.

