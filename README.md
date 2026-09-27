# StopStealer - Advanced Anti-Stealer & Grabber Protection

## What is this?
StopStealer is a defensive security tool that protects your system from:
- **Browser data stealers** (Chrome, Edge, Firefox, Brave, Opera, Yandex)
- **Discord token grabbers**
- **Password/cookie/credit card theft**
- **Screen capture malware**
- **Camera spyware**
- **Clipboard stealers**
- **Keyloggers**
- **Suspicious process injection**

## Protection Modules
| Module | What it does |
|--------|-------------|
| Browser Data Protection | Monitors Login Data, Cookies, Web Data files. Blocks unauthorized access |
| Token Stealer Detection | Detects Discord/browser token extraction patterns |
| Process Guard | Scans for known malicious process names and suspicious behavior |
| Clipboard Protection | Monitors clipboard for sensitive data (tokens, passwords, API keys) |
| Screenshot Monitor | Detects unauthorized screen capture attempts |
| Camera Monitor | Monitors camera access by unknown processes |

## Requirements
- Windows 10/11
- .NET 8.0 SDK (for building)
- Administrator privileges (for service installation)

## Quick Start

### Option 1: Build & Install (PowerShell as Admin)
```powershell
cd D:\stealr\stop
.\StopStealer.Installer\Install.ps1 -Build
```

### Option 2: Manual Build (Visual Studio)
1. Open `StopStealer.sln` in Visual Studio 2022
2. Set build configuration to `Release | x64`
3. Build Solution (Ctrl+Shift+B)
4. Run `StopStealer.Installer\Install.ps1`

### Option 3: Manual Build (CLI)
```powershell
cd D:\stealr\stop
dotnet build StopStealer.sln -c Release
```

## Uninstall
```powershell
.\StopStealer.Installer\Install.ps1 -Uninstall
```

## Project Structure
```
StopStealer/
├── StopStealer.sln              # Solution file
├── StopStealer.Core/            # Core protection library
│   ├── Models.cs                # Data models (ThreatEvent, ProtectionStats, etc.)
│   ├── Logger.cs                # Threat logging engine
│   ├── BrowserProtector.cs      # Browser data protection
│   ├── ClipboardProtector.cs    # Clipboard monitoring
│   ├── ScreenProtector.cs       # Screenshot detection
│   ├── CameraProtector.cs       # Camera access monitoring
│   ├── ProcessGuard.cs          # Malicious process detection
│   └── ProtectionEngine.cs      # Main protection orchestrator
├── StopStealer.Service/         # Windows Service (background)
│   ├── Program.cs               # Service entry point
│   └── Worker.cs                # Background worker + pipe server
├── StopStealer.GUI/             # WPF Dashboard
│   ├── App.xaml                 # Application resources (dark theme)
│   ├── App.xaml.cs              # Tray icon + service communication
│   ├── MainWindow.xaml          # Dashboard UI
│   └── MainWindow.xaml.cs       # UI logic
└── StopStealer.Installer/       # Installer scripts
    └── Install.ps1              # PowerShell installer
```

## How It Works
1. **Windows Service** starts at boot and runs the protection engine
2. **Protection Engine** monitors:
   - File system changes in browser data directories
   - Process creation and module loading
   - Clipboard content changes
   - Screen capture hotkeys and tools
   - Camera access patterns
3. **GUI Application** shows real-time dashboard with:
   - Threat count cards
   - Live threat log
   - Browser status
   - Module status
4. **Named Pipe** communication between service and GUI

## Detection Methods
- **File System Monitoring**: Watches browser sensitive files (Login Data, Cookies, etc.)
- **Process Scanning**: Checks for known malicious process names and patterns
- **Behavioral Analysis**: Detects suspicious access patterns (temp folder execution, module loading)
- **Pattern Matching**: Regex detection for Discord tokens, API keys, passwords in clipboard
- **Module Inspection**: Checks loaded DLLs for screenshot/camera capture libraries

## Notes
- This is a **user-mode** protection tool (no kernel driver required)
- Runs on any Windows 10/11 system with .NET 8 runtime
- Low resource usage (~5-15MB RAM)
- No external dependencies or cloud connections
- All data stays local on your machine
