# Helper Scripts

This directory contains helper scripts for building and setting up the TPM Client project.

## Windows Scripts

### `setup_vs_env.ps1`
Launches Visual Studio Developer PowerShell environment. This provides access to MSVC compiler, CMake, and other build tools.

**Usage:**
- Can be set as Cursor's default terminal profile
- Or run manually: `powershell -ExecutionPolicy Bypass -File scripts\setup_vs_env.ps1`

**For Cursor Integration:**
Add to your Cursor settings.json:
```json
"terminal.integrated.profiles.windows": {
    "VS Developer": {
        "path": "powershell.exe",
        "args": [
            "-NoExit",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            "${workspaceFolder}/scripts/setup_vs_env.ps1"
        ]
    }
}
```

## Linux/macOS Scripts

### `start_swtpm.sh`
Starts the swtpm (software TPM) simulator for development/testing on Linux/macOS.

**Usage:**
```bash
./scripts/start_swtpm.sh
```

### `test_client.sh`
Runs the TPM client tests on Linux/macOS.

**Usage:**
```bash
./scripts/test_client.sh
```

## Main Build Scripts

The main build scripts are in the project root:
- `build.bat` - Windows build script
- `build.sh` - Linux/macOS build script
