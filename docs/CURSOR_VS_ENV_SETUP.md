# Configuring Cursor to Use Visual Studio Developer PowerShell

This guide shows you how to configure Cursor to use the Visual Studio Developer PowerShell environment, which includes CMake, MSVC compiler, and other build tools.

## Quick Setup

### Option 1: Use the Wrapper Script (Recommended)

1. **Find the path to `vs_dev_shell.bat`** in this project:
   ```
   C:\Users\Navitank\Documents\bs\TpmWrapperFull\vs_dev_shell.bat
   ```

2. **Configure Cursor's Terminal Settings:**
   - Open Cursor Settings (Ctrl+,)
   - Search for "terminal integrated shell"
   - Or directly edit settings.json (Ctrl+Shift+P → "Preferences: Open User Settings (JSON)")

3. **Add this configuration:**
   ```json
   {
     "terminal.integrated.defaultProfile.windows": "Command Prompt",
     "terminal.integrated.profiles.windows": {
       "VS Developer Shell": {
         "path": "C:\\Users\\Navitank\\Documents\\bs\\TpmWrapperFull\\vs_dev_shell.bat",
         "args": [],
         "icon": "terminal"
       }
     }
   }
   ```

4. **Set it as default:**
   ```json
   {
     "terminal.integrated.defaultProfile.windows": "VS Developer Shell"
   }
   ```

### Option 2: Direct PowerShell Configuration

If you prefer to use PowerShell directly:

1. **Find your VS Developer PowerShell path:**
   - VS 18 (2024) Build Tools: `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\Launch-VsDevShell.ps1` ✅ **Your installation**
   - VS 2022 Build Tools: `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\Launch-VsDevShell.ps1`
   - VS 2022 Community: `C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1`
   - VS 2019 Build Tools: `C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\Launch-VsDevShell.ps1`

2. **Configure Cursor:**
   ```json
   {
     "terminal.integrated.defaultProfile.windows": "PowerShell",
     "terminal.integrated.profiles.windows": {
       "VS Developer PowerShell": {
         "source": "PowerShell",
         "args": [
           "-NoExit",
           "-ExecutionPolicy",
           "Bypass",
           "-Command",
           "& 'C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\Common7\\Tools\\Launch-VsDevShell.ps1' -Arch amd64"
         ],
         "icon": "terminal-powershell"
       }
     }
   }
   ```

3. **Set as default:**
   ```json
   {
     "terminal.integrated.defaultProfile.windows": "VS Developer PowerShell"
   }
   ```

## Verification

After configuring, open a new terminal in Cursor (Ctrl+`) and verify:

```powershell
# Check CMake
cmake --version

# Check MSVC compiler
cl

# Check Git
git --version

# Check current directory
pwd
```

All commands should work without errors.

## Troubleshooting

### "Execution Policy" Error

If you get an execution policy error, run this in an Administrator PowerShell:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### "VS Dev Shell Not Found"

1. Verify Visual Studio Build Tools is installed
2. Check the path in `setup_vs_env.ps1` matches your installation
3. Try running `setup_vs_env.ps1` directly to see which path it finds

### Terminal Doesn't Launch

1. Check the path to `vs_dev_shell.bat` is correct (use forward slashes or escaped backslashes in JSON)
2. Try using the direct PowerShell method instead
3. Check Cursor's terminal output for error messages

## Alternative: Manual Terminal Launch

If configuration doesn't work, you can manually launch VS Developer PowerShell:

1. Press `Win + S` and search for "Developer PowerShell for VS"
2. Navigate to your project:
   ```powershell
   cd C:\Users\Navitank\Documents\bs\TpmWrapperFull
   ```
3. Run build commands from there

## Using with Build Scripts

Once configured, you can use the build scripts directly in Cursor's terminal:

```powershell
# Build the project
.\build.bat

# Run the client
cd build\bin\Release
.\tpm_client.exe http://your-server:8001

# Or use CMake directly
cd build
cmake --build . --config Release
```

## Notes

- The VS Developer Shell automatically sets up:
  - MSVC compiler (cl.exe)
  - CMake (if installed with VS)
  - Windows SDK paths
  - Other build tools

- You don't need to manually set PATH or environment variables

- The shell persists the environment for the session

- If you close and reopen the terminal, you'll need to launch VS Dev Shell again (or configure Cursor to auto-launch it)

