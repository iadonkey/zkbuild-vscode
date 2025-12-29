# Zeugwerk Build Service VS Code Extension

A VS Code extension for building TwinCAT projects remotely using the Zeugwerk build service.

## Features

- Remote compilation of TwinCAT projects
- Automatic project archiving (respects `.gitignore`)
- Real-time build status polling
- Automatic artifact download
- Build log parsing with error/warning highlighting in VS Code
- Output window integration for build logs

## Requirements

- VS Code 1.74.0 or higher
- A `.Zeugwerk/build.json` file in your workspace root with build configuration

## Configuration

Create a `.Zeugwerk/build.json` file in your workspace root with the following structure:

```json
{
  "tcversion": "optional-tc-version",
  "working-directory": "optional-working-directory",
  "version": "optional-version",
  "skip-build": "optional-skip-build",
  "skip-test": "optional-skip-test",
  "variant-build": "optional-variant-build",
  "variant-test": "optional-variant-test",
  "static-analysis": "optional-static-analysis",
  "installer": "optional-installer",
  "platform": "optional-platform"
}
```

## Usage

1. Open a TwinCAT project workspace in VS Code
2. Run the command `Build with Zeugwerk` from the Command Palette (Ctrl+Shift+P / Cmd+Shift+P)
3. The extension will:
   - Archive your project (excluding files in `.gitignore`)
   - Upload it to the build service
   - Poll for build status
   - Download artifacts when ready
   - Parse `build.log` and show errors/warnings in VS Code

### Setup

1. Install dependencies:
```bash
npm install
```

2. Compile the extension:
```bash
npm run compile
```

Or use watch mode to automatically recompile on changes:
```bash
npm run watch
```

### Debugging

1. **Open the extension project** in VS Code (this repository)

2. **Set breakpoints** in `src/extension.ts` where you want to debug

3. **Press F5** (or go to Run > Start Debugging)
   - This will:
     - Compile the TypeScript code
     - Launch a new "Extension Development Host" window
     - Load your extension in that window

4. **In the Extension Development Host window**:
   - Open a TwinCAT project workspace (or create a test workspace)
   - Create a `build.json` file with your credentials
   - Run the command "Build with Zeugwerk" from Command Palette (Ctrl+Shift+P)

5. **Debugging tips**:
   - The debugger will pause at your breakpoints
   - Check the Debug Console for console.log output
   - Check the Output panel and select "Zeugwerk Build" channel to see extension logs
   - The original VS Code window shows debug information and logs

6. **To stop debugging**: Press Shift+F5 or click the Stop button
