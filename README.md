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
  "username": "your-username",
  "password": "your-password",
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

**Required fields:**
- `username`: Your Zeugwerk build service username
- `password`: Your Zeugwerk build service password

All other fields are optional and correspond to the build parameters used by the build service.

## Usage

1. Open a TwinCAT project workspace in VS Code
2. Ensure `build.json` exists with your credentials
3. Run the command `Build with Zeugwerk` from the Command Palette (Ctrl+Shift+P / Cmd+Shift+P)
4. The extension will:
   - Archive your project (excluding files in `.gitignore`)
   - Upload it to the build service
   - Poll for build status
   - Download artifacts when ready
   - Parse `build.log` and show errors/warnings in VS Code

## How It Works

The extension:
1. Validates that `build.json` exists
2. Creates a zip archive of your project, excluding files listed in `.gitignore` (and `build.json` itself)
3. Sends the archive to the Zeugwerk build service API
4. Polls the build status every 10 seconds
5. Downloads artifacts when the build completes
6. Extracts artifacts to the `archive/` folder
7. Parses `build.log` and displays errors/warnings as VS Code diagnostics

## Build Status Codes

- **203**: Build is queued/pending (polling continues)
- **201**: Build completed successfully (no artifacts)
- **202**: Build completed with artifacts (downloads and extracts)

## Development

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

### Testing Checklist

Before testing, make sure you have:
- [ ] A test TwinCAT project workspace
- [ ] A `.Zeugwerk/build.json` file in the workspace root with valid credentials
- [ ] The extension compiled (`npm run compile` or `npm run watch`)
- [ ] The Extension Development Host window open (after pressing F5)

### Common Issues

- **Extension not found**: Make sure you've run `npm install` and `npm run compile`
- **TypeScript errors**: Check the Problems panel and fix any compilation errors
- **Breakpoints not working**: Ensure the code is compiled and the debugger is attached
- **Command not appearing**: Reload the Extension Development Host window (Ctrl+R or Cmd+R)

## License

MIT License - see [LICENSE](LICENSE) file for details.
