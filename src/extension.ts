import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import archiver from 'archiver';
import AdmZip from 'adm-zip';
import FormData from 'form-data';
import ignore from 'ignore';
import * as https from 'https';
import * as crypto from 'crypto';
import * as keytar from 'keytar';
import { IncomingMessage } from 'http';

interface BuildConfig {
    tcversion?: string;
    'working-directory'?: string;
    version?: string;
    'skip-build'?: string;
    'skip-test'?: string;
    'variant-build'?: string;
    'variant-test'?: string;
    'static-analysis'?: string;
    installer?: string;
    platform?: string;
}

class BuildService {
    private outputChannel: vscode.OutputChannel;
    private diagnosticCollection: vscode.DiagnosticCollection;
    private readonly API_URL = 'https://api.zeugwerk.dev/index.php';

    constructor(outputChannel: vscode.OutputChannel, diagnosticCollection: vscode.DiagnosticCollection) {
        this.outputChannel = outputChannel;
        this.diagnosticCollection = diagnosticCollection;
    }

    private async resetCredentials() {
        await keytar.deletePassword("zkbuild-vscode", "user_credentials");
        vscode.window.showInformationMessage('Credentials have been cleared.');
    }    

    private async getCredentials(): Promise<{ username: string, password: string }> {
        // Try to get stored credentials
        const storedPassword = await keytar.getPassword("zkbuild-vscode", "user_credentials");
        
        if (storedPassword) {
            // If found, parse it (assuming you stored as JSON string)
            return JSON.parse(storedPassword);
        }

        // If not found, ask user for credentials
        const username = await vscode.window.showInputBox({
            prompt: 'Enter your username',
            ignoreFocusOut: true
        });

        if (!username) {
            throw new Error('Username is required');
        }

        const password = await vscode.window.showInputBox({
            prompt: 'Enter your password',
            password: true,
            ignoreFocusOut: true
        });

        if (!password) {
            throw new Error('Password is required');
        }

        // Store credentials securely in Windows Credential Manager
        await keytar.setPassword("zkbuild-vscode", "user_credentials", JSON.stringify({ username, password }));

        return { username, password };
    }

    private createMD5Hash(username: string, workspaceFolder: vscode.WorkspaceFolder): string {
        // Use just the folder name instead of full path
        const folderName = path.basename(workspaceFolder.uri.fsPath);
        const combined = `${username}:${folderName}`;
    
        return crypto.createHash('md5').update(combined).digest('hex');
    }    

    private log(message: string) {
        this.outputChannel.appendLine(message);
    }

    private async checkConfigFile(workspaceFolder: vscode.WorkspaceFolder): Promise<boolean> {
        const configPath = path.join(workspaceFolder.uri.fsPath, '.Zeugwerk', 'build.json');
        if (!fs.existsSync(configPath)) {
            vscode.window.showErrorMessage('Missing build.json file. Please create it with your build configuration.');
            return false;
        }
        return true;
    }

    private async readConfig(workspaceFolder: vscode.WorkspaceFolder): Promise<BuildConfig | null> {
        const configPath = path.join(workspaceFolder.uri.fsPath, '.Zeugwerk', 'build.json');
        try {
            const configContent = fs.readFileSync(configPath, 'utf8');
            return JSON.parse(configContent) as BuildConfig;
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to read build.json: ${error}`);
            return null;
        }
    }

    private async readGitignore(workspaceFolder: vscode.WorkspaceFolder): Promise<string[]> {
        const gitignorePath = path.join(workspaceFolder.uri.fsPath, '.gitignore');
        if (!fs.existsSync(gitignorePath)) {
            return [];
        }
        const gitignoreContent = fs.readFileSync(gitignorePath, 'utf8');
        return gitignoreContent.split('\n').filter((line: string) => line.trim() && !line.startsWith('#'));
    }

    private async createZip(workspaceFolder: vscode.WorkspaceFolder): Promise<string | null> {
        return new Promise((resolve, reject) => {
            const zipPath = path.join(workspaceFolder.uri.fsPath, '.Zeugwerk', '.tmp-build.zip');
            const output = fs.createWriteStream(zipPath);
            const archive = archiver('zip', { zlib: { level: 9 } });

            output.on('close', () => {
                this.log(`Created zip file: ${archive.pointer()} bytes`);
                resolve(zipPath);
            });

            archive.on('error', (err: Error) => {
                reject(err);
            });

            archive.pipe(output);

            // Read .gitignore patterns
            this.readGitignore(workspaceFolder).then(patterns => {
                const ig = ignore().add(patterns);
                ig.add(['.git', '.tmp-build.zip', '.vscode', 'build.json']);

                const addDirectory = (dir: string, baseDir: string) => {
                    const entries = fs.readdirSync(dir, { withFileTypes: true });
                    for (const entry of entries) {
                        const fullPath = path.join(dir, entry.name);
                        const relativePath = path.relative(baseDir, fullPath);
                        
                        // Check if path should be ignored
                        if (ig.ignores(relativePath) || ig.ignores(relativePath + '/')) {
                            continue;
                        }

                        if (entry.isDirectory()) {
                            addDirectory(fullPath, baseDir);
                        } else {
                            archive.file(fullPath, { name: relativePath });
                        }
                    }
                };

                addDirectory(workspaceFolder.uri.fsPath, workspaceFolder.uri.fsPath);
                archive.finalize();
            }).catch(reject);
        });
    }

    private async makeRequest(endpoint: string, formData: FormData, bearerToken?: string): Promise<{ status: string; statusMessage: string; statusCode?: string; body: string; token?: string; artifact?: string }> {
        return new Promise((resolve, reject) => {
            const url = new URL(this.API_URL);
            const headers = formData.getHeaders();
            headers['Accept'] = 'text/x-shell';
            if (bearerToken) {
                headers['Authorization'] = `Bearer ${bearerToken}`;
            }
            const options: https.RequestOptions = {
                hostname: url.hostname,
                port: url.port || 443,
                path: url.pathname + endpoint + url.search,
                method: 'POST',
                headers: headers
            };

            const req = https.request(options, (res: IncomingMessage) => {
                let body = '';
                res.on('data', (chunk: Buffer) => {
                    body += chunk.toString();
                });
                res.on('end', () => {
                    // Parse response similar to bash script:
                    // - Last non-blank line: HTTP status line (e.g., "HTTP/1.1 203" or "HTTP/1.1 500 User authentication failed!")
                    // - Second-to-last non-blank line: token=... or artifact=... (tail -n2 | head -n1)
                    const allLines = body.split('\n');
                    const nonBlankLines = allLines.filter(line => line.trim() !== '');
                    
                    // Get status from last non-blank line (like tail -n1 but skipping blanks)
                    const statusLine = nonBlankLines.length > 0 ? nonBlankLines[nonBlankLines.length - 1].trim() : '';
                    const status = statusLine || `HTTP/1.1 ${res.statusCode}`;
                    
                    // Extract status message: remove "HTTP/1.1 \d+ " prefix
                    let statusMessage = status;
                    const httpStatusMatch = status.match(/^HTTP\/1\.1\s+\d+\s+(.+)$/);
                    if (httpStatusMatch) {
                        statusMessage = httpStatusMatch[1];
                    } else {
                        // If no match, try to remove just "HTTP/1.1 \d+" prefix
                        statusMessage = status.replace(/^HTTP\/1\.1\s+\d+\s*/, '');
                    }
                    
                    // Extract status code (e.g., "203", "201", "202", "500")
                    let statusCode: string | undefined;
                    const statusCodeMatch = status.match(/^HTTP\/1\.1\s+(\d+)/);
                    if (statusCodeMatch) {
                        statusCode = statusCodeMatch[1];
                    }
                    
                    let token: string | undefined;
                    let artifact: string | undefined;

                    // Get token/artifact from second-to-last non-blank line (like tail -n2 | head -n1)
                    if (nonBlankLines.length >= 2) {
                        const secondLastLine = nonBlankLines[nonBlankLines.length - 2].trim();
                        if (secondLastLine.includes('TOKEN=')) {
                            const parts = secondLastLine.split('TOKEN=');
                            if (parts.length > 1) {
                                token = parts.slice(1).join('TOKEN=').trim();
                            }
                        }
                        if (secondLastLine.includes('ARTIFACT=')) {
                            const parts = secondLastLine.split('ARTIFACT=');
                            if (parts.length > 1) {
                                artifact = parts.slice(1).join('ARTIFACT=').trim();
                            }
                        }
                    }

                    resolve({ status, statusMessage, statusCode, body, token, artifact });
                });
            });

            req.on('error', (error: Error) => {
                reject(error);
            });

            formData.pipe(req);
        });
    }

    private async login(): Promise<string | null> {
        this.log('Login...');
        
        const formData = new FormData();

        const { username, password } = await this.getCredentials();

        formData.append('username', username);
        formData.append('password', password);

        try {
            const response = await this.makeRequest('/login', formData);
            
            // Display response body except the last line (which is the HTTP status line)
            const bodyLines = response.body.split('\n');
            const displayLines = bodyLines.length > 1 ? bodyLines.slice(0, -1) : bodyLines;
            const bodyContent = displayLines.join('\n').trim();


            // Check if login was successful (status code 200)
            if (response.statusCode !== '200') {
                if (bodyContent) {
                    this.log(bodyContent);
                }

                // Show status message to user
                if (response.statusMessage) {
                    this.log(`\n${response.statusMessage}`);
                }

                const errorMsg = response.statusMessage || 'Login failed!';
                this.log(errorMsg);
                vscode.window.showErrorMessage(errorMsg);
                await this.resetCredentials();
                return null;
            }

            // Extract bearer token from second-to-last non-blank line (like tail -n2 | head -n1 | cut -d '=' -f2)
            const allLines = response.body.split('\n');
            const nonBlankLines = allLines.filter(line => line.trim() !== '');
            let bearerToken: string | null = null;

            if (nonBlankLines.length >= 2) {
                const secondLastLine = nonBlankLines[nonBlankLines.length - 2].trim();
                if (secondLastLine.includes('bearer_token=')) {
                    const parts = secondLastLine.split('bearer_token=');
                    if (parts.length > 1) {
                        bearerToken = parts.slice(1).join('bearer_token=').trim();
                    }
                } else if (secondLastLine.includes('=')) {
                    // Try to get value after = if it's just "bearer_token=value"
                    const parts = secondLastLine.split('=');
                    if (parts.length > 1) {
                        bearerToken = parts.slice(1).join('=').trim();
                    }
                }
            }

            if (!bearerToken) {
                vscode.window.showErrorMessage('Failed to get bearer token from login response');
                return null;
            }

            return bearerToken;
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to login: ${error}`);
            return null;
        }
    }

    private async requestBuild(zipPath: string, bearerToken: string, config?: BuildConfig | null): Promise<string | null> {
        this.log('Requesting build...');
        
        const formData = new FormData();
        formData.append('async', 'true');
        
        if (config) {
            if (config.tcversion) formData.append('tcversion', config.tcversion);
            if (config['working-directory']) formData.append('working-directory', config['working-directory']);
            if (config.version) formData.append('version', config.version);
            if (config['skip-build']) formData.append('skip-build', config['skip-build']);
            if (config['skip-test']) formData.append('skip-test', config['skip-test']);
            if (config['variant-build']) formData.append('variant-build', config['variant-build']);
            if (config['variant-test']) formData.append('variant-test', config['variant-test']);
            if (config['static-analysis']) formData.append('static-analysis', config['static-analysis']);
            if (config.installer) formData.append('installer', config.installer);
            if (config.platform) formData.append('platform', config.platform);
        }

        
        // Add the zip file
        formData.append('file', fs.createReadStream(zipPath), {
            filename: 'project.zip',
            contentType: 'application/zip'
        });

        try {
            const response = await this.makeRequest('/build', formData, bearerToken);
            // Display response body except the last line (which is the HTTP status line)
            const bodyLines = response.body.split('\n');
            const displayLines = bodyLines.length > 1 ? bodyLines.slice(0, -1) : bodyLines;
            const bodyContent = displayLines.join('\n').trim();

            if (response.statusCode !== '203') {
                if (bodyContent) {
                    this.log(bodyContent);
                }

                // Show status message to user
                if (response.statusMessage) {
                    this.log(`\n${response.statusMessage}`);
                }

                const errorMsg = response.statusMessage || 'Build is not queued!';
                this.log(errorMsg);
                vscode.window.showErrorMessage(errorMsg);
                return null;
            }

            return response.token || null;
        } catch (error) {
            this.log(`Failed to poll build status: ${error}`);
            vscode.window.showErrorMessage(`Failed to request build: ${error}`);
            return null;
        }
    }

    private async pollBuildStatus(bearerToken: string, token: string): Promise<{ status: string; statusCode?: string; statusMessage?: string; artifact?: string; body: string } | null> {
        return new Promise((resolve) => {
            const poll = async () => {
                const formData = new FormData();
                formData.append('async', 'true');
                formData.append('token', token);

                try {
                    const response = await this.makeRequest('/build', formData, bearerToken);
                    // Display response body except the last line (which is the HTTP status line)
                    const bodyLines = response.body.split('\n');
                    const displayLines = bodyLines.length > 1 ? bodyLines.slice(0, -1) : bodyLines;
                    const bodyContent = displayLines.join('\n').trim();

                    // Status 201: Build done (success, no artifacts)
                    if (response.statusCode === '201') {
                        if (bodyContent) {
                            this.log(bodyContent);
                        }

                        // Show status message to user
                        if (response.statusMessage) {
                            this.log(`\n${response.statusMessage}`);
                        }

                        resolve({ status: '201', statusCode: response.statusCode, statusMessage: response.statusMessage, body: response.body });
                        return;
                    }

                    // Status 202: Build done with artifacts
                    if (response.statusCode === '202') {
                        if (bodyContent) {
                            this.log(bodyContent);
                        }

                        // Show status message to user
                        if (response.statusMessage) {
                            this.log(`\n${response.statusMessage}`);
                        }

                        resolve({ status: '202', statusCode: response.statusCode, statusMessage: response.statusMessage, artifact: response.artifact, body: response.body });
                        return;
                    }

                    // Status 203: Still pending
                    if (response.statusCode === '203') {
                        setTimeout(poll, 10000); // Poll every 10 seconds
                        return;
                    }

                    // Error status
                    this.log(bodyContent);
                    const errorMsg = response.statusMessage || 'Build unsuccessful!';

                    this.log(errorMsg);
                    vscode.window.showErrorMessage(errorMsg);
                    resolve(null);
                } catch (error) {
                    this.log(`Failed to poll build status: ${error}`);
                    vscode.window.showErrorMessage(`Failed to poll build status: ${error}`);
                    resolve(null);
                }
            };

            poll();
        });
    }

    private async downloadArtifact(artifactUrl: string): Promise<Buffer | null> {
        const { username, password } = await this.getCredentials();

        return new Promise((resolve, reject) => {
            const url = new URL(artifactUrl);

            const auth = Buffer.from(`${username}:${password}`).toString('base64');
            
            const options: https.RequestOptions = {
                hostname: url.hostname,
                port: url.port || 443,
                path: url.pathname + url.search,
                method: 'GET',
                headers: {
                    'Authorization': `Basic ${auth}`
                }
            };

            const req = https.request(options, (res: IncomingMessage) => {
                if (res.statusCode !== 200) {
                    reject(new Error(`Failed to download artifact: ${res.statusCode}`));
                    return;
                }

                const chunks: Buffer[] = [];
                res.on('data', (chunk: Buffer) => {
                    chunks.push(chunk);
                });
                res.on('end', () => {
                    resolve(Buffer.concat(chunks));
                });
            });

            req.on('error', (error: Error) => {
                reject(error);
            });

            req.end();
        });
    }

    private parseBuildLog(buildLog: string, workspaceFolder: vscode.WorkspaceFolder): Map<vscode.Uri, vscode.Diagnostic[]> {
        const diagnosticsByFile = new Map<vscode.Uri, vscode.Diagnostic[]>();
        const lines = buildLog.split('\n');

        // Common patterns for TwinCAT build errors and warnings
        // Patterns to match various error/warning formats:
        // - error C1234: message in file.cpp(123)
        // - warning: message in file.cpp:123
        // - file.cpp(123): error: message
        // - file.cpp:123:45: error: message
        const errorPatterns = [
            /error\s+(?:C\d+:\s*)?(?:in\s+)?(.+?):\((\d+)(?:,(\d+))?\)/i,
            /(.+?):\((\d+)(?:,(\d+))?\):\s*error:/i,
            /(.+?):(\d+)(?::(\d+))?:\s*error:/i
        ];
        const warningPatterns = [
            /warning\s+(?:C\d+:\s*)?(?:in\s+)?(.+?):\((\d+)(?:,(\d+))?\)/i,
            /(.+?):\((\d+)(?:,(\d+))?\):\s*warning:/i,
            /(.+?):(\d+)(?::(\d+))?:\s*warning:/i
        ];

        for (const line of lines) {
            let match: RegExpMatchArray | null = null;
            let severity: vscode.DiagnosticSeverity | null = null;

            // Try error patterns
            for (const pattern of errorPatterns) {
                match = line.match(pattern);
                if (match) {
                    severity = vscode.DiagnosticSeverity.Error;
                    break;
                }
            }

            // Try warning patterns if no error found
            if (!match) {
                for (const pattern of warningPatterns) {
                    match = line.match(pattern);
                    if (match) {
                        severity = vscode.DiagnosticSeverity.Warning;
                        break;
                    }
                }
            }

            if (match && severity !== null) {
                const filePath = match[1].trim();
                const lineNum = parseInt(match[2]) - 1; // VS Code uses 0-based line numbers
                const colNum = match[3] ? parseInt(match[3]) - 1 : 0;
                
                // Try to resolve the file path
                let fullPath: string;
                if (path.isAbsolute(filePath)) {
                    fullPath = filePath;
                } else {
                    // Try relative to workspace
                    fullPath = path.join(workspaceFolder.uri.fsPath, filePath);
                    // If not found, try with normalized path
                    if (!fs.existsSync(fullPath)) {
                        fullPath = path.normalize(path.join(workspaceFolder.uri.fsPath, filePath));
                    }
                }
                
                if (fs.existsSync(fullPath)) {
                    const uri = vscode.Uri.file(fullPath);
                    const range = new vscode.Range(
                        Math.max(0, lineNum),
                        Math.max(0, colNum),
                        Math.max(0, lineNum),
                        Math.max(0, colNum)
                    );
                    const diagnostic = new vscode.Diagnostic(range, line.trim(), severity);
                    
                    if (!diagnosticsByFile.has(uri)) {
                        diagnosticsByFile.set(uri, []);
                    }
                    diagnosticsByFile.get(uri)!.push(diagnostic);
                }
            }
        }

        return diagnosticsByFile;
    }

    async build(workspaceFolder: vscode.WorkspaceFolder): Promise<void> {
        this.outputChannel.clear();
        this.diagnosticCollection.clear();
        this.outputChannel.show();

        // Check for config file
        if (!(await this.checkConfigFile(workspaceFolder))) {
            return;
        }

        // Read config
        const config = await this.readConfig(workspaceFolder);

        // Create zip file
        this.log('Creating project archive...');
        const zipPath = await this.createZip(workspaceFolder);
        if (!zipPath) {
            vscode.window.showErrorMessage('Failed to create project archive');
            return;
        }

        try {
            // Login first to get bearer token
            const bearerToken = await this.login();
            if (!bearerToken) {
                return;
            }

            // Request build
            const token = await this.requestBuild(zipPath, bearerToken, config);
            if (!token) {
                return;
            }

            // Poll for build status
            this.log('Waiting for build to complete...');
            const result = await this.pollBuildStatus(bearerToken, token);
            
            if (!result) {
                return;
            }

            if (result.status === '201') {
                this.log('\n\nBuild completed successfully (no artifacts)');
                vscode.window.showInformationMessage('Build completed successfully');
                return;
            }

            if (result.status === '202' && result.artifact) {
                this.log('\n\nDownloading artifacts...');
                const artifactBuffer = await this.downloadArtifact(result.artifact);
                
                if (!artifactBuffer) {
                    vscode.window.showErrorMessage('Failed to download artifacts');
                    return;
                }

                // Extract artifact
                const zip = new AdmZip(artifactBuffer);
                const extractPath = path.join(workspaceFolder.uri.fsPath, 'archive');
                zip.extractAllTo(extractPath, true);
                this.log('\n\nArtifacts extracted to archive/');

                // Find and parse build.log
                const buildLogPath = path.join(extractPath, 'build.log');
                if (fs.existsSync(buildLogPath)) {
                    const buildLog = fs.readFileSync(buildLogPath, 'utf8');
                    this.log('\n=== Build Log ===\n');
                    this.log(buildLog);
                    
                    // Parse and show diagnostics
                    const diagnosticsByFile = this.parseBuildLog(buildLog, workspaceFolder);
                    if (diagnosticsByFile.size > 0) {
                        // Set diagnostics for each file
                        for (const [uri, diagnostics] of diagnosticsByFile.entries()) {
                            this.diagnosticCollection.set(uri, diagnostics);
                        }
                        this.log(`\nFound ${diagnosticsByFile.size} file(s) with errors or warnings`);
                    } else {
                        this.log('\nNo errors or warnings found in build log');
                    }
                } else {
                    this.log('Warning: build.log not found in artifacts');
                }

                vscode.window.showInformationMessage('Build completed. Artifacts downloaded.');
            }
        } finally {
            // Clean up zip file
            if (fs.existsSync(zipPath)) {
                fs.unlinkSync(zipPath);
            }
        }
    }
}

export function activate(context: vscode.ExtensionContext) {
    const outputChannel = vscode.window.createOutputChannel('Zeugwerk Build');
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('zkbuild');
    
    const buildService = new BuildService(outputChannel, diagnosticCollection);

    let isBuilding = false;

    const disposable = vscode.commands.registerCommand('zkbuild.build', async () => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0) {
            vscode.window.showErrorMessage('No workspace folder open');
            return;
        }

        if (isBuilding) {
            // Focus output if build is already running
            outputChannel.show(true);
            vscode.window.showInformationMessage('Build is already running...');
            return;
        }
        
        isBuilding = true;

        try {
            if (workspaceFolders.length > 1) {
                const selected = await vscode.window.showWorkspaceFolderPick();
                if (!selected) {
                    return;
                }
                await buildService.build(selected);
            } else {
                await buildService.build(workspaceFolders[0]);
            }
        } finally {
            isBuilding = false;
        }
    });

    context.subscriptions.push(disposable, diagnosticCollection);
}

export function deactivate() {}
