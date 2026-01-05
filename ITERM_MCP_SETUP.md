# iTerm MCP Server Setup Documentation

## Overview
Successfully set up the iTerm MCP (Model Context Protocol) server from https://github.com/pashpashpash/iterm-mcp

## Installation Details

### Repository Location
- **Cloned to:** `/root/.vscode-server/iterm-mcp`
- **Built files:** `/root/.vscode-server/iterm-mcp/build/`
- **Main executable:** `/root/.vscode-server/iterm-mcp/build/index.js`

### Installation Steps Completed
1. ✅ Cloned repository from GitHub
2. ✅ Installed dependencies using `npm install`
3. ✅ Fixed security vulnerabilities with `npm audit fix --force`
4. ✅ Built the project using `npm run build`
5. ✅ Created `blackbox_mcp_settings.json` configuration file

## Configuration

### blackbox_mcp_settings.json
Located at: `/root/.vscode-server/data/User/globalStorage/blackboxapp.blackboxagent/settings/blackbox_mcp_settings.json`

```json
{
  "mcpServers": {
    "github.com/pashpashpash/iterm-mcp": {
      "command": "node",
      "args": ["/root/.vscode-server/iterm-mcp/build/index.js"]
    }
  }
}
```

## Available Tools

The iTerm MCP server provides three main tools:

### 1. write_to_terminal
- **Purpose:** Writes to the active iTerm terminal, often used to run commands
- **Returns:** Number of lines of output produced by the command
- **Use case:** Execute commands in the terminal

### 2. read_terminal_output
- **Purpose:** Reads the requested number of lines from the active iTerm terminal
- **Returns:** Terminal output content
- **Use case:** Inspect command results and terminal state

### 3. send_control_character
- **Purpose:** Sends control characters to the active iTerm terminal
- **Examples:** Ctrl-C, Ctrl-Z, etc.
- **Use case:** Interrupt processes, suspend tasks, etc.

## MCP Inspector

### Current Status
The MCP Inspector is running and accessible at:
- **URL:** http://localhost:6274
- **Proxy Server:** localhost:6277
- **Session Token:** 3c6d7d164cbd1add172d16798720d9a3b9a5f7bf1d56c291f78ab8c583d110a8

### Using the Inspector
The MCP Inspector provides a web interface to:
- View available tools and their schemas
- Test tool invocations
- Monitor server communication
- Debug MCP protocol messages

## Important Notes

### System Requirements
⚠️ **Critical:** This MCP server is specifically designed for **iTerm2 on macOS**

- **Current System:** Linux (Ubuntu/Debian)
- **iTerm2 Status:** Not available on Linux
- **Implication:** The terminal interaction features require iTerm2's AppleScript API

### Functionality on Linux
While the server can be installed and configured on Linux:
- The server will start successfully
- Tool schemas will be available
- **However:** Actual terminal interaction will fail without iTerm2
- The server uses iTerm2-specific AppleScript commands

### Alternative Solutions
For Linux environments, consider:
1. Using standard terminal emulators with different MCP servers
2. Running in a macOS environment (VM, remote machine, etc.)
3. Adapting the code to work with Linux terminal emulators (requires modification)

## Testing the Server

### Method 1: MCP Inspector (Currently Running)
```bash
cd /root/.vscode-server/iterm-mcp
npx @modelcontextprotocol/inspector node build/index.js
```

Access at: http://localhost:6274

### Method 2: Direct Integration
The server can be integrated with MCP-compatible clients using the configuration in `blackbox_mcp_settings.json`

### Method 3: Command Line Testing
```bash
# Run the server directly
node /root/.vscode-server/iterm-mcp/build/index.js
```

## Server Capabilities

### Features
- ✅ Efficient token use (inspect only relevant output)
- ✅ Natural integration with terminal
- ✅ Full terminal control
- ✅ REPL support
- ✅ Control character support (Ctrl-C, Ctrl-Z, etc.)
- ✅ Minimal dependencies

### Safety Considerations
⚠️ **Important Safety Notes:**
- No built-in command safety restrictions
- User responsible for monitoring activity
- Models can behave unexpectedly
- Ability to interrupt is crucial
- Start with small, focused tasks

## Development

### Watch Mode (Auto-rebuild)
```bash
cd /root/.vscode-server/iterm-mcp
npm run watch
```

### View Logs
```bash
tail -n 20 -f ~/Library/Logs/Claude/mcp*.log
```

## File Structure

```
/root/.vscode-server/iterm-mcp/
├── build/
│   ├── index.js (main executable)
│   ├── CommandExecutor.js
│   ├── ProcessTracker.js
│   ├── SendControlCharacter.js
│   └── TtyOutputReader.js
├── src/ (source TypeScript files)
├── package.json
└── tsconfig.json
```

## Next Steps

1. **For macOS Users:**
   - Ensure iTerm2 is running
   - Test tools through MCP Inspector
   - Integrate with Claude Desktop or other MCP clients

2. **For Linux Users:**
   - Use the setup as a reference
   - Consider alternative terminal MCP servers
   - Or adapt the code for Linux terminal emulators

3. **Integration:**
   - The `blackbox_mcp_settings.json` is ready for use
   - Server name: `github.com/pashpashpash/iterm-mcp`
   - Can be integrated with any MCP-compatible client

## Troubleshooting

### Server Won't Start
- Check Node.js version (requires v18+)
- Verify build completed successfully
- Check file permissions on build/index.js

### Tools Not Working
- Verify iTerm2 is running (macOS only)
- Check iTerm2 has necessary permissions
- Review MCP Inspector logs

### Connection Issues
- Ensure no port conflicts (6274, 6277)
- Check firewall settings
- Verify session token if authentication enabled

## Resources

- **Repository:** https://github.com/pashpashpash/iterm-mcp
- **MCP Inspector:** https://github.com/modelcontextprotocol/inspector
- **Original Fork:** https://github.com/ferrislucas/iterm-mcp

## License
MIT License (see repository for details)
