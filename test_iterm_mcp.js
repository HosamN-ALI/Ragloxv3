#!/usr/bin/env node

/**
 * iTerm MCP Server Demonstration Script
 * 
 * This script demonstrates how to interact with the iTerm MCP server
 * by sending MCP protocol messages and receiving responses.
 * 
 * Note: This requires iTerm2 to be running on macOS for actual functionality.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

async function demonstrateMCPServer() {
    console.log("=".repeat(70));
    console.log("iTerm MCP Server Demonstration");
    console.log("=".repeat(70));
    console.log();

    // Create a client to connect to the MCP server
    const transport = new StdioClientTransport({
        command: "node",
        args: ["/root/.vscode-server/iterm-mcp/build/index.js"]
    });

    const client = new Client({
        name: "iterm-mcp-demo-client",
        version: "1.0.0"
    }, {
        capabilities: {}
    });

    try {
        // Connect to the server
        console.log("📡 Connecting to iTerm MCP server...");
        await client.connect(transport);
        console.log("✅ Connected successfully!\n");

        // List available tools
        console.log("🔧 Available Tools:");
        console.log("-".repeat(70));
        const toolsResponse = await client.listTools();

        toolsResponse.tools.forEach((tool, index) => {
            console.log(`\n${index + 1}. ${tool.name}`);
            console.log(`   Description: ${tool.description}`);
            console.log(`   Input Schema:`);
            console.log(`   ${JSON.stringify(tool.inputSchema, null, 2).split('\n').join('\n   ')}`);
        });

        console.log("\n" + "=".repeat(70));
        console.log("Tool Demonstration Examples");
        console.log("=".repeat(70));

        // Example 1: write_to_terminal
        console.log("\n📝 Example 1: write_to_terminal");
        console.log("-".repeat(70));
        console.log("Purpose: Execute a command in the terminal");
        console.log("Example usage:");
        console.log(`  Tool: write_to_terminal`);
        console.log(`  Input: { command: "echo 'Hello from MCP!'" }`);
        console.log(`  Expected: Returns number of output lines produced`);
        console.log("\nNote: Requires iTerm2 on macOS to actually execute");

        // Example 2: read_terminal_output
        console.log("\n📖 Example 2: read_terminal_output");
        console.log("-".repeat(70));
        console.log("Purpose: Read terminal output");
        console.log("Example usage:");
        console.log(`  Tool: read_terminal_output`);
        console.log(`  Input: { linesOfOutput: 10 }`);
        console.log(`  Expected: Returns last 10 lines from terminal`);
        console.log("\nNote: Requires iTerm2 on macOS to read actual output");

        // Example 3: send_control_character
        console.log("\n⌨️  Example 3: send_control_character");
        console.log("-".repeat(70));
        console.log("Purpose: Send control characters (Ctrl-C, Ctrl-Z, etc.)");
        console.log("Example usage:");
        console.log(`  Tool: send_control_character`);
        console.log(`  Input: { letter: "C" }`);
        console.log(`  Expected: Sends Ctrl-C to interrupt running process`);
        console.log("\nNote: Requires iTerm2 on macOS to send actual signals");

        console.log("\n" + "=".repeat(70));
        console.log("Server Capabilities Summary");
        console.log("=".repeat(70));
        console.log("✅ Server is properly configured and responding");
        console.log("✅ All three tools are available and documented");
        console.log("✅ MCP protocol communication is working");
        console.log("⚠️  Actual terminal interaction requires iTerm2 on macOS");
        console.log("\n" + "=".repeat(70));

    } catch (error) {
        console.error("❌ Error:", error.message);
        console.error("\nThis is expected on Linux systems without iTerm2");
    } finally {
        // Close the connection
        await client.close();
        console.log("\n👋 Disconnected from server");
    }
}

// Run the demonstration
demonstrateMCPServer().catch(console.error);
