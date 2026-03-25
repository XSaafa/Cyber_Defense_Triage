#!/usr/bin/env node

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { homedir } from 'os';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Detect OS and get Windsurf config path
function getWindsurfConfigPath() {
  const platform = process.platform;
  
  if (platform === 'win32') {
    const appData = process.env.APPDATA;
    return join(appData, 'Windsurf', 'mcp_config.json');
  } else if (platform === 'darwin' || platform === 'linux') {
    return join(homedir(), '.codeium', 'windsurf', 'mcp_config.json');
  }
  
  throw new Error(`Unsupported platform: ${platform}`);
}

// Get absolute path to server.js (convert to forward slashes)
const serverPath = join(__dirname, 'server.js').replace(/\\/g, '/');

console.log('============================================================');
console.log(' WINDSURF MCP CONFIGURATION SETUP');
console.log('============================================================\n');

console.log(`Detected OS: ${process.platform}`);
console.log(`Server path: ${serverPath}\n`);

// Get config file path
const configPath = getWindsurfConfigPath();
console.log(`Windsurf config path: ${configPath}\n`);

// Ensure directory exists
const configDir = dirname(configPath);
if (!existsSync(configDir)) {
  console.log(`Creating directory: ${configDir}`);
  mkdirSync(configDir, { recursive: true });
}

// Read existing config or create new one
let config = { mcpServers: {} };

if (existsSync(configPath)) {
  console.log('Existing config file found - merging...');
  try {
    const existingContent = readFileSync(configPath, 'utf-8');
    config = JSON.parse(existingContent);
    if (!config.mcpServers) {
      config.mcpServers = {};
    }
  } catch (err) {
    console.log('Warning: Could not parse existing config, creating new one');
    config = { mcpServers: {} };
  }
} else {
  console.log('No existing config - creating new file...');
}

// Add cyber-triage server
config.mcpServers['cyber-triage'] = {
  command: 'node',
  args: [serverPath],
  env: {}
};

// Write config
writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');

console.log('\n✅ Configuration written successfully!\n');
console.log('Final config:');
console.log('─'.repeat(60));
console.log(JSON.stringify(config, null, 2));
console.log('─'.repeat(60));

console.log('\n✅ SETUP COMPLETE!');
console.log('\nNext step: Restart Windsurf completely, then the cyber-triage');
console.log('MCP server will be available in Cascade.\n');
