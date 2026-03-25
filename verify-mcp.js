#!/usr/bin/env node

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('============================================================');
console.log(' MCP SERVER VERIFICATION TEST');
console.log('============================================================\n');

const serverPath = join(__dirname, 'server.js');
console.log(`Starting MCP server: ${serverPath}\n`);

// Spawn the server process
const serverProcess = spawn('node', [serverPath], {
  stdio: ['pipe', 'pipe', 'pipe']
});

let messageId = 1;

// Helper to send JSON-RPC message
function sendMessage(method, params = {}) {
  const message = {
    jsonrpc: '2.0',
    id: messageId++,
    method,
    params
  };
  const json = JSON.stringify(message) + '\n';
  serverProcess.stdin.write(json);
  console.log(`→ Sent: ${method}`);
}

// Helper to send notification (no id)
function sendNotification(method, params = {}) {
  const message = {
    jsonrpc: '2.0',
    method,
    params
  };
  const json = JSON.stringify(message) + '\n';
  serverProcess.stdin.write(json);
  console.log(`→ Sent notification: ${method}`);
}

let buffer = '';
let testStep = 0;
let toolsList = [];

serverProcess.stdout.on('data', (data) => {
  buffer += data.toString();
  
  // Process complete JSON-RPC messages
  const lines = buffer.split('\n');
  buffer = lines.pop(); // Keep incomplete line in buffer
  
  for (const line of lines) {
    if (!line.trim()) continue;
    
    try {
      const response = JSON.parse(line);
      console.log(`← Received:`, JSON.stringify(response, null, 2));
      
      // Handle responses based on test step
      if (testStep === 0 && response.result) {
        // Initialize response received
        console.log('\n✅ Server initialized successfully');
        console.log(`   Server: ${response.result.serverInfo?.name || 'unknown'}`);
        console.log(`   Version: ${response.result.serverInfo?.version || 'unknown'}\n`);
        
        testStep = 1;
        // Send initialized notification
        sendNotification('notifications/initialized');
        
        // Request tools list
        setTimeout(() => {
          sendMessage('tools/list');
        }, 100);
        
      } else if (testStep === 1 && response.result?.tools) {
        // Tools list received
        toolsList = response.result.tools;
        console.log(`\n✅ Received ${toolsList.length} tools:`);
        toolsList.forEach(tool => {
          console.log(`   - ${tool.name}: ${tool.description}`);
        });
        
        testStep = 2;
        // Test triage_alert tool
        console.log('\n📋 Testing triage_alert tool...\n');
        setTimeout(() => {
          sendMessage('tools/call', {
            name: 'triage_alert',
            arguments: {
              alert_description: 'ransomware encrypting files detected on DESKTOP-01',
              source_system: 'Windows Defender',
              affected_asset: 'DESKTOP-01'
            }
          });
        }, 100);
        
      } else if (testStep === 2 && response.result?.content) {
        // Tool call result received
        console.log('\n✅ Tool call successful!');
        console.log('\n📄 Response:');
        console.log('─'.repeat(60));
        response.result.content.forEach(item => {
          if (item.type === 'text') {
            console.log(item.text);
          }
        });
        console.log('─'.repeat(60));
        
        console.log('\n✅ ALL TESTS PASSED!');
        console.log('\nThe MCP server is working correctly.');
        console.log('It can now be used by Windsurf/Cascade.\n');
        
        // Clean exit
        serverProcess.kill();
        process.exit(0);
      }
      
    } catch (err) {
      // Ignore parse errors for incomplete messages
    }
  }
});

serverProcess.stderr.on('data', (data) => {
  const msg = data.toString();
  if (msg.includes('running on stdio')) {
    console.log('✅ Server started\n');
    
    // Send initialize request
    setTimeout(() => {
      sendMessage('initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {
          roots: { listChanged: true },
          sampling: {}
        },
        clientInfo: {
          name: 'verify-mcp-test',
          version: '1.0.0'
        }
      });
    }, 500);
  }
});

serverProcess.on('error', (err) => {
  console.error('❌ Failed to start server:', err);
  process.exit(1);
});

serverProcess.on('exit', (code) => {
  if (code !== 0 && code !== null) {
    console.error(`\n❌ Server exited with code ${code}`);
    process.exit(1);
  }
});

// Timeout after 10 seconds
setTimeout(() => {
  console.error('\n❌ Test timeout - server did not respond in time');
  serverProcess.kill();
  process.exit(1);
}, 10000);
