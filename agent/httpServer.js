#!/usr/bin/env node
// HTTP + SSE server — bridges the AI agent to the React dashboard
// Runs on port 3001 (proxied by Vite on /api/*)

import http from 'http'
import { investigate } from './investigator.js'

const PORT = process.env.AGENT_PORT || 3001

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type'
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = ''
    req.on('data', chunk => { body += chunk })
    req.on('end', () => resolve(body))
    req.on('error', reject)
  })
}

const server = http.createServer(async (req, res) => {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS_HEADERS)
    res.end()
    return
  }

  // POST /api/investigate — streams SSE events as agent works
  if (req.url === '/api/investigate' && req.method === 'POST') {
    let body
    try {
      body = JSON.parse(await readBody(req))
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json', ...CORS_HEADERS })
      res.end(JSON.stringify({ error: 'Invalid JSON body' }))
      return
    }

    const { incident } = body
    if (!incident || !incident.trim()) {
      res.writeHead(400, { 'Content-Type': 'application/json', ...CORS_HEADERS })
      res.end(JSON.stringify({ error: 'incident field is required' }))
      return
    }

    // SSE response
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      ...CORS_HEADERS
    })

    // Send a heartbeat so the client knows the stream started
    res.write('event: start\ndata: {}\n\n')

    try {
      for await (const event of investigate(incident)) {
        res.write(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`)
        if (event.type === 'report' || event.type === 'error') break
      }
    } catch (err) {
      res.write(`event: error\ndata: ${JSON.stringify({ type: 'error', message: err.message })}\n\n`)
    }

    res.write('event: done\ndata: {}\n\n')
    res.end()
    return
  }

  // Health check
  if (req.url === '/health' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json', ...CORS_HEADERS })
    res.end(JSON.stringify({ status: 'ok', service: 'cyber-triage-agent' }))
    return
  }

  res.writeHead(404, { 'Content-Type': 'application/json', ...CORS_HEADERS })
  res.end(JSON.stringify({ error: 'Not found' }))
})

server.listen(PORT, () => {
  console.log(`🤖 Cyber Triage Agent HTTP server running on http://localhost:${PORT}`)
  console.log(`   POST /api/investigate  — run autonomous investigation (SSE stream)`)
  console.log(`   GET  /health           — health check`)
})
