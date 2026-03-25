#!/usr/bin/env node
// Autonomous SOC Investigator — Claude-powered agentic loop
// Can run standalone:  node agent/investigator.js "alert description here"

import Anthropic from '@anthropic-ai/sdk'
import { TOOL_DEFINITIONS, executeTool } from '../lib/triageTools.js'

const client = new Anthropic()

const SYSTEM_PROMPT = `You are an expert SOC (Security Operations Center) analyst and incident responder.
You have been given a set of triage tools. Your job is to autonomously investigate security incidents.

When given an incident, you MUST:
1. Always start by calling triage_alert to classify the severity and type
2. If the incident mentions log entries, call classify_log to analyze them
3. Extract any IOCs (IPs, domains, hashes, URLs) from the incident and call scan_ioc for each
4. If any CVEs are mentioned, call check_cve to get full details
5. Always finish by calling get_playbook for the appropriate incident type
6. After all tool calls are complete, write a comprehensive INCIDENT REPORT

Your final report MUST include:
- ## Incident Summary (2-3 sentences)
- ## Severity & Classification
- ## MITRE ATT&CK Mapping (if applicable)
- ## IOCs Identified (list all found)
- ## Immediate Actions Required (prioritized)
- ## Full Response Playbook
- ## Analyst Recommendations

Be thorough. The more tools you call, the better the investigation.`

/**
 * Run an autonomous investigation.
 * Returns an async generator that yields step events as the agent works.
 *
 * Event types:
 *   { type: 'thinking',     text }         — agent reasoning text
 *   { type: 'tool_call',    name, input }  — about to call a tool
 *   { type: 'tool_result',  name, result } — tool returned data
 *   { type: 'report',       text }         — final incident report
 *   { type: 'error',        message }      — something went wrong
 */
export async function* investigate(incidentDescription) {
  const messages = [
    {
      role: 'user',
      content: `Investigate this security incident:\n\n${incidentDescription}`
    }
  ]

  let iterations = 0
  const MAX_ITERATIONS = 20 // safety cap

  while (iterations < MAX_ITERATIONS) {
    iterations++

    let response
    try {
      response = await client.messages.create({
        model: 'claude-opus-4-6',
        max_tokens: 4096,
        system: SYSTEM_PROMPT,
        tools: TOOL_DEFINITIONS,
        messages
      })
    } catch (err) {
      yield { type: 'error', message: `Claude API error: ${err.message}` }
      return
    }

    // Yield any text blocks as "thinking"
    for (const block of response.content) {
      if (block.type === 'text' && block.text.trim()) {
        yield { type: 'thinking', text: block.text }
      }
    }

    // If Claude is done (no more tool calls) — final report
    if (response.stop_reason === 'end_turn') {
      const finalText = response.content
        .filter(b => b.type === 'text')
        .map(b => b.text)
        .join('\n')
      yield { type: 'report', text: finalText }
      return
    }

    // Handle tool calls
    if (response.stop_reason === 'tool_use') {
      const toolUseBlocks = response.content.filter(b => b.type === 'tool_use')
      const toolResults = []

      for (const block of toolUseBlocks) {
        yield { type: 'tool_call', name: block.name, input: block.input }

        let result
        try {
          result = await executeTool(block.name, block.input)
        } catch (err) {
          result = `Tool execution error: ${err.message}`
        }

        yield { type: 'tool_result', name: block.name, result }

        toolResults.push({
          type: 'tool_result',
          tool_use_id: block.id,
          content: result
        })
      }

      // Feed results back to Claude
      messages.push({ role: 'assistant', content: response.content })
      messages.push({ role: 'user', content: toolResults })
    }
  }

  yield { type: 'error', message: 'Investigation exceeded maximum iterations' }
}

// ─── CLI entrypoint ───────────────────────────────────────────────────────────

if (process.argv[1].endsWith('investigator.js')) {
  const incident = process.argv.slice(2).join(' ')
  if (!incident) {
    console.error('Usage: node agent/investigator.js "describe the security incident here"')
    process.exit(1)
  }

  console.log('\n🤖 Starting autonomous investigation...\n')
  console.log('─'.repeat(60))

  for await (const event of investigate(incident)) {
    switch (event.type) {
      case 'thinking':
        console.log('\n💭 Agent thinking:\n' + event.text)
        break
      case 'tool_call':
        console.log(`\n🔧 Calling tool: ${event.name}`)
        console.log('   Input:', JSON.stringify(event.input, null, 2))
        break
      case 'tool_result':
        console.log(`\n✅ ${event.name} result (truncated):`)
        console.log(event.result.slice(0, 400) + (event.result.length > 400 ? '...' : ''))
        break
      case 'report':
        console.log('\n' + '═'.repeat(60))
        console.log('📋 FINAL INCIDENT REPORT')
        console.log('═'.repeat(60))
        console.log(event.text)
        break
      case 'error':
        console.error('\n❌ Error:', event.message)
        break
    }
  }
}
