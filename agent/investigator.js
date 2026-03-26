#!/usr/bin/env node
// Autonomous SOC Investigator — Groq-powered agentic loop
// Can run standalone:  node agent/investigator.js "alert description here"

import Groq from 'groq-sdk'
import { TOOL_DEFINITIONS, executeTool } from '../lib/triageTools.js'

let client = null
function getClient() {
  if (!client) client = new Groq({ apiKey: process.env.GROQ_API_KEY })
  return client
}

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
    { role: 'system', content: SYSTEM_PROMPT },
    { role: 'user', content: `Investigate this security incident:\n\n${incidentDescription}` }
  ]

  let iterations = 0
  const MAX_ITERATIONS = 20 // safety cap

  while (iterations < MAX_ITERATIONS) {
    iterations++

    let response
    try {
      response = await getClient().chat.completions.create({
        model: 'llama-3.3-70b-versatile',
        max_tokens: 4096,
        tools: TOOL_DEFINITIONS,
        tool_choice: 'auto',
        messages
      })
    } catch (err) {
      yield { type: 'error', message: `Groq API error: ${err.message}` }
      return
    }

    const choice = response.choices[0]
    const message = choice.message

    // Yield text content as "thinking"
    if (message.content && message.content.trim()) {
      yield { type: 'thinking', text: message.content }
    }

    // Done — no more tool calls
    if (choice.finish_reason === 'stop') {
      yield { type: 'report', text: message.content }
      return
    }

    // Handle tool calls
    if (choice.finish_reason === 'tool_calls' && message.tool_calls) {
      const toolResults = []

      for (const toolCall of message.tool_calls) {
        const name = toolCall.function.name

        let input
        try {
          input = JSON.parse(toolCall.function.arguments)
        } catch {
          input = {}
        }

        yield { type: 'tool_call', name, input }

        let result
        try {
          result = await executeTool(name, input)
        } catch (err) {
          result = `Tool execution error: ${err.message}`
        }

        yield { type: 'tool_result', name, result }

        toolResults.push({
          role: 'tool',
          tool_call_id: toolCall.id,
          content: result
        })
      }

      // Feed results back to the model
      messages.push(message)           // assistant message with tool_calls
      messages.push(...toolResults)    // tool result messages
    }
  }

  yield { type: 'error', message: 'Investigation exceeded maximum iterations' }
}

// ─── CLI entrypoint ───────────────────────────────────────────────────────────

if (process.argv[1]?.endsWith('investigator.js')) {
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
