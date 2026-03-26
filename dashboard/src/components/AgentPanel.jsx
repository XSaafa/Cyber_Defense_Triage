import { useState, useRef, useEffect } from 'react'

const TOOL_LABELS = {
  triage_alert: { icon: '🚨', label: 'Triaging Alert' },
  classify_log:  { icon: '📋', label: 'Classifying Log' },
  scan_ioc:      { icon: '🔍', label: 'Scanning IOC' },
  check_cve:     { icon: '🐛', label: 'Checking CVE' },
  get_playbook:  { icon: '📖', label: 'Loading Playbook' },
}

function StepItem({ event }) {
  const [expanded, setExpanded] = useState(false)

  if (event.type === 'thinking') {
    return (
      <div className="flex items-start gap-3 py-2">
        <span className="text-blue-400 mt-0.5">💭</span>
        <p className="text-gray-300 text-sm leading-relaxed">{event.text}</p>
      </div>
    )
  }

  if (event.type === 'tool_call') {
    const meta = TOOL_LABELS[event.name] || { icon: '🔧', label: event.name }
    return (
      <div className="flex items-center gap-3 py-2">
        <span className="text-yellow-400">{meta.icon}</span>
        <span className="text-yellow-300 text-sm font-medium">{meta.label}</span>
        <span className="text-gray-500 text-xs font-mono truncate max-w-xs">
          {JSON.stringify(event.input).slice(0, 80)}
        </span>
      </div>
    )
  }

  if (event.type === 'tool_result') {
    const meta = TOOL_LABELS[event.name] || { icon: '✅', label: event.name }
    const preview = event.result.slice(0, 120).replace(/\n/g, ' ')
    return (
      <div className="py-2">
        <button
          onClick={() => setExpanded(e => !e)}
          className="flex items-center gap-3 w-full text-left hover:opacity-80"
        >
          <span className="text-green-400">✅</span>
          <span className="text-green-300 text-sm font-medium">{meta.label} complete</span>
          <span className="text-gray-500 text-xs ml-auto">{expanded ? '▲ hide' : '▼ expand'}</span>
        </button>
        {!expanded && (
          <p className="text-gray-500 text-xs mt-1 ml-7 truncate">{preview}...</p>
        )}
        {expanded && (
          <pre className="mt-2 ml-7 text-xs text-gray-300 bg-gray-900 rounded p-3 overflow-auto max-h-64 whitespace-pre-wrap">
            {event.result}
          </pre>
        )}
      </div>
    )
  }

  if (event.type === 'error') {
    return (
      <div className="flex items-start gap-3 py-2">
        <span className="text-red-400">❌</span>
        <p className="text-red-300 text-sm">{event.message}</p>
      </div>
    )
  }

  return null
}

function ReportView({ text }) {
  // Convert markdown-ish text to styled sections
  const lines = text.split('\n')
  return (
    <div className="space-y-1">
      {lines.map((line, i) => {
        if (line.startsWith('## ')) {
          return <h2 key={i} className="text-lg font-bold text-white mt-4 mb-1">{line.slice(3)}</h2>
        }
        if (line.startsWith('### ')) {
          return <h3 key={i} className="text-sm font-semibold text-red-400 mt-3 mb-1">{line.slice(4)}</h3>
        }
        if (line.startsWith('**') && line.endsWith('**')) {
          return <p key={i} className="text-sm font-semibold text-gray-200">{line.slice(2, -2)}</p>
        }
        if (line.startsWith('- ') || line.startsWith('* ')) {
          return <p key={i} className="text-sm text-gray-300 pl-4">• {line.slice(2)}</p>
        }
        if (/^\d+\. /.test(line)) {
          return <p key={i} className="text-sm text-gray-300 pl-4">{line}</p>
        }
        if (line.startsWith('🔴') || line.startsWith('🟠') || line.startsWith('🟡') || line.startsWith('🟢')) {
          return <p key={i} className="text-sm font-bold text-yellow-300">{line}</p>
        }
        if (line.trim() === '' || line.startsWith('─') || line.startsWith('═')) {
          return <div key={i} className="h-2" />
        }
        return <p key={i} className="text-sm text-gray-300">{line}</p>
      })}
    </div>
  )
}

export default function AgentPanel() {
  const [incident, setIncident] = useState('')
  const [steps, setSteps] = useState([])
  const [report, setReport] = useState(null)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState(null)
  const stepsEndRef = useRef(null)

  useEffect(() => {
    stepsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [steps])

  async function runInvestigation() {
    if (!incident.trim() || running) return

    setSteps([])
    setReport(null)
    setError(null)
    setRunning(true)

    try {
      const res = await fetch('/api/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incident: incident.trim() })
      })

      if (!res.ok) {
        const text = await res.text()
        let message = `Server error (${res.status})`
        try { message = JSON.parse(text).error || message } catch {}
        throw new Error(message)
      }

      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const parts = buffer.split('\n\n')
        buffer = parts.pop() // keep incomplete chunk

        for (const part of parts) {
          if (!part.trim()) continue
          const lines = part.split('\n')
          let eventType = ''
          let dataLine = ''

          for (const line of lines) {
            if (line.startsWith('event: ')) eventType = line.slice(7)
            if (line.startsWith('data: ')) dataLine = line.slice(6)
          }

          if (eventType === 'done' || eventType === 'start') continue
          if (!dataLine || !dataLine.trim()) continue

          let event
          try {
            event = JSON.parse(dataLine)
          } catch {
            continue // skip malformed SSE frames
          }

          if (!event || typeof event !== 'object') continue

          if (event.type === 'report') {
            setReport(event.text)
          } else if (event.type === 'error') {
            setError(event.message)
          } else if (event.type) {
            setSteps(prev => [...prev, event])
          }
        }
      }
    } catch (err) {
      const msg = err.message || String(err)
      if (msg.includes('Failed to fetch') || msg.includes('NetworkError') || msg.includes('fetch')) {
        setError('Cannot reach the agent server. Make sure it is running: npm run agent')
      } else {
        setError(msg)
      }
    } finally {
      setRunning(false)
    }
  }

  function reset() {
    setSteps([])
    setReport(null)
    setError(null)
    setIncident('')
  }

  const toolCallCount = steps.filter(s => s.type === 'tool_call').length

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white mb-1">AI Investigator</h2>
        <p className="text-gray-400 text-sm">
          Describe any security incident. The agent will autonomously triage, classify logs, scan IOCs,
          check CVEs, and produce a full incident report — no manual tool selection needed.
        </p>
      </div>

      {/* Input area */}
      {!running && !report && (
        <div className="space-y-3">
          <textarea
            value={incident}
            onChange={e => setIncident(e.target.value)}
            placeholder={`Describe the incident, e.g.:\n\n"EDR alert on WORKSTATION-42: suspicious process cmd.exe spawned from excel.exe, connecting to 185.220.101.45 on port 4444. User: john.doe. Possible CVE-2021-40444 exploitation."`}
            rows={6}
            className="w-full bg-gray-800 border border-gray-600 rounded-lg px-4 py-3 text-gray-100
                       placeholder-gray-500 text-sm resize-none focus:outline-none focus:border-red-500
                       focus:ring-1 focus:ring-red-500"
          />
          <button
            onClick={runInvestigation}
            disabled={!incident.trim()}
            className="px-6 py-3 bg-red-600 hover:bg-red-700 disabled:bg-gray-700 disabled:text-gray-500
                       text-white font-semibold rounded-lg transition-colors flex items-center gap-2"
          >
            <span>🤖</span>
            Auto-Investigate
          </button>
        </div>
      )}

      {/* Live investigation steps */}
      {(running || steps.length > 0) && !report && (
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              {running && (
                <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
              )}
              <span className="text-sm font-medium text-gray-300">
                {running ? 'Investigating...' : 'Investigation complete'}
              </span>
            </div>
            {toolCallCount > 0 && (
              <span className="text-xs text-gray-500">{toolCallCount} tool{toolCallCount !== 1 ? 's' : ''} called</span>
            )}
          </div>

          <div className="space-y-0.5 divide-y divide-gray-700/50">
            {steps.map((step, i) => (
              <StepItem key={i} event={step} />
            ))}
          </div>
          <div ref={stepsEndRef} />
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded-lg p-4">
          <p className="text-red-400 text-sm font-medium">❌ Investigation failed</p>
          <p className="text-red-300 text-sm mt-1">{error}</p>
          {error.includes('fetch') || error.includes('network') || error.includes('connect') ? (
            <p className="text-gray-400 text-xs mt-2">
              Make sure the agent server is running: <code className="bg-gray-800 px-1 rounded">npm run agent</code>
            </p>
          ) : null}
          <button onClick={reset} className="mt-3 text-xs text-gray-400 hover:text-white underline">
            Try again
          </button>
        </div>
      )}

      {/* Final report */}
      {report && (
        <div className="space-y-4">
          {/* Steps summary (collapsed) */}
          {steps.length > 0 && (
            <details className="bg-gray-800 rounded-lg border border-gray-700">
              <summary className="px-4 py-3 cursor-pointer text-sm text-gray-400 hover:text-gray-200">
                🔍 Investigation steps ({toolCallCount} tools called) — click to expand
              </summary>
              <div className="px-4 pb-4 space-y-0.5 divide-y divide-gray-700/50">
                {steps.map((step, i) => (
                  <StepItem key={i} event={step} />
                ))}
              </div>
            </details>
          )}

          {/* The report */}
          <div className="bg-gray-800 rounded-lg border border-gray-600 p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold text-white">📋 Incident Report</h3>
              <button
                onClick={() => navigator.clipboard?.writeText(report)}
                className="text-xs text-gray-400 hover:text-white border border-gray-600 hover:border-gray-400
                           rounded px-2 py-1 transition-colors"
              >
                Copy
              </button>
            </div>
            <div className="prose prose-invert max-w-none">
              <ReportView text={report} />
            </div>
          </div>

          <button
            onClick={reset}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 text-sm rounded-lg transition-colors"
          >
            ← New Investigation
          </button>
        </div>
      )}
    </div>
  )
}
