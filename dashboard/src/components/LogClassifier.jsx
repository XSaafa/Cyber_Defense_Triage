import { useState } from 'react'
import { classifyLog } from '../lib/triageEngine'
import SeverityBadge from './SeverityBadge'

function LogClassifier() {
  const [logEntry, setLogEntry] = useState('')
  const [logType, setLogType] = useState('')
  const [result, setResult] = useState(null)

  const logTypes = ['', 'syslog', 'windows_event', 'web_server', 'firewall', 'auth', 'application']

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!logEntry.trim()) return

    const classificationResult = classifyLog(logEntry, logType || null)
    setResult(classificationResult)
  }

  const handleClear = () => {
    setLogEntry('')
    setLogType('')
    setResult(null)
  }

  return (
    <div className="max-w-6xl">
      <div className="mb-8">
        <h2 className="text-3xl font-bold text-white mb-2">📋 Log Classifier</h2>
        <p className="text-gray-400">Analyze raw log entries to detect attack patterns and security events</p>
      </div>

      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6 mb-6">
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Log Entry *
            </label>
            <textarea
              value={logEntry}
              onChange={(e) => setLogEntry(e.target.value)}
              className="w-full px-4 py-3 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
              rows="6"
              placeholder="Paste raw log entry here, e.g.:&#10;Jun 12 03:14:22 web01 sshd[1234]: Failed password for root from 45.33.32.156 port 54321"
              required
            />
          </div>

          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Log Type (Optional)
            </label>
            <select
              value={logType}
              onChange={(e) => setLogType(e.target.value)}
              className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
            >
              {logTypes.map(type => (
                <option key={type} value={type}>
                  {type || 'Auto-detect'}
                </option>
              ))}
            </select>
          </div>

          <div className="flex space-x-3">
            <button
              type="submit"
              className="px-6 py-2 bg-red-600 hover:bg-red-700 text-white font-medium rounded-lg transition-colors"
            >
              Classify Log
            </button>
            <button
              type="button"
              onClick={handleClear}
              className="px-6 py-2 bg-gray-700 hover:bg-gray-600 text-white font-medium rounded-lg transition-colors"
            >
              Clear
            </button>
          </div>
        </form>
      </div>

      {result && (
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
          <h3 className="text-xl font-bold text-white mb-4">Classification Result</h3>

          {result.logType && (
            <div className="mb-4">
              <span className="text-gray-400">Log Type: </span>
              <span className="text-white font-medium">{result.logType}</span>
            </div>
          )}

          <div className="mb-6 p-4 bg-gray-900 rounded-lg border border-gray-600">
            <p className="text-xs text-gray-400 mb-2">Log Entry:</p>
            <pre className="text-sm text-gray-300 font-mono whitespace-pre-wrap break-words">
              {logEntry.slice(0, 500)}{logEntry.length > 500 ? '...' : ''}
            </pre>
          </div>

          {result.topMatch ? (
            <>
              <div className="mb-6">
                <div className="flex items-center space-x-3 mb-4">
                  <SeverityBadge severity={result.topMatch.severity} />
                  <h4 className="text-xl font-semibold text-white">{result.topMatch.type}</h4>
                </div>
                
                <div className="p-4 bg-gray-900 rounded-lg border border-gray-600 mb-4">
                  <p className="text-sm text-gray-400 mb-2">What this log indicates:</p>
                  <p className="text-gray-300">{result.topMatch.description}</p>
                </div>

                <div className="p-4 bg-yellow-900/30 border border-yellow-700 rounded-lg">
                  <p className="text-sm text-yellow-400 font-semibold mb-2">Immediate Action:</p>
                  <p className="text-gray-300">{result.topMatch.action}</p>
                </div>
              </div>

              {result.matches.length > 1 && (
                <div className="mb-6">
                  <h4 className="text-lg font-semibold text-orange-400 mb-3">Additional Patterns Detected</h4>
                  <div className="space-y-2">
                    {result.matches.slice(1).map((match, i) => (
                      <div key={i} className="p-3 bg-gray-900 rounded-lg border border-gray-600">
                        <p className="text-white font-medium">{match.type}</p>
                        <p className="text-sm text-gray-400">{match.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <h4 className="text-lg font-semibold text-cyan-400 mb-3">Forensic Analysis Tips</h4>
                <ul className="list-disc list-inside space-y-1 text-gray-300 p-4 bg-gray-900 rounded-lg border border-gray-600">
                  <li>Extract the source IP and look it up on AbuseIPDB or VirusTotal</li>
                  <li>Check if this pattern appears in other log sources in the same time window</li>
                  <li>Look for what happened BEFORE and AFTER this log entry (context window ±5 min)</li>
                  <li>Preserve this log entry and its neighbors before log rotation</li>
                </ul>
              </div>
            </>
          ) : (
            <div className="p-6 bg-green-900/20 border border-green-700 rounded-lg">
              <h4 className="text-lg font-semibold text-green-400 mb-2">✓ No Known Attack Pattern Detected</h4>
              <p className="text-gray-300 mb-4">This log entry does not match known attack signatures.</p>
              
              {result.hasIp && result.hasError && (
                <p className="text-yellow-400 text-sm mb-2">
                  ⚠️ Note: Contains an IP address and error/denial — consider correlating this IP against threat intel feeds.
                </p>
              )}
              
              {result.hasSuccess && (
                <p className="text-yellow-400 text-sm mb-2">
                  ⚠️ Note: Log indicates a successful action. If unexpected, investigate the user/source.
                </p>
              )}
              
              <p className="text-gray-400 text-sm mt-4">
                Recommendation: Log for baseline, monitor for pattern recurrence.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default LogClassifier
