import { useState } from 'react'
import { triageAlert } from '../lib/triageEngine'
import SeverityBadge from './SeverityBadge'

function TriagePanel() {
  const [alertDescription, setAlertDescription] = useState('')
  const [sourceSystem, setSourceSystem] = useState('')
  const [affectedAsset, setAffectedAsset] = useState('')
  const [result, setResult] = useState(null)

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!alertDescription.trim()) return

    const triageResult = triageAlert(alertDescription, sourceSystem || null, affectedAsset || null)
    setResult(triageResult)
  }

  const handleClear = () => {
    setAlertDescription('')
    setSourceSystem('')
    setAffectedAsset('')
    setResult(null)
  }

  return (
    <div className="max-w-6xl">
      <div className="mb-8">
        <h2 className="text-3xl font-bold text-white mb-2">🚨 Alert Triage</h2>
        <p className="text-gray-400">Paste a security alert to get instant severity assessment and response actions</p>
      </div>

      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6 mb-6">
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Alert Description *
            </label>
            <textarea
              value={alertDescription}
              onChange={(e) => setAlertDescription(e.target.value)}
              className="w-full px-4 py-3 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
              rows="4"
              placeholder="e.g., Multiple failed SSH login attempts from 192.168.1.100 on prod-server"
              required
            />
          </div>

          <div className="grid grid-cols-2 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Source System (Optional)
              </label>
              <input
                type="text"
                value={sourceSystem}
                onChange={(e) => setSourceSystem(e.target.value)}
                className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
                placeholder="e.g., CrowdStrike, Splunk"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Affected Asset (Optional)
              </label>
              <input
                type="text"
                value={affectedAsset}
                onChange={(e) => setAffectedAsset(e.target.value)}
                className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
                placeholder="e.g., DESKTOP-01, 10.0.1.5"
              />
            </div>
          </div>

          <div className="flex space-x-3">
            <button
              type="submit"
              className="px-6 py-2 bg-red-600 hover:bg-red-700 text-white font-medium rounded-lg transition-colors"
            >
              Triage Alert
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
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-2xl font-bold text-white mb-2">{result.alertType}</h3>
              <SeverityBadge severity={result.severity} />
            </div>
            {result.severityInfo && (
              <div className="text-right">
                <p className="text-sm text-gray-400">SLA</p>
                <p className="text-lg font-semibold text-white">{result.severityInfo.sla}</p>
              </div>
            )}
          </div>

          {result.sourceSystem && (
            <div className="mb-4">
              <span className="text-gray-400">Source: </span>
              <span className="text-white font-medium">{result.sourceSystem}</span>
            </div>
          )}

          {result.affectedAsset && (
            <div className="mb-4">
              <span className="text-gray-400">Affected Asset: </span>
              <span className="text-white font-medium">{result.affectedAsset}</span>
            </div>
          )}

          {result.severityInfo && (
            <div className="mb-6 p-4 bg-gray-900 rounded-lg border border-gray-600">
              <p className="text-gray-300">{result.severityInfo.description}</p>
            </div>
          )}

          {result.mitreEntry && (
            <div className="mb-6">
              <h4 className="text-lg font-semibold text-cyan-400 mb-3">MITRE ATT&CK Mapping</h4>
              <div className="grid grid-cols-3 gap-4">
                <div className="p-3 bg-gray-900 rounded-lg border border-gray-600">
                  <p className="text-xs text-gray-400 mb-1">Tactic</p>
                  <p className="text-white font-medium">{result.mitreEntry.tactic}</p>
                </div>
                <div className="p-3 bg-gray-900 rounded-lg border border-gray-600">
                  <p className="text-xs text-gray-400 mb-1">Technique</p>
                  <p className="text-white font-medium">{result.mitreEntry.technique}</p>
                </div>
                <div className="p-3 bg-gray-900 rounded-lg border border-gray-600">
                  <p className="text-xs text-gray-400 mb-1">Sub-technique</p>
                  <p className="text-white font-medium">{result.mitreEntry.subtechnique}</p>
                </div>
              </div>
            </div>
          )}

          <div className="mb-6">
            <h4 className="text-lg font-semibold text-yellow-400 mb-3">Immediate Actions</h4>
            <div className="p-4 bg-gray-900 rounded-lg border border-gray-600">
              {result.severity === 'critical' && (
                <div className="mb-4 p-3 bg-red-900/30 border border-red-700 rounded-lg">
                  <p className="text-red-400 font-bold mb-2">⚠️ DO NOT DELAY - EXECUTE NOW:</p>
                  <ol className="list-decimal list-inside space-y-1 text-gray-300">
                    <li>Notify incident commander immediately</li>
                    <li>ISOLATE affected system from network</li>
                    <li>Preserve evidence (RAM dump, processes)</li>
                    <li>Open incident ticket and start timeline</li>
                  </ol>
                </div>
              )}
              {result.severity === 'high' && (
                <ol className="list-decimal list-inside space-y-1 text-gray-300">
                  <li>Verify alert is not false positive</li>
                  <li>Identify all affected assets</li>
                  <li>Notify team lead and begin containment</li>
                  <li>Preserve logs before rotation</li>
                </ol>
              )}
              {result.severity === 'medium' && (
                <ol className="list-decimal list-inside space-y-1 text-gray-300">
                  <li>Investigate alert context</li>
                  <li>Correlate with other alerts</li>
                  <li>Monitor for escalation</li>
                </ol>
              )}
              {result.severity === 'low' && (
                <ol className="list-decimal list-inside space-y-1 text-gray-300">
                  <li>Log and monitor</li>
                  <li>Review during business hours</li>
                </ol>
              )}
            </div>
          </div>

          {result.playbook && (
            <div>
              <h4 className="text-lg font-semibold text-green-400 mb-3">Response Playbook Preview</h4>
              <div className="p-4 bg-gray-900 rounded-lg border border-gray-600">
                <p className="text-white font-medium mb-3">{result.playbook.name}</p>
                <ol className="list-decimal list-inside space-y-2 text-gray-300">
                  {result.playbook.steps.slice(0, 4).map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ol>
                <p className="text-sm text-gray-500 mt-3 italic">
                  View full playbook in the Playbooks tab
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default TriagePanel
