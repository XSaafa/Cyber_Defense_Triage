import { useState } from 'react'
import { playbooks } from '../lib/triageEngine'

function PlaybookViewer() {
  const [selectedPlaybook, setSelectedPlaybook] = useState(null)
  const [showIocs, setShowIocs] = useState(true)

  const playbookList = Object.entries(playbooks).map(([key, value]) => ({
    id: key,
    ...value
  }))

  return (
    <div className="max-w-6xl">
      <div className="mb-8">
        <h2 className="text-3xl font-bold text-white mb-2">📖 Incident Response Playbooks</h2>
        <p className="text-gray-400">Step-by-step SOC response procedures for common security incidents</p>
      </div>

      <div className="grid grid-cols-3 gap-4 mb-6">
        {playbookList.map(playbook => (
          <button
            key={playbook.id}
            onClick={() => setSelectedPlaybook(playbook)}
            className={`p-4 rounded-lg border-2 transition-all text-left ${
              selectedPlaybook?.id === playbook.id
                ? 'bg-red-900/30 border-red-500'
                : 'bg-gray-800 border-gray-700 hover:border-gray-600'
            }`}
          >
            <h3 className="text-lg font-semibold text-white mb-1">{playbook.name}</h3>
            <p className="text-sm text-gray-400">{playbook.steps.length} steps</p>
          </button>
        ))}
      </div>

      {selectedPlaybook ? (
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
          <div className="mb-6">
            <h3 className="text-2xl font-bold text-white mb-2">{selectedPlaybook.name}</h3>
            <div className="p-3 bg-blue-900/30 border border-blue-700 rounded-lg">
              <p className="text-blue-300 text-sm">
                ℹ️ This is a first-responder triage playbook. Escalate to your IR team for full forensic investigation.
              </p>
            </div>
          </div>

          <div className="mb-6">
            <h4 className="text-xl font-semibold text-cyan-400 mb-4">Response Steps (Follow in Order)</h4>
            <div className="space-y-4">
              {selectedPlaybook.steps.map((step, i) => {
                const [phase, ...detailParts] = step.split(':')
                const detail = detailParts.join(':').trim()
                
                return (
                  <div key={i} className="p-4 bg-gray-900 rounded-lg border border-gray-600">
                    <div className="flex items-start">
                      <div className="flex-shrink-0 w-8 h-8 bg-red-600 rounded-full flex items-center justify-center text-white font-bold mr-3">
                        {i + 1}
                      </div>
                      <div className="flex-1">
                        <h5 className="text-lg font-semibold text-white mb-1">{phase}</h5>
                        <p className="text-gray-300">{detail}</p>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {selectedPlaybook.iocs_to_look_for && (
            <div className="mb-6">
              <div className="flex items-center justify-between mb-4">
                <h4 className="text-xl font-semibold text-yellow-400">IOCs to Hunt For</h4>
                <button
                  onClick={() => setShowIocs(!showIocs)}
                  className="text-sm text-gray-400 hover:text-white transition-colors"
                >
                  {showIocs ? 'Hide' : 'Show'}
                </button>
              </div>
              
              {showIocs && (
                <div className="p-4 bg-yellow-900/20 border border-yellow-700 rounded-lg">
                  <ul className="space-y-2">
                    {selectedPlaybook.iocs_to_look_for.map((ioc, i) => (
                      <li key={i} className="flex items-start">
                        <span className="text-yellow-400 mr-2">•</span>
                        <span className="text-gray-300">{ioc}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          <div className="mb-6">
            <h4 className="text-xl font-semibold text-orange-400 mb-4">Escalation Criteria</h4>
            <div className="p-4 bg-orange-900/20 border border-orange-700 rounded-lg">
              <p className="text-gray-300 mb-3">Escalate to senior IR analyst / management if:</p>
              <ul className="list-disc list-inside space-y-1 text-gray-300">
                <li>Confirmed data exfiltration of PII or sensitive records</li>
                <li>Attack has spread to 3+ systems</li>
                <li>Critical infrastructure or domain controllers are affected</li>
                <li>Regulatory notification may be required (GDPR, HIPAA, PCI-DSS)</li>
              </ul>
            </div>
          </div>

          <div>
            <h4 className="text-xl font-semibold text-green-400 mb-4">Evidence Preservation Checklist</h4>
            <div className="p-4 bg-gray-900 border border-gray-600 rounded-lg">
              <div className="space-y-2">
                {[
                  'RAM capture (use WinPmem or LiME)',
                  'Disk image (write-blocked)',
                  'Network flow logs',
                  'Authentication logs (past 7 days)',
                  'Timeline documented with UTC timestamps'
                ].map((item, i) => (
                  <label key={i} className="flex items-center space-x-3 text-gray-300 cursor-pointer hover:text-white">
                    <input type="checkbox" className="w-4 h-4 rounded border-gray-600 bg-gray-800" />
                    <span>{item}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-12 text-center">
          <p className="text-gray-400 text-lg">Select a playbook from above to view details</p>
        </div>
      )}
    </div>
  )
}

export default PlaybookViewer
