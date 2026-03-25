import { useState, useEffect } from 'react'
import SeverityBadge from './SeverityBadge'

function IncidentTimeline() {
  const [incidents, setIncidents] = useState([])
  const [formData, setFormData] = useState({
    timestamp: '',
    type: '',
    severity: 'medium',
    notes: ''
  })

  useEffect(() => {
    const saved = localStorage.getItem('cyber-triage-incidents')
    if (saved) {
      setIncidents(JSON.parse(saved))
    }
  }, [])

  const saveIncidents = (newIncidents) => {
    setIncidents(newIncidents)
    localStorage.setItem('cyber-triage-incidents', JSON.stringify(newIncidents))
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    
    const newIncident = {
      id: Date.now(),
      timestamp: formData.timestamp || new Date().toISOString(),
      type: formData.type,
      severity: formData.severity,
      notes: formData.notes,
      createdAt: new Date().toISOString()
    }

    const updated = [...incidents, newIncident].sort((a, b) => 
      new Date(b.timestamp) - new Date(a.timestamp)
    )
    
    saveIncidents(updated)
    
    setFormData({
      timestamp: '',
      type: '',
      severity: 'medium',
      notes: ''
    })
  }

  const handleDelete = (id) => {
    if (confirm('Delete this incident?')) {
      saveIncidents(incidents.filter(i => i.id !== id))
    }
  }

  const handleClearAll = () => {
    if (confirm('Clear all incidents? This cannot be undone.')) {
      saveIncidents([])
    }
  }

  const incidentTypes = [
    'Ransomware',
    'Phishing',
    'Brute Force',
    'Data Exfiltration',
    'Lateral Movement',
    'DDoS',
    'Insider Threat',
    'Web Defacement',
    'Malware',
    'Other'
  ]

  return (
    <div className="max-w-6xl">
      <div className="mb-8">
        <h2 className="text-3xl font-bold text-white mb-2">⏱️ Incident Timeline</h2>
        <p className="text-gray-400">Track and document security incidents chronologically</p>
      </div>

      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6 mb-6">
        <h3 className="text-xl font-semibold text-white mb-4">Add New Incident</h3>
        
        <form onSubmit={handleSubmit}>
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Timestamp
              </label>
              <input
                type="datetime-local"
                value={formData.timestamp}
                onChange={(e) => setFormData({ ...formData, timestamp: e.target.value })}
                className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
              />
              <p className="text-xs text-gray-500 mt-1">Leave empty to use current time</p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Incident Type *
              </label>
              <select
                value={formData.type}
                onChange={(e) => setFormData({ ...formData, type: e.target.value })}
                className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
                required
              >
                <option value="">Select type...</option>
                {incidentTypes.map(type => (
                  <option key={type} value={type}>{type}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Severity
            </label>
            <div className="grid grid-cols-4 gap-2">
              {['low', 'medium', 'high', 'critical'].map(sev => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setFormData({ ...formData, severity: sev })}
                  className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                    formData.severity === sev
                      ? sev === 'critical' ? 'bg-red-500 text-white' :
                        sev === 'high' ? 'bg-orange-400 text-gray-900' :
                        sev === 'medium' ? 'bg-yellow-400 text-gray-900' :
                        'bg-green-400 text-gray-900'
                      : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  {sev.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Notes *
            </label>
            <textarea
              value={formData.notes}
              onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
              className="w-full px-4 py-3 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
              rows="3"
              placeholder="Brief description of the incident, affected systems, initial response..."
              required
            />
          </div>

          <button
            type="submit"
            className="px-6 py-2 bg-red-600 hover:bg-red-700 text-white font-medium rounded-lg transition-colors"
          >
            Add Incident
          </button>
        </form>
      </div>

      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-semibold text-white">
            Timeline ({incidents.length} incidents)
          </h3>
          {incidents.length > 0 && (
            <button
              onClick={handleClearAll}
              className="text-sm text-red-400 hover:text-red-300 transition-colors"
            >
              Clear All
            </button>
          )}
        </div>

        {incidents.length === 0 ? (
          <div className="text-center py-12">
            <p className="text-gray-400 text-lg">No incidents recorded yet</p>
            <p className="text-gray-500 text-sm mt-2">Add your first incident above to start tracking</p>
          </div>
        ) : (
          <div className="space-y-4">
            {incidents.map((incident, index) => (
              <div key={incident.id} className="relative pl-8 pb-6 border-l-2 border-gray-700 last:border-l-0 last:pb-0">
                <div className="absolute -left-2 top-0 w-4 h-4 bg-red-500 rounded-full border-2 border-gray-800"></div>
                
                <div className="bg-gray-900 rounded-lg border border-gray-600 p-4">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <SeverityBadge severity={incident.severity} />
                      <h4 className="text-lg font-semibold text-white">{incident.type}</h4>
                    </div>
                    <button
                      onClick={() => handleDelete(incident.id)}
                      className="text-gray-500 hover:text-red-400 transition-colors"
                    >
                      ✕
                    </button>
                  </div>

                  <div className="mb-3">
                    <p className="text-sm text-gray-400">
                      {new Date(incident.timestamp).toLocaleString('en-US', {
                        year: 'numeric',
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                        hour12: false
                      })} UTC
                    </p>
                  </div>

                  <p className="text-gray-300">{incident.notes}</p>

                  <p className="text-xs text-gray-500 mt-3">
                    Logged: {new Date(incident.createdAt).toLocaleString()}
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="mt-6 p-4 bg-blue-900/20 border border-blue-700 rounded-lg">
        <p className="text-blue-300 text-sm">
          ℹ️ Timeline data is stored locally in your browser. Export important incidents to your SIEM or ticketing system.
        </p>
      </div>
    </div>
  )
}

export default IncidentTimeline
