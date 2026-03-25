import { useState } from 'react'
import TriagePanel from './components/TriagePanel'
import LogClassifier from './components/LogClassifier'
import PlaybookViewer from './components/PlaybookViewer'
import IOCScanner from './components/IOCScanner'
import CVEChecker from './components/CVEChecker'
import IncidentTimeline from './components/IncidentTimeline'

function App() {
  const [activeTab, setActiveTab] = useState('triage')

  const tabs = [
    { id: 'triage', name: 'Triage', icon: '🚨' },
    { id: 'logs', name: 'Log Classifier', icon: '📋' },
    { id: 'playbooks', name: 'Playbooks', icon: '📖' },
    { id: 'ioc', name: 'IOC Scanner', icon: '🔍' },
    { id: 'cve', name: 'CVE Checker', icon: '🐛' },
    { id: 'timeline', name: 'Incident Timeline', icon: '⏱️' }
  ]

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100">
      <div className="flex h-screen">
        <aside className="w-64 bg-gray-800 border-r border-gray-700">
          <div className="p-6">
            <h1 className="text-2xl font-bold text-red-500">🛡️ Cyber Triage</h1>
            <p className="text-sm text-gray-400 mt-1">First Responder Dashboard</p>
          </div>
          
          <nav className="mt-6">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`w-full text-left px-6 py-3 flex items-center space-x-3 transition-colors ${
                  activeTab === tab.id
                    ? 'bg-gray-700 text-white border-l-4 border-red-500'
                    : 'text-gray-400 hover:bg-gray-750 hover:text-gray-200'
                }`}
              >
                <span className="text-xl">{tab.icon}</span>
                <span className="font-medium">{tab.name}</span>
              </button>
            ))}
          </nav>

          <div className="absolute bottom-0 w-64 p-6 border-t border-gray-700">
            <p className="text-xs text-gray-500">
              Offline-first security triage tool
            </p>
            <p className="text-xs text-gray-600 mt-1">
              v1.0.0 | No external APIs
            </p>
          </div>
        </aside>

        <main className="flex-1 overflow-y-auto">
          <div className="p-8">
            {activeTab === 'triage' && <TriagePanel />}
            {activeTab === 'logs' && <LogClassifier />}
            {activeTab === 'playbooks' && <PlaybookViewer />}
            {activeTab === 'ioc' && <IOCScanner />}
            {activeTab === 'cve' && <CVEChecker />}
            {activeTab === 'timeline' && <IncidentTimeline />}
          </div>
        </main>
      </div>
    </div>
  )
}

export default App
