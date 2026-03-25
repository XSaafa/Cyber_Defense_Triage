import { useState } from 'react';
import { scanIoc } from '../lib/triageEngine';
import { enrichIOCInBrowser, saveAPIKey, getAPIKey } from '../lib/threatIntelAPI';

function IOCScanner() {
  const [iocValue, setIocValue] = useState('');
  const [iocType, setIocType] = useState('ip');
  const [result, setResult] = useState(null);
  const [enrichment, setEnrichment] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showApiSettings, setShowApiSettings] = useState(false);
  const [apiKeys, setApiKeys] = useState({
    virustotal: getAPIKey('virustotal') || '',
    abuseipdb: getAPIKey('abuseipdb') || ''
  });

  const iocTypes = [
    { value: 'ip', label: 'IP Address', example: '185.220.101.47' },
    { value: 'domain', label: 'Domain', example: 'malicious-site.com' },
    { value: 'hash', label: 'File Hash', example: 'a1b2c3d4e5f6...' },
    { value: 'url', label: 'URL', example: 'http://phishing-site.com/login' },
    { value: 'email', label: 'Email', example: 'attacker@evil.com' }
  ];

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!iocValue.trim()) return;
    
    setLoading(true);
    const scanResult = scanIoc(iocValue, iocType);
    setResult(scanResult);
    
    // Get external threat intelligence
    try {
      const enrichData = await enrichIOCInBrowser(iocValue, iocType);
      setEnrichment(enrichData);
    } catch (error) {
      console.error('Enrichment error:', error);
      setEnrichment(null);
    }
    
    setLoading(false);
  };

  const handleSaveApiKeys = () => {
    if (apiKeys.virustotal) {
      saveAPIKey('virustotal', apiKeys.virustotal);
    }
    if (apiKeys.abuseipdb) {
      saveAPIKey('abuseipdb', apiKeys.abuseipdb);
    }
    setShowApiSettings(false);
    alert('API keys saved! Rescan IOCs to use external threat intelligence.');
  };

  const handleClear = () => {
    setIocValue('');
    setIocType('ip');
    setResult(null);
    setEnrichment(null);
  };

  const handleExample = () => {
    const example = iocTypes.find(t => t.value === iocType)?.example;
    if (example) {
      setIocValue(example);
    }
  };

  return (
    <div className="max-w-6xl">
      <div className="mb-8">
        <h2 className="text-3xl font-bold text-white mb-2">🔍 IOC Scanner</h2>
        <p className="text-gray-400">Analyze Indicators of Compromise with external threat intelligence</p>
      </div>

      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6 mb-6">
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              IOC Type
            </label>
            <div className="grid grid-cols-5 gap-2">
              {iocTypes.map(type => (
                <button
                  key={type.value}
                  type="button"
                  onClick={() => setIocType(type.value)}
                  className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                    iocType === type.value
                      ? 'bg-red-600 text-white'
                      : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  {type.label}
                </button>
              ))}
            </div>
          </div>

          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              IOC Value *
            </label>
            <div className="flex space-x-2">
              <input
                type="text"
                value={iocValue}
                onChange={(e) => setIocValue(e.target.value)}
                className="flex-1 px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 font-mono focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
                placeholder={`Enter ${iocTypes.find(t => t.value === iocType)?.label.toLowerCase()}...`}
                required
              />
              <button
                type="button"
                onClick={handleExample}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded-lg transition-colors"
              >
                Example
              </button>
            </div>
          </div>

          <div className="flex space-x-3">
            <button
              type="submit"
              disabled={loading}
              className="px-6 py-2 bg-red-600 hover:bg-red-700 disabled:bg-red-400 text-white font-medium rounded-lg transition-colors"
            >
              {loading ? 'Scanning...' : 'Scan IOC'}
            </button>
            <button
              type="button"
              onClick={handleClear}
              className="px-6 py-2 bg-gray-700 hover:bg-gray-600 text-white font-medium rounded-lg transition-colors"
            >
              Clear
            </button>
            <button
              type="button"
              onClick={() => setShowApiSettings(!showApiSettings)}
              className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors"
              title="Configure API Keys for External Threat Intelligence"
            >
              🔑 API Keys
            </button>
          </div>
        </form>
      </div>

      {showApiSettings && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-6">
          <h3 className="text-lg font-semibold mb-3">🌐 External Threat Intelligence API Keys</h3>
          <p className="text-sm text-gray-400 mb-4">
            Add API keys to enrich IOC scans with real-time threat intelligence from multiple sources.
          </p>
          
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium mb-1">
                VirusTotal API Key
                <a href="https://www.virustotal.com/" target="_blank" rel="noopener noreferrer" className="ml-2 text-blue-400 text-xs">
                  (Get free key)
                </a>
              </label>
              <input
                type="password"
                value={apiKeys.virustotal}
                onChange={(e) => setApiKeys({...apiKeys, virustotal: e.target.value})}
                placeholder="Enter VirusTotal API key"
                className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-1">
                AbuseIPDB API Key
                <a href="https://www.abuseipdb.com/" target="_blank" rel="noopener noreferrer" className="ml-2 text-blue-400 text-xs">
                  (Get free key)
                </a>
              </label>
              <input
                type="password"
                value={apiKeys.abuseipdb}
                onChange={(e) => setApiKeys({...apiKeys, abuseipdb: e.target.value})}
                placeholder="Enter AbuseIPDB API key"
                className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm"
              />
            </div>
          </div>
          
          <div className="flex gap-2 mt-4">
            <button
              onClick={handleSaveApiKeys}
              className="flex-1 bg-green-600 hover:bg-green-700 text-white font-medium py-2 px-4 rounded transition-colors"
            >
              Save API Keys
            </button>
            <button
              onClick={() => setShowApiSettings(false)}
              className="bg-gray-700 hover:bg-gray-600 text-white font-medium py-2 px-4 rounded transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {enrichment && enrichment.overallReputation !== 'unknown' && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-6">
          <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
            🌐 External Threat Intelligence
            {enrichment.cacheHit && <span className="text-xs text-gray-500">(cached)</span>}
          </h3>
          
          <div className="mb-3">
            <span className="text-sm text-gray-400">Overall Reputation: </span>
            <span className={`font-bold ${
              enrichment.overallReputation === 'malicious' ? 'text-red-500' :
              enrichment.overallReputation === 'suspicious' ? 'text-orange-500' :
              'text-green-500'
            }`}>
              {enrichment.overallReputation.toUpperCase()}
            </span>
          </div>
          
          <div className="space-y-3">
            {enrichment.sources.map((source, idx) => (
              <div key={idx} className="bg-gray-900 rounded p-3">
                <div className="font-semibold text-blue-400 mb-2">{source.source}</div>
                
                {source.available ? (
                  <div className="text-sm space-y-1">
                    {source.source === 'AbuseIPDB' && (
                      <>
                        <div>Abuse Score: <span className="font-mono">{source.abuseScore}/100</span></div>
                        <div>Total Reports: {source.totalReports}</div>
                        <div>Country: {source.country || 'Unknown'}</div>
                        <div>ISP: {source.isp || 'Unknown'}</div>
                      </>
                    )}
                    
                    {source.source === 'VirusTotal' && (
                      <>
                        <div>Detection Ratio: <span className="font-mono">{source.detectionRatio}</span></div>
                        <div>Malicious: {source.malicious}, Suspicious: {source.suspicious}</div>
                      </>
                    )}
                    
                    {source.source === 'AlienVault OTX' && (
                      <>
                        <div>Pulse Count: {source.pulseCount}</div>
                        {source.tags && source.tags.length > 0 && (
                          <div>Tags: {source.tags.join(', ')}</div>
                        )}
                      </>
                    )}
                    
                    {source.source === 'Emerging Threats' && (
                      <div>{source.message}</div>
                    )}
                  </div>
                ) : (
                  <div className="text-sm text-gray-500">{source.message || source.error}</div>
                )}
              </div>
            ))}
          </div>
          
          <div className="text-xs text-gray-500 mt-3">
            Enriched at: {new Date(enrichment.enrichedAt).toLocaleString()}
          </div>
        </div>
      )}

      {result && (
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
          <div className="mb-6">
            <h3 className="text-2xl font-bold text-white mb-2">
              IOC Analysis: {result.iocType.toUpperCase()}
            </h3>
            <div className="p-4 bg-gray-900 rounded-lg border border-gray-600">
              <p className="text-sm text-gray-400 mb-1">Original IOC:</p>
              <p className="text-white font-mono break-all">{result.iocValue}</p>
            </div>
          </div>

          <div className="mb-6 p-4 bg-yellow-900/30 border border-yellow-700 rounded-lg">
            <p className="text-sm text-yellow-400 mb-1">Defanged IOC (safe to share):</p>
            <p className="text-white font-mono break-all">{result.defanged}</p>
            <p className="text-xs text-gray-400 mt-2">
              Always defang IOCs before sharing in emails, tickets, or reports to prevent accidental clicks.
            </p>
          </div>

          <div className="mb-6">
            <h4 className="text-xl font-semibold text-cyan-400 mb-4">Recommended Validation Tools</h4>
            <div className="grid grid-cols-2 gap-3">
              {result.tools.map((tool, i) => (
                <div key={i} className="p-3 bg-gray-900 rounded-lg border border-gray-600">
                  <p className="text-white">• {tool}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="mb-6">
            <h4 className="text-xl font-semibold text-purple-400 mb-4">What to Check</h4>
            <div className="space-y-2">
              {result.checks.map((check, i) => (
                <div key={i} className="p-3 bg-gray-900 rounded-lg border border-gray-600 flex items-start">
                  <span className="text-purple-400 font-bold mr-3">{i + 1}.</span>
                  <span className="text-gray-300">{check}</span>
                </div>
              ))}
            </div>
          </div>

          <div>
            <h4 className="text-xl font-semibold text-orange-400 mb-4">Response Actions</h4>
            <div className="space-y-2">
              {result.response.map((action, i) => (
                <div key={i} className="p-3 bg-orange-900/20 border border-orange-700 rounded-lg flex items-start">
                  <span className="text-orange-400 font-bold mr-3">{i + 1}.</span>
                  <span className="text-gray-300">{action}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default IOCScanner;
