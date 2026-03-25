import { useState } from 'react';
import { checkNVD } from '../lib/threatIntelAPI';

function CVEChecker() {
  const [cveId, setCveId] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!cveId.trim()) return;
    
    setLoading(true);
    try {
      const nvdData = await checkNVD(cveId.trim());
      setResult(nvdData);
    } catch (error) {
      console.error('CVE lookup error:', error);
      setResult({
        available: false,
        error: error.message
      });
    }
    setLoading(false);
  };

  const handleClear = () => {
    setCveId('');
    setResult(null);
  };

  const handleExample = () => {
    setCveId('CVE-2021-44228');
  };

  const getSeverityColor = (severity) => {
    const sev = severity?.toUpperCase();
    if (sev === 'CRITICAL') return 'text-red-500';
    if (sev === 'HIGH') return 'text-orange-500';
    if (sev === 'MEDIUM') return 'text-yellow-500';
    if (sev === 'LOW') return 'text-green-500';
    return 'text-gray-400';
  };

  const getSeverityBg = (severity) => {
    const sev = severity?.toUpperCase();
    if (sev === 'CRITICAL') return 'bg-red-900/30 border-red-700';
    if (sev === 'HIGH') return 'bg-orange-900/30 border-orange-700';
    if (sev === 'MEDIUM') return 'bg-yellow-900/30 border-yellow-700';
    if (sev === 'LOW') return 'bg-green-900/30 border-green-700';
    return 'bg-gray-900/30 border-gray-700';
  };

  return (
    <div className="max-w-6xl">
      <div className="mb-8">
        <h2 className="text-3xl font-bold text-white mb-2">🔍 CVE Vulnerability Checker</h2>
        <p className="text-gray-400">Look up Common Vulnerabilities and Exposures from NVD database</p>
      </div>

      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6 mb-6">
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              CVE Identifier *
            </label>
            <div className="flex space-x-2">
              <input
                type="text"
                value={cveId}
                onChange={(e) => setCveId(e.target.value)}
                className="flex-1 px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-white placeholder-gray-500 font-mono focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
                placeholder="Enter CVE ID (e.g., CVE-2021-44228)"
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
            <p className="text-xs text-gray-500 mt-2">
              Format: CVE-YYYY-NNNNN (e.g., CVE-2021-44228 for Log4Shell)
            </p>
          </div>

          <div className="flex space-x-3">
            <button
              type="submit"
              disabled={loading}
              className="px-6 py-2 bg-red-600 hover:bg-red-700 disabled:bg-red-400 text-white font-medium rounded-lg transition-colors"
            >
              {loading ? 'Checking...' : 'Check CVE'}
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

      {result && !result.available && (
        <div className="bg-red-900/30 border border-red-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-red-400 mb-2">⚠️ NVD API Unavailable</h3>
          <p className="text-gray-300">{result.error || result.message || 'Could not connect to NVD database'}</p>
          <p className="text-sm text-gray-400 mt-2">
            Note: NVD API works without a key but has rate limits (5 requests per 30 seconds).
            Get a free API key at <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noopener noreferrer" className="text-blue-400 underline">nvd.nist.gov</a> to increase to 50 requests per 30 seconds.
          </p>
        </div>
      )}

      {result && result.available && !result.found && (
        <div className="bg-yellow-900/30 border border-yellow-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-yellow-400 mb-2">❓ CVE Not Found</h3>
          <p className="text-gray-300">CVE ID <span className="font-mono">{cveId}</span> was not found in the NVD database.</p>
          <p className="text-sm text-gray-400 mt-2">
            This CVE may not exist or hasn't been published to NVD yet.
          </p>
        </div>
      )}

      {result && result.found && (
        <div className="space-y-6">
          <div className={`rounded-lg border p-6 ${getSeverityBg(result.severity)}`}>
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="text-2xl font-bold text-white mb-1">{result.cveId}</h3>
                <div className="flex items-center gap-4">
                  <span className={`text-3xl font-bold ${getSeverityColor(result.severity)}`}>
                    {result.cvssScore || 'N/A'}
                  </span>
                  <span className={`px-3 py-1 rounded-full text-sm font-semibold ${getSeverityColor(result.severity)}`}>
                    {result.severity}
                  </span>
                </div>
              </div>
              <div className="text-right text-sm text-gray-400">
                <div>Published: {new Date(result.published).toLocaleDateString()}</div>
                <div>Modified: {new Date(result.lastModified).toLocaleDateString()}</div>
              </div>
            </div>

            {result.cvssVector && (
              <div className="mb-4 p-3 bg-gray-900/50 rounded">
                <div className="text-xs text-gray-400 mb-1">CVSS Vector</div>
                <code className="text-sm text-cyan-400">{result.cvssVector}</code>
              </div>
            )}
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <h4 className="text-xl font-semibold text-white mb-3">📄 Description</h4>
            <p className="text-gray-300 leading-relaxed">{result.description}</p>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <h4 className="text-xl font-semibold text-purple-400 mb-3">🐛 Weakness (CWE)</h4>
            <p className="text-gray-300">{result.weaknesses}</p>
          </div>

          {(result.exploitabilityScore || result.impactScore) && (
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
              <h4 className="text-xl font-semibold text-orange-400 mb-4">📊 Metrics</h4>
              <div className="grid grid-cols-2 gap-4">
                {result.exploitabilityScore && (
                  <div className="p-4 bg-gray-900 rounded-lg">
                    <div className="text-sm text-gray-400 mb-1">Exploitability Score</div>
                    <div className="text-2xl font-bold text-orange-400">{result.exploitabilityScore}</div>
                    <div className="text-xs text-gray-500 mt-1">How easy to exploit (0-10)</div>
                  </div>
                )}
                {result.impactScore && (
                  <div className="p-4 bg-gray-900 rounded-lg">
                    <div className="text-sm text-gray-400 mb-1">Impact Score</div>
                    <div className="text-2xl font-bold text-red-400">{result.impactScore}</div>
                    <div className="text-xs text-gray-500 mt-1">Potential damage (0-10)</div>
                  </div>
                )}
              </div>
            </div>
          )}

          {result.references && result.references.length > 0 && (
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
              <h4 className="text-xl font-semibold text-blue-400 mb-4">🔗 References</h4>
              <div className="space-y-2">
                {result.references.map((ref, idx) => (
                  <div key={idx} className="p-3 bg-gray-900 rounded-lg">
                    <a 
                      href={ref.url} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:text-blue-300 underline break-all"
                    >
                      {ref.url}
                    </a>
                    <div className="text-xs text-gray-500 mt-1">Source: {ref.source}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <h4 className="text-xl font-semibold text-green-400 mb-4">🎯 Severity Assessment</h4>
            <div className="space-y-3">
              {result.cvssScore >= 9.0 && (
                <div className="p-4 bg-red-900/30 border border-red-700 rounded-lg">
                  <div className="flex items-start gap-3">
                    <span className="text-2xl">🔴</span>
                    <div>
                      <div className="font-semibold text-red-400 mb-1">CRITICAL</div>
                      <div className="text-sm text-gray-300">Immediate patching required. Likely actively exploited in the wild.</div>
                    </div>
                  </div>
                </div>
              )}
              {result.cvssScore >= 7.0 && result.cvssScore < 9.0 && (
                <div className="p-4 bg-orange-900/30 border border-orange-700 rounded-lg">
                  <div className="flex items-start gap-3">
                    <span className="text-2xl">🟠</span>
                    <div>
                      <div className="font-semibold text-orange-400 mb-1">HIGH</div>
                      <div className="text-sm text-gray-300">Patch as soon as possible. High risk of exploitation.</div>
                    </div>
                  </div>
                </div>
              )}
              {result.cvssScore >= 4.0 && result.cvssScore < 7.0 && (
                <div className="p-4 bg-yellow-900/30 border border-yellow-700 rounded-lg">
                  <div className="flex items-start gap-3">
                    <span className="text-2xl">🟡</span>
                    <div>
                      <div className="font-semibold text-yellow-400 mb-1">MEDIUM</div>
                      <div className="text-sm text-gray-300">Schedule patching in regular maintenance window.</div>
                    </div>
                  </div>
                </div>
              )}
              {result.cvssScore > 0 && result.cvssScore < 4.0 && (
                <div className="p-4 bg-green-900/30 border border-green-700 rounded-lg">
                  <div className="flex items-start gap-3">
                    <span className="text-2xl">🟢</span>
                    <div>
                      <div className="font-semibold text-green-400 mb-1">LOW</div>
                      <div className="text-sm text-gray-300">Monitor and patch when convenient.</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="text-sm text-gray-500 text-center">
            Data source: National Vulnerability Database (NVD)
          </div>
        </div>
      )}
    </div>
  );
}

export default CVEChecker;
