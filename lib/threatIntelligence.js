// Threat Intelligence Integration Module
// Integrates with external threat feeds for real-time IOC enrichment

import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Simple in-memory cache
const cache = new Map();
const CACHE_TTL = parseInt(process.env.THREAT_INTEL_CACHE_TTL || '3600') * 1000; // 1 hour default

// Load API keys from environment or .env file
function loadEnvConfig() {
  const envPath = join(__dirname, '..', '.env');
  if (existsSync(envPath)) {
    const envContent = readFileSync(envPath, 'utf-8');
    envContent.split('\n').forEach(line => {
      const [key, value] = line.split('=');
      if (key && value && !key.startsWith('#')) {
        process.env[key.trim()] = value.trim();
      }
    });
  }
}

loadEnvConfig();

// Cache helper functions
function getCached(key) {
  const cached = cache.get(key);
  if (!cached) return null;
  
  if (Date.now() - cached.timestamp > CACHE_TTL) {
    cache.delete(key);
    return null;
  }
  
  return cached.data;
}

function setCache(key, data) {
  cache.set(key, {
    data,
    timestamp: Date.now()
  });
}

// ============================================================================
// MITRE ATT&CK Integration
// ============================================================================

export async function fetchMitreAttackData() {
  const cacheKey = 'mitre_attack_data';
  const cached = getCached(cacheKey);
  if (cached) return cached;

  try {
    // MITRE ATT&CK STIX data (public, no API key needed)
    const response = await fetch('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json');
    
    if (!response.ok) {
      throw new Error(`MITRE API error: ${response.status}`);
    }
    
    const data = await response.json();
    
    // Extract techniques
    const techniques = data.objects
      .filter(obj => obj.type === 'attack-pattern')
      .map(technique => ({
        id: technique.external_references?.[0]?.external_id || 'Unknown',
        name: technique.name,
        description: technique.description,
        tactics: technique.kill_chain_phases?.map(phase => phase.phase_name) || [],
        url: technique.external_references?.[0]?.url || ''
      }));
    
    const result = {
      techniques,
      lastUpdated: new Date().toISOString(),
      count: techniques.length
    };
    
    setCache(cacheKey, result);
    return result;
    
  } catch (error) {
    console.error('MITRE ATT&CK fetch error:', error.message);
    return {
      techniques: [],
      error: error.message,
      lastUpdated: new Date().toISOString()
    };
  }
}

export async function enrichMitreMapping(attackType) {
  const mitreData = await fetchMitreAttackData();
  
  if (!mitreData.techniques.length) {
    return null;
  }
  
  // Search for matching technique
  const searchTerm = attackType.toLowerCase();
  const matches = mitreData.techniques.filter(t => 
    t.name.toLowerCase().includes(searchTerm) ||
    t.description.toLowerCase().includes(searchTerm)
  );
  
  return matches.length > 0 ? matches[0] : null;
}

// ============================================================================
// AlienVault OTX Integration
// ============================================================================

export async function checkOTXReputation(iocValue, iocType) {
  const apiKey = process.env.OTX_API_KEY;
  
  if (!apiKey || apiKey === 'your_otx_api_key_here') {
    return {
      source: 'AlienVault OTX',
      available: false,
      message: 'API key not configured. Get free key at https://otx.alienvault.com/'
    };
  }
  
  const cacheKey = `otx_${iocType}_${iocValue}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;
  
  try {
    let endpoint = '';
    
    switch (iocType) {
      case 'ip':
        endpoint = `https://otx.alienvault.com/api/v1/indicators/IPv4/${iocValue}/general`;
        break;
      case 'domain':
        endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${iocValue}/general`;
        break;
      case 'hash':
        endpoint = `https://otx.alienvault.com/api/v1/indicators/file/${iocValue}/general`;
        break;
      case 'url':
        endpoint = `https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(iocValue)}/general`;
        break;
      default:
        return { source: 'AlienVault OTX', available: false, message: 'Unsupported IOC type' };
    }
    
    const response = await fetch(endpoint, {
      headers: {
        'X-OTX-API-KEY': apiKey
      }
    });
    
    if (!response.ok) {
      throw new Error(`OTX API error: ${response.status}`);
    }
    
    const data = await response.json();
    
    const result = {
      source: 'AlienVault OTX',
      available: true,
      pulseCount: data.pulse_info?.count || 0,
      reputation: data.pulse_info?.count > 0 ? 'malicious' : 'clean',
      tags: data.pulse_info?.pulses?.slice(0, 5).map(p => p.name) || [],
      references: data.pulse_info?.references || [],
      lastSeen: data.pulse_info?.pulses?.[0]?.modified || null
    };
    
    setCache(cacheKey, result);
    return result;
    
  } catch (error) {
    console.error('OTX API error:', error.message);
    return {
      source: 'AlienVault OTX',
      available: false,
      error: error.message
    };
  }
}

// ============================================================================
// AbuseIPDB Integration
// ============================================================================

export async function checkAbuseIPDB(ipAddress) {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  
  if (!apiKey || apiKey === 'your_abuseipdb_api_key_here') {
    return {
      source: 'AbuseIPDB',
      available: false,
      message: 'API key not configured. Get free key at https://www.abuseipdb.com/'
    };
  }
  
  const cacheKey = `abuseipdb_${ipAddress}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;
  
  try {
    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ipAddress}`, {
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`AbuseIPDB API error: ${response.status}`);
    }
    
    const data = await response.json();
    const ipData = data.data;
    
    const result = {
      source: 'AbuseIPDB',
      available: true,
      abuseScore: ipData.abuseConfidenceScore,
      reputation: ipData.abuseConfidenceScore > 50 ? 'malicious' : 
                  ipData.abuseConfidenceScore > 25 ? 'suspicious' : 'clean',
      totalReports: ipData.totalReports,
      lastReported: ipData.lastReportedAt,
      country: ipData.countryCode,
      isp: ipData.isp,
      usageType: ipData.usageType,
      isWhitelisted: ipData.isWhitelisted
    };
    
    setCache(cacheKey, result);
    return result;
    
  } catch (error) {
    console.error('AbuseIPDB API error:', error.message);
    return {
      source: 'AbuseIPDB',
      available: false,
      error: error.message
    };
  }
}

// ============================================================================
// VirusTotal Integration
// ============================================================================

export async function checkVirusTotal(iocValue, iocType) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  
  if (!apiKey || apiKey === 'your_virustotal_api_key_here') {
    return {
      source: 'VirusTotal',
      available: false,
      message: 'API key not configured. Get free key at https://www.virustotal.com/'
    };
  }
  
  const cacheKey = `virustotal_${iocType}_${iocValue}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;
  
  try {
    let endpoint = '';
    
    switch (iocType) {
      case 'ip':
        endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${iocValue}`;
        break;
      case 'domain':
        endpoint = `https://www.virustotal.com/api/v3/domains/${iocValue}`;
        break;
      case 'hash':
        endpoint = `https://www.virustotal.com/api/v3/files/${iocValue}`;
        break;
      case 'url':
        // URL needs to be base64 encoded without padding
        const urlId = Buffer.from(iocValue).toString('base64').replace(/=/g, '');
        endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
        break;
      default:
        return { source: 'VirusTotal', available: false, message: 'Unsupported IOC type' };
    }
    
    const response = await fetch(endpoint, {
      headers: {
        'x-apikey': apiKey
      }
    });
    
    if (!response.ok) {
      throw new Error(`VirusTotal API error: ${response.status}`);
    }
    
    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;
    
    const result = {
      source: 'VirusTotal',
      available: true,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      reputation: stats.malicious > 0 ? 'malicious' : 
                  stats.suspicious > 0 ? 'suspicious' : 'clean',
      detectionRatio: `${stats.malicious}/${stats.malicious + stats.harmless + stats.undetected}`,
      lastAnalysis: data.data.attributes.last_analysis_date
    };
    
    setCache(cacheKey, result);
    return result;
    
  } catch (error) {
    console.error('VirusTotal API error:', error.message);
    return {
      source: 'VirusTotal',
      available: false,
      error: error.message
    };
  }
}

// ============================================================================
// Emerging Threats Feed (Free, no API key)
// ============================================================================

export async function checkEmergingThreats(ipAddress) {
  const cacheKey = `emerging_threats_${ipAddress}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;
  
  try {
    // Fetch Emerging Threats compromised IPs list
    const response = await fetch('https://rules.emergingthreats.net/blockrules/compromised-ips.txt');
    
    if (!response.ok) {
      throw new Error(`Emerging Threats error: ${response.status}`);
    }
    
    const text = await response.text();
    const ipList = text.split('\n').filter(line => line && !line.startsWith('#'));
    
    const isListed = ipList.includes(ipAddress);
    
    const result = {
      source: 'Emerging Threats',
      available: true,
      listed: isListed,
      reputation: isListed ? 'malicious' : 'unknown',
      listSize: ipList.length,
      message: isListed ? 'IP found in compromised hosts list' : 'IP not found in threat list'
    };
    
    setCache(cacheKey, result);
    return result;
    
  } catch (error) {
    console.error('Emerging Threats error:', error.message);
    return {
      source: 'Emerging Threats',
      available: false,
      error: error.message
    };
  }
}

// ============================================================================
// Aggregated IOC Enrichment
// ============================================================================

export async function enrichIOC(iocValue, iocType) {
  const enrichments = [];
  
  // Run all checks in parallel
  const checks = [];
  
  if (iocType === 'ip') {
    checks.push(
      checkAbuseIPDB(iocValue),
      checkEmergingThreats(iocValue),
      checkOTXReputation(iocValue, iocType),
      checkVirusTotal(iocValue, iocType)
    );
  } else {
    checks.push(
      checkOTXReputation(iocValue, iocType),
      checkVirusTotal(iocValue, iocType)
    );
  }
  
  const results = await Promise.allSettled(checks);
  
  results.forEach(result => {
    if (result.status === 'fulfilled') {
      enrichments.push(result.value);
    }
  });
  
  // Calculate overall reputation
  const reputations = enrichments
    .filter(e => e.available && e.reputation)
    .map(e => e.reputation);
  
  let overallReputation = 'unknown';
  if (reputations.includes('malicious')) {
    overallReputation = 'malicious';
  } else if (reputations.includes('suspicious')) {
    overallReputation = 'suspicious';
  } else if (reputations.includes('clean')) {
    overallReputation = 'clean';
  }
  
  return {
    ioc: iocValue,
    type: iocType,
    overallReputation,
    sources: enrichments,
    enrichedAt: new Date().toISOString(),
    cacheHit: false
  };
}

// ============================================================================
// Auto-update MITRE mappings in knowledge base
// ============================================================================

export async function updateMitreKnowledgeBase() {
  const mitreData = await fetchMitreAttackData();
  
  if (!mitreData.techniques.length) {
    return { success: false, error: 'Failed to fetch MITRE data' };
  }
  
  const kbPath = join(__dirname, '..', 'knowledge-base', 'mitre-map.json');
  const currentMap = JSON.parse(readFileSync(kbPath, 'utf-8'));
  
  // Update with latest technique details
  const updatedMap = { ...currentMap };
  let updatedCount = 0;
  
  for (const [attackType, mapping] of Object.entries(currentMap)) {
    const technique = mitreData.techniques.find(t => 
      t.id === mapping.technique || 
      t.name.toLowerCase().includes(attackType.toLowerCase())
    );
    
    if (technique) {
      updatedMap[attackType] = {
        ...mapping,
        tactic: technique.tactics[0] || mapping.tactic,
        technique: technique.id,
        subtechnique: mapping.subtechnique || `${technique.id} - ${technique.name}`,
        description: technique.description.substring(0, 200) + '...',
        url: technique.url,
        lastUpdated: new Date().toISOString()
      };
      updatedCount++;
    }
  }
  
  // Backup old file
  const backupPath = kbPath.replace('.json', `.backup.${Date.now()}.json`);
  writeFileSync(backupPath, JSON.stringify(currentMap, null, 2));
  
  // Write updated file
  writeFileSync(kbPath, JSON.stringify(updatedMap, null, 2));
  
  return {
    success: true,
    updatedCount,
    totalTechniques: Object.keys(updatedMap).length,
    backupPath
  };
}

// ============================================================================
// NVD (National Vulnerability Database) Integration
// ============================================================================

export async function checkNVD(cveId) {
  const apiKey = process.env.NVD_API_KEY;
  
  const cacheKey = `nvd_${cveId}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;
  
  try {
    // NVD API 2.0 endpoint
    const headers = {
      'Accept': 'application/json'
    };
    
    // Add API key if available (increases rate limit from 5 to 50 requests per 30 seconds)
    if (apiKey && apiKey !== 'your_nvd_api_key_here') {
      headers['apiKey'] = apiKey;
    }
    
    const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`, {
      headers
    });
    
    if (!response.ok) {
      throw new Error(`NVD API error: ${response.status}`);
    }
    
    const data = await response.json();
    
    if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
      return {
        source: 'NVD',
        available: true,
        found: false,
        message: `CVE ${cveId} not found in NVD database`
      };
    }
    
    const vuln = data.vulnerabilities[0].cve;
    const metrics = vuln.metrics;
    
    // Get CVSS score (prefer v3.1, fallback to v3.0, then v2.0)
    let cvssScore = null;
    let cvssVector = null;
    let severity = 'Unknown';
    
    if (metrics.cvssMetricV31 && metrics.cvssMetricV31.length > 0) {
      cvssScore = metrics.cvssMetricV31[0].cvssData.baseScore;
      cvssVector = metrics.cvssMetricV31[0].cvssData.vectorString;
      severity = metrics.cvssMetricV31[0].cvssData.baseSeverity;
    } else if (metrics.cvssMetricV30 && metrics.cvssMetricV30.length > 0) {
      cvssScore = metrics.cvssMetricV30[0].cvssData.baseScore;
      cvssVector = metrics.cvssMetricV30[0].cvssData.vectorString;
      severity = metrics.cvssMetricV30[0].cvssData.baseSeverity;
    } else if (metrics.cvssMetricV2 && metrics.cvssMetricV2.length > 0) {
      cvssScore = metrics.cvssMetricV2[0].cvssData.baseScore;
      cvssVector = metrics.cvssMetricV2[0].cvssData.vectorString;
      severity = cvssScore >= 7.0 ? 'HIGH' : cvssScore >= 4.0 ? 'MEDIUM' : 'LOW';
    }
    
    // Get CWE (Common Weakness Enumeration)
    const weaknesses = vuln.weaknesses?.map(w => 
      w.description.map(d => d.value).join(', ')
    ).join('; ') || 'Not specified';
    
    // Get references
    const references = vuln.references?.slice(0, 5).map(ref => ({
      url: ref.url,
      source: ref.source
    })) || [];
    
    const result = {
      source: 'NVD',
      available: true,
      found: true,
      cveId: vuln.id,
      description: vuln.descriptions?.find(d => d.lang === 'en')?.value || 'No description',
      cvssScore,
      cvssVector,
      severity,
      weaknesses,
      published: vuln.published,
      lastModified: vuln.lastModified,
      references,
      exploitabilityScore: metrics.cvssMetricV31?.[0]?.exploitabilityScore || 
                           metrics.cvssMetricV30?.[0]?.exploitabilityScore || null,
      impactScore: metrics.cvssMetricV31?.[0]?.impactScore || 
                   metrics.cvssMetricV30?.[0]?.impactScore || null
    };
    
    setCache(cacheKey, result);
    return result;
    
  } catch (error) {
    console.error('NVD API error:', error.message);
    return {
      source: 'NVD',
      available: false,
      error: error.message,
      message: apiKey ? 'API error occurred' : 'Get API key at https://nvd.nist.gov/developers/request-an-api-key for higher rate limits'
    };
  }
}

export async function searchNVDByKeyword(keyword, maxResults = 10) {
  const apiKey = process.env.NVD_API_KEY;
  
  const cacheKey = `nvd_search_${keyword}_${maxResults}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;
  
  try {
    const headers = {
      'Accept': 'application/json'
    };
    
    if (apiKey && apiKey !== 'your_nvd_api_key_here') {
      headers['apiKey'] = apiKey;
    }
    
    const response = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=${maxResults}`,
      { headers }
    );
    
    if (!response.ok) {
      throw new Error(`NVD API error: ${response.status}`);
    }
    
    const data = await response.json();
    
    const cves = data.vulnerabilities?.map(v => {
      const cve = v.cve;
      const metrics = cve.metrics;
      
      let cvssScore = null;
      let severity = 'Unknown';
      
      if (metrics.cvssMetricV31 && metrics.cvssMetricV31.length > 0) {
        cvssScore = metrics.cvssMetricV31[0].cvssData.baseScore;
        severity = metrics.cvssMetricV31[0].cvssData.baseSeverity;
      } else if (metrics.cvssMetricV30 && metrics.cvssMetricV30.length > 0) {
        cvssScore = metrics.cvssMetricV30[0].cvssData.baseScore;
        severity = metrics.cvssMetricV30[0].cvssData.baseSeverity;
      }
      
      return {
        cveId: cve.id,
        description: cve.descriptions?.find(d => d.lang === 'en')?.value.substring(0, 150) + '...' || 'No description',
        cvssScore,
        severity,
        published: cve.published
      };
    }) || [];
    
    const result = {
      source: 'NVD',
      available: true,
      keyword,
      totalResults: data.totalResults || 0,
      cves
    };
    
    setCache(cacheKey, result);
    return result;
    
  } catch (error) {
    console.error('NVD search error:', error.message);
    return {
      source: 'NVD',
      available: false,
      error: error.message
    };
  }
}

// ============================================================================
// Cache management
// ============================================================================

export function getCacheStats() {
  return {
    size: cache.size,
    keys: Array.from(cache.keys()),
    ttl: CACHE_TTL / 1000 + ' seconds'
  };
}

export function clearCache() {
  const size = cache.size;
  cache.clear();
  return { cleared: size };
}
