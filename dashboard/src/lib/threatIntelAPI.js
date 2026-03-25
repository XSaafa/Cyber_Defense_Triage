// Threat Intelligence API for Dashboard
// This module provides the same threat intelligence capabilities to the React dashboard

const API_BASE = '/api/threat-intel'; // Will be proxied through Vite dev server

// For development, we'll use the same logic as the server
// In production, this would call a backend API endpoint

import severityRules from '../../../knowledge-base/severity-rules.json';
import playbooks from '../../../knowledge-base/playbooks.json';
import logPatterns from '../../../knowledge-base/log-patterns.json';
import mitreMap from '../../../knowledge-base/mitre-map.json';

// Simple in-memory cache for the dashboard
const cache = new Map();
const CACHE_TTL = 3600 * 1000; // 1 hour

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
// External API Integration (Browser-compatible)
// ============================================================================

export async function enrichIOCInBrowser(iocValue, iocType) {
  const cacheKey = `ioc_${iocType}_${iocValue}`;
  const cached = getCached(cacheKey);
  if (cached) return { ...cached, cacheHit: true };

  const enrichments = [];
  
  // Check VirusTotal (if API key is available in localStorage)
  const vtApiKey = localStorage.getItem('virustotal_api_key');
  if (vtApiKey && vtApiKey !== 'your_virustotal_api_key_here') {
    try {
      const vtResult = await checkVirusTotalBrowser(iocValue, iocType, vtApiKey);
      enrichments.push(vtResult);
    } catch (error) {
      console.error('VirusTotal error:', error);
    }
  }
  
  // Check AbuseIPDB (if IP and API key available)
  if (iocType === 'ip') {
    const abuseApiKey = localStorage.getItem('abuseipdb_api_key');
    if (abuseApiKey && abuseApiKey !== 'your_abuseipdb_api_key_here') {
      try {
        const abuseResult = await checkAbuseIPDBBrowser(iocValue, abuseApiKey);
        enrichments.push(abuseResult);
      } catch (error) {
        console.error('AbuseIPDB error:', error);
      }
    }
    
    // Emerging Threats is free, no API key needed
    try {
      const etResult = await checkEmergingThreatsBrowser(iocValue);
      enrichments.push(etResult);
    } catch (error) {
      console.error('Emerging Threats error:', error);
    }
  }
  
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
  
  const result = {
    ioc: iocValue,
    type: iocType,
    overallReputation,
    sources: enrichments,
    enrichedAt: new Date().toISOString(),
    cacheHit: false
  };
  
  setCache(cacheKey, result);
  return result;
}

async function checkVirusTotalBrowser(iocValue, iocType, apiKey) {
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
        const urlId = btoa(iocValue).replace(/=/g, '');
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
    
    return {
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
    
  } catch (error) {
    return {
      source: 'VirusTotal',
      available: false,
      error: error.message
    };
  }
}

async function checkAbuseIPDBBrowser(ipAddress, apiKey) {
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
    
    return {
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
    
  } catch (error) {
    return {
      source: 'AbuseIPDB',
      available: false,
      error: error.message
    };
  }
}

async function checkEmergingThreatsBrowser(ipAddress) {
  try {
    // Note: This may fail due to CORS. In production, proxy through backend
    const response = await fetch('https://rules.emergingthreats.net/blockrules/compromised-ips.txt');
    
    if (!response.ok) {
      throw new Error(`Emerging Threats error: ${response.status}`);
    }
    
    const text = await response.text();
    const ipList = text.split('\n').filter(line => line && !line.startsWith('#'));
    
    const isListed = ipList.includes(ipAddress);
    
    return {
      source: 'Emerging Threats',
      available: true,
      listed: isListed,
      reputation: isListed ? 'malicious' : 'unknown',
      listSize: ipList.length,
      message: isListed ? 'IP found in compromised hosts list' : 'IP not found in threat list'
    };
    
  } catch (error) {
    return {
      source: 'Emerging Threats',
      available: false,
      error: error.message,
      message: 'CORS may block this request - use MCP server for full access'
    };
  }
}

// ============================================================================
// MITRE ATT&CK Integration
// ============================================================================

export async function fetchMitreAttackDataBrowser() {
  const cacheKey = 'mitre_attack_data';
  const cached = getCached(cacheKey);
  if (cached) return cached;

  try {
    const response = await fetch('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json');
    
    if (!response.ok) {
      throw new Error(`MITRE API error: ${response.status}`);
    }
    
    const data = await response.json();
    
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

export async function enrichMitreMappingBrowser(attackType) {
  const mitreData = await fetchMitreAttackDataBrowser();
  
  if (!mitreData.techniques.length) {
    return null;
  }
  
  const searchTerm = attackType.toLowerCase();
  const matches = mitreData.techniques.filter(t => 
    t.name.toLowerCase().includes(searchTerm) ||
    t.description.toLowerCase().includes(searchTerm)
  );
  
  return matches.length > 0 ? matches[0] : null;
}

// ============================================================================
// API Key Management
// ============================================================================

export function saveAPIKey(service, apiKey) {
  localStorage.setItem(`${service}_api_key`, apiKey);
}

export function getAPIKey(service) {
  return localStorage.getItem(`${service}_api_key`) || '';
}

export function hasAPIKey(service) {
  const key = getAPIKey(service);
  return key && key !== `your_${service}_api_key_here` && key.length > 0;
}

export function clearAPIKeys() {
  localStorage.removeItem('virustotal_api_key');
  localStorage.removeItem('abuseipdb_api_key');
  localStorage.removeItem('otx_api_key');
  localStorage.removeItem('shodan_api_key');
}

// ============================================================================
// Cache Management
// ============================================================================

export function getCacheStats() {
  return {
    size: cache.size,
    keys: Array.from(cache.keys()),
    ttl: CACHE_TTL / 1000 + ' seconds'
  };
}

export function clearThreatIntelCache() {
  const size = cache.size;
  cache.clear();
  return { cleared: size };
}
