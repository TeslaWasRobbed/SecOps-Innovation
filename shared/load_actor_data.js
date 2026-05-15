// Load real actor tracking data for Actor Watch
async function loadActorTrackingData() {
  try {
    const response = await fetch('shared/actor_tracking_data.json');
    if (!response.ok) {
      throw new Error('Could not load tracking data');
    }
    return await response.json();
  } catch (error) {
    console.warn('Could not load real tracking data, using fallback:', error);
    return null;
  }
}

// Enhanced actor data with real MITRE techniques and tools
const ENHANCED_ACTOR_DATA = {
  'fin7': {
    description: 'Financially motivated threat group that has primarily targeted the U.S. retail, restaurant, and hospitality sectors since mid-2015.',
    techniques: [
      {id: 'T1566.002', name: 'Spearphishing Link', tactic: 'initial-access'},
      {id: 'T1059.003', name: 'Windows Command Shell', tactic: 'execution'},
      {id: 'T1055', name: 'Process Injection', tactic: 'defense-evasion'},
      {id: 'T1003.001', name: 'LSASS Memory', tactic: 'credential-access'},
      {id: 'T1021.001', name: 'Remote Desktop Protocol', tactic: 'lateral-movement'},
      {id: 'T1005', name: 'Data from Local System', tactic: 'collection'}
    ],
    tools: ['CARBANAK', 'GRIFFON', 'POWERSOURCE', 'Cobalt Strike', 'Mimikatz'],
    sectors: ['Retail', 'Hospitality', 'Financial Services'],
    activeCampaigns: 3
  },
  'fin8': {
    description: 'Financially motivated threat group known to launch tailored spear-phishing campaigns targeting the financial, retail, and hospitality industries.',
    techniques: [
      {id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'initial-access'},
      {id: 'T1204.002', name: 'Malicious File', tactic: 'execution'},
      {id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'defense-evasion'},
      {id: 'T1547.001', name: 'Registry Run Keys', tactic: 'persistence'},
      {id: 'T1082', name: 'System Information Discovery', tactic: 'discovery'}
    ],
    tools: ['PUNCHBUGGY', 'PUNCHTRACK', 'BadHatch', 'PowerShell Empire', 'Metasploit'],
    sectors: ['Financial Services', 'Retail', 'Hospitality'],
    activeCampaigns: 2
  },
  'fin6': {
    description: 'Financially motivated threat group that has compromised point-of-sale systems in the hospitality and retail sectors.',
    techniques: [
      {id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'initial-access'},
      {id: 'T1505.003', name: 'Web Shell', tactic: 'persistence'},
      {id: 'T1003.001', name: 'LSASS Memory', tactic: 'credential-access'}
    ],
    tools: ['TRINITY', 'FrameworkPOS', 'More_eggs'],
    sectors: ['Hospitality', 'Retail', 'E-commerce'],
    activeCampaigns: 1
  },
  'fin11': {
    description: 'Financially motivated threat group that has been active since at least 2016, known for large-scale malware distribution campaigns.',
    techniques: [
      {id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'initial-access'},
      {id: 'T1204.002', name: 'Malicious File', tactic: 'execution'},
      {id: 'T1547.001', name: 'Registry Run Keys / Startup Folder', tactic: 'persistence'}
    ],
    tools: ['Clop', 'FlawedAmmyy', 'SDBbot'],
    sectors: ['Financial Services', 'Healthcare', 'Retail'],
    activeCampaigns: 4
  },
  'fin12': {
    description: 'Financially motivated threat group that has conducted ransomware attacks against healthcare, financial, and critical infrastructure organizations.',
    techniques: [
      {id: 'T1078.002', name: 'Domain Accounts', tactic: 'initial-access'},
      {id: 'T1021.001', name: 'Remote Desktop Protocol', tactic: 'lateral-movement'},
      {id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'impact'}
    ],
    tools: ['RYUK', 'Cobalt Strike', 'PowerShell Empire'],
    sectors: ['Healthcare', 'Financial Services', 'Critical Infrastructure'],
    activeCampaigns: 2
  },
  'carbanak': {
    description: 'Financially motivated cybercriminal group that has stolen over $1 billion from financial institutions worldwide.',
    techniques: [
      {id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'initial-access'},
      {id: 'T1055', name: 'Process Injection', tactic: 'defense-evasion'},
      {id: 'T1021.001', name: 'Remote Desktop Protocol', tactic: 'lateral-movement'}
    ],
    tools: ['Carbanak', 'Cobalt Strike', 'Mimikatz'],
    sectors: ['Banking', 'Financial Services', 'Payment Processors'],
    activeCampaigns: 1
  },
  'silence': {
    description: 'Financially motivated threat group that primarily targets financial institutions in Eastern Europe, Russia, and Central Asia.',
    techniques: [
      {id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'initial-access'},
      {id: 'T1112', name: 'Modify Registry', tactic: 'defense-evasion'},
      {id: 'T1005', name: 'Data from Local System', tactic: 'collection'}
    ],
    tools: ['Silence', 'TrueBot', 'Farse'],
    sectors: ['Banking', 'Financial Services', 'Money Transfer Services'],
    activeCampaigns: 1
  },
  'lazarus': {
    description: 'North Korean state-sponsored threat group responsible for numerous high-profile attacks including the Sony Pictures hack and WannaCry ransomware.',
    techniques: [
      {id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'initial-access'},
      {id: 'T1059.003', name: 'Windows Command Shell', tactic: 'execution'},
      {id: 'T1055', name: 'Process Injection', tactic: 'defense-evasion'},
      {id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'impact'}
    ],
    tools: ['BADCALL', 'HOPLIGHT', 'TYPEFRAME', 'WannaCry'],
    sectors: ['Financial Services', 'Cryptocurrency', 'Media', 'Government'],
    activeCampaigns: 5
  },
  'apt29': {
    description: 'Russian government-sponsored threat group attributed to the Foreign Intelligence Service (SVR), known for sophisticated and persistent attacks.',
    techniques: [
      {id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'initial-access'},
      {id: 'T1055', name: 'Process Injection', tactic: 'defense-evasion'},
      {id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'defense-evasion'},
      {id: 'T1082', name: 'System Information Discovery', tactic: 'discovery'}
    ],
    tools: ['HAMMERTOSS', 'POWERDUKE', 'BEACON', 'Cobalt Strike'],
    sectors: ['Government', 'Healthcare', 'Technology', 'Research'],
    activeCampaigns: 3
  },
  'apt28': {
    description: 'Russian military intelligence (GRU) threat group known for targeting government, military, and security organizations worldwide.',
    techniques: [
      {id: 'T1566.002', name: 'Spearphishing Link', tactic: 'initial-access'},
      {id: 'T1059.003', name: 'Windows Command Shell', tactic: 'execution'},
      {id: 'T1003.001', name: 'LSASS Memory', tactic: 'credential-access'},
      {id: 'T1021.001', name: 'Remote Desktop Protocol', tactic: 'lateral-movement'}
    ],
    tools: ['X-Agent', 'Sofacy', 'Komplex', 'GAMEFISH'],
    sectors: ['Government', 'Military', 'Defense', 'Media'],
    activeCampaigns: 4
  }
};

// Generate recent activity based on real context or fallback
function generateRecentActivity(actorKey, trackingData) {
  const actor = trackingData?.actors?.[actorKey];
  
  if (actor?.recent_contexts?.length > 0) {
    // Use real contexts from digest mentions
    return actor.recent_contexts.map(context => 
      `Mentioned in ${context.date} digest: "${context.context.substring(0, 100)}..."`
    );
  }
  
  return [];
}

// Merge real tracking data with enhanced actor information
async function buildProductionActorData() {
  const trackingData = await loadActorTrackingData();
  const productionActors = {};
  
  // Get all actors from tracking data or fall back to enhanced data
  const allActorKeys = trackingData ? 
    Object.keys(trackingData.actors) : 
    Object.keys(ENHANCED_ACTOR_DATA);
  
  for (const actorKey of allActorKeys) {
    const trackingActor = trackingData?.actors?.[actorKey];
    const enhancedActor = ENHANCED_ACTOR_DATA[actorKey];
    
    if (!enhancedActor && !trackingActor) continue;
    
    productionActors[actorKey] = {
      // Basic info from tracking data or enhanced data
      name: trackingActor?.name || enhancedActor?.name || actorKey.toUpperCase(),
      id: trackingActor?.id || '',
      aliases: trackingActor?.aliases || [actorKey.toUpperCase()],
      type: trackingActor?.type || 'unknown',
      
      // Real tracking metrics (will be 0 initially, grow over time)
      digestMentions: trackingActor?.total_mentions || 0,
      digestAppearances: trackingActor?.digest_appearances || 0,
      firstSeen: trackingActor?.first_seen || null,
      lastSeen: trackingActor?.last_seen || null,
      
      // Enhanced intelligence data
      description: enhancedActor?.description || 'Intelligence profile being developed...',
      techniques: enhancedActor?.techniques || [],
      tools: enhancedActor?.tools || [],
      sectors: enhancedActor?.sectors || [],
      activeCampaigns: enhancedActor?.activeCampaigns || 0,
      
      // Recent activity from real mentions or fallback
      recentActivity: generateRecentActivity(actorKey, trackingData)
    };
  }
  
  return {
    actors: productionActors,
    metadata: {
      lastUpdated: trackingData?.last_updated || new Date().toISOString(),
      totalDigestsScanned: trackingData?.total_digests_scanned || 0,
      usingRealData: !!trackingData
    }
  };
}

// Export for use in Actor Watch page
window.buildProductionActorData = buildProductionActorData;
