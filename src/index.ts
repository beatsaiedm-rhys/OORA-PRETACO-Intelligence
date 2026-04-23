export type SignalSeverity = 'low' | 'medium' | 'high' | 'critical';

export type IntelligenceSignal = {
  id: string;
  title: string;
  region: string;
  source: string;
  sourceReliability: 1 | 2 | 3 | 4 | 5;
  severity: SignalSeverity;
  tags: string[];
  observedAt: string;
  summary?: string;
};

export type SignalCluster = {
  id: string;
  region: string;
  tags: string[];
  severity: SignalSeverity;
  riskScore: number;
  signalIds: string[];
  title: string;
};

export type WatchRule = {
  id: string;
  label: string;
  regions?: string[];
  tags?: string[];
  minimumSeverity?: SignalSeverity;
};

export type SituationBrief = {
  generatedAt: string;
  criticalCount: number;
  highPriorityRegions: string[];
  executiveSummary: string;
  clusters: SignalCluster[];
  watchHits: Array<{ ruleId: string; signalIds: string[] }>;
  signals: IntelligenceSignal[];
};

const severityRank: Record<SignalSeverity, number> = { low: 1, medium: 2, high: 3, critical: 4 };
const rankSeverity = (rank: number): SignalSeverity => (rank >= 4 ? 'critical' : rank >= 3 ? 'high' : rank >= 2 ? 'medium' : 'low');

function normalizeTag(tag: string): string {
  return tag.trim().toLowerCase().replace(/\s+/g, '-');
}

function signalRisk(signal: IntelligenceSignal): number {
  const severity = severityRank[signal.severity] * 18;
  const reliability = signal.sourceReliability * 8;
  const recencyHours = Math.max(0, (Date.now() - new Date(signal.observedAt).getTime()) / 36e5);
  const recency = Math.max(0, 24 - Math.min(24, recencyHours));
  return Math.max(0, Math.min(100, Math.round(severity + reliability + recency)));
}

export function normalizeSignal(signal: IntelligenceSignal): IntelligenceSignal {
  return {
    ...signal,
    region: signal.region.trim() || 'global',
    source: signal.source.trim() || 'unknown',
    sourceReliability: Math.max(1, Math.min(5, signal.sourceReliability)) as IntelligenceSignal['sourceReliability'],
    tags: Array.from(new Set(signal.tags.map(normalizeTag).filter(Boolean))),
    observedAt: new Date(signal.observedAt).toISOString(),
  };
}

export function dedupeSignals(signals: IntelligenceSignal[]): IntelligenceSignal[] {
  const seen = new Map<string, IntelligenceSignal>();
  signals.map(normalizeSignal).forEach((signal) => {
    const key = `${signal.region}:${signal.title.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim()}`;
    const existing = seen.get(key);
    if (!existing || signalRisk(signal) > signalRisk(existing)) seen.set(key, signal);
  });
  return Array.from(seen.values());
}

export function clusterSignals(signals: IntelligenceSignal[]): SignalCluster[] {
  const buckets = new Map<string, IntelligenceSignal[]>();
  dedupeSignals(signals).forEach((signal) => {
    const primaryTag = signal.tags[0] || 'general';
    const key = `${signal.region}:${primaryTag}`;
    buckets.set(key, [...(buckets.get(key) || []), signal]);
  });

  return Array.from(buckets.entries()).map(([key, bucket]) => {
    const [region, primaryTag] = key.split(':');
    const riskScore = Math.round(bucket.reduce((sum, signal) => sum + signalRisk(signal), 0) / bucket.length);
    const severity = rankSeverity(Math.max(...bucket.map((signal) => severityRank[signal.severity])));
    const allTags = Array.from(new Set(bucket.flatMap((signal) => signal.tags))).slice(0, 10);
    return {
      id: `cluster-${region}-${primaryTag}`.replace(/[^a-z0-9-]/gi, '-').toLowerCase(),
      region,
      tags: allTags,
      severity,
      riskScore,
      signalIds: bucket.map((signal) => signal.id),
      title: `${region} / ${primaryTag}: ${bucket.length} signal(s), ${riskScore}/100 risk`,
    };
  }).sort((left, right) => right.riskScore - left.riskScore);
}

export function evaluateWatchRules(signals: IntelligenceSignal[], rules: WatchRule[]): Array<{ ruleId: string; signalIds: string[] }> {
  const normalized = dedupeSignals(signals);
  return rules.map((rule) => {
    const signalIds = normalized
      .filter((signal) => {
        const regionMatch = !rule.regions?.length || rule.regions.map((item) => item.toLowerCase()).includes(signal.region.toLowerCase());
        const tagMatch = !rule.tags?.length || rule.tags.map(normalizeTag).some((tag) => signal.tags.includes(tag));
        const severityMatch = !rule.minimumSeverity || severityRank[signal.severity] >= severityRank[rule.minimumSeverity];
        return regionMatch && tagMatch && severityMatch;
      })
      .map((signal) => signal.id);
    return { ruleId: rule.id, signalIds };
  }).filter((hit) => hit.signalIds.length > 0);
}

export function buildSituationBrief(signals: IntelligenceSignal[], rules: WatchRule[] = []): SituationBrief {
  const normalized = dedupeSignals(signals).sort((left, right) => signalRisk(right) - signalRisk(left));
  const clusters = clusterSignals(normalized);
  const criticalCount = normalized.filter((signal) => signal.severity === 'critical').length;
  const highPriorityRegions = Array.from(new Set(clusters.filter((cluster) => cluster.riskScore >= 65).map((cluster) => cluster.region))).slice(0, 8);
  const topCluster = clusters[0];
  const executiveSummary = criticalCount
    ? `${criticalCount} critical signal(s) require immediate review. Highest cluster: ${topCluster?.title || 'n/a'}.`
    : `No critical signal detected. ${highPriorityRegions.length} region(s) remain on elevated watch.`;

  return {
    generatedAt: new Date().toISOString(),
    criticalCount,
    highPriorityRegions,
    executiveSummary,
    clusters,
    watchHits: evaluateWatchRules(normalized, rules),
    signals: normalized,
  };
}

export function filterSignals(signals: IntelligenceSignal[], query: { tag?: string; region?: string; minimumSeverity?: SignalSeverity }): IntelligenceSignal[] {
  return dedupeSignals(signals).filter((signal) => {
    const tagMatch = !query.tag || signal.tags.includes(normalizeTag(query.tag));
    const regionMatch = !query.region || signal.region.toLowerCase() === query.region.toLowerCase();
    const severityMatch = !query.minimumSeverity || severityRank[signal.severity] >= severityRank[query.minimumSeverity];
    return tagMatch && regionMatch && severityMatch;
  });
}

export function createSignal(params: Omit<IntelligenceSignal, 'id' | 'observedAt'> & { id?: string; observedAt?: string }): IntelligenceSignal {
  const id = params.id || `sig-${Math.abs([...params.title].reduce((sum, char) => sum + char.charCodeAt(0), 0))}-${Date.now()}`;
  return normalizeSignal({
    ...params,
    id,
    observedAt: params.observedAt || new Date().toISOString(),
  });
}
