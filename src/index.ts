export type IntelligenceSignal = {
  id: string;
  title: string;
  region: string;
  source: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  tags: string[];
  observedAt: string;
};

export type SituationBrief = {
  generatedAt: string;
  criticalCount: number;
  highPriorityRegions: string[];
  executiveSummary: string;
  signals: IntelligenceSignal[];
};

const severityRank = { low: 1, medium: 2, high: 3, critical: 4 } as const;

export function buildSituationBrief(signals: IntelligenceSignal[]): SituationBrief {
  const sorted = [...signals].sort((left, right) => severityRank[right.severity] - severityRank[left.severity]);
  const criticalCount = sorted.filter((signal) => signal.severity === 'critical').length;
  const highPriorityRegions = Array.from(new Set(sorted.filter((signal) => severityRank[signal.severity] >= 3).map((signal) => signal.region))).slice(0, 8);

  return {
    generatedAt: new Date().toISOString(),
    criticalCount,
    highPriorityRegions,
    executiveSummary: criticalCount
      ? `${criticalCount} critical signal(s) require immediate review across ${highPriorityRegions.join(', ') || 'tracked regions'}.`
      : `No critical signal detected. ${highPriorityRegions.length} region(s) remain on elevated watch.`,
    signals: sorted,
  };
}

export function filterSignals(signals: IntelligenceSignal[], tag: string): IntelligenceSignal[] {
  const normalized = tag.trim().toLowerCase();
  return signals.filter((signal) => signal.tags.some((item) => item.toLowerCase() === normalized));
}
