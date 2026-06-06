// TypeScript definitions for @jatin/lean

export interface PruneCandidate {
  path: string;
  size: number;
  category: string;
  packageName: string;
}

export interface ScanResult {
  totalFiles: number;
  totalSize: number;
  totalPackages: number;
  candidatesCount: number;
  potentialSavings: number;
  savingsPercentage: number;
  candidates?: PruneCandidate[];
}

export interface HealthResult {
  missingDeps: string[];
  circularDeps: string[];
  outdatedCount: number;
  securityIssues: number;
  overallHealth: 'healthy' | 'warning' | 'critical';
}

export interface DedupResult {
  duplicateGroups: number;
  totalDuplicates: number;
  wastedSpace: number;
  potentialSavings: number;
}

export interface SystemAssessment {
  recommendations: string[];
  cpuScore: number;
  memoryScore: number;
  ioScore: number;
  overallScore: number;
}

export interface BenchmarkResult {
  name: string;
  meanNs: number;
  medianNs: number;
  minNs: number;
  maxNs: number;
  opsPerSec: number;
}

export interface SystemInfo {
  os: string;
  arch: string;
  cpuCores: number;
  simdTier: string;
}

export interface AiContext {
  tool: string;
  version: string;
  capabilities: string[];
  systemInfo: SystemInfo;
}

/**
 * Scan node_modules directory for optimization opportunities
 */
export function scanNodeModules(path?: string): Promise<ScanResult>;

/**
 * Run health check on node_modules
 */
export function checkHealth(path?: string): Promise<HealthResult>;

/**
 * Find duplicate files in node_modules
 */
export function findDuplicates(path?: string): Promise<DedupResult>;

/**
 * Analyze compression potential
 * @returns Compression savings percentage
 */
export function analyzeCompression(path?: string): Promise<number>;

/**
 * Analyze tree-shaking potential
 * @returns Tree-shaking savings percentage
 */
export function analyzeTreeshake(path?: string): Promise<number>;

/**
 * Get dependency graph size
 * @returns Total dependencies count
 */
export function getDependencyGraph(path?: string): Promise<number>;

/**
 * Assess system performance
 */
export function assessSystem(): Promise<SystemAssessment>;

/**
 * Detect CPU capabilities
 * @returns SIMD tier (e.g., "AVX2")
 */
export function detectCpuCapabilities(): Promise<string>;

/**
 * Run benchmark suite
 */
export function runBenchmarks(): Promise<BenchmarkResult[]>;

/**
 * Get tool version
 */
export function getVersion(): string;

/**
 * Get AI-friendly context
 */
export function getAiContext(): Promise<AiContext>;

// Aliases
export { scanNodeModules as scan };
export { checkHealth as health };
export { findDuplicates as dedup };
export { analyzeCompression as compress };
export { analyzeTreeshake as treeshake };
export { getDependencyGraph as deps };
export { assessSystem as system };
export { detectCpuCapabilities as cpu };
export { runBenchmarks as bench };
export { getVersion as version };
export { getAiContext as ai };
