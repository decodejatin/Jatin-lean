// Node.js bindings for jatin-lean
const { platform, arch } = require('os');
const path = require('path');

// Load the native addon
let nativeBinding;
try {
  // Try loading from the root directory first (for npm package)
  nativeBinding = require(path.join(__dirname, 'index.node'));
} catch (e1) {
  try {
    // Fallback to target/release for development
    const bindingPath = path.join(__dirname, 'target/release');
    let libName;
    
    if (platform() === 'win32') {
      libName = 'jatin_lean.dll';
    } else if (platform() === 'darwin') {
      libName = 'libjatin_lean.dylib';
    } else {
      libName = 'libjatin_lean.so';
    }
    
    nativeBinding = require(path.join(bindingPath, libName));
  } catch (e2) {
    throw new Error(
      `Failed to load jatin-lean native binding. ` +
      `Platform: ${platform()}, Arch: ${arch()}. ` +
      `Errors: ${e1.message}, ${e2.message}`
    );
  }
}

/**
 * Unpack binary candidate buffer
 * @param {Buffer} buffer - Raw binary payload
 * @returns {Array<Object>} List of candidate objects
 */
function unpackCandidates(buffer) {
  if (!buffer || buffer.length < 4) return [];
  const totalRecords = buffer.readUInt32LE(0);
  let offset = 4;
  const candidates = [];
  
  const categories = [
    'Documentation',
    'TestAsset',
    'BuildArtifact',
    'SourceMap',
    'CiConfig',
    'TypeScriptSource',
    'Example'
  ];
  
  for (let i = 0; i < totalRecords; i++) {
    if (offset >= buffer.length) break;
    
    const pathLen = buffer.readUInt16LE(offset);
    offset += 2;
    
    const pathStr = buffer.toString('utf8', offset, offset + pathLen);
    offset += pathLen;
    
    const size = Number(buffer.readBigUInt64LE(offset));
    offset += 8;
    
    const catIdx = buffer.readUInt8(offset);
    offset += 1;
    const category = categories[catIdx] || 'Unknown';
    
    const pkgLen = buffer.readUInt16LE(offset);
    offset += 2;
    
    const packageName = buffer.toString('utf8', offset, offset + pkgLen);
    offset += pkgLen;
    
    candidates.push({
      path: pathStr,
      size,
      category,
      packageName
    });
  }
  
  return candidates;
}

/**
 * Scan node_modules directory for optimization opportunities
 * @param {string} path - Path to project directory
 * @returns {Promise<ScanResult>}
 */
async function scanNodeModules(projectPath = '.') {
  const result = await nativeBinding.scanNodeModules(projectPath);
  if (result.candidatesBuffer) {
    result.candidates = unpackCandidates(result.candidatesBuffer);
    delete result.candidatesBuffer;
  }
  return result;
}

/**
 * Run health check on node_modules
 * @param {string} path - Path to project directory
 * @returns {Promise<HealthResult>}
 */
async function checkHealth(projectPath = '.') {
  return nativeBinding.checkHealth(projectPath);
}

/**
 * Find duplicate files in node_modules
 * @param {string} path - Path to project directory
 * @returns {Promise<DedupResult>}
 */
async function findDuplicates(projectPath = '.') {
  return nativeBinding.findDuplicates(projectPath);
}

/**
 * Analyze compression potential
 * @param {string} path - Path to project directory
 * @returns {Promise<number>} Compression savings percentage
 */
async function analyzeCompression(projectPath = '.') {
  return nativeBinding.analyzeCompression(projectPath);
}

/**
 * Analyze tree-shaking potential
 * @param {string} path - Path to project directory
 * @returns {Promise<number>} Tree-shaking savings percentage
 */
async function analyzeTreeshake(projectPath = '.') {
  return nativeBinding.analyzeTreeshake(projectPath);
}

/**
 * Get dependency graph size
 * @param {string} path - Path to project directory
 * @returns {Promise<number>} Total dependencies count
 */
async function getDependencyGraph(projectPath = '.') {
  return nativeBinding.getDependencyGraph(projectPath);
}

/**
 * Assess system performance
 * @returns {Promise<SystemAssessment>}
 */
async function assessSystem() {
  return nativeBinding.assessSystem();
}

/**
 * Detect CPU capabilities
 * @returns {Promise<string>} SIMD tier (e.g., "AVX2")
 */
async function detectCpuCapabilities() {
  return nativeBinding.detectCpuCapabilities();
}

/**
 * Run benchmark suite
 * @returns {Promise<BenchmarkResult[]>}
 */
async function runBenchmarks() {
  return nativeBinding.runBenchmarks();
}

/**
 * Get tool version
 * @returns {string}
 */
function getVersion() {
  return nativeBinding.getVersion();
}

/**
 * Get AI-friendly context
 * @returns {Promise<AiContext>}
 */
async function getAiContext() {
  return nativeBinding.getAiContext();
}

// Export all functions
module.exports = {
  scanNodeModules,
  checkHealth,
  findDuplicates,
  analyzeCompression,
  analyzeTreeshake,
  getDependencyGraph,
  assessSystem,
  detectCpuCapabilities,
  runBenchmarks,
  getVersion,
  getAiContext,
  
  // Aliases
  scan: scanNodeModules,
  health: checkHealth,
  dedup: findDuplicates,
  compress: analyzeCompression,
  treeshake: analyzeTreeshake,
  deps: getDependencyGraph,
  system: assessSystem,
  cpu: detectCpuCapabilities,
  bench: runBenchmarks,
  version: getVersion,
  ai: getAiContext,
};
