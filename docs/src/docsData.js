// Auto-import all markdown files from the docs root directory
const markdownModules = import.meta.glob('../*.md', { query: '?raw', import: 'default', eager: true });

export const DOCS_MANIFEST = [
  {
    id: '01_SYSTEM_OVERVIEW',
    file: '../01_SYSTEM_OVERVIEW.md',
    title: '01. System Overview',
    category: 'Architecture',
    icon: 'book',
    svg: 'system_architecture.svg',
    description: 'System architecture, invariants, and workspace crates responsibilities.'
  },
  {
    id: '02_SAFETY_INVARIANTS',
    file: '../02_SAFETY_INVARIANTS.md',
    title: '02. Safety Invariants',
    category: 'Core Principles',
    icon: 'shield',
    svg: 'safety_tiers.svg',
    description: 'Strict Tier-0 Zero-TX boundary and cryptographic safety permit validation.'
  },
  {
    id: '03_PROTOCOL_HEURISTICS',
    file: '../03_PROTOCOL_HEURISTICS.md',
    title: '03. Protocol Timing & Specs',
    category: 'Protocol Foundations',
    icon: 'binary',
    svg: 'modbus_timing.svg',
    description: 'Protocol timing tolerances, CRC verification, and serial framing rules.'
  },
  {
    id: 'FOSS_INSPIRATION',
    file: '../FOSS_INSPIRATION.md',
    title: 'Open-Source Inspiration',
    category: 'Protocol Foundations',
    icon: 'git',
    svg: 'foss_inspiration_flow.svg',
    description: 'Open-source reference implementations and proven industrial bus algorithms.'
  },
  {
    id: '04_HARDWARE_LAYER',
    file: '../04_HARDWARE_LAYER.md',
    title: '04. Hardware Layer & HAL',
    category: 'Hardware & Simulation',
    icon: 'cpu',
    svg: 'hal_replay.svg',
    description: 'Asynchronous BusInterface trait and deterministic ReplayInterface.'
  },
  {
    id: '05_DISSECTORS_AND_COMPLIANCE',
    file: '../05_DISSECTORS_AND_COMPLIANCE.md',
    title: '05. Dissectors & Compliance',
    category: 'Protocol Engines',
    icon: 'check',
    svg: 'crc_scanner.svg',
    description: 'Zero-panic nom parsers and Zeek ICSNPP compliant protocol auditor.'
  },
  {
    id: '06_REGISTER_INFERENCE',
    file: '../06_REGISTER_INFERENCE.md',
    title: '06. Semantic Inference',
    category: 'Analysis Engine',
    icon: 'activity',
    svg: 'word_orders.svg',
    description: 'Cansniffer bit-deltas, SavvyCAN Welford jitter, and Float32 plausibility.'
  },
  {
    id: '07_MCP_TOOLS',
    file: '../07_MCP_TOOLS.md',
    title: '07. MCP Diagnostic Tools',
    category: 'AI Telemetry',
    icon: 'bot',
    svg: 'mcp_sequence.svg',
    description: 'The 8 core Model Context Protocol diagnostic tools for AI coding agents.'
  },
  {
    id: '08_CLI_AND_FIELD_WORKFLOWS',
    file: '../08_CLI_AND_FIELD_WORKFLOWS.md',
    title: '08. Field CLI & Workflows',
    category: 'Field Operations',
    icon: 'terminal',
    svg: 'field_wiring.svg',
    description: 'Terminal user interface, cabinet wiring topology, and field operations.'
  },
  {
    id: '09_HTTP_TELEMETRY_API',
    file: '../09_HTTP_TELEMETRY_API.md',
    title: '09. HTTP & SSE Telemetry',
    category: 'Field Operations',
    icon: 'globe',
    svg: 'http_telemetry.svg',
    description: 'Asynchronous REST endpoints and real-time SSE telemetry daemon.'
  },
];

export function getDocContent(id) {
  const doc = DOCS_MANIFEST.find(d => d.id === id);
  if (!doc) return '';
  return markdownModules[doc.file] || '';
}
