export type StrengthLabel = "weak" | "fair" | "strong" | "very_strong";

export interface BreachResult {
  pwned: boolean;
  occurrences: number;
  source: string;
}

export interface AnalyzeResult {
  advisory: true;
  aborted: boolean;
  breach: BreachResult;
  guess_number: number | null;
  strength_bits: number | null;
  keyspace_bits: number;
  label: StrengthLabel | null;
  reasons: string[];
}

export interface AnalyzeOptions {
  user_agent?: string;
  skip_breach?: boolean;
  skip_model?: boolean;
}

/** Initialize the WASM module (call once before other APIs). */
export default function init(
  module_or_path?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module
): Promise<unknown>;

/** Full analysis including optional HIBP (async). */
export function analyze(
  password: string,
  options?: AnalyzeOptions
): Promise<AnalyzeResult>;

/** Offline analysis (no network). Pass true to skip Markov/MC. */
export function analyzeOffline(
  password: string,
  skipModel?: boolean | null
): AnalyzeResult;

/** HIBP-only check. */
export function checkPwned(
  password: string,
  userAgent?: string | null
): Promise<BreachResult>;
