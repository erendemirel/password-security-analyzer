export type AnalyzeOptions = {
  user_agent?: string;
  userAgent?: string;
  skip_breach?: boolean;
  skipBreach?: boolean;
  skip_model?: boolean;
  skipModel?: boolean;
  hibp_offline?: string;
  hibpOffline?: string;
  timeout_ms?: number;
  timeoutMs?: number;
};

export type AnalyzeResult = Record<string, unknown>;

export function analyze(password: string, options?: AnalyzeOptions): AnalyzeResult;
export function analyzeOffline(password: string, options?: AnalyzeOptions): AnalyzeResult;
export function checkPwned(password: string, options?: AnalyzeOptions): AnalyzeResult;
export function modelInfo(): AnalyzeResult;
