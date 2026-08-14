import type { Request, Response, NextFunction, RequestHandler } from 'express';

export type SanitizerMode = 'block' | 'detect' | 'monitor';

export interface DetectionEvent {
  ts: string;
  mode: SanitizerMode;
  method?: string;
  path: string;
  ip: string;
  field: string;
  pattern: string;
  sample: string;
  rateLimit?: {
    count: number;
    limited: boolean;
    remaining: number;
  } | null;
}

export interface RateLimitOptions {
  windowMs?: number;
  max?: number;
}

export interface SqlSanitizerOptions {
  /** block (default) | detect (log only) | monitor (log + attach req.sqlSanitizer) */
  mode?: SanitizerMode;
  /** Skip scanning for these paths (exact or prefix: "/webhooks" → "/webhooks/...") */
  allowRoutes?: Array<string | RegExp>;
  /** Skip these body/query field names (matches suffix paths too, e.g. "bio" → "user.bio") */
  allowFields?: string[];
  /** Structured detection callback */
  onDetection?: (event: DetectionEvent, req: Request) => void;
  /** Logger with warn/log, or a function. null disables logging. */
  logger?:
    | { warn?: (payload: unknown) => void; log?: (payload: unknown) => void }
    | ((payload: unknown) => void)
    | null;
  /** Count detections per client; in block mode excess returns 429 */
  rateLimit?: RateLimitOptions;
  /** Override client identity for rate limiting */
  clientKey?: (req: Request) => string;
  errorMessage?: Record<string, unknown>;
  rateLimitMessage?: Record<string, unknown>;
}

export interface CheckResult {
  detected: boolean;
  pattern: string | null;
  value: string | null;
}

export interface SanitizerStats {
  totalRequests: number;
  detections: number;
  blocked: number;
  rateLimited: number;
  byPattern: Record<string, number>;
}

export interface SqlSanitizerMiddleware extends RequestHandler {
  stats: SanitizerStats;
  options: SqlSanitizerOptions;
  resetRateLimit?: () => void;
}

export interface SecurityHeadersOptions {
  frameguard?: boolean;
  noSniff?: boolean;
  xssFilter?: boolean;
  referrerPolicy?: boolean;
  referrerPolicyValue?: string;
  contentSecurityPolicy?: boolean | string;
}

export declare function hasSqlInjection(value: unknown): boolean;
export declare function check(value: unknown): CheckResult;
export declare function collectValues(input: unknown, out: string[]): void;
export declare function collectFromRequest(
  req: Request,
  options?: { allowFields?: string[] }
): Array<{ path: string; value: string }>;
export declare function createMiddleware(options?: SqlSanitizerOptions): SqlSanitizerMiddleware;
export declare function securityHeaders(options?: SecurityHeadersOptions): RequestHandler;

interface SqlSanitizerCallable {
  (options?: SqlSanitizerOptions): SqlSanitizerMiddleware;
  (req: Request, res: Response, next: NextFunction): void;
  hasSqlInjection: typeof hasSqlInjection;
  check: typeof check;
  collectValues: typeof collectValues;
  collectFromRequest: typeof collectFromRequest;
  createMiddleware: typeof createMiddleware;
  securityHeaders: typeof securityHeaders;
  default: SqlSanitizerCallable;
}

declare const sqlSanitizer: SqlSanitizerCallable;
export default sqlSanitizer;
