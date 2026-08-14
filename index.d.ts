import type { Request, Response, NextFunction, RequestHandler } from 'express';

export type SanitizerMode = 'block' | 'detect' | 'monitor';
export type Sensitivity = 'balanced' | 'strict' | 'paranoid';

export interface DetectionEvent {
  ts: string;
  mode: SanitizerMode;
  sensitivity?: Sensitivity;
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
  /**
   * Detection aggressiveness.
   * - balanced (default): contextual attacks; allows O'Brien-style text
   * - strict: balanced + comment/keyword and hex heuristics
   * - paranoid: legacy bare `'`, `#`, `--` matching
   */
  sensitivity?: Sensitivity;
  allowRoutes?: Array<string | RegExp>;
  allowFields?: string[];
  onDetection?: (event: DetectionEvent, req: Request) => void;
  logger?:
    | { warn?: (payload: unknown) => void; log?: (payload: unknown) => void }
    | ((payload: unknown) => void)
    | null;
  rateLimit?: RateLimitOptions;
  clientKey?: (req: Request) => string;
  errorMessage?: Record<string, unknown>;
  rateLimitMessage?: Record<string, unknown>;
}

export interface CheckResult {
  detected: boolean;
  pattern: string | null;
  value: string | null;
  normalized: string | null;
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

export interface ParameterizedQuery {
  text: string;
  values: unknown[];
  dialect: 'pg' | 'mysql';
}

export declare function hasSqlInjection(
  value: unknown,
  options?: { sensitivity?: Sensitivity }
): boolean;
export declare function check(
  value: unknown,
  options?: { sensitivity?: Sensitivity }
): CheckResult;
export declare function normalizeForDetection(input: string): string;
export declare function collectValues(input: unknown, out: string[]): void;
export declare function collectFromRequest(
  req: Request,
  options?: { allowFields?: string[] }
): Array<{ path: string; value: string }>;
export declare function collectPathSegments(
  req: Partial<Request>,
  out: Array<{ path: string; value: string }>
): void;
export declare function createMiddleware(options?: SqlSanitizerOptions): SqlSanitizerMiddleware;
export declare function securityHeaders(options?: SecurityHeadersOptions): RequestHandler;
export declare function sql(strings: TemplateStringsArray, ...values: unknown[]): ParameterizedQuery;
export declare function sqlQ(strings: TemplateStringsArray, ...values: unknown[]): ParameterizedQuery;
export declare function looksLikeConcatenatedSql(query: string): boolean;

interface SqlSanitizerCallable {
  (options?: SqlSanitizerOptions): SqlSanitizerMiddleware;
  (req: Request, res: Response, next: NextFunction): void;
  hasSqlInjection: typeof hasSqlInjection;
  check: typeof check;
  normalizeForDetection: typeof normalizeForDetection;
  collectValues: typeof collectValues;
  collectFromRequest: typeof collectFromRequest;
  collectPathSegments: typeof collectPathSegments;
  createMiddleware: typeof createMiddleware;
  securityHeaders: typeof securityHeaders;
  sql: typeof sql;
  sqlQ: typeof sqlQ;
  looksLikeConcatenatedSql: typeof looksLikeConcatenatedSql;
  default: SqlSanitizerCallable;
}

declare const sqlSanitizer: SqlSanitizerCallable;
export default sqlSanitizer;
