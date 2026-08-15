import type { Request, Response, NextFunction, RequestHandler } from 'express';

export type SanitizerMode = 'block' | 'detect' | 'monitor';
export type Sensitivity = 'balanced' | 'strict' | 'paranoid';
export type PresetName = 'api' | 'form' | 'graphql';

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
  mode?: SanitizerMode;
  sensitivity?: Sensitivity;
  /** Named defaults: api | form | graphql */
  preset?: PresetName;
  /**
   * Trust proxy headers when resolving client IP.
   * false = ignore X-Forwarded-For (anti-spoof).
   * true = leftmost XFF / CDN headers.
   * number = hop count from the right.
   */
  trustProxy?: boolean | number | string;
  /** Built-in stats path, e.g. '/__sql-sanitizer/stats' */
  statsRoute?: string | null;
  /** Optional shared secret for statsRoute (header x-sql-sanitizer-token or ?token=) */
  statsToken?: string | null;
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
  statsHandler: RequestHandler;
  prometheus: () => string;
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

export interface ScanFinding {
  file: string;
  line: number;
  column: number;
  pattern: string;
  sample: string;
}

export declare const PRESETS: Record<PresetName, Partial<SqlSanitizerOptions>>;
export declare function getPreset(name: PresetName | string): Partial<SqlSanitizerOptions>;
export declare function applyPreset(options?: SqlSanitizerOptions): SqlSanitizerOptions;

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

export declare function fastify(options?: SqlSanitizerOptions): ((request: any, reply: any) => Promise<void>) & {
  stats: SanitizerStats;
  options: SqlSanitizerOptions;
};
export declare function fastifyPlugin(options?: SqlSanitizerOptions): ((instance: any) => Promise<void>) & {
  stats: SanitizerStats;
  options: SqlSanitizerOptions;
};
export declare function koa(options?: SqlSanitizerOptions): ((ctx: any, next: () => Promise<void>) => Promise<void>) & {
  stats: SanitizerStats;
  options: SqlSanitizerOptions;
};
export declare function nest(options?: SqlSanitizerOptions): SqlSanitizerMiddleware;

export declare function toPrometheus(stats: SanitizerStats, prefix?: string): string;
export declare function createStatsHandler(
  middleware: SqlSanitizerMiddleware,
  options?: { format?: 'json' | 'prometheus'; token?: string }
): RequestHandler;
export declare function resolveClientIp(
  req: Partial<Request>,
  options?: { trustProxy?: boolean | number | string; clientKey?: (req: any) => string }
): string;
export declare function defaultClientKey(req: Partial<Request>): string;
export declare function scanContent(filePath: string, content: string): ScanFinding[];
export declare function scanDirectory(
  rootDir: string,
  options?: { extensions?: string[]; ignore?: string[] }
): { root: string; filesScanned: number; findings: ScanFinding[] };

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
  fastify: typeof fastify;
  fastifyPlugin: typeof fastifyPlugin;
  koa: typeof koa;
  nest: typeof nest;
  PRESETS: typeof PRESETS;
  getPreset: typeof getPreset;
  applyPreset: typeof applyPreset;
  toPrometheus: typeof toPrometheus;
  createStatsHandler: typeof createStatsHandler;
  resolveClientIp: typeof resolveClientIp;
  defaultClientKey: typeof defaultClientKey;
  scanDirectory: typeof scanDirectory;
  scanContent: typeof scanContent;
  default: SqlSanitizerCallable;
}

declare const sqlSanitizer: SqlSanitizerCallable;
export default sqlSanitizer;
