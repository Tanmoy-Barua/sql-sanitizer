import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const sqlSanitizer = require('./index.js');

export default sqlSanitizer;
export const hasSqlInjection = sqlSanitizer.hasSqlInjection;
export const check = sqlSanitizer.check;
export const collectValues = sqlSanitizer.collectValues;
export const collectFromRequest = sqlSanitizer.collectFromRequest;
export const createMiddleware = sqlSanitizer.createMiddleware;
export const securityHeaders = sqlSanitizer.securityHeaders;
