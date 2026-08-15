'use strict';

const { createMiddleware } = require('./middleware');

/**
 * Map a framework request into an Express-like shape for createMiddleware.
 */
function asExpressLike(source, map) {
  return {
    method: map.method || source.method,
    url: map.url || source.url,
    originalUrl: map.originalUrl || source.originalUrl || source.url,
    path: map.path || source.path || (source.url && String(source.url).split('?')[0]),
    query: map.query != null ? map.query : source.query || {},
    params: map.params != null ? map.params : source.params || {},
    body: map.body != null ? map.body : source.body,
    files: map.files != null ? map.files : source.files,
    headers: map.headers || source.headers || {},
    ip: map.ip || source.ip,
    socket: map.socket || source.socket || (source.raw && source.raw.socket),
    rawBody: map.rawBody || source.rawBody,
  };
}

/**
 * Fastify preHandler / onRequest compatible plugin factory.
 * Usage:
 *   fastify.addHook('preHandler', sqlSanitizer.fastify())
 *   // or
 *   await fastify.register(sqlSanitizer.fastifyPlugin(options))
 *
 * @param {object} [options]
 */
function fastify(options) {
  const mw = createMiddleware(options || {});

  async function fastifyHandler(request, reply) {
    const req = asExpressLike(request, {
      originalUrl: request.raw && request.raw.url,
      url: request.url,
      path: request.routerPath || (request.url && request.url.split('?')[0]),
      query: request.query,
      params: request.params,
      body: request.body,
      headers: request.headers,
      ip: request.ip,
      socket: request.raw && request.raw.socket,
    });

    await new Promise((resolve, reject) => {
      let settled = false;
      const res = {
        status(code) {
          this.statusCode = code;
          return this;
        },
        json(payload) {
          if (settled) return this;
          settled = true;
          reply.code(this.statusCode || 403).send(payload);
          resolve('blocked');
          return this;
        },
      };

      try {
        mw(req, res, (err) => {
          if (settled) return;
          settled = true;
          if (err) reject(err);
          else resolve('next');
        });
      } catch (err) {
        reject(err);
      }
    }).then((result) => {
      if (result === 'blocked') {
        return;
      }
      return undefined;
    });
  }

  fastifyHandler.stats = mw.stats;
  fastifyHandler.options = mw.options;
  fastifyHandler.resetRateLimit = mw.resetRateLimit;
  return fastifyHandler;
}

/**
 * Fastify plugin (fp-style) that registers a preHandler hook.
 * @param {object} [options]
 */
function fastifyPlugin(options) {
  const handler = fastify(options);
  async function plugin(fastifyInstance) {
    fastifyInstance.addHook('preHandler', handler);
  }
  plugin[Symbol.for('skip-override')] = true;
  plugin.stats = handler.stats;
  plugin.options = handler.options;
  return plugin;
}

/**
 * Koa middleware factory.
 * @param {object} [options]
 */
function koa(options) {
  const mw = createMiddleware(options || {});

  async function koaMiddleware(ctx, next) {
    const req = asExpressLike(ctx.request, {
      originalUrl: ctx.originalUrl || ctx.url,
      url: ctx.url,
      path: ctx.path,
      query: ctx.query,
      params: ctx.params || {},
      body: ctx.request.body,
      files: ctx.request.files || ctx.files,
      headers: ctx.headers,
      ip: ctx.ip,
      socket: ctx.req && ctx.req.socket,
    });

    const blocked = await new Promise((resolve, reject) => {
      const res = {
        status(code) {
          this.statusCode = code;
          return this;
        },
        json(payload) {
          ctx.status = this.statusCode || 403;
          ctx.body = payload;
          resolve(true);
          return this;
        },
      };
      try {
        mw(req, res, (err) => {
          if (err) reject(err);
          else resolve(false);
        });
      } catch (err) {
        reject(err);
      }
    });

    if (!blocked) {
      await next();
    }
  }

  koaMiddleware.stats = mw.stats;
  koaMiddleware.options = mw.options;
  koaMiddleware.resetRateLimit = mw.resetRateLimit;
  return koaMiddleware;
}

/**
 * NestJS-compatible middleware (works with Express or Fastify adapter via Express-like req/res).
 * Usage in Nest:
 *   consumer.apply(sqlSanitizer.nest(options)).forRoutes('*');
 *
 * @param {object} [options]
 */
function nest(options) {
  const mw = createMiddleware(options || {});
  function nestMiddleware(req, res, next) {
    return mw(req, res, next);
  }
  nestMiddleware.stats = mw.stats;
  nestMiddleware.options = mw.options;
  nestMiddleware.resetRateLimit = mw.resetRateLimit;
  return nestMiddleware;
}

module.exports = {
  asExpressLike,
  fastify,
  fastifyPlugin,
  koa,
  nest,
};
