import type { Server } from 'node:http';
import type { RequestHandler } from 'express';

/** Drain peers even if one fails, but never advance past a failed phase. */
export function createShutdown(phases: Array<Array<() => Promise<unknown>>>) {
  let running: Promise<void> | undefined;
  return (): Promise<void> => running ??= (async () => {
    for (const phase of phases) {
      const results = await Promise.allSettled(phase.map(task => Promise.resolve().then(task)));
      const failures = results.filter((result): result is PromiseRejectedResult => result.status === 'rejected');
      if (failures.length) throw new Error(`${failures.length} shutdown operations failed`);
    }
  })();
}

export class HttpServerLifecycle {
  private server?: Server;
  private draining = false;
  private closing?: Promise<void>;

  readonly admission: RequestHandler = (_req, res, next) => {
    if (this.draining) {
      res.setHeader('Connection', 'close');
      res.status(503).json({ error: 'Service shutting down' });
      return;
    }
    next();
  };

  attach(server: Server): void { this.server = server; }

  close(): Promise<void> {
    this.draining = true;
    return this.closing ??= new Promise<void>((resolve, reject) => {
      if (!this.server) { resolve(); return; }
      this.server.close(error => error ? reject(error) : resolve());
    });
  }
}
