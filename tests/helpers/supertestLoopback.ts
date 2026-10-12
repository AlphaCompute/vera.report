import request from 'supertest';
import type { Server } from 'http';

// Own the lifecycle of listeners we bind, without depending on Supertest's
// private cleanup bookkeeping (which differs between 7.2 and 7.3). Binding
// only at dispatch also avoids leaking a server for an unconsumed request.
export function installSupertestLoopback(): void {
  const prototype = request.Test.prototype as any;
  const installed = Symbol.for('vera.supertestLoopback');
  if (prototype[installed]) return;
  prototype[installed] = true;
  const originalAddress = prototype.serverAddress;
  const originalEnd = prototype.end;
  const requests = new WeakMap<object, { server: Server; path: string }>();
  type State = { ready: Promise<void>; pending: number; closing?: Promise<void> };
  const servers = new WeakMap<Server, State>();

  function bind(server: Server): Promise<void> {
    return new Promise((resolve, reject) => {
      const clear = () => {
        server.removeListener('error', onError);
        server.removeListener('listening', onListening);
      };
      const onError = (error: Error) => { clear(); reject(error); };
      const onListening = () => { clear(); resolve(); };
      server.once('error', onError);
      server.once('listening', onListening);
      try { server.listen(0, '127.0.0.1'); } catch (error) { onError(error as Error); }
    });
  }

  prototype.serverAddress = function (server: Server, path: string): string {
    if (server.address() && !servers.has(server)) return originalAddress.call(this, server, path);
    requests.set(this, { server, path });
    return `http://127.0.0.1${path}`;
  };

  prototype.end = function (callback: (...args: any[]) => void) {
    const target = requests.get(this);
    if (!target) return originalEnd.call(this, callback);
    requests.delete(this);
    const { server, path } = target;
    let state = servers.get(server);
    // A caller can start a listener after constructing the request. It remains
    // theirs, just like a listener already running at construction time.
    if (!state && server.address()) {
      this.url = originalAddress.call(this, server, path);
      return originalEnd.call(this, callback);
    }
    if (!state || state.closing) {
      const closing = state?.closing;
      state = { pending: 0, ready: closing ? closing.then(() => bind(server)) : bind(server) };
      servers.set(server, state);
    }
    const owned = state;
    owned.pending += 1;
    let completed = false;
    const finish = (...args: any[]) => {
      if (completed) return;
      completed = true;
      owned.pending -= 1;
      if (owned.pending !== 0) { callback(...args); return; }
      if (!server.listening) {
        if (servers.get(server) === owned) servers.delete(server);
        callback(...args);
        return;
      }
      owned.closing = new Promise<void>(resolve => server.close(() => resolve()));
      void owned.closing.then(() => {
        if (servers.get(server) === owned) servers.delete(server);
        callback(...args);
      });
    };
    void owned.ready.then(() => {
      this.url = originalAddress.call(this, server, path);
      // The original end still performs all assertions and cookie handling;
      // neither it nor its version-specific private state owns this listener.
      originalEnd.call(this, finish);
    }).catch(error => finish(error));
    return this;
  };
}
