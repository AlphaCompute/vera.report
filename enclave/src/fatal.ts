/** Last-resort handlers for an enclave process. Continuing after an unexpected
 * exception can leave security state partial, and Node 22 would otherwise print
 * the exception (which can contain request or secret material) before exiting.
 * Wipe what the process holds, log a content-free line, and exit; the
 * entrypoint decides whether to restart or stop the bundle. */
export function installFatalHandlers(component: string, wipe: () => void = () => {}): void {
  let failed = false;
  const fatal = (): never => {
    if (!failed) {
      failed = true;
      try { wipe(); } catch { /* exiting regardless */ }
      process.stderr.write(`${component}: fatal runtime failure\n`);
    }
    process.exit(1);
  };
  process.on('uncaughtException', fatal);
  process.on('unhandledRejection', fatal);
}
