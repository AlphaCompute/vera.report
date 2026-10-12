// No OpenPGP import: the reporter pages keep crypto loading lazy.
type Clock = { signing: () => number; verification: () => number };
let clock: Clock = { signing: () => Date.now(), verification: () => Date.now() };

/** Browser bootstrap supplies its attested clock once. The enclave does not
 * install a clock and continues using its own time. No operation changes a
 * process-wide Date or OpenPGP config while other operations are in flight. */
export function setPgpClock(source: Clock): void { clock = source; }
export function pgpSigningDate(): Date { return new Date(clock.signing()); }
export function pgpVerificationDate(): Date { return new Date(clock.verification()); }
