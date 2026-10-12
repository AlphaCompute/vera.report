/** Keep retry credentials only in this page's memory. A changed draft starts a
 * new attempt; an identical retry can recover its accepted receipt after a lost
 * response. File identity is stable across FormData construction in the wizard.
 */
export function createSubmissionAttemptKey(
  randomKey = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join(''),
): (body: FormData) => string {
  let previous: Array<[string, FormDataEntryValue]> | undefined;
  let key: string;
  return body => {
    const entries = Array.from(body.entries());
    if (!previous || previous.length !== entries.length ||
        entries.some(([name, value], i) => previous![i][0] !== name || previous![i][1] !== value)) {
      key = randomKey();
      previous = entries;
    }
    return key;
  };
}
