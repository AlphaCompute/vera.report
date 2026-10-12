/** Keep automatic paging bounded on the participant device. Nothing is rendered
 * until the complete verified read finishes; oversize collections fail explicitly. */
export function confidentialPageBudget() {
  let total = 0, pages = 0;
  return (value: unknown): void => {
    const bytes = new TextEncoder().encode(JSON.stringify(value)).length;
    total += bytes; pages++;
    if (bytes > 240 * 1024 || total > 100 * 1024 * 1024 || pages > 10_000) {
      throw new Error('Confidential collection exceeds local read capacity');
    }
  };
}
