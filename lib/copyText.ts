/** Returns success only when the browser confirms a clipboard write. */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const input = document.createElement('textarea');
    input.value = text;
    input.style.position = 'fixed';
    input.style.left = '-9999px';
    const focused = document.activeElement;
    // A modal's focus trap rejects a temporary input outside the dialog. Keep
    // the fallback inside it so Copy also works in leave-page warnings.
    const scope = focused instanceof Element ? focused.closest('[role="dialog"], [role="alertdialog"]') : null;
    (scope ?? document.body).appendChild(input);
    try {
      input.select();
      return document.execCommand('copy');
    } catch {
      return false;
    } finally {
      input.remove();
      if (focused instanceof HTMLElement) focused.focus();
    }
  }
}
