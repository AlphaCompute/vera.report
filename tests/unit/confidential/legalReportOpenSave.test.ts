import { readFileSync } from 'node:fs';
import path from 'node:path';
import { REPORT_WORKSPACE_SAVE_FAILED, saveOpenedReport } from '../../../components/vera/confidential/LegalReportView';

const component = readFileSync(path.join(__dirname, '../../../components/vera/confidential/LegalReportView.tsx'), 'utf8');
const caseView = component.slice(component.indexOf('export function CaseView('));
const load = caseView.slice(caseView.indexOf('const load = useCallback'), caseView.indexOf('}, [session, caseId]);'));

describe('saving the workspace after a legal organization opens a report', () => {
  test('a failed save becomes a warning, not an error', async () => {
    await expect(saveOpenedReport(() => Promise.reject(new Error('newer history in another tab')))).resolves.toBe(REPORT_WORKSPACE_SAVE_FAILED);
    await expect(saveOpenedReport(() => Promise.resolve())).resolves.toBeNull();
  });

  test('the warning says the report is open and does not blame the secure connection', () => {
    expect(REPORT_WORKSPACE_SAVE_FAILED).toMatch(/^The report is open, but the latest report history could not be saved on this device/);
    expect(REPORT_WORKSPACE_SAVE_FAILED).not.toMatch(/could not be opened|secure connection/);
  });

  test('the save runs after the open try/catch, so its failure cannot replace the open report', () => {
    const tryBlock = load.slice(load.indexOf('try {'), load.indexOf('} catch (caught) {'));
    expect(tryBlock).toContain('publish({ state: "ready", opened });');
    expect(tryBlock).not.toContain('persistFirmWorkspace');
    expect(tryBlock).not.toContain('recordRequestGranted');
    const after = load.slice(load.indexOf('} catch (caught) {'));
    // Every catch path returns, so only a successful open reaches the save.
    expect(after).toMatch(/Try again in a moment\."\) \}\);\s*return;\s*\}/);
    expect(after).toContain('await saveOpenedReport(persistFirmWorkspace)');
    // The warning is attached to the same open report; the view stays "ready".
    expect(after).toMatch(/current\.state === "ready" && current\.opened === opened \? \{ \.\.\.current, saveWarning \} : current/);
    expect(caseView).toContain('{view.saveWarning && <Banner tone="attention"');
  });
});
