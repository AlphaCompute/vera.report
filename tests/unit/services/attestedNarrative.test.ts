import processes = require('node:child_process');
import path from 'node:path';
import {
    AttestedNarrative,
    attestedNarrativeConfiguration,
    type NarrativeSettings,
} from '../../../src/services/attestedNarrative';
const tid = 'VRA-1234567890ABCDEF';
const config = (): NarrativeSettings => ({
    pythonExecutable: '/pinned/python',
    moduleRoot: process.cwd(),
    port: 15003,
    keyArn: 'arn:aws:kms:us-east-2:000000000000:key/12345678-1234-1234-1234-123456789012',
    pcrs: { '0': '1'.repeat(96), '1': '2'.repeat(96), '2': '3'.repeat(96) },
    credentials: jest.fn(async () => ({
        accessKeyId: 'test-access',
        secretAccessKey: 'SECRET-SENTINEL',
        sessionToken: 'TOKEN-SENTINEL',
        expiration: new Date(Date.now() + 60000).toISOString(),
    })),
});
const original = processes.spawn;
let spy: jest.SpyInstance;
let adapter: AttestedNarrative;
let mode: string;
let children: processes.ChildProcess[];
beforeEach(() => {
    mode = 'ok';
    children = [];
    spy = jest.spyOn(processes, 'spawn').mockImplementation((_e, _a, options) => {
        const child = original(
            process.execPath,
            [path.resolve('tests/helpers/attestedNarrativeChild.cjs'), mode],
            options,
        );
        children.push(child);
        return child;
    });
});
afterEach(async () => {
    await adapter?.close();
    spy.mockRestore();
});
test('explicit independent settings use private pipe and minimal environment, no credentials in argv', async () => {
    adapter = new AttestedNarrative(config());
    const sealed = await adapter.encrypt(tid, 'offline input');
    expect(sealed.format).toBe('recipient-narrative:v1');
    expect(await adapter.decrypt(tid, sealed)).toBe('offline narrative');
    expect(spy.mock.calls[0][1]).toEqual(['-E', '-s', '-B', '-m', 'enclave.verification.narrative']);
    expect(spy.mock.calls[0][2].env).toEqual({ PATH: '/usr/bin:/bin' });
    expect(JSON.stringify(spy.mock.calls)).not.toMatch(/SECRET-SENTINEL|TOKEN-SENTINEL/);
});
test.each(['stderr', 'malformed', 'large'])(
    'rejects %s provider-process outcome generically and does not retry',
    async (failure) => {
        mode = failure;
        adapter = new AttestedNarrative(config());
        await expect(adapter.encrypt(tid, 'offline')).rejects.toThrow(/^Narrative unavailable$/);
        expect(children).toHaveLength(1);
        expect(children[0].exitCode !== null || children[0].signalCode !== null).toBe(true);
    },
);
test('concurrent calls reject; abort drains actual process before admission reopens', async () => {
    mode = 'hang';
    adapter = new AttestedNarrative(config());
    const signal = new AbortController();
    const pending = adapter.encrypt(tid, 'offline', signal.signal).catch((e) => e);
    await expect(adapter.encrypt(tid, 'other')).rejects.toThrow('Narrative unavailable');
    while (!children.length) await new Promise<void>((r) => setImmediate(r));
    signal.abort();
    expect((await pending).message).toBe('Narrative unavailable');
    expect(children[0].signalCode).toBe('SIGKILL');
    mode = 'ok';
    expect((await adapter.encrypt(tid, 'next')).format).toBe('recipient-narrative:v1');
});
test('close during stalled credentials prevents late child and permanently closes adapter', async () => {
    const settings = config();
    let release!: (v: any) => void;
    settings.credentials = jest.fn(
        () =>
            new Promise((r) => {
                release = r;
            }),
    );
    adapter = new AttestedNarrative(settings);
    const pending = adapter.encrypt(tid, 'offline').catch((e) => e);
    await new Promise<void>((r) => setImmediate(r));
    await adapter.close();
    expect((await pending).message).toBe('Narrative unavailable');
    release(await config().credentials(new AbortController().signal));
    await new Promise<void>((r) => setImmediate(r));
    expect(spy).not.toHaveBeenCalled();
    await expect(adapter.encrypt(tid, 'offline')).rejects.toThrow('Narrative unavailable');
});
test('malformed/rebound envelope refuses credentials', async () => {
    const settings = config();
    adapter = new AttestedNarrative(settings);
    await expect(
        adapter.decrypt(tid, { format: 'recipient-narrative:v1', trackingId: 'VRA-AAAAAAAAAAAAAAAA' } as any),
    ).rejects.toThrow('Narrative unavailable');
    expect(settings.credentials).not.toHaveBeenCalled();
    expect(spy).not.toHaveBeenCalled();
});
test('default-disabled; write activation cannot bypass read configuration', () => {
    expect(attestedNarrativeConfiguration({} as any)).toEqual({ writes: false });
    for (const env of [
        { ATTESTED_NARRATIVE_WRITES_ENABLED: 'true' },
        { ATTESTED_NARRATIVE_ENABLED: 'yes' },
        { ATTESTED_NARRATIVE_ENABLED: 'true' },
    ])
        expect(() => attestedNarrativeConfiguration(env as any)).toThrow('Narrative unavailable');
    expect(spy).not.toHaveBeenCalled();
});

test('maximum-size control-character narrative fits the private process pipe', async () => {
    adapter = new AttestedNarrative(config());
    const plaintext = '\u0000'.repeat(8 * 1024 * 1024);
    const sealed = await adapter.encrypt(tid, plaintext);
    mode = 'control-output';
    expect(await adapter.decrypt(tid, sealed)).toBe(plaintext);
});

test.each(['invalid-base64', 'invalid-utf8'])('rejects %s plaintext from the private pipe', async (failure) => {
    adapter = new AttestedNarrative(config());
    const sealed = await adapter.encrypt(tid, 'offline');
    mode = failure;
    await expect(adapter.decrypt(tid, sealed)).rejects.toThrow(/^Narrative unavailable$/);
});
