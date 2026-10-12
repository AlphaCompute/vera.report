import { spawn } from 'node:child_process';
import path from 'node:path';
import { createAttestedEcsCredentials } from './attestedEcsCredentials';
import {
    MAX_NARRATIVE,
    validateRecipientNarrative,
    type RecipientNarrativeEnvelope,
} from './recipientNarrativeEnvelope';
const FAILURE = 'Narrative unavailable';
const MAX_PIPE = 12 * 1024 * 1024;
export interface NarrativeSettings {
    pythonExecutable: string;
    moduleRoot: string;
    port: number;
    keyArn: string;
    pcrs: { '0': string; '1': string; '2': string };
    credentials: (
        signal: AbortSignal,
    ) => Promise<{ accessKeyId: string; secretAccessKey: string; sessionToken: string; expiration: string }>;
}
/** Caller authorization stays at the existing intake/admin/worker boundary. No raw-key API exists. */
export class AttestedNarrative {
    private active?: Promise<unknown>;
    private controller?: AbortController;
    private closed = false;
    private readonly settings: NarrativeSettings;
    constructor(settings: NarrativeSettings) {
        if (
            !path.isAbsolute(settings.pythonExecutable) ||
            !path.isAbsolute(settings.moduleRoot) ||
            !Number.isInteger(settings.port) ||
            settings.port < 1 ||
            settings.port > 65535 ||
            !/^arn:aws:kms:us-east-2:000000000000:key\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(
                settings.keyArn,
            ) ||
            Object.keys(settings.pcrs).sort().join(',') !== '0,1,2' ||
            Object.values(settings.pcrs).some(
                (v) => typeof v !== 'string' || !/^[a-fA-F0-9]{96}$/.test(v) || /^0+$/.test(v),
            ) ||
            typeof settings.credentials !== 'function'
        )
            throw new Error(FAILURE);
        this.settings = { ...settings, pcrs: { ...settings.pcrs } };
    }
    encrypt(trackingId: string, plaintext: string, signal?: AbortSignal): Promise<RecipientNarrativeEnvelope> {
        if (typeof plaintext !== 'string' || !plaintext.length || Buffer.byteLength(plaintext) > MAX_NARRATIVE)
            return Promise.reject(new Error(FAILURE));
        return this.operation('encrypt', trackingId, plaintext, signal).then((v) =>
            validateRecipientNarrative(v, trackingId),
        );
    }
    decrypt(trackingId: string, value: RecipientNarrativeEnvelope, signal?: AbortSignal): Promise<string> {
        let snapshot: RecipientNarrativeEnvelope;
        try {
            snapshot = validateRecipientNarrative(value, trackingId);
        } catch {
            return Promise.reject(new Error(FAILURE));
        }
        return this.operation('decrypt', trackingId, snapshot, signal).then((v) => {
            if (typeof v !== 'string' || Buffer.byteLength(v) > MAX_NARRATIVE) throw new Error(FAILURE);
            return v;
        });
    }
    private operation(operation: string, trackingId: string, value: unknown, external?: AbortSignal): Promise<unknown> {
        if (this.closed || this.active || external?.aborted || !/^VRA-[A-F0-9]{16}$/.test(trackingId))
            return Promise.reject(new Error(FAILURE));
        const controller = new AbortController();
        this.controller = controller;
        const abort = () => controller.abort();
        external?.addEventListener('abort', abort, { once: true });
        const timer = setTimeout(abort, 30_000);
        this.active = this.perform(operation, trackingId, value, controller.signal)
            .catch(() => {
                throw new Error(FAILURE);
            })
            .finally(() => {
                clearTimeout(timer);
                external?.removeEventListener('abort', abort);
                this.controller = undefined;
                this.active = undefined;
            });
        return this.active;
    }
    private async perform(
        operation: string,
        trackingId: string,
        value: unknown,
        signal: AbortSignal,
    ): Promise<unknown> {
        const supplied = await new Promise<Awaited<ReturnType<NarrativeSettings['credentials']>>>((resolve, reject) => {
            const abort = () => reject(new Error(FAILURE));
            signal.addEventListener('abort', abort, { once: true });
            Promise.resolve()
                .then(() => {
                    signal.throwIfAborted();
                    return this.settings.credentials(signal);
                })
                .then(resolve, reject)
                .finally(() => signal.removeEventListener('abort', abort));
        });
        signal.throwIfAborted();
        const credentials = {
            accessKeyId: supplied.accessKeyId,
            secretAccessKey: supplied.secretAccessKey,
            sessionToken: supplied.sessionToken,
            expiration: supplied.expiration,
        };
        if (
            Object.values(credentials).some((v) => typeof v !== 'string' || !v.length || v.length > 8192) ||
            !Number.isFinite(Date.parse(credentials.expiration)) ||
            Date.parse(credentials.expiration) <= Date.now()
        )
            throw new Error(FAILURE);
        let pipeValue = value;
        if (operation === 'encrypt') {
            const plaintext = Buffer.from(value as string, 'utf8');
            try { pipeValue = plaintext.toString('base64'); }
            finally { plaintext.fill(0); }
        }
        const input = Buffer.from(
            JSON.stringify({
                operation,
                trackingId,
                value: pipeValue,
                port: this.settings.port,
                keyArn: this.settings.keyArn,
                pcrs: this.settings.pcrs,
                credentials,
            }),
        );
        try {
            if (input.length > MAX_PIPE) throw new Error(FAILURE);
            return await new Promise((resolve, reject) => {
                const child = spawn(
                    this.settings.pythonExecutable,
                    ['-E', '-s', '-B', '-m', 'enclave.verification.narrative'],
                    {
                        cwd: this.settings.moduleRoot,
                        env: { PATH: '/usr/bin:/bin' } as unknown as NodeJS.ProcessEnv,
                        stdio: ['pipe', 'pipe', 'pipe'],
                    },
                );
                const chunks: Buffer[] = [];
                let size = 0,
                    failed = false;
                const stop = () => {
                    failed = true;
                    child.stdin.destroy();
                    child.kill('SIGKILL');
                };
                signal.addEventListener('abort', stop, { once: true });
                child.on('error', stop);
                child.stdin.on('error', stop);
                child.stdout.on('error', stop);
                child.stderr.on('error', stop);
                child.stderr.on('data', stop);
                child.stdout.on('data', (chunk: Buffer) => {
                    size += chunk.length;
                    if (failed || size > MAX_PIPE) {
                        chunk.fill(0);
                        stop();
                    } else chunks.push(chunk);
                });
                child.once('close', (code) => {
                    signal.removeEventListener('abort', stop);
                    const output = Buffer.concat(chunks);
                    try {
                        if (failed || signal.aborted || code !== 0) throw new Error(FAILURE);
                        const result = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(output));
                        if (!result || Object.keys(result).join(',') !== 'value') throw new Error(FAILURE);
                        if (operation === 'decrypt') {
                            if (typeof result.value !== 'string' || result.value.length > 4 * Math.ceil(MAX_NARRATIVE / 3))
                                throw new Error(FAILURE);
                            const plaintext = Buffer.from(result.value, 'base64');
                            try {
                                if (plaintext.length > MAX_NARRATIVE || plaintext.toString('base64') !== result.value)
                                    throw new Error(FAILURE);
                                resolve(new TextDecoder('utf8', { fatal: true }).decode(plaintext));
                            } finally { plaintext.fill(0); }
                        } else resolve(result.value);
                    } catch {
                        reject(new Error(FAILURE));
                    } finally {
                        output.fill(0);
                        chunks.forEach((x) => x.fill(0));
                    }
                });
                child.stdin.end(input);
            });
        } finally {
            input.fill(0);
        }
    }
    async close(): Promise<void> {
        this.closed = true;
        this.controller?.abort();
        await this.active?.catch(() => {});
    }
}
let configured: AttestedNarrative | undefined;
function flag(value: string | undefined): boolean {
    if (value === undefined || value === 'false') return false;
    if (value === 'true') return true;
    throw new Error(FAILURE);
}
export function attestedNarrativeConfiguration(env: NodeJS.ProcessEnv = process.env): {
    reader?: AttestedNarrative;
    writes: boolean;
} {
    const enabled = flag(env.ATTESTED_NARRATIVE_ENABLED),
        writes = flag(env.ATTESTED_NARRATIVE_WRITES_ENABLED);
    if (writes && !enabled) throw new Error(FAILURE);
    if (!enabled) return { writes: false };
    if (!configured) {
        const port = env.ATTESTED_NARRATIVE_PORT;
        if (!port || !/^\d{1,5}$/.test(port)) throw new Error(FAILURE);
        configured = new AttestedNarrative({
            pythonExecutable: '/opt/vera-attestation/venv/bin/python',
            moduleRoot: '/opt/vera-attestation',
            port: Number(port),
            keyArn: env.ATTESTED_NARRATIVE_KEY_ARN || '',
            pcrs: {
                '0': env.ATTESTED_NARRATIVE_PCR0 || '',
                '1': env.ATTESTED_NARRATIVE_PCR1 || '',
                '2': env.ATTESTED_NARRATIVE_PCR2 || '',
            },
            credentials: createAttestedEcsCredentials(
                env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI || '',
                env.ATTESTED_NARRATIVE_TASK_ROLE_ARN || '',
            ),
        });
    }
    return { reader: configured, writes };
}
export async function closeAttestedNarrative(): Promise<void> {
    await configured?.close();
}
