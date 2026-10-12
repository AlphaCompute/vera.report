import { env } from '../config/env';
import { retryWithBackoff } from '../utils/retry';

export type ChatMessage = { role: 'system' | 'user' | 'assistant'; content: string };

const REQUEST_TIMEOUT_MS = 30_000;

class ShroudError extends Error {
    constructor(message: string, readonly retryable: boolean) {
        super(message);
        this.name = 'ShroudError';
    }
}

export function isShroudConfigured(): boolean {
    return !!env.SHROUD_API_KEY;
}

function cleanResponseText(raw: string): string {
    let content = raw.replace(/<think>[\s\S]*?<\/think>/g, '').trim();
    if (content.startsWith('```json')) {
        content = content.slice(7);
    } else if (content.startsWith('```')) {
        content = content.slice(3);
    }
    if (content.endsWith('```')) {
        content = content.slice(0, -3);
    }
    return content.trim();
}

async function runInference(messages: ChatMessage[], signal?: AbortSignal): Promise<string> {
    let res: Response;
    try {
      res = await fetch(`${env.SHROUD_BASE_URL}/v1/chat/completions`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${env.SHROUD_API_KEY}`,
        },
        body: JSON.stringify({
            model: env.SHROUD_MODEL,
            messages,
            temperature: 0.3,
            max_tokens: 500,
            stream: false,
            chat_template_kwargs: { enable_thinking: false },
        }),
        redirect: 'error',
        signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(REQUEST_TIMEOUT_MS)]) : AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    } catch {
        // Transport exceptions can contain request URLs, credentials or report bytes.
        throw new ShroudError('[SHROUD] inference transport unavailable', true);
    }

    if (!res.ok) {
        // Provider error bodies can echo the private report or authorization data.
        try { await res.body?.cancel(); } catch { /* Never expose cleanup errors. */ }
        // 5xx/429/408 are transient (enclave restart, scaling, rate limit) and
        // safe to retry; other 4xx are deterministic gateway rejections.
        const retryable = res.status >= 500 || res.status === 429 || res.status === 408;
        throw new ShroudError(`[SHROUD] inference request failed (status ${res.status})`, retryable);
    }

    let parsed: unknown;
    try {
        if (!res.body) throw new Error();
        const reader = res.body.getReader();
        const chunks: Uint8Array[] = [];
        let size = 0;
        for (;;) {
            const {done, value} = await reader.read();
            if (done) break;
            size += value.length;
            if (size > 256_000) { await reader.cancel(); throw new Error(); }
            chunks.push(value);
        }
        parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch (error) {
        const transient = error instanceof Error && ['AbortError', 'TimeoutError', 'TypeError'].includes(error.name);
        throw new ShroudError('[SHROUD] invalid inference response', transient);
    }
    const body = parsed as {
        choices?: { message?: { content?: string } }[];
    };
    const content = body?.choices?.[0]?.message?.content;
    if (typeof content !== 'string' || !content.trim() || content.length > 100_000) throw new ShroudError('[SHROUD] invalid inference response', false);
    const cleaned = cleanResponseText(content);
    if (!cleaned) throw new ShroudError('[SHROUD] invalid inference response', false);
    return cleaned;
}

export async function shroudChat(messages: ChatMessage[], signal?: AbortSignal): Promise<string> {
    if (!isShroudConfigured()) {
        throw new Error('[SHROUD] SHROUD_API_KEY not configured — inference disabled');
    }

    return retryWithBackoff(() => runInference(messages, signal), {
        signal,
        maxRetries: 3,
        baseDelayMs: 2000,
        // Retry transient failures (network errors, timeouts, 5xx/429/408).
        // Deterministic gateway rejections (4xx) carry retryable=false and fail fast.
        shouldRetry: (error) => !(error instanceof ShroudError) || error.retryable,
    });
}
