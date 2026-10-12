import { Readable } from 'node:stream';
import { proxyClientQuotaKey, proxyRateLimitHeaders } from '../../../src/utils/proxyRateLimit';
import { tryAdmitSubmitProxy } from '../../../src/utils/proxySubmitQuota';
import {
    EVIDENCE_TRANSFER_TIMEOUT_MS,
    MAX_CLIENT_UPLOADS,
    MAX_PROCESS_UPLOADS,
    MAX_REPORT_EVIDENCE_BYTES,
    UPLOAD_IDLE_MS,
    UPLOAD_MIN_BYTES_PER_SEC,
    UPLOAD_PROGRESS_GRACE_MS,
    uploadBehindReceivePace,
    uploadReceiveDeadlineMs,
} from '../../../src/utils/evidenceLimits';
import type { NextApiRequest, NextApiResponse } from 'next';

export const config = {
    api: {
        bodyParser: false, // Forward raw body (FormData with files)
    },
};

/**
 * POST /api/whistleblower/submit
 * Proxy to Express backend for report submission
 */
let activeUploads = 0;
const byClient = new Map<string, number>();

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    // Only an explicit frontend opt-out permits legacy plaintext intake.
    if (process.env.CONFIDENTIAL_CASES_ENABLED === 'true' || process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES !== '0') {
        res.setHeader('Cache-Control', 'no-store');
        return res.status(409).json({ success: false, error: 'confidential_intake_required',
            message: 'Secure intake is required. Reload the application before submitting.' });
    }

    // Stream multipart with backpressure; Express enforces each file and aggregate.
    const maxBytes = MAX_REPORT_EVIDENCE_BYTES + 32 * 1024 * 1024 + 64 * 1024;
    const contentLength = Number(req.headers['content-length']);
    if (!Number.isFinite(contentLength) || contentLength < 0) {
        return res.status(411).json({ error: 'Content-Length required' });
    }
    if (contentLength > maxBytes) return res.status(413).json({ error: 'Upload too large' });

    const clientKey = proxyClientQuotaKey(req);
    if (activeUploads >= MAX_PROCESS_UPLOADS || (byClient.get(clientKey) || 0) >= MAX_CLIENT_UPLOADS) {
        res.setHeader('Retry-After', '30');
        return res.status(503).json({ error: 'upload_capacity_busy', message: 'Evidence transfer capacity is busy; retry shortly.' });
    }

    // Quota before taking a slot so exhausted clients cannot occupy capacity.
    if (!tryAdmitSubmitProxy(req)) {
        res.setHeader('Retry-After', '60');
        return res.status(429).json({
            success: false,
            error: 'Too many submissions. Please try again later.',
        });
    }

    activeUploads++;
    byClient.set(clientKey, (byClient.get(clientKey) || 0) + 1);
    const controller = new AbortController();
    const timer = setTimeout(() => { controller.abort(); req.destroy(); }, EVIDENCE_TRANSFER_TIMEOUT_MS);
    let bytesReceived = 0, lastProgress = Date.now();
    const startedAt = Date.now();
    const receiveDeadlineMs = uploadReceiveDeadlineMs(contentLength);
    const progressTimer = setInterval(() => {
        if (req.complete) return;
        const elapsed = Date.now() - startedAt;
        if (
            Date.now() - lastProgress >= UPLOAD_IDLE_MS
            || elapsed >= receiveDeadlineMs
            || (elapsed >= UPLOAD_PROGRESS_GRACE_MS && bytesReceived < (elapsed / 1000) * UPLOAD_MIN_BYTES_PER_SEC)
            || uploadBehindReceivePace(bytesReceived, contentLength, elapsed, receiveDeadlineMs)
        ) {
            controller.abort();
            req.destroy();
        }
    }, 1000);
    progressTimer.unref();
    const cancel = () => controller.abort();
    req.once('aborted', cancel);
    res.once('close', cancel);
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');
    try {
        const backendUrl = process.env.BACKEND_URL || 'http://localhost:3001';

        async function* body() {
            let size = 0;
            for await (const chunk of req) {
                size += Buffer.byteLength(chunk);
                bytesReceived = size; lastProgress = Date.now();
                if (size > maxBytes) throw new Error('Upload too large');
                yield chunk;
            }
        }

        // Forward to Express backend with original headers
        const response = await fetch(`${backendUrl}/api/whistleblower/submit`, {
            method: 'POST',
            headers: {
                ...proxyRateLimitHeaders(req, 'POST', '/api/whistleblower/submit'),
                'content-type': req.headers['content-type'] || 'application/octet-stream',
                ...(typeof req.headers['x-idempotency-key'] === 'string'
                    ? { 'x-idempotency-key': req.headers['x-idempotency-key'] } : {}),
            },
            body: Readable.toWeb(Readable.from(body())) as ReadableStream,
            duplex: 'half',
            signal: controller.signal,
            redirect: 'error',
        } as RequestInit & { duplex: 'half' });

        const data = await response.json();
        return res.status(response.status).json(data);
    } catch (error: any) {
        console.error('[Submit Proxy] Backend submission failed');
        if (!res.headersSent && !res.destroyed) return res.status(502).json({
            success: false,
            error: 'Failed to submit report to backend',
        });
    } finally {
        activeUploads--;
        const remaining = (byClient.get(clientKey) || 1) - 1;
        if (remaining <= 0) byClient.delete(clientKey);
        else byClient.set(clientKey, remaining);
        clearTimeout(timer); clearInterval(progressTimer); req.removeListener('aborted', cancel); res.removeListener('close', cancel);
    }
}
