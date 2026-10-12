import { reportContactError } from '../utils/reportContact';
import { confidentialIntakeOnly } from '../middleware/confidentialIntakeOnly';
import { EvidenceValidationError } from '../utils/evidenceValidationError';
import { evidenceCommitment, CURRENT_EVIDENCE_HASH_VERSION, type EvidenceHashVersion } from '../utils/evidenceCommitment';
import { createIntakeConsent } from '../utils/intakeConsent';
import { createReporterAccess, receiptCode, REPORTER_CODE_PATTERN, LEGACY_REPORTER_CODE_PATTERN } from '../services/reporterAccess';
import { evidenceUpload as upload } from '../middleware/evidenceUpload';
import { EVIDENCE_TRANSFER_TIMEOUT_MS } from '../utils/evidenceLimits';
import { reserveIntake, reserveUpload, withUploadBudget } from '../middleware/uploadBudget';
import { extractMetadataIsolated } from '../services/metadataWorker';
import { parseMetadataSelection } from '../utils/metadataSelection';
import { incidentTimeframeError } from '../utils/reportIntakeRules';
import { notifySubmission } from '../services/submissionNotificationWorker';
import { submissionNotificationsEnabled } from '../services/submissionWebhook';
import { evidenceResponseHeaders } from '../utils/evidenceResponse';
import { logger } from '../utils/logger';
import { isConfidentialIdentifier, isConfidentialOwnerCode } from '../utils/confidentialIdentifiers';
/**
 * Whistleblower API Router
 * Implements CE-55: Secure Submission Backend
 *
 * Endpoints:
 * - POST /api/whistleblower/submit - Submit anonymous report
 * - GET /api/whistleblower/status/:trackingId - Check report status
 */

import { Router, Request, Response, NextFunction } from 'express';
import multer from 'multer';
import crypto from 'node:crypto';
import { decryptReportNarrative, encryptReportNarrative } from '../services/reportNarrative';
import { encryptRewardContact, decryptRewardContact } from '../services/rewardContact';
import { parseSubmitterElection } from '../utils/submitterDisclosure';
import { encryptSubmitterDisclosure } from '../services/submitterDisclosure';
import rateLimit from 'express-rate-limit';
import { requestRateLimitKey } from '../utils/proxyRateLimit';
import { sharedRateLimitStore } from '../utils/mongoRateLimitStore';
import { evidenceEncryptionService } from '../services/evidenceEncryption';
import { EvidenceStorageError } from '../services/evidenceStorageError';
import { readEvidenceCiphertext, decryptEvidenceOrLog } from '../services/evidenceRead';
import { decryptStoredCiphertext } from '../services/evidenceStorageCipher';
import { persistSubmissionEvidence } from '../services/submissionEvidence';
import { submissionAttemptStore, submissionPayloadHash, submissionKeyHash, IntakeLeaseLostError } from '../services/submissionAttempt';
import { veniceAIService } from '../services/veniceAI';
import { verifyReport } from '../services/reportScoring';
import { reportScoringWorker } from '../services/reportScoringWorker';
import { isShroudConfigured } from '../services/shroudClient';
import { ExtractedMetadata } from '../services/metadataExtractor';
import { reportPersistenceService, type ReportRecord, type EvidenceDecryptionParams } from '../services/reportPersistence';
import { requestTimeout } from '../middleware/security';
import { requireInternalSecret } from '../middleware/internalSecret';
import { buildActivity, mapReports, computeStats, mapStatus } from '../services/dashboardReportsMapper';
import { decryptContactValue } from '../services/reportFieldCrypto';
import { getCachedEnclaveAttestation } from '../services/enclaveAttestation';

const router = Router();

// Legacy isolation: confidential-format identifiers (VERA-OWNER-1 recovery codes,
// 64-hex confidential case IDs) are rejected before any legacy lookup, decrypt or
// log. Confidential cases live only in separate confidential_* collections that no
// route in this router reads. The response is the same generic format error a
// malformed legacy code receives, and the value is never logged or echoed.
function rejectConfidentialIdentifier(res: Response): void {
  res.setHeader('Cache-Control', 'private, no-store');
  res.status(400).json({ success: false, error: 'Invalid tracking ID format' });
}
router.param('trackingId', (req, res, next, value) => {
  if (isConfidentialIdentifier(value)) { rejectConfidentialIdentifier(res); return; }
  next();
});
router.use((req, res, next) => {
  if (isConfidentialOwnerCode(req.get('X-Reporter-Credential'))) { rejectConfidentialIdentifier(res); return; }
  next();
});

// The tracking ID is a reporter credential. Protect both content and errors,
// including limiter responses, from caching and referrer propagation.
router.use('/status/:trackingId', (_req, res, next) => {
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// Rate limiting for submission endpoint (strict: 5 submissions per 15 minutes per IP)
const submitLimiter = rateLimit({
  keyGenerator: requestRateLimitKey,
  store: sharedRateLimitStore('whistleblower.submit'),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: {
    success: false,
    error: 'Too many submissions. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting for status checks (looser: 60 requests per minute per IP)
const statusLimiter = rateLimit({
  keyGenerator: requestRateLimitKey,
  store: sharedRateLimitStore('whistleblower.status'),
  windowMs: 60 * 1000, // 1 minute
  max: 60,
  message: {
    success: false,
    error: 'Too many requests. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// File analysis takes the same scarce transfer slots as submissions and has no UI
// caller, so it gets its own strict budget instead of the looser status limit.
const analyzeLimiter = rateLimit({
  keyGenerator: requestRateLimitKey,
  store: sharedRateLimitStore('whistleblower.analyze'),
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: {
    success: false,
    error: 'Too many requests. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Public enclave attestation — served from a short server-side cache; keep tighter than status.
const attestationLimiter = rateLimit({
  keyGenerator: requestRateLimitKey,
  store: sharedRateLimitStore('whistleblower.attestation'),
  windowMs: 60 * 1000,
  max: 20,
  message: {
    success: false,
    error: 'Too many attestation requests. Please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Reports are persisted to MongoDB via reportPersistenceService.
// MongoDB is required: storage outages must never produce a success receipt.

/**
 * Generate a unique tracking ID
 */
function generateTrackingId(): string {
  return `VRA-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
}

/**
 * `proofStatus` is always present so a client can tell "no proof yet" from "no
 * proof ever" without inspecting `zkProof` for null. Blockchain proofs are no
 * longer issued: new reports, and reports still queued for a proof when proving
 * stopped, report 'not_applicable'. Historical reports keep the proof they were
 * given; reports proved inline, and every report accepted before
 * proofGeneration existed, report 'attached'.
 */
function proofStatus(report: ReportRecord): 'attached' | 'failed' | 'not_applicable' {
  if (report.zkProof) return 'attached';
  const state = report.proofGeneration?.state;
  if (state === 'failed') return state;
  if (!state) return 'attached';
  return 'not_applicable';
}

async function submissionReceipt(report: ReportRecord) {
  return {
    success: true, trackingId: await receiptCode(report), evidenceHash: report.evidenceHash,
    evidenceHashVersion: report.evidenceHashVersion ?? 'sha256-concat-v1',
    zkProof: report.zkProof ?? null,
    proofStatus: proofStatus(report),
    message: 'Report submitted successfully.', status: mapStatus(report.status),
  };
}

/**
 * Reject a malformed retry key before multer buffers multipart evidence. The
 * handler validates it again; this only keeps a bad request from spending
 * memory on uploads first.
 */
function rejectMalformedRetryKey(req: Request, res: Response, next: NextFunction): void {
  const retryKey = req.get('X-Idempotency-Key');
  if (retryKey !== undefined && !/^[a-f0-9]{64}$/i.test(retryKey)) {
    res.status(400).json({
      success: false,
      error: 'invalid_idempotency_key',
      message: 'Invalid submission retry key.',
    });
    return;
  }
  next();
}

router.post('/analyze', confidentialIntakeOnly, analyzeLimiter, reserveIntake, requestTimeout(EVIDENCE_TRANSFER_TIMEOUT_MS), upload.array('files', 5), withUploadBudget(async (req: Request, res: Response) => {
  logger.info('🔍 [WHISTLEBLOWER] Analyzing files for metadata');

  const controller = new AbortController();
  const cancel = () => controller.abort();
  req.once('aborted', cancel);
  res.once('close', cancel);
  try {
    const files = req.files as Express.Multer.File[];

    if (!files || files.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'No files provided for analysis'
      });
    }

    const results: ExtractedMetadata[] = [];

    for (const file of files) {
      logger.debug('[METADATA] Analyzing uploaded file');

      const metadata = await extractMetadataIsolated(
        file.buffer,
        file.originalname,
        file.mimetype, controller.signal
      );

      results.push(metadata);

      logger.info(`✅ [METADATA] Found ${metadata.items.length} metadata items, risk: ${metadata.summary.riskLevel}`);
    }

    res.json({
      success: true,
      files: results,
      totalItems: results.reduce((sum, r) => sum + r.items.length, 0),
      highRiskCount: results.reduce((sum, r) => sum + r.items.filter(i => i.risk === 'high').length, 0)
    });

  } catch (error: any) {
    req.logError?.('Whistleblower analysis error', 'error', { stack: error.stack });
    if (!res.headersSent && !res.destroyed) res.status(500).json({
      success: false,
      error: 'Failed to analyze files'
    });
  } finally { req.removeListener('aborted', cancel); res.removeListener('close', cancel); }
}));

router.post('/submit', confidentialIntakeOnly, submitLimiter, reserveIntake, requestTimeout(EVIDENCE_TRANSFER_TIMEOUT_MS), rejectMalformedRetryKey, upload.array('files', 5), withUploadBudget(async (req: Request, res: Response) => {
  logger.info('📥 [WHISTLEBLOWER] New submission received');
  const narrativeAbort = new AbortController();
  const cancelNarrative = () => narrativeAbort.abort();
  req.once('aborted', cancelNarrative);
  res.once('close', cancelNarrative);
  const retryKey = req.get('X-Idempotency-Key');
  let ownedKeyHash: string | undefined;
  let ownedLeaseId: string | undefined;
  // Hoisted so the outer catch knows the submission reached the point where
  // a failed intake is definitively safe to retry.
  let proofPending: ReportRecord['proofGeneration'];
  let anonymousUserId = crypto.randomBytes(32).toString('hex');

  try {
    const body = req.body ?? {};
    const {
      description, evidenceType, urgency, location, dateOfIncident,
      stripSelection: stripSelectionRaw, wantsReward, contactMethod, contactValue,
      categories: categoriesRaw, consentPsst, psstTreatment, consentLegalReview, consentAgency, consentPress,
      jurisdiction, disseminationRecipients: disseminationRecipientsRaw,
    } = body;
    const files = req.files as Express.Multer.File[];
    let submitterElection;
    try {
      submitterElection = parseSubmitterElection(body);
    } catch (error) {
      return res.status(400).json({ success: false, error: (error as Error).message });
    }

    // Retained for legacy clients; accepted image formats are always sanitized.
    let stripSelection: Record<string, boolean>;
    try {
      stripSelection = parseMetadataSelection(stripSelectionRaw);
    } catch {
      req.logError?.('Invalid metadata selection format', 'error');
      return res.status(400).json({
        success: false,
        error: 'stripSelection must be a JSON object of boolean values.'
      });
    }

    if (description !== undefined && typeof description !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Description must be a string'
      });
    }

    // MVP intake requires a narrative, matching the website flow (#703).
    if (!description || !description.trim()) {
      return res.status(400).json({
        success: false,
        error: 'Please provide a description, even when attaching evidence files.'
      });
    }

    if (description.length > 50000) {
      return res.status(400).json({
        success: false,
        error: 'Description exceeds maximum length (50,000 characters)'
      });
    }

    // Multipart bracket/repeated fields can be objects or arrays. Validate the
    // legacy category even when the separate categories field is supplied.
    if (evidenceType !== undefined && (typeof evidenceType !== 'string' || evidenceType.length > 100)) {
      return res.status(400).json({
        success: false,
        error: 'Evidence type must be a string of at most 100 characters'
      });
    }
    if (categoriesRaw !== undefined && typeof categoriesRaw !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Invalid categories format. Must be a JSON array of category slugs.'
      });
    }

    // Validate urgency
    const VALID_URGENCIES = ['low', 'medium', 'high', 'critical'];
    if (urgency && !VALID_URGENCIES.includes(urgency)) {
      return res.status(400).json({
        success: false,
        error: `Invalid urgency. Must be one of: ${VALID_URGENCIES.join(', ')}`
      });
    }

    // Validate location
    if (location && (typeof location !== 'string' || location.length > 500)) {
      return res.status(400).json({
        success: false,
        error: 'Location must be a string under 500 characters'
      });
    }

    // Validate dateOfIncident
    if (dateOfIncident && (typeof dateOfIncident !== 'string' || dateOfIncident.length > 100)) {
      return res.status(400).json({
        success: false,
        error: 'Date of incident must be a string under 100 characters'
      });
    }

    // A report describes something that already happened. The wizard's date
    // picker accepted 2099-12-31 and stored it verbatim, which reaches a
    // reviewer as a fact about the case rather than as a typo (#853).
    const timeframeError = dateOfIncident ? incidentTimeframeError(dateOfIncident) : null;
    if (timeframeError) {
      return res.status(400).json({
        success: false,
        error: timeframeError
      });
    }

    // Validate supplied contacts independently of reward eligibility. Older API
    // clients may omit them; the web form requires a contact before submitting.
    if (wantsReward === 'true' || contactMethod !== undefined || contactValue !== undefined) {
      const contactProblem = reportContactError(contactMethod, contactValue);
      if (contactProblem) return res.status(400).json({ success: false, error: contactProblem });
    }

    // Parse dissemination taxonomy categories (JSON array of taxonomy slugs)
    const { isCategorySlug, normalizeCategory, PSST_TREATMENTS } =
      await import('../services/dissemination/taxonomy');
    let categories: string[] = [];
    if (categoriesRaw) {
      try {
        const parsed = JSON.parse(categoriesRaw);
        if (!Array.isArray(parsed) || !parsed.every((c: unknown) => typeof c === 'string')) {
          throw new Error('not a string array');
        }
        categories = parsed
          .map((c: string) => (isCategorySlug(c) ? c : normalizeCategory(c)))
          .filter((c): c is NonNullable<typeof c> => c !== null);
      } catch {
        return res.status(400).json({
          success: false,
          error: 'Invalid categories format. Must be a JSON array of category slugs.'
        });
      }
    } else if (evidenceType) {
      const mapped = normalizeCategory(evidenceType);
      if (mapped) categories = [mapped];
    }

    // Legal review is permitted by default; recipient selection never authorizes automatic sending.
    const disseminationRecipients: string[] = [];

    // Restrict explicit new intake selections to the US-only MVP. Preserve
    // omitted jurisdiction for older API clients; never relabel it as US.
    if (jurisdiction && jurisdiction !== 'us') {
      return res.status(400).json({
        success: false,
        error: 'Vera currently accepts reports under United States jurisdiction only.'
      });
    }

    // Preserve per-channel restrictions and explicit opt-outs in the versioned snapshot.
    const VALID_TREATMENTS = PSST_TREATMENTS.map((t) => t.value as string);
    if (psstTreatment && !VALID_TREATMENTS.includes(psstTreatment)) {
      return res.status(400).json({
        success: false,
        error: `Invalid Psst treatment. Must be one of: ${VALID_TREATMENTS.join(', ')}`
      });
    }
    let consent: NonNullable<ReportRecord['consent']>;
    try {
      // Clients before #926 sent the legal-review election as `consentAgency`;
      // intake never grants agency dispatch, and an omitted election is no consent.
      consent = createIntakeConsent(consentLegalReview !== undefined ? consentLegalReview : consentAgency);
    } catch (error) {
      return res.status(400).json({ success: false, error: (error as Error).message });
    }

    let evidenceHashVersion: EvidenceHashVersion = CURRENT_EVIDENCE_HASH_VERSION;
    let evidenceHash = evidenceCommitment(description || '', files || [], evidenceHashVersion);

    let trackingId = generateTrackingId();
    if (retryKey !== undefined) {
      if (!/^[a-f0-9]{64}$/i.test(retryKey)) {
        return res.status(400).json({ success: false, error: 'invalid_idempotency_key', message: 'Invalid submission retry key.' });
      }
      const keyHash = submissionKeyHash(retryKey.toLowerCase());
      const payloadHash = submissionPayloadHash(req.body, files || []);
      let attempt = await submissionAttemptStore.get(keyHash);
      let owner = false;
      if (!attempt) {
        ({ attempt, owner } = await submissionAttemptStore.reserve(keyHash, payloadHash, trackingId, evidenceHash, evidenceHashVersion));
      }
      if (attempt.payloadHash !== payloadHash) {
        return res.status(409).json({ success: false, error: 'idempotency_payload_mismatch', message: 'This retry belongs to different report content. Restore the original content to recover its receipt.' });
      }
      trackingId = attempt.trackingId;
      // Retries must retain the original proof commitment across upgrades.
      if (attempt.evidenceHash) {
        evidenceHashVersion = attempt.evidenceHashVersion ?? 'sha256-concat-v1';
        const expected = evidenceCommitment(description || '', files || [], evidenceHashVersion);
        if (expected !== attempt.evidenceHash) throw new Error('Submission evidence binding changed');
        evidenceHash = attempt.evidenceHash;
      }
      if (!owner) {
        const accepted = await reportPersistenceService.get(trackingId);
        if (accepted) {
          await submissionAttemptStore.completeIntake(keyHash);
          return res.json(await submissionReceipt(accepted));
        }
        // A crash after atomic acceptance must replay the selected encrypted
        // plan, not re-encrypt files or mint a different reporter credential.
        if (attempt.state === 'accepted' && attempt.preparedIntake) {
          const recovered = await reportPersistenceService.materializeIntake(attempt.preparedIntake);
          await submissionAttemptStore.completeIntake(keyHash);
          return res.json(await submissionReceipt(recovered));
        }
        // Attempts left 'unknown' by the former on-chain proof path are never
        // resumed here: their outcome cannot be resolved, so they stay in progress.
        const resumed = await submissionAttemptStore.claimRetry(keyHash, payloadHash);
        if (resumed) { attempt = resumed; owner = true; }
        else return res.status(503).set('Retry-After', '10').json({
          success: false, error: 'submission_in_progress',
          message: 'Your earlier submission is still processing or its outcome is not yet known. Keep this page open and retry to check for its receipt. We have not started another submission.',
        });
      }
      ownedKeyHash = keyHash;
      ownedLeaseId = attempt.leaseId;
      anonymousUserId = attempt.userId || anonymousUserId;
    }
    logger.debug('[WHISTLEBLOWER] Report identifier created');

    // Blockchain proofs are no longer issued. Record that on the report so its
    // receipt says so. Nothing was broadcast, so an intake failure below stays
    // safe to retry.
    proofPending = { state: 'not_applicable', attempts: 0, nextAttemptAt: new Date(), userId: anonymousUserId };

    const rewardData: ReportRecord['reward'] = { wantsReward: wantsReward === 'true' };
    if (contactMethod && contactValue) {
      rewardData.contactMethod = contactMethod || undefined;
      if (contactValue) {
        const contact = await encryptRewardContact(contactValue, trackingId);
        rewardData.encryptedContactValue = contact.ciphertext;
        rewardData.contactKeyWrapped = contact.wrappedKey;
      }
    }

    // Persist report record to MongoDB.
    const report: ReportRecord = {
      reporterAccess: await createReporterAccess(trackingId),
      trackingId,
      evidenceHash,
      evidenceHashVersion,
      status: 'pending',
      submitter: await encryptSubmitterDisclosure(submitterElection, trackingId),
      processingStatus: 'processing',
      scoringJob: { state: 'pending', attempts: 0, nextAttemptAt: new Date() },
      submissionNotification: submissionNotificationsEnabled() ? { state: 'pending', source: 'web', attempts: 0, nextAttemptAt: new Date() } : undefined,
      adminNotification: { state: 'pending', attempts: 0, nextAttemptAt: new Date() },
      category: evidenceType || undefined,
      categories: categories.length > 0 ? categories : undefined,
      urgency: urgency || undefined,
      location: location || undefined,
      dateOfIncident: dateOfIncident || undefined,
      jurisdiction: jurisdiction || undefined,
      consent,
      proofGeneration: proofPending,
      reward: rewardData,
      disseminationRecipients: disseminationRecipients.length > 0 ? disseminationRecipients : undefined,
      // Narrative encrypted at rest under the KMS envelope: a per-record data key,
      // wrapped by keyEnvelope (KMS when KMS_AT_REST_KEY_ID is set). Revealed
      // on-demand via the admin-gated /narrative endpoint. Readers still accept the
      // legacy encryptedDescription for pre-envelope records (decryptReportNarrative).
      encryptedNarrative: description ? await encryptReportNarrative(trackingId, description, narrativeAbort.signal) : undefined,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    // Complete every evidence upload and manifest/key write before publishing
    // the report. A partial intake must never look like an accepted report.
    const stagedEvidence: Array<EvidenceDecryptionParams & { fileKey: string }> = [];
    const processedFiles = await persistSubmissionEvidence(trackingId, files || [], stripSelection,
      ownedKeyHash ? async (fileKey, params) => { stagedEvidence.push({ fileKey, ...params }); } : undefined);
    report.ipfsHash = processedFiles[0]?.ipfsHash;
    let acceptedReport = report;
    if (ownedKeyHash) {
      if (!ownedLeaseId) throw new IntakeLeaseLostError();
      const prepared = await reportPersistenceService.prepareIntake(report, stagedEvidence);
      // A late owner cannot overwrite manifests, report fields or credentials.
      await submissionAttemptStore.acceptIntake(ownedKeyHash, ownedLeaseId, prepared);
      acceptedReport = await reportPersistenceService.materializeIntake(prepared);
      await submissionAttemptStore.completeIntake(ownedKeyHash);
    } else await reportPersistenceService.upsert(report);

    // The durable intent survives a crash before this in-process hint runs.
    void reportScoringWorker.tick(trackingId).catch(() => logger.error('[SCORING_QUEUE] Hint failed; durable work retained'));

    // Return immediately with tracking ID and proof state
    if (!res.headersSent) res.json(await submissionReceipt(acceptedReport));
    await notifySubmission(trackingId, report.createdAt, 'web');

  } catch (error: any) {
    // A submission that fails before acceptance broadcast nothing, so its
    // reservation is definitively safe to retry. Without this the attempt
    // stays 'active' and every retry gets submission_in_progress forever.
    let restartAllowed = !ownedKeyHash && !!proofPending;
    if (ownedKeyHash) {
      const state = proofPending ? 'retryable' as const : undefined;
      if (state) {
        try {
          await submissionAttemptStore.release(ownedKeyHash, state, ownedLeaseId);
          restartAllowed = state === 'retryable';
        } catch { /* Keep the original key when ownership or persistence is uncertain. */ }
      }
    }
    if (error instanceof IntakeLeaseLostError && !res.headersSent) {
      return res.status(503).set('Retry-After', '10').json({
        success: false, error: 'submission_in_progress',
        message: 'Submission recovery is in progress. Retry the same content and key to recover its receipt.',
      });
    }
    if (error instanceof EvidenceValidationError && !res.headersSent) {
      if (ownedKeyHash && !restartAllowed) {
        return res.status(503).set('Retry-After', '10').json({
          success: false, error: 'submission_in_progress',
          message: 'Submission ownership could not be confirmed. Retry the original content and key to recover its receipt.',
        });
      }
      return res.status(422).json({
        success: false, error: 'invalid_evidence_file', message: error.message,
        // Validation precedes acceptance. Only a definitively unsubmitted
        // attempt may be replaced; a recovered proof must keep its identity.
        restartAllowed,
      });
    }
    if (error instanceof EvidenceStorageError && !res.headersSent) {
      return res.status(503).json({
        success: false,
        error: error.code,
        message: 'We could not save your attached files. Keep this page open and retry the same submission.',
      });
    }
    req.logError?.('Whistleblower submit error', 'error', { stack: error.stack });
    if (res.headersSent) return;
    res.status(500).json({
      success: false,
      error: 'Failed to submit report. Please try again.',
      message: retryKey
        ? 'We could not confirm your submission. Keep this page open and retry to check for its receipt; we will not start another submission while its outcome is unknown.'
        : 'Failed to submit report. Please try again.'
    });
  } finally {
    req.removeListener('aborted', cancelNarrative);
    res.removeListener('close', cancelNarrative);
  }
}));

router.get('/status/:trackingId', statusLimiter, async (req: Request, res: Response) => {
  try {
    const header = req.get('X-Reporter-Credential');
    const code = (header || req.params.trackingId as string).toUpperCase();
    if (!header && REPORTER_CODE_PATTERN.test(code)) return res.status(400).json({ success: false, error: 'Use the reporter credential header' });
    let trackingId = code;

    if (!trackingId || typeof trackingId !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Tracking ID is required and must be a string'
      });
    }

    // Validate tracking ID format (VRA-XXXXXXXXXXXXXXXX)
    if (!(REPORTER_CODE_PATTERN.test(code) || LEGACY_REPORTER_CODE_PATTERN.test(code))) {
      return res.status(400).json({
        success: false,
        error: 'Invalid tracking ID format'
      });
    }

    // MongoDB is the source of record for all report state — status, narrative,
    // and verification. ElizaOS is fully decommissioned (backfill complete).
    const report = await reportPersistenceService.getForReporter(code);

    if (report) {
      trackingId = report.trackingId;
      const status = mapStatus(report.status || 'pending');

      // FR-11: expose per-channel submission state to the reporter — entity +
      // state + receipt presence only, no admin identities or notes. (Two-way
      // relay follow-up arrives with the relay slice.)
      let dissemination: { entityId: string; entityName: string; state: string; receipted: boolean }[] = [];
      // Phase 3c: the relay thread turns the status page into a two-way
      // follow-up surface (agency/counsel questions ↔ anonymous replies).
      let relay: { direction: string; entityName?: string; body: string; at: Date }[] = [];
      try {
        const { disseminationService } = await import('../services/dissemination/disseminationService');
        const channels = await disseminationService.status(trackingId);
        dissemination = channels
          .filter((c) => !['suppressed', 'withdrawn'].includes(c.state))
          .map((c) => ({
            entityId: c.entityId,
            entityName: c.entityName,
            state: c.state,
            receipted: c.receipts.length > 0,
          }));

        const { relayService } = await import('../services/dissemination/relayService');
        const thread = await relayService.getThread(trackingId);
        relay = thread.map((m) => ({
          direction: m.direction,
          entityName: m.entityName,
          body: m.body,
          at: m.createdAt,
        }));
      } catch {
        // Dissemination status is additive — never fail the status check over it.
      }

      return res.json({
        success: true,
        trackingId: code,
        status,
        evidenceHash: report.evidenceHash || null,
        evidenceHashVersion: report.evidenceHashVersion ?? 'sha256-concat-v1',
        ipfsHash: report.ipfsHash,
        category: report.category || null,
        urgency: report.urgency || null,
        location: report.location || null,
        dateOfIncident: report.dateOfIncident || null,
        verification: report.verification ? {
          credibilityScore: report.verification.credibilityScore,
          category: report.verification.category
        } : null,
        zkProof: report?.zkProof ? {
          proofHash: report.zkProof.proofHash,
          // nullifier + publicSignals are deliberately NOT exposed here: the
          // nullifier is identity-adjacent (it correlates repeat submissions
          // from the same reporter), and this endpoint is reachable by anyone
          // holding the tracking ID (VERA-PDR-001 §10 identity firewall).
          verified: report.zkProof.verified,
          proofType: report.zkProof.proofType,
          txHash: report.zkProof.txHash,
          contractAddress: report.zkProof.contractAddress,
          network: report.zkProof.network,
        } : null,
        // Lets the UI distinguish "still proving" from "never got a proof"
        // while polling (#277). Attempt counts and error text stay internal:
        // this endpoint is reachable by anyone holding the tracking ID.
        proofStatus: proofStatus(report),
        dissemination,
        relay,
        createdAt: report.createdAt,
        updatedAt: report?.updatedAt,
      });
    }

    return res.status(404).json({
      success: false,
      error: 'Report not found'
    });

  } catch (error: any) {
    req.logError?.('Whistleblower status check error', 'error', { stack: error.stack });
    res.status(500).json({
      success: false,
      error: 'Failed to get report status. Please try again.'
    });
  }
});

router.post('/status/:trackingId/relay', statusLimiter, async (req: Request, res: Response) => {
  try {
    const header = req.get('X-Reporter-Credential');
    const code = (header || req.params.trackingId as string).toUpperCase();
    if (!header && REPORTER_CODE_PATTERN.test(code)) return res.status(400).json({ success: false, error: 'Use the reporter credential header' });
    let trackingId = code;
    if (!trackingId || !(REPORTER_CODE_PATTERN.test(code) || LEGACY_REPORTER_CODE_PATTERN.test(code))) {
      return res.status(400).json({ success: false, error: 'Invalid tracking ID format' });
    }

    const { message } = req.body ?? {};
    if (typeof message !== 'string' || !message.trim()) {
      return res.status(400).json({ success: false, error: 'message is required' });
    }

    // Only reports that exist can have a thread — avoids junk threads for
    // guessed tracking IDs.
    const report = await reportPersistenceService.getForReporter(code);
    if (!report) {
      return res.status(404).json({ success: false, error: 'Report not found' });
    }

    trackingId = report.trackingId;
    const { relayService } = await import('../services/dissemination/relayService');
    const result = await relayService.postFromReporter(trackingId, message);
    if (!result.ok) {
      return res.status(400).json({ success: false, error: result.error });
    }
    res.json({ success: true });
  } catch (error: any) {
    req.logError?.('Relay reply error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to send reply. Please try again.' });
  }
});

router.post('/status/access/rotate', statusLimiter, async (req: Request, res: Response) => {
  try {
    const code = req.get('X-Reporter-Credential') || '';
    // Only a reporter code rotates. A legacy VRA- report ID also appears in agency
    // email and admin views, so rotating with it would let any holder mint a code
    // and permanently lock the reporter out (the ID stops working once a code exists).
    if (!REPORTER_CODE_PATTERN.test(code)) return res.status(404).json({ success: false, error: 'Report not found' });
    const report = await reportPersistenceService.getForReporter(code);
    if (!report) return res.status(404).json({ success: false, error: 'Report not found' });
    const reporterAccess = await createReporterAccess(report.trackingId);
    if (!await reportPersistenceService.rotateReporterAccess(report.trackingId, report.reporterAccess?.hash, reporterAccess)) {
      return res.status(409).json({ success: false, error: 'Access changed; use your current code' });
    }
    return res.json({ success: true, trackingId: await receiptCode({ trackingId: report.trackingId, reporterAccess }) });
  } catch { return res.status(503).json({ success: false, error: 'Access rotation unavailable' }); }
});

router.get('/evidence/:trackingId/:filename', requireInternalSecret, statusLimiter, reserveUpload, requestTimeout(EVIDENCE_TRANSFER_TIMEOUT_MS), withUploadBudget(async (req: Request, res: Response) => {
  const trackingId = req.params.trackingId as string;
  // Express has already decoded the path parameter; decoding twice breaks
  // legacy filenames containing a literal percent sign. It only reaches a
  // header through evidenceResponseHeaders, which strips control characters,
  // quotes and backslashes, so it cannot split or inject headers.
  // nosemgrep: ajinabraham.njsscan.headers.header_injection.generic_header_injection
  const filename = req.params.filename as string;

  // Validate tracking ID format
  if (!trackingId || !/^VRA-[A-F0-9]{16}$/i.test(trackingId)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid tracking ID'
    });
  }

  // Validate filename - prevent path traversal
  if (!filename || filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({
      success: false,
      error: 'Invalid filename'
    });
  }
  const fileKey = `${trackingId}/${filename}`;

  try {
    const params = await reportPersistenceService.getEvidenceParams(fileKey);
    if (!params) {
      return res.status(404).json({ success: false, error: 'Evidence not found' });
    }

    // Layer 1: use the selected encrypted-storage backend for both writes/reads.
    const encryptedFile = await readEvidenceCiphertext(params.originalCID);

    const decrypted = await decryptEvidenceOrLog(async () => {
      // Storage layer; records without pinataSalt use the legacy fixed salt.
      const evidenceEncryptedBuffer = await decryptStoredCiphertext(
        encryptedFile, params.encryptionKey, params.pinataIv, params.pinataAuthTag, params.pinataSalt,
      );

      // Layer 2: Decrypt evidence encryption layer (AES-256-GCM with PBKDF2 key)
      const result = await evidenceEncryptionService.decryptEvidence(
        {
          encryptedData: evidenceEncryptedBuffer.toString('base64'),
          encryptionMetadata: {
            algorithm: 'aes-256-gcm',
            salt: params.evidenceSalt,
            iv: params.evidenceIv,
            authTag: params.evidenceAuthTag,
            keyVersion: 'v1.0',
          },
          contentMetadata: { originalType: params.mimetype, size: params.contentSize, hash: params.contentHash },
        },
        params.encryptionKey
      );

      // Legacy files have no persisted plaintext digest; both GCM layers still
      // authenticate them. Never substitute the report aggregate digest here.
      if (params.contentHash !== undefined && !result.isValid) {
        throw new Error('Evidence plaintext integrity check failed');
      }
      return result;
    });
    res.set(evidenceResponseHeaders(filename, params.mimetype));
    res.send(decrypted.content);
  } catch (error: any) {
    req.logError?.('Evidence retrieval failed', 'error', { fileKey, stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to retrieve evidence from IPFS' });
  }
}));

router.get('/reward-contact/:trackingId', requireInternalSecret, statusLimiter, async (req: Request, res: Response) => {
  try {
    const trackingId = req.params.trackingId as string;

    if (!trackingId || !/^VRA-[A-F0-9]{16}$/i.test(trackingId)) {
      return res.status(400).json({ success: false, error: 'Invalid tracking ID format' });
    }

    const report = await reportPersistenceService.get(trackingId);
    if (!report) {
      return res.status(404).json({ success: false, error: 'Report not found' });
    }

    if (!report.reward?.encryptedContactValue) {
      return res.json({ success: true, contactMethod: report.reward?.contactMethod || null, contactValue: null });
    }

    try {
      const decryptedValue = report.reward.contactKeyWrapped
        ? await decryptRewardContact({ ciphertext: report.reward.encryptedContactValue, wrappedKey: report.reward.contactKeyWrapped }, trackingId)
        : decryptContactValue(report.reward.encryptedContactValue);
      return res.json({
        success: true,
        contactMethod: report.reward.contactMethod,
        contactValue: decryptedValue,
      });
    } catch (decryptError) {
      req.logError?.('Failed to decrypt contact value', 'error', { trackingId, stack: (decryptError as Error).stack });
      return res.status(500).json({ success: false, error: 'Failed to decrypt contact information' });
    }
  } catch (error: any) {
    req.logError?.('Reward contact fetch error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to fetch reward contact' });
  }
});

router.get('/narrative/:trackingId', requireInternalSecret, statusLimiter, async (req: Request, res: Response) => {
  try {
    const trackingId = req.params.trackingId as string;

    if (!trackingId || !/^VRA-[A-F0-9]{16}$/i.test(trackingId)) {
      return res.status(400).json({ success: false, error: 'Invalid tracking ID format' });
    }

    const report = await reportPersistenceService.get(trackingId);
    if (!report) {
      return res.status(404).json({ success: false, error: 'Report not found' });
    }

    // Pre-migration or text-less reports carry no encrypted narrative.
    if (!report.encryptedDescription && !report.encryptedNarrative) {
      return res.json({ success: true, narrative: null });
    }

    try {
      return res.json({ success: true, narrative: await decryptReportNarrative(report) });
    } catch (decryptError) {
      req.logError?.('Failed to decrypt narrative', 'error', { trackingId, stack: (decryptError as Error).stack });
      return res.status(500).json({ success: false, error: 'Failed to decrypt narrative' });
    }
  } catch (error: any) {
    req.logError?.('Narrative fetch error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to fetch narrative' });
  }
});

/**
 * Admin dashboard — list reports from Mongo (the source of record), mapped to the
 * dashboard shape (evidence join + activity + Shroud score). Reached only via the
 * Next admin proxy, which enforces the Auth0 admin role; requireInternalSecret is
 * defense-in-depth. Narrative stays encrypted (revealed via /narrative).
 */
// POST keeps reporter access codes out of URLs and access logs.
router.post('/admin/reports/search', requireInternalSecret, async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store');
  const query = req.body?.query;
  if (typeof query !== 'string' || !query.trim() || query.length > 128 || isConfidentialIdentifier(query) ||
      (/^VRC-/i.test(query.trim()) && !REPORTER_CODE_PATTERN.test(query.trim()))) {
    return res.status(400).json({ success: false, error: 'Enter a full report code or category (up to 128 characters)' });
  }
  try {
    const matches = await reportPersistenceService.searchAdmin(query, 101);
    const reports = matches.slice(0, 100);
    const evidence = await reportPersistenceService.listEvidenceByTrackingIds(reports.map(r => r.trackingId));
    return res.json({ success: true, data: { reports: mapReports(reports, evidence), hasMore: matches.length > 100 }, source: 'mongodb' });
  } catch {
    return res.status(503).json({ success: false, error: 'Report search is temporarily unavailable' });
  }
});

router.get('/admin/reports', requireInternalSecret, async (req: Request, res: Response) => {
  try {
    const limit = Math.min(parseInt(String(req.query.limit ?? '100'), 10) || 100, 500);
    const trackingId = typeof req.query.trackingId === 'string' ? req.query.trackingId : undefined;
    if (isConfidentialIdentifier(trackingId)) { rejectConfidentialIdentifier(res); return; }
    const reports = await reportPersistenceService.list(limit, trackingId);
    const evidence = await reportPersistenceService.listEvidenceByTrackingIds(reports.map((r) => r.trackingId));
    return res.json({ success: true, data: { reports: mapReports(reports, evidence) }, source: 'mongodb' });
  } catch (error: any) {
    req.logError?.('Admin reports fetch error', 'error', { stack: error.stack });
    return res.status(500).json({ success: false, error: 'Failed to fetch reports' });
  }
});

/**
 * Admin dashboard — aggregate stats over all reports (Mongo source of record).
 */
router.get('/admin/stats', requireInternalSecret, async (_req: Request, res: Response) => {
  try {
    const reports = await reportPersistenceService.list(0); // 0 = all reports
    return res.json({ success: true, data: computeStats(reports), source: 'mongodb' });
  } catch (error: any) {
    return res.status(500).json({ success: false, error: 'Failed to fetch stats' });
  }
});

// Admin triage statuses (dashboard vocabulary). The AI/submit pipeline sets its
// own processingStatus; legacy pipeline values are not admin-settable.
const ADMIN_REPORT_STATUSES = new Set(['pending', 'reviewing', 'investigating', 'resolved', 'dismissed']);

/**
 * Admin dashboard — update a report's triage status, persisted to MongoDB (the
 * source of record). Replaces the legacy ElizaOS status PATCH; the Next admin
 * route proxies here. `:trackingId` is the VRA id (== the dashboard reportId).
 */
router.get('/admin/reports/:trackingId/notes', requireInternalSecret, async (req: Request, res: Response) => {
  try {
    const notes = await reportPersistenceService.listInternalNotes(String(req.params.trackingId));
    if (!notes) return res.status(404).json({ success: false, error: 'report_not_found' });
    return res.json({ success: true, notes });
  } catch {
    return res.status(500).json({ success: false, error: 'Failed to load notes' });
  }
});

router.post('/admin/reports/:trackingId/notes', requireInternalSecret, async (req: Request, res: Response) => {
  const { text, authorId } = req.body ?? {};
  if (typeof text !== 'string' || !text.trim() || text.trim().length > 5000 || typeof authorId !== 'string' || !authorId.trim()) {
    return res.status(400).json({ success: false, error: 'invalid_note' });
  }
  try {
    const note = await reportPersistenceService.addInternalNote(String(req.params.trackingId), text.trim(), authorId);
    if (!note) return res.status(404).json({ success: false, error: 'report_not_found' });
    return res.status(201).json({ success: true, note });
  } catch {
    return res.status(500).json({ success: false, error: 'Failed to save note' });
  }
});

router.patch('/admin/reports/:trackingId/status', requireInternalSecret, async (req: Request, res: Response) => {
  try {
    const trackingId = String(req.params.trackingId);
    const status = (req.body ?? {}).status;
    if (typeof status !== 'string' || !ADMIN_REPORT_STATUSES.has(status)) {
      return res.status(400).json({ success: false, error: 'invalid_status' });
    }
    const existing = await reportPersistenceService.get(trackingId);
    if (!existing) {
      return res.status(404).json({ success: false, error: 'report_not_found' });
    }
    await reportPersistenceService.setAdminStatus(trackingId, status as ReportRecord['status']);
    const updated = await reportPersistenceService.get(trackingId);
    if (!updated) throw new Error('Report update was not persisted');
    return res.json({ success: true, data: { trackingId, status: updated.status, activity: buildActivity(updated) }, source: 'mongodb' });
  } catch (error: any) {
    req.logError?.('Admin status update error', 'error', { stack: error.stack });
    return res.status(500).json({ success: false, error: 'Failed to update status' });
  }
});

/**
 * Admin dashboard — re-run the Shroud AI verification on a report and persist the
 * result (processingStatus + verification). The triage `status` is left untouched,
 * so a re-analysis can't revert a report out of reviewing/investigating/resolved.
 * Reached via the Next admin proxy (Auth0 admin role); requireInternalSecret is
 * defense-in-depth. Replaces the legacy ElizaOS analysis proxy.
 */
router.post('/admin/reports/:trackingId/reanalyze', requireInternalSecret, async (req: Request, res: Response) => {
  try {
    // Scoring is optional (deferred to v2; unconfigured in production). Say so
    // plainly instead of surfacing a generic re-analysis failure.
    if (!isShroudConfigured()) {
      return res.status(503).json({ success: false, error: 'scoring_unavailable' });
    }
    const trackingId = String(req.params.trackingId);
    const report = await reportPersistenceService.get(trackingId);
    if (!report) {
      return res.status(404).json({ success: false, error: 'report_not_found' });
    }

    let description: string;
    try { description = await decryptReportNarrative(report) || ''; }
    catch { return res.status(503).json({ success: false, error: 'narrative_unavailable' }); }
    const evidenceType = report.category || report.categories?.[0] || 'other';
    const evidenceDocs = await reportPersistenceService.listEvidenceByTrackingIds([trackingId]);

    // Re-run the same Shroud verification used at intake, and persist it. Only the
    // AI verification (+ processingStatus) is updated — the admin triage `status`
    // is deliberately left untouched so a re-analysis can't revert a report out of
    // reviewing/investigating/resolved.
    const verification = await verifyReport({
      description,
      evidenceType,
      hasEvidence: evidenceDocs.length > 0,
    });

    await reportPersistenceService.patch(trackingId, {
      processingStatus: 'completed',
      verification: {
        isLegitimate: verification.isLegitimate,
        credibilityScore: verification.credibilityScore,
        category: verification.category,
        organizationType: verification.organizationType,
        namedOrganization: verification.namedOrganization ?? undefined,
        spamIndicators: verification.spamIndicators,
        contentAnalysis: verification.contentAnalysis,
        riskLevel: verification.riskLevel,
      },
    });

    return res.json({ success: true, data: { trackingId, verification }, source: 'shroud' });
  } catch (error: any) {
    req.logError?.('Admin reanalyze error', 'error', { stack: error.stack });
    return res.status(502).json({ success: false, error: 'Failed to re-analyze report' });
  }
});

router.get('/health', (req: Request, res: Response) => {
  res.json({
    success: true,
    service: 'whistleblower',
    veniceAI: veniceAIService.isConfigured() ? 'configured' : 'unavailable',
    shroud: isShroudConfigured() ? 'configured' : 'unavailable',
    timestamp: new Date().toISOString()
  });
});

/**
 * Live Nitro PCR0 from the co-located enclave's NSM identity document.
 * Independent of ENCLAVE_ENABLED. Returns 200 `{ available: false }` when no
 * enclave can answer (bridge absent, unreachable, or an enclave build without
 * attestIdentity) so an expected deployment state never counts as a 5xx.
 * 502 is reserved for an enclave that answers with an invalid attestation.
 * Only PCR0 is returned: the raw NSM document exposes host identifiers.
 * Does not claim that report crypto flows through the enclave.
 */
router.get('/enclave/attestation', attestationLimiter, async (_req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  try {
    const result = await getCachedEnclaveAttestation();
    return res.json(result.available ? { available: true, pcr0: result.pcr0 } : { available: false });
  } catch {
    return res.status(502).json({ error: 'enclave_attestation_invalid' });
  }
});

// Handle multer errors (file type rejection, size limit, etc.)
router.use((err: Error, _req: Request, res: Response, next: Function) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ success: false, error: err.message });
  }
  if (err.message?.startsWith('File type not allowed')) {
    return res.status(415).json({ success: false, error: err.message });
  }
  next(err);
});

export default router;
