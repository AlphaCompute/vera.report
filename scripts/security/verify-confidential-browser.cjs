#!/usr/bin/env node
// Synthetic browser crypto acceptance, independent of the legacy app routes.
// Prerequisites: npm ci at root and in qa/, plus Playwright Chromium.
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const { execFile } = require('node:child_process');
const ts = require('typescript');
const { webpack } = require('next/dist/compiled/webpack/webpack');
const { chromium } = require('../../qa/node_modules/@playwright/test');
const { BROWSER_ENTRY_MODULES, collectBrowserModules } = require('./confidential-browser-modules.cjs');

async function main() {
  const root = path.resolve(__dirname, '../..');
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'vera-confidential-browser-'));
  let browser, server;
  try {
    const rootPackage = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8'));
    const enclavePackage = JSON.parse(await fs.readFile(path.join(root, 'enclave/package.json'), 'utf8'));
    if (rootPackage.dependencies.openpgp !== enclavePackage.dependencies.openpgp) {
      throw new Error('Browser and enclave must pin the same OpenPGP version');
    }
    // Compile the actual enclave package, not a separately copied policy helper.
    await new Promise((resolve, reject) => execFile(process.execPath,
      [path.join(root, 'enclave/node_modules/typescript/bin/tsc'), '-p', path.join(root, 'enclave/tsconfig.json')],
      { cwd: root, timeout: 600_000, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
        if (error) reject(new Error(`Enclave compile failed (${error.code || error.signal || 'unknown'}; killed=${error.killed}): ${stdout}${stderr}`)); else resolve();
      }));
    const enclaveAuthorization = require('../../enclave/dist/confidential/authorization.js');
    const enclavePgp = require('../../enclave/dist/confidential/pgp.js');
    for (const name of collectBrowserModules(path.join(root, 'enclave/src/confidential'))) {
      const source = await fs.readFile(path.join(root, 'enclave/src/confidential', `${name}.ts`), 'utf8');
      const result = ts.transpileModule(source, { compilerOptions: {
        target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, rewriteRelativeImportExtensions: true,
      } });
      await fs.writeFile(path.join(temporary, `${name}.js`), result.outputText);
    }
    await fs.writeFile(path.join(temporary, 'entry.js'),
      BROWSER_ENTRY_MODULES.filter(name => name !== 'pgp').map(name => `export * from './${name}.js';`).join(' ') +
      " export { generateKey, readKey } from './pgp.js';");
    const stats = await new Promise((resolve, reject) => {
      const compiler = webpack({
        mode: 'production', target: 'web', entry: path.join(temporary, 'entry.js'),
        output: { path: temporary, filename: 'bundle.js', library: { name: 'VeraConfidentialTest', type: 'window' } },
        resolve: { modules: [path.join(root, 'node_modules')], conditionNames: ['browser', 'import', 'default'] },
        optimization: { minimize: false },
      });
      compiler.run((error, result) => compiler.close(closeError => {
        if (error || closeError) reject(error || closeError);
        else if (!result || result.hasErrors()) reject(new Error(result?.toString({ all: false, errors: true })));
        else resolve(result);
      }));
    });
    const modules = [...stats.compilation.modules].map(module => module.resource || '');
    if (!modules.some(file => file.endsWith('/openpgp/dist/openpgp.min.mjs')) ||
        modules.some(file => file.includes('/openpgp/dist/node/'))) {
      throw new Error('Unexpected OpenPGP browser dependency resolution');
    }
    const bundle = await fs.readFile(path.join(temporary, 'bundle.js'));
    server = http.createServer((req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      if (req.url === '/bundle.js') {
        res.setHeader('Content-Type', 'text/javascript'); res.end(bundle);
      } else if (req.url === '/') {
        res.setHeader('Content-Type', 'text/html');
        res.end('<!doctype html><title>Synthetic confidential case test</title><script src="/bundle.js"></script>');
      } else { res.statusCode = 404; res.end(); }
    });
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    const url = `http://127.0.0.1:${server.address().port}`;
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.route('**/*', route => route.request().url().startsWith(`${url}/`) ? route.continue() : route.abort());
    await page.goto(url);
    // Only the synthetic test bundle exposes the internal explicit-root PKI
    // primitive. The public verifier itself has no root override.
    const fixture = require('../../tests/confidential-runtime/attestation-fixture.cjs').createPkiFixture();
    const browserPki = await page.evaluate(async input => {
      const api = window.VeraConfidentialTest;
      const bytes = value => Uint8Array.from(atob(value), char => char.charCodeAt(0));
      const policy = { nonce: bytes(input.nonce), now: input.now,
        expectedPcrs: new Map(input.pcrs.map(([index, value]) => [index, bytes(value)])) };
      const document = bytes(input.document), key = bytes(input.publicKey), root = bytes(input.root);
      const prepared = await api.prepareApplicationAttestation(document, key, policy);
      await api.verifyAttestationPki(prepared, root, input.now);
      let browserRejectedUntrustedRoot = false, browserRejectedForgedSignature = false;
      try { await api.verifyApplicationAttestation(document, key, policy); }
      catch { browserRejectedUntrustedRoot = true; }
      prepared.signature[0] ^= 1;
      try { await api.verifyAttestationPki(prepared, root, input.now); }
      catch { browserRejectedForgedSignature = true; }
      return { browserSyntheticPkiVerified: true, browserRejectedUntrustedRoot, browserRejectedForgedSignature };
    }, { now: fixture.now, nonce: fixture.nonce.toString('base64'), publicKey: fixture.publicKey.toString('base64'),
      root: fixture.root.toString('base64'), document: fixture.document.toString('base64'),
      pcrs: [...fixture.expectedPcrs].map(([index, value]) => [index, value.toString('base64')]) });
    if (Object.values(browserPki).some(value => value !== true)) throw new Error('Browser PKI acceptance failed');
    // Synthetic transport interoperability only: no claim this Node process is
    // an enclave. Product creation requires createApprovedChannelRequest.
    const { createSessionCore } = require('../../enclave/dist/application-channel-sessions.js');
    const { ApplicationChannelIdentity } = require('../../enclave/dist/application-channel-identity.js');
    const channelKeys = await enclavePgp.generateKey({ type: 'ecc', curve: 'curve25519Legacy',
      userIDs: [{ name: 'Synthetic enclave channel' }], format: 'object' });
    const sessions = createSessionCore(async body => {
      if (new TextDecoder().decode(body) !== 'SYNTHETIC PRIVATE CHANNEL REQUEST') throw new Error('Channel body mismatch');
      return new TextEncoder().encode('SYNTHETIC PRIVATE CHANNEL RESPONSE');
    }, async nonce => new ApplicationChannelIdentity(channelKeys.privateKey, { nonce,
      publicKey: Buffer.from(channelKeys.publicKey.write()).toString('base64'), document: 'synthetic-not-AWS' }), () => performance.now());
    await sessions.open('1'.repeat(64));
    const channelCiphertext = await page.evaluate(async armoredKey => {
      const api = window.VeraConfidentialTest;
      window.syntheticPendingChannel = await api.sealChannelRequest(await api.readKey({ armoredKey }),
        '1'.repeat(64), new TextEncoder().encode('SYNTHETIC PRIVATE CHANNEL REQUEST'));
      return window.syntheticPendingChannel.ciphertext;
    }, channelKeys.publicKey.armor());
    if (channelCiphertext.includes('SYNTHETIC PRIVATE')) throw new Error('Plaintext channel request');
    let channelReply, serverReplayDenied = false;
    try {
      channelReply = await sessions.execute('1'.repeat(64), channelCiphertext);
      try { await sessions.execute('1'.repeat(64), channelCiphertext); } catch { serverReplayDenied = true; }
    } finally { sessions.close(); }
    if (!serverReplayDenied) throw new Error('Server session replay was accepted');
    if (channelReply.includes('SYNTHETIC PRIVATE')) throw new Error('Plaintext channel response');
    const browserEnclaveEncryptedRoundtrip = await page.evaluate(async ciphertext => {
      const response = await window.syntheticPendingChannel.openResponse(ciphertext);
      const matches = new TextDecoder().decode(response) === 'SYNTHETIC PRIVATE CHANNEL RESPONSE';
      let replayDenied = false;
      try { await window.syntheticPendingChannel.openResponse(ciphertext); } catch { replayDenied = true; }
      delete window.syntheticPendingChannel;
      return matches && replayDenied;
    }, channelReply);
    if (!browserEnclaveEncryptedRoundtrip) throw new Error('Encrypted browser/enclave roundtrip failed');
    const result = await page.evaluate(async () => {
      const api = window.VeraConfidentialTest;
      const cbor = api.decodeAttestationCbor(new Uint8Array([0xbf, 0x01, 0x38, 0x22, 0xff]));
      let duplicateCborDenied = false;
      try { api.decodeAttestationCbor(new Uint8Array([0xa2, 0x01, 0x00, 0x18, 0x01, 0x01])); }
      catch { duplicateCborDenied = true; }
      if (!(cbor instanceof Map) || cbor.get(1) !== -35 || !duplicateCborDenied) {
        throw new Error('Browser CBOR parser acceptance failed');
      }
      const hex = n => n.toString(16).padStart(64, '0');
      const caseOwner = await api.createCaseOwner();
      const owner = caseOwner.privateKey, trust = caseOwner.trust, caseId = trust.caseId;
      const [legal, admin] = await Promise.all(['legal', 'admin'].map(async name =>
        (await api.generateKey({ type: 'ecc', curve: 'curve25519Legacy',
          userIDs: [{ name: `Synthetic ${name}` }], format: 'object' })).privateKey));
      const now = Date.now(), context = { caseId, objectId: hex(2), scope: 'evidence', keyEpoch: 1, objectRevision: 1 };
      const recipientKeyId = await api.caseRecipientKeyId(legal.toPublic());
      const enrollmentChallenge = { format: 'vera-legal-enrollment/v1', invitationId: hex(7), organizationId: hex(4),
        providerOrganizationId: 'org_synthetic', subject: 'auth0|synthetic', recipientKeyId, nonce: hex(8), expiresAt: now + 60_000 };
      const enrollmentProof = await api.signEnrollmentChallenge(enrollmentChallenge, legal);
      // The single participant proof format (firm role), verified below by the compiled enclave.
      const participantContext = { audience: 'vera-confidential-cases', role: 'organization', caseId,
        organizationId: hex(4), operation: 'open-case', challenge: hex(10), nonce: hex(8), serverKeyId: hex(9), issuedAt: now };
      const participantProof = await api.signParticipantRequest({ ...participantContext,
        body: new TextEncoder().encode('SYNTHETIC PRIVATE OPERATION') }, legal);
      const requestCiphertext = await api.createLegalAccessRequest({ requestId: hex(6), scopes: ['evidence'],
        objectRevisionLimit: null, purpose: 'SYNTHETIC-PRIVATE-LEGAL-REQUEST', issuedAt: now, expiresAt: now + 60_000 },
        hex(4), legal, trust);
      const accessRequest = await api.openDeliveredLegalAccessRequest({ caseId: context.caseId, requestId: hex(6),
        organizationId: hex(4), recipientKeyId, expiresAt: now + 60_000, status: 'pending', ciphertext: requestCiphertext }, context.caseId, owner,
        [{ organizationId: hex(4), publicKey: legal.toPublic(), approved: true }], now);
      async function signed(statement) {
        const wire = await api.signOwnerStatement(statement, owner);
        return { wire, ...await api.verifyOwnerStatement(wire, trust) };
      }
      const grant = await signed({ kind: 'grant', caseId, revision: 2, grantId: hex(3),
        organizationId: accessRequest.organizationId, recipientKeyId: accessRequest.recipientKeyId,
        scopes: accessRequest.scopes, keyEpoch: 1, objectRevisionLimit: accessRequest.objectRevisionLimit,
        issuedAt: now, expiresAt: now + 60_000 });
      const releaseManifestWire = api.canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
        sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
        eifSha256: hex(11), imageSha256: hex(12), configurationSha256: hex(13), provenanceSha256: hex(14),
        protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
        measurements: { pcr0: '11'.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });
      const releaseDigest = (await api.readReleaseManifest(releaseManifestWire)).digest;
      const release = await signed({ kind: 'release', caseId, revision: 1, releaseDigest, issuedAt: now });
      const sentinel = 'SYNTHETIC-PRIVATE-BROWSER-EVIDENCE';
      const object = await api.sealCaseObject(context, new TextEncoder().encode(sentinel), owner);
      const ciphertextDigest = await api.caseObjectDigest(object.ciphertext);
      // Each object is listed in the owner-signed manifest by its own ID and ciphertext digest.
      const rangeContext = { ...context, objectId: hex(21) };
      const rangePayload = new TextEncoder().encode('SYNTHETIC PRIVATE RANGED EVIDENCE '.repeat(7000));
      const rangeOwned = await api.sealCaseObject(rangeContext, rangePayload, owner);
      const rangeCiphertextDigest = await api.caseObjectDigest(rangeOwned.ciphertext);
      const manifest = await signed({ kind: 'manifest', caseId, revision: 2, objects: [{
        objectId: context.objectId, scope: context.scope, objectRevision: context.objectRevision,
        keyEpoch: context.keyEpoch, ciphertextDigest }, { objectId: rangeContext.objectId, scope: rangeContext.scope,
        objectRevision: rangeContext.objectRevision, keyEpoch: rangeContext.keyEpoch, ciphertextDigest: rangeCiphertextDigest }] });
      const previousState = await signed({ kind: 'checkpoint', caseId, revision: 1, keyEpoch: 1,
        previousDigest: null, listingDigest: null, manifestDigest: null, issuedAt: now, grantDigests: [], releaseDigests: [] });
      const checkpoint = await signed({ kind: 'checkpoint', caseId, revision: 2, keyEpoch: 1,
        previousDigest: previousState.digest, listingDigest: null, manifestDigest: manifest.digest,
        issuedAt: now, grantDigests: [grant.digest], releaseDigests: [release.digest] });
      // The checkpoint's signed previousDigest is the single state-history link.
      if (checkpoint.statement.previousDigest !== previousState.digest) throw new Error('Browser checkpoint link mismatch');
      const auth = { trust, grant: grant.wire, release: release.wire, manifest: manifest.wire, checkpoint: checkpoint.wire,
        checkpointDigest: checkpoint.digest, request: { organizationId: hex(4), recipientKeyId,
          objectId: context.objectId, ciphertextDigest,
          scope: 'evidence', releaseDigest, keyEpoch: 1, objectRevision: 1, now } };
      const approved = await api.approvedReleasePolicy({ manifest: releaseManifestWire, release: release.wire,
        checkpoint: checkpoint.wire, checkpointDigest: checkpoint.digest, trust, now, nonce: new Uint8Array(32).fill(1) });
      if (approved.releaseDigest !== releaseDigest || approved.policy.expectedPcrs.size !== 3 ||
          !approved.policy.expectedPcrs.get(1).every(value => value === 0x22)) throw new Error('Owner release binding failed');
      const shared = await api.grantCaseObject(object, context, owner, legal.toPublic(), auth);
      const recovered = await api.openOwnerCaseObject(object, context, owner);
      const opened = await api.openGrantedCaseObject(shared, context, legal, auth);
      const preparedGrant = await api.prepareOwnerGrant({ trust, owner, now, releaseDigest,
        checkpoint: checkpoint.wire, checkpointDigest: checkpoint.digest, manifest: manifest.wire, release: release.wire,
        directory: [{ organizationId: hex(4), publicKey: legal.toPublic(), approved: true }],
        delivery: { caseId: context.caseId, requestId: hex(6), organizationId: hex(4), recipientKeyId,
          expiresAt: now + 60000, status: 'pending', ciphertext: requestCiphertext },
        decision: { grantId: hex(22), scopes: ['evidence'], objectRevisionLimit: 1, expiresAt: now + 60000 },
        objects: [{ objectId: context.objectId, ...object }, { objectId: rangeContext.objectId, ...rangeOwned }] });
      const preparedEnvelope = preparedGrant.body.envelopes.find(item => item.objectId === context.objectId);
      const preparedOpened = await api.openGrantedCaseObject({ ciphertext: object.ciphertext,
        recipientEnvelope: preparedEnvelope.envelope }, context, legal, { ...auth, grant: preparedGrant.grant,
        checkpoint: preparedGrant.body.checkpoint, checkpointDigest: preparedGrant.checkpointDigest });
      if (new TextDecoder().decode(preparedOpened) !== sentinel || preparedGrant.body.envelopes.length !== 2)
        throw new Error('Browser owner grant preparation failed');
      const rangeAuth = { ...auth, request: { ...auth.request, objectId: rangeContext.objectId, ciphertextDigest: rangeCiphertextDigest } };
      const rangeShared = await api.grantCaseObject(rangeOwned, rangeContext, owner, legal.toPublic(), rangeAuth);
      const rangeBytes = new TextEncoder().encode(rangeShared.ciphertext);
      const rangeHash = new Uint8Array(await crypto.subtle.digest('SHA-256', rangeBytes));
      const rangeDescriptor = { ...rangeContext, totalBytes: rangeBytes.length,
        ciphertextDigest: Array.from(rangeHash, value => value.toString(16).padStart(2, '0')).join('') };
      let rangeCount = 0;
      const assembled = await api.collectGrantedCaseRanges(rangeDescriptor, async (offset, length) => {
        rangeCount++;
        let binary = ''; for (const byte of rangeBytes.subarray(offset, offset + length)) binary += String.fromCharCode(byte);
        return { ...rangeDescriptor, offset, chunk: btoa(binary), recipientEnvelope: rangeShared.recipientEnvelope };
      });
      const rangeOpened = await api.openGrantedCaseObject(assembled, rangeContext, legal, rangeAuth);
      if (rangeCount < 2 || rangeOpened.length !== rangePayload.length ||
          !rangeOpened.every((value, index) => value === rangePayload[index])) throw new Error('Browser range reconstruction failed');
      const recovery = await api.createOwnerRecovery(caseOwner, checkpoint.wire);
      let denied = 0;
      for (const operation of [
        () => api.openLegalAccessRequest(requestCiphertext, context.caseId, admin,
          [{ organizationId: hex(4), publicKey: legal.toPublic(), approved: true }], now),
        () => api.openOwnerCaseObject(object, context, admin),
        () => api.openGrantedCaseObject(shared, context, admin, auth),
        () => api.grantCaseObject(object, context, owner, admin.toPublic(), auth),
        () => api.openGrantedCaseObject(shared, context, legal,
          { ...auth, request: { ...auth.request, releaseDigest: hex(99) } }),
      ]) {
        try { await operation(); } catch { denied++; }
      }
      return { browserCborChecked: true, ownerApprovedMeasurementsBound: true, browserRangedObjectOpened: true, browserOwnerGrantPrepared: true,
        ownerRecovered: new TextDecoder().decode(recovered) === sentinel,
        legalOpened: new TextDecoder().decode(opened) === sentinel,
        sameCiphertext: shared.ciphertext === object.ciphertext,
        ciphertextOnly: !JSON.stringify([object, shared]).includes(sentinel), denied,
        requestVerified: accessRequest.purpose === 'SYNTHETIC-PRIVATE-LEGAL-REQUEST' && accessRequest.recipientKeyId === recipientKeyId,
        requestPrivate: !requestCiphertext.includes('SYNTHETIC-PRIVATE-LEGAL-REQUEST'),
        recoveryTransfer: { code: recovery.recoveryCode, encryptedPackage: recovery.encryptedPackage,
          pin: recovery.pin, object, context, fingerprint: owner.getFingerprint() },
        authorizationTransfer: { ...auth, trust: { caseId: trust.caseId, ownerFingerprint: trust.ownerFingerprint,
          armoredPublicKey: trust.ownerPublicKey.armor() } },
        enrollmentTransfer: { challenge: enrollmentChallenge, proof: enrollmentProof, publicKey: legal.toPublic().armor() },
        participantTransfer: { context: participantContext, proof: participantProof, publicKey: legal.toPublic().armor() } };
    });
    const { recoveryTransfer, authorizationTransfer, enrollmentTransfer, participantTransfer, ...verification } = result;
    if (!verification.ownerRecovered || !verification.legalOpened || !verification.sameCiphertext || !verification.ciphertextOnly ||
        !verification.requestVerified || !verification.requestPrivate || verification.denied !== 5) {
      throw new Error('Synthetic browser acceptance failed');
    }
    // Synthetic browser-generated consent must be accepted by the compiled
    // enclave policy and rejected for a different release. No participant private
    // key or recovery code is supplied to this policy verifier.
    const runtimeAuth = { ...authorizationTransfer, trust: {
      caseId: authorizationTransfer.trust.caseId,
      ownerFingerprint: authorizationTransfer.trust.ownerFingerprint,
      ownerPublicKey: await enclavePgp.readKey({ armoredKey: authorizationTransfer.trust.armoredPublicKey }),
    } };
    await enclaveAuthorization.authorizeCaseRead(runtimeAuth);
    let compiledEnclaveDeniedWrongRelease = false;
    try {
      await enclaveAuthorization.authorizeCaseRead({ ...runtimeAuth,
        request: { ...runtimeAuth.request, releaseDigest: 'f'.repeat(64) } });
    } catch { compiledEnclaveDeniedWrongRelease = true; }
    if (!compiledEnclaveDeniedWrongRelease) throw new Error('Compiled enclave authorization failed');
    const enclaveEnrollment = require('../../enclave/dist/confidential/enrollmentProof.js');
    await enclaveEnrollment.verifyEnrollmentProof(enrollmentTransfer.challenge, enrollmentTransfer.proof,
      await enclavePgp.readKey({ armoredKey: enrollmentTransfer.publicKey }));
    const participantRuntime = require('../../enclave/dist/confidential/participantRequest.js');
    const { issuedAt: participantIssuedAt, ...participantExpected } = participantTransfer.context;
    await participantRuntime.verifyParticipantRequest(participantTransfer.proof, { ...participantExpected,
      body: new TextEncoder().encode('SYNTHETIC PRIVATE OPERATION'), now: participantIssuedAt },
      await enclavePgp.readKey({ armoredKey: participantTransfer.publicKey }));
    // A separate browser context starts without the first device's keys/storage.
    const freshContext = await browser.newContext();
    const freshPage = await freshContext.newPage();
    await freshPage.route('**/*', route => route.request().url().startsWith(`${url}/`) ? route.continue() : route.abort());
    await freshPage.goto(url);
    const recoveryResult = await freshPage.evaluate(async transfer => {
      const api = window.VeraConfidentialTest;
      const restored = await api.restoreOwnerRecovery(transfer.code, transfer.encryptedPackage, transfer.pin);
      const plaintext = await api.openOwnerCaseObject(transfer.object, transfer.context, restored.privateKey);
      const wrongCode = (transfer.code[0] === 'A' ? 'B' : 'A') + transfer.code.slice(1);
      let wrongCodeDenied = false;
      try { await api.restoreOwnerRecovery(wrongCode, transfer.encryptedPackage); } catch { wrongCodeDenied = true; }
      return { recoveredOnFreshBrowser: new TextDecoder().decode(plaintext) === 'SYNTHETIC-PRIVATE-BROWSER-EVIDENCE',
        ownerIdentityPreserved: restored.trust.ownerFingerprint === transfer.fingerprint,
        freshnessPending: restored.freshness === 'requires-current-state-verification', wrongCodeDenied };
    }, recoveryTransfer);
    if (Object.values(recoveryResult).some(value => value !== true)) throw new Error('Fresh browser recovery failed');
    // Firm member key distribution: a browser steward wraps the organization key
    // to a member device and rotates it; the compiled enclave module verifies both.
    const memberTransfer = await freshPage.evaluate(async () => {
      const api = window.VeraConfidentialTest;
      const hex = n => n.toString(16).padStart(64, '0');
      const make = async name => (await api.generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })).privateKey;
      const [organization, steward, member] = [await make('Synthetic org'), await make('Synthetic steward'), await make('Synthetic member')];
      const envelope = await api.wrapOrganizationKeyForMember({ organizationId: hex(1), memberId: hex(2), keyEpoch: 1, issuedAt: 1_800_000_000_000 },
        organization, member.toPublic(), steward);
      const rotated = await api.rotateOrganizationKey({ organizationId: hex(1), previousKeyEpoch: 1, removedMemberIds: [hex(3)],
        issuedAt: 1_800_000_000_000 }, organization);
      const browserVerified = (await api.verifyOrganizationKeyContinuity(rotated.continuity,
        { organizationId: hex(1), previousPublicKey: organization.toPublic() })).statement.ownerApproval === 'required';
      return { envelope, continuity: rotated.continuity, browserVerified, organization: organization.toPublic().armor(),
        steward: steward.toPublic().armor(), member: member.armor(), next: rotated.organizationKey.getFingerprint() };
    });
    const enclaveMembers = require('../../enclave/dist/confidential/firmMembers.js');
    const memberHex = n => n.toString(16).padStart(64, '0');
    const organizationPublicKey = await enclavePgp.readKey({ armoredKey: memberTransfer.organization });
    const memberOpened = await enclaveMembers.unwrapOrganizationKey(memberTransfer.envelope, { organizationId: memberHex(1),
      memberId: memberHex(2), keyEpoch: 1, organizationPublicKey,
      steward: await enclavePgp.readKey({ armoredKey: memberTransfer.steward }) },
      await enclavePgp.readPrivateKey({ armoredKey: memberTransfer.member }));
    const continuity = await enclaveMembers.verifyOrganizationKeyContinuity(memberTransfer.continuity,
      { organizationId: memberHex(1), previousPublicKey: organizationPublicKey });
    if (!memberTransfer.browserVerified || memberOpened.organizationKey.getFingerprint() !== organizationPublicKey.getFingerprint() ||
        continuity.nextPublicKey.getFingerprint() !== memberTransfer.next) throw new Error('Firm member key distribution interop failed');
    // Organization setup: statements signed in the browser verify in the compiled enclave,
    // and both sides compute the same onboarding terms digest.
    const setupTransfer = await freshPage.evaluate(async () => {
      const api = window.VeraConfidentialTest;
      const hex = n => n.toString(16).padStart(64, '0');
      const organization = (await api.generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic org' }], format: 'object' })).privateKey;
      const recipientKeyId = await api.caseRecipientKeyId(organization.toPublic());
      const termsDigest = await api.firmOnboardingTermsDigest();
      const custody = await api.signFirmSetupStatement({ format: 'vera-legal-key-custody/v1', organizationId: hex(1), recipientKeyId,
        method: 'second-custodian-copy', attestedAt: 1_800_000_000_000 }, organization);
      const terms = await api.signFirmSetupStatement({ format: 'vera-legal-onboarding-terms/v1', organizationId: hex(1), recipientKeyId,
        termsVersion: api.FIRM_ONBOARDING_TERMS_VERSION, termsDigest, acknowledgedAt: 1_800_000_000_000 }, organization);
      return { custody, terms, termsDigest, recipientKeyId, organization: organization.toPublic().armor() };
    });
    const enclaveSetup = require('../../enclave/dist/confidential/firmSetup.js');
    const setupKey = await enclavePgp.readKey({ armoredKey: setupTransfer.organization });
    const setupExpected = { organizationId: memberHex(1), recipientKeyId: setupTransfer.recipientKeyId, publicKey: setupKey };
    await enclaveSetup.verifyFirmSetupStatement(setupTransfer.custody, { ...setupExpected, kind: 'custody' }, 1_800_000_000_000);
    await enclaveSetup.verifyFirmSetupStatement(setupTransfer.terms, { ...setupExpected, kind: 'terms' }, 1_800_000_000_000);
    if (await enclaveSetup.firmOnboardingTermsDigest() !== setupTransfer.termsDigest) throw new Error('Organization setup interop failed');
    console.log(JSON.stringify({ browser: 'Chromium', browserVersion: browser.version(), bundleBytes: bundle.length,
      ...verification, ...recoveryResult, ...browserPki, compiledEnclaveAuthorized: true, compiledEnclaveDeniedWrongRelease,
      browserEnrollmentProofVerified: true, browserParticipantProofVerified: true, browserFirmMemberKeysInterop: true, browserFirmSetupInterop: true, browserEnclaveEncryptedRoundtrip, serverReplayDenied }));
  } finally {
    if (browser) await browser.close();
    if (server) await new Promise(resolve => server.close(resolve));
    await fs.rm(temporary, { recursive: true, force: true });
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
