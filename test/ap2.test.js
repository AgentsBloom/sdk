import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import fc from 'fast-check';
import {
  verifyAp2Mandate,
  createAp2Mandate,
  didKeyFromEd25519PublicKey,
  ed25519PublicKeyFromDidKey,
  resetAp2ReplayCache,
} from '../lib/ap2.js';

const AUDIENCE = 'https://store.test';

/** Builds a raw (header.payload.signature) token, signing with the given key. */
function buildToken(header, payload, privateKey) {
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto.sign(null, Buffer.from(signingInput), privateKey).toString('base64url');
  return `${signingInput}.${signature}`;
}

describe('did:key Ed25519 encode/decode', () => {

  it('round-trips an arbitrary Ed25519 public key through did:key encoding', () => {
    for (let i = 0; i < 10; i++) {
      const { publicKey } = crypto.generateKeyPairSync('ed25519');
      const did = didKeyFromEd25519PublicKey(publicKey);
      assert.match(did, /^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
      const recovered = ed25519PublicKeyFromDidKey(did);
      assert.ok(recovered, 'expected did:key to decode back to a public key');
      assert.strictEqual(
        recovered.export({ type: 'spki', format: 'der' }).toString('hex'),
        publicKey.export({ type: 'spki', format: 'der' }).toString('hex')
      );
    }
  });

  it('returns null for a malformed did:key string', () => {
    assert.strictEqual(ed25519PublicKeyFromDidKey('did:key:z6MkpTHR8VNsBxYpjW...'), null);
    assert.strictEqual(ed25519PublicKeyFromDidKey('not-a-did-key-at-all'), null);
    assert.strictEqual(ed25519PublicKeyFromDidKey(''), null);
    assert.strictEqual(ed25519PublicKeyFromDidKey(null), null);
  });

  // Feature: ap2-hardening, Property: did:key encode/decode round-trips for any Ed25519 key
  it('property: encode(decode(x)) === x for any generated Ed25519 keypair', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 0 }), () => {
        const { publicKey } = crypto.generateKeyPairSync('ed25519');
        const did = didKeyFromEd25519PublicKey(publicKey);
        const recovered = ed25519PublicKeyFromDidKey(did);
        assert.strictEqual(
          recovered.export({ type: 'spki', format: 'der' }).toString('hex'),
          publicKey.export({ type: 'spki', format: 'der' }).toString('hex')
        );
      }),
      { numRuns: 100 }
    );
  });

});

describe('createAp2Mandate + verifyAp2Mandate (happy path)', () => {

  beforeEach(() => resetAp2ReplayCache());

  it('creates a self-certifying did:key mandate that verifies successfully', () => {
    const { token } = createAp2Mandate({ audience: AUDIENCE, maxBudget: 100 });
    const result = verifyAp2Mandate({ 'x-ap2-mandate': `Bearer ${token}` }, {}, { expectedAudience: AUDIENCE });
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.verified, true);
    assert.strictEqual(result.selfCertifying, true);
    assert.strictEqual(result.mandates.intentMandate.maxBudget, 100);
  });

  it('accepts an order total within budget', () => {
    const { token } = createAp2Mandate({ audience: AUDIENCE, maxBudget: 200 });
    const result = verifyAp2Mandate(
      { 'x-ap2-mandate': `Bearer ${token}` },
      { orderTotal: 150 },
      { expectedAudience: AUDIENCE }
    );
    assert.strictEqual(result.valid, true);
  });

  it('passes through as valid-but-unverified when no mandate header is present at all', () => {
    const result = verifyAp2Mandate({}, {});
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.verified, false);
    assert.strictEqual(result.protocol, 'AP2');
  });

});

describe('verifyAp2Mandate - rejects unverifiable mandates outright (closes the original bypass)', () => {

  beforeEach(() => resetAp2ReplayCache());

  it('rejects a mandate with alg:none and no signature (the classic bypass)', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'did:key:z6MkpTHR8VNsBxYpjW...', // fake, not a real encoded key
      aud: AUDIENCE,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: crypto.randomUUID(),
      intentMandate: { maxBudget: 999999 },
    })).toString('base64url');
    const token = `${header}.${payload}.`;

    const result = verifyAp2Mandate({ 'x-ap2-mandate': `Bearer ${token}` }, { orderTotal: 999999 }, { expectedAudience: AUDIENCE });
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.verified, undefined);
  });

  it('rejects an issuer that is not a real did:key and no trusted key is configured', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'not-a-did-key-issuer',
      aud: AUDIENCE,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: crypto.randomUUID(),
      intentMandate: { maxBudget: 100 },
    })).toString('base64url');
    const token = `${header}.${payload}.fake-signature`;

    const result = verifyAp2Mandate({ 'x-ap2-mandate': `Bearer ${token}` }, {}, { expectedAudience: AUDIENCE });
    assert.strictEqual(result.valid, false);
    assert.match(result.reason, /Cannot verify mandate/);
  });

  it('rejects a well-formed but placeholder/fake did:key issuer (invalid base58 payload length)', () => {
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    const header = { alg: 'EdDSA', typ: 'JWT' };
    const payload = {
      iss: 'did:key:z6MkpTHR8VNsBxYpjW...', // looks plausible, isn't a real encoded Ed25519 key
      aud: AUDIENCE,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: crypto.randomUUID(),
      intentMandate: { maxBudget: 100 },
    };
    const token = buildToken(header, payload, privateKey);

    const result = verifyAp2Mandate({ 'x-ap2-mandate': `Bearer ${token}` }, {}, { expectedAudience: AUDIENCE });
    assert.strictEqual(result.valid, false);
    assert.match(result.reason, /not a valid Ed25519 did:key/);
  });

  it('rejects a mandate whose signature does not match its did:key issuer (signed by a different key)', () => {
    const { privateKey: signingKey } = crypto.generateKeyPairSync('ed25519');
    const { publicKey: claimedPublicKey } = crypto.generateKeyPairSync('ed25519'); // different keypair
    const claimedDid = didKeyFromEd25519PublicKey(claimedPublicKey);

    const header = { alg: 'EdDSA', typ: 'JWT' };
    const payload = {
      iss: claimedDid, // claims to be the OTHER keypair's did
      aud: AUDIENCE,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: crypto.randomUUID(),
      intentMandate: { maxBudget: 100 },
    };
    const token = buildToken(header, payload, signingKey); // but signs with a DIFFERENT key

    const result = verifyAp2Mandate({ 'x-ap2-mandate': `Bearer ${token}` }, {}, { expectedAudience: AUDIENCE });
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.reason, 'Invalid signature');
  });

  it('rejects a mandate missing a jti claim', () => {
    const { token: withJti } = createAp2Mandate({ audience: AUDIENCE, maxBudget: 100 });
    const [h, p] = withJti.split('.');
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
    delete payload.jti;
    // Re-sign with a fresh key since we changed the payload.
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    const publicKey = crypto.createPublicKey(privateKey);
    payload.iss = didKeyFromEd25519PublicKey(publicKey);
    const token = buildToken(JSON.parse(Buffer.from(h, 'base64url').toString()), payload, privateKey);

    const result = verifyAp2Mandate({ 'x-ap2-mandate': `Bearer ${token}` }, {}, { expectedAudience: AUDIENCE });
    assert.strictEqual(result.valid, false);
    assert.match(result.reason, /jti/);
  });

});

describe('verifyAp2Mandate - replay protection', () => {

  beforeEach(() => resetAp2ReplayCache());

  it('rejects a mandate that has already been consumed once', () => {
    const { token } = createAp2Mandate({ audience: AUDIENCE, maxBudget: 100 });
    const first = verifyAp2Mandate({ 'x-ap2-mandate': `Bearer ${token}` }, {}, { expectedAudience: AUDIENCE });
    assert.strictEqual(first.valid, true);

    const second = verifyAp2Mandate({ 'x-ap2-mandate': `Bearer ${token}` }, {}, { expectedAudience: AUDIENCE });
    assert.strictEqual(second.valid, false);
    assert.match(second.reason, /replay/i);
  });

  it('allows two distinct mandates (different jti) from the same issuer', () => {
    const { token: t1 } = createAp2Mandate({ audience: AUDIENCE, maxBudget: 100 });
    const { token: t2 } = createAp2Mandate({ audience: AUDIENCE, maxBudget: 100 });
    assert.strictEqual(verifyAp2Mandate({ 'x-ap2-mandate': `Bearer ${t1}` }, {}, { expectedAudience: AUDIENCE }).valid, true);
    assert.strictEqual(verifyAp2Mandate({ 'x-ap2-mandate': `Bearer ${t2}` }, {}, { expectedAudience: AUDIENCE }).valid, true);
  });

});

describe('verifyAp2Mandate - audience and merchantScope binding', () => {

  beforeEach(() => resetAp2ReplayCache());

  it('rejects a mandate whose aud does not match the expected audience', () => {
    const { token } = createAp2Mandate({ audience: 'https://other-store.test', maxBudget: 100 });
    const result = verifyAp2Mandate({ 'x-ap2-mandate': `Bearer ${token}` }, {}, { expectedAudience: AUDIENCE });
    assert.strictEqual(result.valid, false);
    assert.match(result.reason, /audience/);
  });

  it('rejects a mandate whose merchantScope does not match the expected audience', () => {
    const { token } = createAp2Mandate({ audience: AUDIENCE, merchantScope: 'https://different-scope.test', maxBudget: 100 });
    const result = verifyAp2Mandate({ 'x-ap2-mandate': `Bearer ${token}` }, {}, { expectedAudience: AUDIENCE });
    assert.strictEqual(result.valid, false);
    assert.match(result.reason, /merchantScope/);
  });

  it('accepts when no expectedAudience is provided by the caller (opt-out)', () => {
    const { token } = createAp2Mandate({ audience: 'https://anything.test', maxBudget: 100 });
    const result = verifyAp2Mandate({ 'x-ap2-mandate': `Bearer ${token}` }, {});
    assert.strictEqual(result.valid, true);
  });

});

describe('verifyAp2Mandate - bounded mandate lifetime', () => {

  beforeEach(() => resetAp2ReplayCache());

  it('rejects a mandate whose exp - iat exceeds the configured maximum lifetime', () => {
    const { token } = createAp2Mandate({ audience: AUDIENCE, maxBudget: 100, lifetimeSec: 7200 });
    const result = verifyAp2Mandate(
      { 'x-ap2-mandate': `Bearer ${token}` },
      {},
      { expectedAudience: AUDIENCE, maxMandateLifetimeSec: 3600 }
    );
    assert.strictEqual(result.valid, false);
    assert.match(result.reason, /lifetime/);
  });

  it('accepts a mandate within the configured maximum lifetime', () => {
    const { token } = createAp2Mandate({ audience: AUDIENCE, maxBudget: 100, lifetimeSec: 1800 });
    const result = verifyAp2Mandate(
      { 'x-ap2-mandate': `Bearer ${token}` },
      {},
      { expectedAudience: AUDIENCE, maxMandateLifetimeSec: 3600 }
    );
    assert.strictEqual(result.valid, true);
  });

});

describe('verifyAp2Mandate - category enforcement', () => {

  beforeEach(() => resetAp2ReplayCache());

  it('rejects when the requested category is not in the mandate allowedCategories', () => {
    const { token } = createAp2Mandate({ audience: AUDIENCE, maxBudget: 100, allowedCategories: ['shoes', 'apparel'] });
    const result = verifyAp2Mandate(
      { 'x-ap2-mandate': `Bearer ${token}` },
      {},
      { expectedAudience: AUDIENCE, requestedCategories: ['electronics'] }
    );
    assert.strictEqual(result.valid, false);
    assert.match(result.reason, /allowedCategories/);
  });

  it('accepts when the requested category overlaps with allowedCategories', () => {
    const { token } = createAp2Mandate({ audience: AUDIENCE, maxBudget: 100, allowedCategories: ['shoes', 'apparel'] });
    const result = verifyAp2Mandate(
      { 'x-ap2-mandate': `Bearer ${token}` },
      {},
      { expectedAudience: AUDIENCE, requestedCategories: ['apparel'] }
    );
    assert.strictEqual(result.valid, true);
  });

  it('does not enforce categories when the mandate has none declared', () => {
    const { token } = createAp2Mandate({ audience: AUDIENCE, maxBudget: 100 });
    const result = verifyAp2Mandate(
      { 'x-ap2-mandate': `Bearer ${token}` },
      {},
      { expectedAudience: AUDIENCE, requestedCategories: ['anything'] }
    );
    assert.strictEqual(result.valid, true);
  });

});

describe('verifyAp2Mandate - merchant-trusted key path (out-of-band, non-did:key issuer)', () => {

  beforeEach(() => resetAp2ReplayCache());

  it('verifies a mandate from a fixed issuer string signed by a merchant-trusted key', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const header = { alg: 'EdDSA', typ: 'JWT' };
    const payload = {
      iss: 'my-registered-agent-v1', // not a did:key - relies on the trusted key instead
      aud: AUDIENCE,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: crypto.randomUUID(),
      intentMandate: { maxBudget: 300 },
    };
    const token = buildToken(header, payload, privateKey);

    const result = verifyAp2Mandate(
      { 'x-ap2-mandate': `Bearer ${token}` },
      {},
      { trustedPublicKey: publicKey, expectedAudience: AUDIENCE }
    );
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.verified, true);
    assert.strictEqual(result.selfCertifying, false);
  });

  it('rejects an unsupported algorithm even with a trusted key configured', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const header = { alg: 'HS256', typ: 'JWT' }; // not in the allowed set
    const payload = {
      iss: 'my-registered-agent-v1',
      aud: AUDIENCE,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: crypto.randomUUID(),
      intentMandate: { maxBudget: 300 },
    };
    const token = buildToken(header, payload, privateKey);

    const result = verifyAp2Mandate(
      { 'x-ap2-mandate': `Bearer ${token}` },
      {},
      { trustedPublicKey: publicKey, expectedAudience: AUDIENCE }
    );
    assert.strictEqual(result.valid, false);
    assert.match(result.reason, /Unsupported signature algorithm/);
  });

});

describe('verifyAp2Mandate - temporal validity (still enforced)', () => {

  beforeEach(() => resetAp2ReplayCache());

  it('rejects an expired mandate', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const did = didKeyFromEd25519PublicKey(publicKey);
    const header = { alg: 'EdDSA', typ: 'JWT' };
    const payload = {
      iss: did,
      aud: AUDIENCE,
      iat: Math.floor(Date.now() / 1000) - 7200,
      exp: Math.floor(Date.now() / 1000) - 3600,
      jti: crypto.randomUUID(),
      intentMandate: { maxBudget: 100 },
    };
    const token = buildToken(header, payload, privateKey);
    const result = verifyAp2Mandate({ 'x-ap2-mandate': `Bearer ${token}` }, {}, { expectedAudience: AUDIENCE });
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.reason, 'Token expired');
  });

  it('rejects a mandate issued in the future', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const did = didKeyFromEd25519PublicKey(publicKey);
    const header = { alg: 'EdDSA', typ: 'JWT' };
    const payload = {
      iss: did,
      aud: AUDIENCE,
      iat: Math.floor(Date.now() / 1000) + 7200,
      exp: Math.floor(Date.now() / 1000) + 14400,
      jti: crypto.randomUUID(),
      intentMandate: { maxBudget: 100 },
    };
    const token = buildToken(header, payload, privateKey);
    const result = verifyAp2Mandate({ 'x-ap2-mandate': `Bearer ${token}` }, {}, { expectedAudience: AUDIENCE });
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.reason, 'Token issued in the future');
  });

});

describe('verifyAp2Mandate - budget enforcement (still enforced)', () => {

  beforeEach(() => resetAp2ReplayCache());

  it('rejects when order total exceeds maxBudget', () => {
    const { token } = createAp2Mandate({ audience: AUDIENCE, maxBudget: 50 });
    const result = verifyAp2Mandate({ 'x-ap2-mandate': `Bearer ${token}` }, { orderTotal: 100 }, { expectedAudience: AUDIENCE });
    assert.strictEqual(result.valid, false);
    assert.match(result.reason, /maxBudget/);
  });

});
