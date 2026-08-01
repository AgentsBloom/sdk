import crypto from 'crypto';

/**
 * Hardened AP2 (Agent Payments Protocol) mandate verification.
 *
 * This module replaces the previous "valid but unverified" bypass in
 * packages/sdk/index.js's verifyAP2Mandates: a mandate that could not be
 * cryptographically verified was still returned as `{ valid: true,
 * verified: false }` and the checkout gate only checked `!ap2MandateResult`
 * / budget, never `.verified`. That meant any attacker could hand-craft an
 * unsigned (or badly-signed) mandate claiming an arbitrary maxBudget and
 * have it treated as authorization to check out.
 *
 * The rules enforced here:
 *   1. If no mandate header is present at all, AP2 simply isn't in use for
 *      this request - that's still `{ valid: true, verified: false }` so
 *      non-AP2 traffic (REST/ACP) is never blocked by AP2 logic.
 *   2. If a mandate header IS present, it MUST verify successfully or the
 *      request is rejected outright (`valid: false`). There is no
 *      "valid but unverified" middle ground once a mandate is presented.
 *   3. Signature verification uses either (a) a merchant-configured
 *      trusted public key (out-of-band trust, any of ES256/384/512,
 *      RS256/384/512, EdDSA), or (b) self-certifying did:key issuers
 *      (Ed25519/EdDSA only - the public key IS the issuer identifier, so
 *      no pre-registration is needed for arbitrary agents/wallets).
 *   4. Mandates must carry a unique `jti` and are checked against a
 *      bounded in-memory replay cache - a captured valid mandate cannot be
 *      replayed to trigger a second charge.
 *   5. `aud` is checked against the caller-supplied expected audience
 *      (the merchant's own base URL) when one is provided, so a mandate
 *      signed for store A cannot be replayed against store B.
 *   6. Mandate lifetime (`exp - iat`) is bounded, so a "valid forever"
 *      mandate cannot be crafted even with a real signature.
 */

// --- base58btc (Bitcoin alphabet) - no external dependency ---
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_MAP = new Map(BASE58_ALPHABET.split('').map((c, i) => [c, i]));

/** @param {Buffer} buffer @returns {string} */
function base58Encode(buffer) {
  if (buffer.length === 0) return '';
  let value = 0n;
  for (const byte of buffer) value = value * 256n + BigInt(byte);

  let encoded = '';
  while (value > 0n) {
    const remainder = value % 58n;
    value = value / 58n;
    encoded = BASE58_ALPHABET[Number(remainder)] + encoded;
  }

  let leadingZeros = 0;
  for (const byte of buffer) {
    if (byte === 0) leadingZeros++;
    else break;
  }
  return BASE58_ALPHABET[0].repeat(leadingZeros) + encoded;
}

/** @param {string} str @returns {Buffer} */
function base58Decode(str) {
  if (str.length === 0) return Buffer.alloc(0);
  let value = 0n;
  for (const char of str) {
    const digit = BASE58_MAP.get(char);
    if (digit === undefined) throw new Error(`Invalid base58 character: ${char}`);
    value = value * 58n + BigInt(digit);
  }

  const bytes = [];
  while (value > 0n) {
    bytes.unshift(Number(value % 256n));
    value = value / 256n;
  }

  let leadingZeros = 0;
  for (const char of str) {
    if (char === BASE58_ALPHABET[0]) leadingZeros++;
    else break;
  }
  return Buffer.concat([Buffer.alloc(leadingZeros, 0), Buffer.from(bytes)]);
}

// Ed25519 multicodec (0xed) varint-encoded as [0xed, 0x01], per the did:key
// Ed25519 method spec (multicodec ed25519-pub prefix).
const ED25519_MULTICODEC_PREFIX = Buffer.from([0xed, 0x01]);

// Fixed 12-byte SPKI DER prefix for Ed25519 public keys (RFC 8410) - Ed25519
// has no algorithm parameters, so the DER encoding of any Ed25519 SPKI key
// is always this fixed prefix followed by the raw 32-byte public key.
const ED25519_SPKI_DER_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * Derives a did:key identifier from an Ed25519 public key.
 * @param {crypto.KeyObject|Buffer} publicKey - a Node KeyObject or raw 32-byte public key
 * @returns {string} e.g. "did:key:z6Mk..."
 */
export function didKeyFromEd25519PublicKey(publicKey) {
  const rawKey = Buffer.isBuffer(publicKey)
    ? publicKey
    : publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const prefixed = Buffer.concat([ED25519_MULTICODEC_PREFIX, rawKey]);
  return `did:key:z${base58Encode(prefixed)}`;
}

/**
 * Derives an Ed25519 public KeyObject from a did:key identifier.
 * @param {string} didKey - e.g. "did:key:z6Mk..."
 * @returns {crypto.KeyObject|null} null if the identifier is not a
 *   well-formed Ed25519 did:key (caller treats this as "cannot verify")
 */
export function ed25519PublicKeyFromDidKey(didKey) {
  if (typeof didKey !== 'string' || !didKey.startsWith('did:key:z')) return null;
  try {
    const multibase = didKey.slice('did:key:'.length);
    const decoded = base58Decode(multibase.slice(1)); // drop leading 'z' multibase prefix
    if (
      decoded.length !== ED25519_MULTICODEC_PREFIX.length + 32 ||
      !decoded.subarray(0, 2).equals(ED25519_MULTICODEC_PREFIX)
    ) {
      return null;
    }
    const rawKey = decoded.subarray(2);
    const der = Buffer.concat([ED25519_SPKI_DER_PREFIX, rawKey]);
    return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    return null;
  }
}

// --- Replay protection ---
// A bounded, TTL-cleaned cache of mandate `jti`s that have already been
// consumed. Sized generously; entries are removed once the mandate they
// belonged to would have expired anyway, so the cache cannot grow forever
// even under sustained attack traffic.
const seenMandateJtis = new Map(); // jti -> expiresAtMs
const REPLAY_CACHE_MAX_SIZE = 50_000;

const replayCleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [jti, expiresAtMs] of seenMandateJtis.entries()) {
    if (expiresAtMs < now) seenMandateJtis.delete(jti);
  }
}, 60 * 1000);
replayCleanupInterval.unref?.();

/** Clears all replay-tracking state. Exposed for tests and shutdown(). */
export function resetAp2ReplayCache() {
  seenMandateJtis.clear();
}

/** Stops the background cleanup timer. Called from index.js's shutdown(). */
export function stopAp2ReplayCleanup() {
  clearInterval(replayCleanupInterval);
}

function isReplay(jti, expMs) {
  if (seenMandateJtis.has(jti)) return true;
  if (seenMandateJtis.size < REPLAY_CACHE_MAX_SIZE) {
    seenMandateJtis.set(jti, expMs);
  }
  return false;
}

// --- Signature verification helpers ---

/**
 * Algorithms accepted when the merchant has configured an explicit,
 * out-of-band-trusted public key. The merchant already trusts this key by
 * configuring it, so we support the same breadth of algorithms the
 * original implementation advertised.
 */
const EXPLICIT_KEY_ALLOWED_ALGS = new Set(['EdDSA', 'ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512']);

function hashAlgForJwtAlg(alg) {
  if (alg === 'EdDSA') return null; // Ed25519/Ed448 signature algorithm is built into the key
  if (alg.includes('384')) return 'SHA384';
  if (alg.includes('512')) return 'SHA512';
  return 'SHA256';
}

/**
 * Verifies an AP2 mandate SD-JWT presented in an incoming request.
 *
 * @param {Record<string, string>} [headers]
 * @param {Record<string, unknown>} [body]
 * @param {object} [options]
 * @param {crypto.KeyObject|Buffer|string|null} [options.trustedPublicKey] - merchant-configured
 *   out-of-band-trusted key (any format accepted by crypto.createPublicKey, or an
 *   already-constructed KeyObject). When set, this key is used instead of deriving
 *   one from a did:key issuer, and the broader algorithm set is permitted.
 * @param {string} [options.expectedAudience] - if set, `aud` must equal this value
 * @param {number} [options.maxMandateLifetimeSec=3600] - maximum allowed `exp - iat`
 * @param {boolean} [options.requireJti=true] - reject mandates without a `jti` claim
 * @param {string[]} [options.requestedCategories] - if set and the mandate's
 *   `intentMandate.allowedCategories` is present, the two must overlap
 * @returns {{ valid: boolean, verified: boolean, protocol: 'AP2', reason?: string, mandates?: object }}
 */
export function verifyAp2Mandate(headers = {}, body = {}, options = {}) {
  const {
    trustedPublicKey = null,
    expectedAudience = null,
    maxMandateLifetimeSec = 3600,
    requireJti = true,
    requestedCategories = null,
  } = options;

  const mandateHeader = headers['x-ap2-mandate'] || headers['authorization'];
  if (!mandateHeader) {
    // AP2 simply isn't in use for this request - not a security decision.
    return { valid: true, protocol: 'AP2', verified: false, note: 'No AP2 Mandates attached' };
  }

  let header, payload, signatureB64;
  try {
    const token = String(mandateHeader).replace(/^Bearer\s+/i, '');
    const parts = token.split('.');
    if (parts.length < 3) return { valid: false, reason: 'Invalid AP2 Mandate SD-JWT format', protocol: 'AP2' };
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    signatureB64 = parts[2];
  } catch {
    return { valid: false, reason: 'Invalid AP2 Mandate SD-JWT format', protocol: 'AP2' };
  }

  // --- Required claims present ---
  if (!payload.iss) return { valid: false, reason: 'Missing issuer', protocol: 'AP2' };
  if (!payload.aud) return { valid: false, reason: 'Missing audience', protocol: 'AP2' };
  if (typeof payload.iat !== 'number') return { valid: false, reason: 'Missing iat', protocol: 'AP2' };
  if (typeof payload.exp !== 'number') return { valid: false, reason: 'Missing exp', protocol: 'AP2' };
  if (requireJti && !payload.jti) {
    return { valid: false, reason: 'Missing jti (required for replay protection)', protocol: 'AP2' };
  }

  // --- Temporal validity ---
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) return { valid: false, reason: 'Token expired', protocol: 'AP2' };
  if (payload.iat > now) return { valid: false, reason: 'Token issued in the future', protocol: 'AP2' };

  // --- Bounded mandate lifetime ---
  if (payload.exp - payload.iat > maxMandateLifetimeSec) {
    return { valid: false, reason: `Mandate lifetime exceeds maximum allowed (${maxMandateLifetimeSec}s)`, protocol: 'AP2' };
  }

  // --- Resolve verification key + algorithm policy ---
  let publicKey = null;
  let usingSelfCertifyingKey = false;

  if (trustedPublicKey) {
    try {
      publicKey = trustedPublicKey instanceof crypto.KeyObject
        ? trustedPublicKey
        : crypto.createPublicKey(trustedPublicKey);
    } catch {
      return { valid: false, reason: 'Configured trusted public key is invalid', protocol: 'AP2' };
    }
    if (!EXPLICIT_KEY_ALLOWED_ALGS.has(header.alg)) {
      return { valid: false, reason: `Unsupported signature algorithm: ${header.alg}`, protocol: 'AP2' };
    }
  } else if (String(payload.iss).startsWith('did:key:')) {
    usingSelfCertifyingKey = true;
    if (header.alg !== 'EdDSA') {
      return { valid: false, reason: 'did:key issuers require the EdDSA algorithm', protocol: 'AP2' };
    }
    publicKey = ed25519PublicKeyFromDidKey(payload.iss);
    if (!publicKey) {
      return { valid: false, reason: 'Issuer is not a valid Ed25519 did:key identifier', protocol: 'AP2' };
    }
  } else {
    // No merchant-trusted key configured, and the issuer isn't a
    // self-certifying did:key we can derive a key from - there is no way
    // to verify this mandate, so it must be rejected rather than passed
    // through as "valid but unverified".
    return {
      valid: false,
      reason: 'Cannot verify mandate: issuer is not a did:key and no trusted public key is configured',
      protocol: 'AP2',
    };
  }

  // --- Signature verification (mandatory) ---
  try {
    const [encodedHeader, encodedPayload] = String(mandateHeader).replace(/^Bearer\s+/i, '').split('.');
    const signingInput = Buffer.from(`${encodedHeader}.${encodedPayload}`);
    const signature = Buffer.from(signatureB64, 'base64url');
    const hashAlg = hashAlgForJwtAlg(header.alg);
    const isValid = crypto.verify(hashAlg, signingInput, publicKey, signature);
    if (!isValid) return { valid: false, reason: 'Invalid signature', protocol: 'AP2' };
  } catch (err) {
    return { valid: false, reason: `Signature verification failed: ${err.message}`, protocol: 'AP2' };
  }

  // --- Audience binding ---
  if (expectedAudience && payload.aud !== expectedAudience) {
    return {
      valid: false,
      reason: `Mandate audience "${payload.aud}" does not match this store ("${expectedAudience}")`,
      protocol: 'AP2',
    };
  }

  // --- merchantScope binding (if the mandate declares one, it must match too) ---
  const merchantScope = payload.intentMandate?.merchantScope;
  if (expectedAudience && merchantScope && merchantScope !== expectedAudience) {
    return {
      valid: false,
      reason: `Mandate merchantScope "${merchantScope}" does not match this store ("${expectedAudience}")`,
      protocol: 'AP2',
    };
  }

  // --- Replay protection ---
  if (payload.jti) {
    if (isReplay(payload.jti, payload.exp * 1000)) {
      return { valid: false, reason: 'Mandate has already been used (replay detected)', protocol: 'AP2' };
    }
  }

  // --- Category enforcement (only if both the mandate and caller supply it) ---
  const allowedCategories = payload.intentMandate?.allowedCategories;
  if (Array.isArray(allowedCategories) && Array.isArray(requestedCategories) && requestedCategories.length > 0) {
    const overlaps = requestedCategories.some((c) => allowedCategories.includes(c));
    if (!overlaps) {
      return {
        valid: false,
        reason: `Requested categories [${requestedCategories.join(', ')}] are not within the mandate's allowedCategories [${allowedCategories.join(', ')}]`,
        protocol: 'AP2',
      };
    }
  }

  // --- Budget enforcement (checked here for the common case where the
  // caller already knows the order total; the SDK middleware also
  // re-checks this at the /ap2/checkout call site once the cart total is known) ---
  const maxBudget = payload.intentMandate?.maxBudget ?? payload.paymentMandate?.maxBudget;
  if (maxBudget !== undefined && body?.orderTotal !== undefined) {
    if (Number(body.orderTotal) > Number(maxBudget)) {
      return { valid: false, reason: 'Order total exceeds Intent Mandate maxBudget limit', protocol: 'AP2' };
    }
  }

  return {
    valid: true,
    protocol: 'AP2',
    verified: true,
    selfCertifying: usingSelfCertifyingKey,
    mandates: payload,
  };
}

/**
 * Builds and signs a complete AP2 Intent+Payment Mandate SD-JWT for
 * agent-side tooling (test harnesses, demos, or a real agent's own wallet
 * integration). The issuer is a did:key derived from the signing keypair,
 * so the resulting mandate self-certifies without any prior key
 * registration with the merchant.
 *
 * @param {object} options
 * @param {string} options.audience - the merchant/store base URL this mandate authorizes (required)
 * @param {number} options.maxBudget - spending cap enforced by the merchant on checkout
 * @param {string} [options.currency='USD']
 * @param {string[]} [options.allowedCategories] - optional category allowlist
 * @param {string} [options.merchantScope] - defaults to `audience`
 * @param {number} [options.lifetimeSec=3600] - mandate validity window
 * @param {string} [options.paymentMethod='tokenized_card']
 * @param {string} [options.subject='user_wallet_delegation']
 * @param {crypto.KeyObject} [options.privateKey] - reuse an existing Ed25519 private key;
 *   a fresh ephemeral keypair is generated if omitted
 * @returns {{ token: string, did: string, publicKey: crypto.KeyObject, privateKey: crypto.KeyObject }}
 */
export function createAp2Mandate(options = {}) {
  const {
    audience,
    maxBudget,
    currency = 'USD',
    allowedCategories,
    merchantScope,
    lifetimeSec = 3600,
    paymentMethod = 'tokenized_card',
    subject = 'user_wallet_delegation',
    privateKey: providedPrivateKey,
  } = options;

  if (!audience) throw new Error('createAp2Mandate requires an `audience` (the target store base URL)');
  if (maxBudget === undefined) throw new Error('createAp2Mandate requires a `maxBudget`');

  const { privateKey, publicKey } = providedPrivateKey
    ? { privateKey: providedPrivateKey, publicKey: crypto.createPublicKey(providedPrivateKey) }
    : crypto.generateKeyPairSync('ed25519');

  const did = didKeyFromEd25519PublicKey(publicKey);
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + lifetimeSec;

  const header = { alg: 'EdDSA', typ: 'JWT' };
  const payload = {
    iss: did,
    aud: audience,
    sub: subject,
    iat,
    exp,
    jti: crypto.randomUUID(),
    intentMandate: {
      maxBudget,
      currency,
      merchantScope: merchantScope || audience,
      ...(allowedCategories ? { allowedCategories } : {}),
    },
    paymentMandate: {
      paymentMethod,
      currency,
    },
  };

  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto.sign(null, Buffer.from(signingInput), privateKey).toString('base64url');

  return { token: `${signingInput}.${signature}`, did, publicKey, privateKey };
}
