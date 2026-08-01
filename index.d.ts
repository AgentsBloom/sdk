export type Protocol = 'WEBMCP' | 'UCP' | 'ACP' | 'AP2' | 'AGENTSBLOOM_REST';

export type AgentActionHandler = (
  params: Record<string, unknown>,
  req: unknown,
  res: unknown
) => unknown | Promise<unknown>;

export interface AgentAction {
  method?: string;
  description?: string;
  params?: Record<string, string>;
  handler: AgentActionHandler;
}

export interface AgentsBloomConfig {
  apiKey?: string | null;
  agentSecret?: string | null;
  name?: string;
  description?: string;
  actions?: Record<string, AgentAction>;
  llmsDoc?: string;
  baseUrl?: string;
  corsOrigin?: string;
  merchantJwks?: Record<string, unknown>;
  agentJwks?: {
    keys: Array<Record<string, unknown>>;
  };
  agentJwksUrl?: string;
  signature?: {
    maxAgeMs?: number;
  };
  ap2PublicKey?: unknown;
  ap2?: {
    expectedAudience?: string;
    maxMandateLifetimeSec?: number;
    requireJti?: boolean;
    requestedCategories?: string[];
  };
  rateLimit?: {
    max?: number;
    windowMs?: number;
  };
  idempotency?: {
    ttlMs?: number;
  };
  demoMode?: boolean;
  disableSignatureAuth?: boolean;
  disableHtmlInjection?: boolean;
}

export type AgentsBloomMiddleware = (
  req: unknown,
  res: unknown,
  next: (error?: unknown) => void
) => unknown;

export interface TelemetryOptions {
  otlpEndpoint?: string;
  serviceName?: string;
  samplingRatio?: number;
  apiKey?: string;
}

export interface TelemetryConfig {
  otlpEndpoint: string;
  serviceName: string;
  samplingRatio: number;
}

export interface Ap2VerificationResult {
  valid: boolean;
  verified?: boolean;
  protocol: 'AP2';
  reason?: string;
  note?: string;
  selfCertifying?: boolean;
  mandates?: Record<string, unknown>;
}

export interface Ap2VerifyOptions {
  trustedPublicKey?: unknown;
  expectedAudience?: string;
  maxMandateLifetimeSec?: number;
  requireJti?: boolean;
  requestedCategories?: string[];
}

export interface CreateAp2MandateOptions {
  audience: string;
  maxBudget: number;
  currency?: string;
  allowedCategories?: string[];
  merchantScope?: string;
  lifetimeSec?: number;
  paymentMethod?: string;
  subject?: string;
  privateKey?: unknown;
}

export interface Ap2Mandate {
  token: string;
  did: string;
  publicKey: unknown;
  privateKey: unknown;
}

export function agentsbloom(config?: AgentsBloomConfig): AgentsBloomMiddleware;
export function setupTelemetry(options?: TelemetryOptions): Promise<TelemetryConfig>;
export function shutdown(): Promise<void>;
export function resolveProtocol(req: {
  headers?: Record<string, string | undefined>;
  path?: string;
  url?: string;
}): Protocol;
export function verifyAP2Mandates(
  headers?: Record<string, string | undefined>,
  body?: Record<string, unknown>,
  publicKeyOrOptions?: unknown | Ap2VerifyOptions
): Ap2VerificationResult;
export function createAp2Mandate(options: CreateAp2MandateOptions): Ap2Mandate;
export function didKeyFromEd25519PublicKey(publicKey: unknown): string;
export function ed25519PublicKeyFromDidKey(didKey: string): unknown | null;
export function resetAp2ReplayCache(): void;
