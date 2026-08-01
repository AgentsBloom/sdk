/**
 * OTLP trace exporter initialization for the AgentsBloom SDK.
 *
 * The OpenTelemetry SDK packages required to actually export spans
 * (@opentelemetry/sdk-trace-node, sdk-trace-base, exporter-trace-otlp-http,
 * resources, semantic-conventions) are loaded via dynamic import() so that
 * a merchant application that never calls setupTelemetry() is never forced
 * to install them. They are declared as optionalDependencies in
 * package.json rather than dependencies.
 */

/**
 * Initialize an OTLP trace exporter/provider pair.
 *
 * @param {Object} options
 * @param {string} options.otlpEndpoint - OTLP collector base URL (traces are posted to `${otlpEndpoint}/v1/traces`)
 * @param {string} options.serviceName - Service name attached as the resource's service.name attribute
 * @param {number} options.samplingRatio - Trace sampling ratio 0.0-1.0 (currently informational; not yet wired into a sampler)
 * @param {string} options.apiKey - API key sent as a Bearer token in the exporter's Authorization header
 * @returns {Promise<{ provider: import('@opentelemetry/sdk-trace-node').NodeTracerProvider, exporter: import('@opentelemetry/exporter-trace-otlp-http').OTLPTraceExporter } | null>}
 *   The initialized provider/exporter handle, or null if the optional OTel SDK packages are unavailable.
 */
let optionalDependencyWarningLogged = false;

export async function initExporter({ otlpEndpoint, serviceName, samplingRatio, apiKey } = {}) {
  try {
    const { NodeTracerProvider } = await import('@opentelemetry/sdk-trace-node');
    const { BatchSpanProcessor } = await import('@opentelemetry/sdk-trace-base');
    const { OTLPTraceExporter } = await import('@opentelemetry/exporter-trace-otlp-http');
    const { Resource } = await import('@opentelemetry/resources');
    const { SemanticResourceAttributes } = await import('@opentelemetry/semantic-conventions');

    const exporter = new OTLPTraceExporter({
      url: `${otlpEndpoint}/v1/traces`,
      headers: { Authorization: `Bearer ${apiKey}` },
    });
    const provider = new NodeTracerProvider({
      resource: new Resource({ [SemanticResourceAttributes.SERVICE_NAME]: serviceName }),
    });
    provider.addSpanProcessor(new BatchSpanProcessor(exporter));
    provider.register();
    return { provider, exporter };
  } catch {
    if (!optionalDependencyWarningLogged) {
      optionalDependencyWarningLogged = true;
      console.warn('🌸 AgentsBloom: OTel SDK packages unavailable, continuing without export.');
    }
    return null;
  }
}
