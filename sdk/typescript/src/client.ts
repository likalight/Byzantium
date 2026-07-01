import type {
  AgentRegistration,
  ByzantiumError,
  CreateMandateRequest,
  LiabilityReceipt,
  SpendMandate,
  TrustCheckRequest,
  TrustCheckResponse,
} from "./types.js";

export interface ByzantiumClientConfig {
  /** Byzantium gateway base URL, e.g. "https://gateway.byzantium.ai" */
  baseUrl: string;
  /** API key (Bearer token) */
  apiKey: string;
  /** Request timeout in ms. Default: 5000 */
  timeoutMs?: number;
}

/**
 * Byzantium agent SDK client.
 *
 * ```ts
 * const byz = new ByzantiumClient({
 *   baseUrl: "https://gateway.byzantium.ai",
 *   apiKey: process.env.BYZ_API_KEY!,
 * });
 *
 * const result = await byz.trustCheck({
 *   agent_did: "did:byz:my-agent",
 *   action_type: "Payment",
 *   rail_id: "x402",
 *   amount_cents: 5000,
 * });
 *
 * if (result.verdict.verdict !== "PASS") {
 *   throw new Error(`Trust check failed: ${result.verdict.verdict}`);
 * }
 * ```
 */
export class ByzantiumClient {
  private baseUrl: string;
  private apiKey: string;
  private timeoutMs: number;

  constructor(config: ByzantiumClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.apiKey = config.apiKey;
    this.timeoutMs = config.timeoutMs ?? 5000;
  }

  // ── Trust ─────────────────────────────────────────────────────────────────

  /**
   * Run a trust-check. This is the core hot-path call — <200ms guaranteed.
   * Returns PASS/FLAG/BLOCK + a signed PassToken on PASS.
   */
  async trustCheck(req: TrustCheckRequest): Promise<TrustCheckResponse> {
    return this.post<TrustCheckResponse>("/v1/trust-check", req);
  }

  /**
   * Convenience: throw if trust-check doesn't PASS.
   * Attach the returned PassToken to the downstream request.
   */
  async requirePass(req: TrustCheckRequest): Promise<NonNullable<TrustCheckResponse["token"]>> {
    const result = await this.trustCheck(req);
    if (result.verdict.verdict !== "PASS" || !result.token) {
      const reason =
        "reason" in result.verdict ? result.verdict.reason : result.verdict.verdict;
      throw new ByzantiumTrustError(result.verdict.verdict as any, reason, result.request_id);
    }
    return result.token;
  }

  // ── Mandates ──────────────────────────────────────────────────────────────

  async createMandate(req: CreateMandateRequest): Promise<SpendMandate> {
    return this.post<SpendMandate>("/v1/mandates", req);
  }

  async getMandate(mandateId: string): Promise<SpendMandate> {
    return this.get<SpendMandate>(`/v1/mandates/${mandateId}`);
  }

  async revokeMandate(mandateId: string): Promise<void> {
    await this.post<void>(`/v1/mandates/${mandateId}/revoke`, {});
  }

  // ── Receipts ──────────────────────────────────────────────────────────────

  async createReceipt(receipt: Omit<LiabilityReceipt, "id" | "timestamp">): Promise<LiabilityReceipt> {
    return this.post<LiabilityReceipt>("/v1/receipts", receipt);
  }

  async getInclusionProof(receiptId: string): Promise<unknown> {
    return this.get(`/v1/receipts/${receiptId}/proof`);
  }

  // ── Agents ────────────────────────────────────────────────────────────────

  async registerAgent(reg: AgentRegistration): Promise<{ agent_did: string }> {
    return this.post("/v1/agents", reg);
  }

  async getAgent(did: string): Promise<AgentRegistration> {
    return this.get<AgentRegistration>(`/v1/agents/${encodeURIComponent(did)}`);
  }

  async deactivateAgent(did: string): Promise<void> {
    await this.post<void>(`/v1/agents/${encodeURIComponent(did)}/deactivate`, {});
  }

  // ── Audit ─────────────────────────────────────────────────────────────────

  async listAuditReceipts(params?: {
    agent_did?: string;
    limit?: number;
    from?: string;
    to?: string;
  }): Promise<unknown> {
    const qs = params ? "?" + new URLSearchParams(params as Record<string, string>).toString() : "";
    return this.get(`/v1/audit/receipts${qs}`);
  }

  // ── Health ────────────────────────────────────────────────────────────────

  async health(): Promise<{ status: string; version: string }> {
    return this.get("/health");
  }

  // ── Private HTTP helpers ──────────────────────────────────────────────────

  private async post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>("POST", path, body);
  }

  private async get<T>(path: string): Promise<T> {
    return this.request<T>("GET", path);
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (response.status === 429) {
      const retryAfter = response.headers.get("retry-after") ?? "1";
      throw new ByzantiumRateLimitError(parseInt(retryAfter, 10) * 1000);
    }

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const err = data as ByzantiumError;
      throw new ByzantiumApiError(response.status, err.error ?? "unknown error", path);
    }

    return data as T;
  }
}

// ── Error classes ─────────────────────────────────────────────────────────────

export class ByzantiumTrustError extends Error {
  constructor(
    public readonly verdict: "FLAG" | "BLOCK",
    public readonly reason: string,
    public readonly requestId: string,
  ) {
    super(`Trust check ${verdict}: ${reason}`);
    this.name = "ByzantiumTrustError";
  }
}

export class ByzantiumApiError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string,
    public readonly path: string,
  ) {
    super(`Byzantium API error ${statusCode} at ${path}: ${message}`);
    this.name = "ByzantiumApiError";
  }
}

export class ByzantiumRateLimitError extends Error {
  constructor(public readonly retryAfterMs: number) {
    super(`Rate limited — retry after ${retryAfterMs}ms`);
    this.name = "ByzantiumRateLimitError";
  }
}
