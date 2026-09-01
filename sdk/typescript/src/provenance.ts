/**
 * Runtime-signed execution provenance.
 *
 * This is the integration that makes an agent's off-chain behaviour usable as
 * underwriting evidence, and it is deliberately the only part of the SDK that an
 * agent framework has to embed.
 *
 * # Why the SDK does not hold a key
 *
 * The rule the gateway enforces is that the *runtime* signs, not the agent. An
 * agent attesting to its own good behaviour is a claim, not evidence. So this
 * module never generates, stores, or touches key material: it builds the exact
 * canonical bytes the gateway will verify and hands them to a `sign` function you
 * supply, which should be backed by an HSM, a KMS, or at minimum a key the agent
 * process cannot read.
 *
 * That also avoids shipping a post-quantum signature implementation in
 * JavaScript, which would be the weakest link in the chain rather than the
 * strongest.
 *
 * @example
 * ```ts
 * const recorder = new ProvenanceRecorder({
 *   agentDid: "did:byz:trader-01",
 *   runtimeId: "runtime-1",
 *   sign: (bytes) => kms.signMlDsa(bytes),
 * });
 *
 * await recorder.record("tool_call", { tool: "fetch_quote" });
 * await recorder.record("human_approval", { approver: "ops@acme.com" });
 * await client.submitProvenance(recorder.drain());
 * ```
 */

/** Kinds of execution step, mirroring the gateway's `ProvenanceKind`. */
export type ProvenanceKind =
  | "tool_call"
  | "plan"
  | "memory_write"
  | "human_approval"
  | "observation"
  | "payment_intent";

export interface ProvenanceEvent {
  agent_did: string;
  session_id: string;
  seq: number;
  kind: ProvenanceKind;
  /** RFC 3339 timestamp. */
  at: string;
  /** `sha256:<hex>` over the payload. The payload itself never leaves. */
  payload_hash: string;
  label?: string | null;
  ok: boolean;
}

export interface SignedProvenance {
  event: ProvenanceEvent;
  runtime_id: string;
  /** Raw signature bytes. */
  signature: number[];
}

/** Signs canonical bytes with the runtime key. Never given to the agent. */
export type RuntimeSigner = (bytes: Uint8Array) => Promise<Uint8Array> | Uint8Array;

export interface ProvenanceRecorderOptions {
  agentDid: string;
  runtimeId: string;
  sign: RuntimeSigner;
  /** Defaults to a fresh random session. */
  sessionId?: string;
  /**
   * Hashes a payload to `sha256:<hex>`. Defaults to WebCrypto, which is
   * available in Node 18+ and every modern browser.
   */
  hash?: (bytes: Uint8Array) => Promise<string>;
}

function randomUuid(): string {
  const c = globalThis.crypto;
  if (c && typeof c.randomUUID === "function") return c.randomUUID();
  // Fallback for environments without randomUUID. Only used for session
  // grouping, never for anything security-bearing.
  const b = new Uint8Array(16);
  if (c && typeof c.getRandomValues === "function") c.getRandomValues(b);
  else for (let i = 0; i < 16; i++) b[i] = Math.floor(Math.random() * 256);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

async function defaultHash(bytes: Uint8Array): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error(
      "WebCrypto is unavailable; pass a `hash` function to ProvenanceRecorder",
    );
  }
  const digest = await subtle.digest("SHA-256", bytes as BufferSource);
  const hex = [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `sha256:${hex}`;
}

/**
 * Canonical signing bytes for an event.
 *
 * Key order is fixed and must match the gateway exactly — it rebuilds this
 * string independently and compares signatures, so a different ordering is
 * indistinguishable from a forgery. The keys are in the same sorted order Rust's
 * `serde_json::Map` (a BTreeMap) produces.
 */
export function signingPayload(event: ProvenanceEvent): Uint8Array {
  const canonical = {
    agent_did: event.agent_did,
    at: Date.parse(event.at),
    kind: event.kind,
    label: event.label ?? null,
    ok: event.ok,
    payload_hash: event.payload_hash,
    seq: event.seq,
    session_id: event.session_id,
  };
  return new TextEncoder().encode(JSON.stringify(canonical));
}

export class ProvenanceRecorder {
  private readonly agentDid: string;
  private readonly runtimeId: string;
  private readonly sessionId: string;
  private readonly sign: RuntimeSigner;
  private readonly hash: (bytes: Uint8Array) => Promise<string>;
  private seq = 0;
  private buffer: SignedProvenance[] = [];

  constructor(opts: ProvenanceRecorderOptions) {
    if (!opts.agentDid) throw new Error("agentDid is required");
    if (!opts.runtimeId) throw new Error("runtimeId is required");
    if (typeof opts.sign !== "function") {
      throw new Error("a sign function is required — the runtime signs, not the agent");
    }
    this.agentDid = opts.agentDid;
    this.runtimeId = opts.runtimeId;
    this.sessionId = opts.sessionId ?? randomUuid();
    this.sign = opts.sign;
    this.hash = opts.hash ?? defaultHash;
  }

  get session(): string {
    return this.sessionId;
  }

  /** Number of events waiting to be submitted. */
  get pending(): number {
    return this.buffer.length;
  }

  /**
   * Record one execution step.
   *
   * `payload` is hashed locally and discarded — only the digest is ever
   * transmitted, so tool arguments, plans, and memory contents stay with the
   * operator. Sequence numbers are assigned here and must be strictly
   * increasing within a session; the gateway rejects gaps backwards and repeats
   * as replay.
   */
  async record(
    kind: ProvenanceKind,
    payload: unknown,
    opts: { label?: string; ok?: boolean; at?: Date } = {},
  ): Promise<SignedProvenance> {
    const encoded =
      payload instanceof Uint8Array
        ? payload
        : new TextEncoder().encode(
            typeof payload === "string" ? payload : JSON.stringify(payload ?? null),
          );

    const event: ProvenanceEvent = {
      agent_did: this.agentDid,
      session_id: this.sessionId,
      seq: ++this.seq,
      kind,
      at: (opts.at ?? new Date()).toISOString(),
      payload_hash: await this.hash(encoded),
      label: opts.label ?? null,
      ok: opts.ok ?? true,
    };

    const signature = await this.sign(signingPayload(event));
    const signed: SignedProvenance = {
      event,
      runtime_id: this.runtimeId,
      signature: Array.from(signature),
    };
    this.buffer.push(signed);
    return signed;
  }

  /** Take everything buffered, leaving the recorder empty. */
  drain(): SignedProvenance[] {
    const out = this.buffer;
    this.buffer = [];
    return out;
  }

  /** Look without taking. */
  peek(): readonly SignedProvenance[] {
    return this.buffer;
  }
}
