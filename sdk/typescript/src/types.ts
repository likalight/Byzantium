// Core domain types mirroring the Byzantium Rust types

export type ActionType =
  | "Payment"
  | "ApiCall"
  | "DataAccess"
  | "ContractExecution"
  | "CrossAgentDelegation"
  | { Custom: string };

export interface Counterparty {
  id: string;
  chain?: string;
  address?: string;
}

export type TrustVerdict =
  | { verdict: "PASS" }
  | { verdict: "FLAG"; reason: string }
  | { verdict: "BLOCK"; reason: string };

export interface PassToken {
  agent_did: string;
  verdict: TrustVerdict;
  mandate_hash: string;
  reputation_threshold_met: boolean;
  valid_until: string; // ISO 8601
  signature: number[]; // ML-DSA signature bytes
}

export interface TrustCheckRequest {
  agent_did: string;
  action_type: ActionType;
  rail_id: string;
  amount_cents?: number;
  counterparty?: Counterparty;
}

export interface TrustCheckResponse {
  verdict: TrustVerdict;
  token?: PassToken;
  request_id: string;
  checked_at: string;
  latency_ms: number;
}

export interface SpendMandate {
  id: string;
  agent_did: string;
  operator_id: string;
  counterparty_whitelist: string[];
  allowed_action_types: ActionType[];
  per_tx_cap_cents: number;
  daily_cap_cents: number;
  valid_from: string;
  valid_until: string;
}

export interface CreateMandateRequest {
  agent_did: string;
  operator_id: string;
  counterparty_whitelist?: string[];
  allowed_action_types: ActionType[];
  per_tx_cap_cents: number;
  daily_cap_cents: number;
  valid_from?: string;
  valid_until: string;
}

export interface LiabilityReceipt {
  id: string;
  agent_did: string;
  action_type: ActionType;
  counterparty?: Counterparty;
  amount_cents?: number;
  outcome: "Success" | "Failure" | "Reverted" | "Disputed";
  mandate_id: string;
  rail_id: string;
  timestamp: string;
}

export interface AgentRegistration {
  agent_did: string;
  operator_id: string;
  public_key_hex: string;
  metadata?: Record<string, string>;
}

export interface ByzantiumError {
  error: string;
  code?: string;
}

// ------------------------------- Underwriting --------------------------------

export type KycTier = "unverified" | "basic" | "verified" | "institutional";
export type Currency = "USD" | "SGD" | "EUR" | "GBP" | "JPY";
export type AssetClass = "stablecoin" | "major_fiat" | "volatile";
export type LiabilityModel = "bureau" | "underwritten";

/** An amount in minor units. Integer-only: a limit that drifts can be crossed. */
export interface Money {
  minor_units: number;
  currency: Currency;
}

export interface RegisterPrincipalRequest {
  agent_did: string;
  principal_ref: string;
  kyc_tier: KycTier;
  sanctions_clear: boolean;
  jurisdiction?: string;
  entity_age_days?: number;
}

export interface PrincipalRegistration {
  agent_did: string;
  principal_ref: string;
  kyc_tier: KycTier;
  eligible: boolean;
  agents_under_principal: number;
}

export interface LimitScope {
  chains: string[];
  asset_classes: AssetClass[];
  counterparty_classes: string[];
  action_types: ActionType[];
}

/** Who bears the loss if the limit turns out to be wrong. */
export interface Guarantee {
  model: LiabilityModel;
  guarantor: string;
  covered: Money;
}

/** The portable credential. Short-lived by design. */
export interface LimitAttestation {
  sub: string;
  prn: string;
  iss: string;
  tier: string;
  lim_single: Money;
  lim_window: Money;
  window_secs: number;
  ccy: Currency;
  scope: LimitScope;
  fee_bps: number;
  collateral_bps: number;
  nbf: string;
  exp: string;
  /** Merkle commitment over the evidence. Never the evidence itself. */
  ev: string;
  mandate_hash: string;
  guarantee?: Guarantee | null;
  collateral_required?: Money | null;
  signature?: number[] | null;
  issuer_pubkey?: string | null;
}

export interface IssueLimitRequest {
  agent_did: string;
  ccy?: Currency;
  chains?: string[];
  asset_classes?: AssetClass[];
  counterparty_classes?: string[];
  action_types?: ActionType[];
}

export interface IssueLimitResponse {
  issued: boolean;
  attestation: LimitAttestation | null;
  tier: string;
  score: number;
  /** Every control that shaped the limit, in order. */
  reasons: string[];
  refusal?: string;
}

export interface DrawInput {
  amount_minor: number;
  currency: Currency;
  asset_class: AssetClass;
  chain: string;
  action_type: ActionType;
  counterparty_class?: string | null;
}

export interface VerifyLimitRequest {
  attestation: LimitAttestation;
  draw: DrawInput;
}

export interface VerifyLimitResponse {
  permitted: boolean;
  /** The draw in the attestation's unit of account, after the haircut. */
  effective_minor: number;
  effective_ccy: string;
  window_used_minor: number;
  fee_minor: number;
  refusal?: string;
}

export interface SettleDrawRequest {
  agent_did: string;
  amount_minor: number;
  currency: Currency;
  /** False releases the exposure instead of consuming window capacity. */
  settled: boolean;
}

export interface RevokeLimitsRequest {
  agent_did?: string;
  principal_ref?: string;
  /** Future values schedule the cutoff rather than firing it immediately. */
  effective_from?: string;
}

export interface SubmitProvenanceResponse {
  accepted: number;
  rejected: number;
  rejections: string[];
  acceptance_rate_bps: number;
  evidence_ref: string;
  weighted_total: number;
  human_approvals: number;
}
