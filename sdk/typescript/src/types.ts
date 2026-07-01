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
