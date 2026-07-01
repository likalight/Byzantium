/**
 * Drop-in middleware for common agent frameworks.
 * Each middleware calls Byzantium trust-check before allowing the action.
 */

import { ByzantiumClient, ByzantiumTrustError } from "./client.js";
import type { ActionType, Counterparty, PassToken } from "./types.js";

export interface TrustMiddlewareOptions {
  client: ByzantiumClient;
  agentDid: string;
  railId?: string;
  /** Called when trust-check blocks. Default: throw ByzantiumTrustError */
  onBlock?: (reason: string) => void | Promise<void>;
}

// ── Anthropic tool-use middleware ─────────────────────────────────────────────

export interface AnthropicToolInput {
  amount_cents?: number;
  counterparty_id?: string;
  [key: string]: unknown;
}

/**
 * Wrap an Anthropic tool handler with Byzantium trust-check.
 *
 * ```ts
 * const safeTool = withByzantiumCheck(paymentTool, {
 *   client: byz,
 *   agentDid: "did:byz:my-agent",
 *   railId: "x402",
 * });
 * ```
 */
export function withByzantiumCheck<TInput extends AnthropicToolInput, TOutput>(
  toolFn: (input: TInput) => TOutput | Promise<TOutput>,
  opts: TrustMiddlewareOptions & { actionType: ActionType },
): (input: TInput) => Promise<TOutput> {
  return async (input: TInput): Promise<TOutput> => {
    const counterparty: Counterparty | undefined = input.counterparty_id
      ? { id: input.counterparty_id }
      : undefined;

    const token = await opts.client.requirePass({
      agent_did: opts.agentDid,
      action_type: opts.actionType,
      rail_id: opts.railId ?? "custom",
      amount_cents: input.amount_cents,
      counterparty,
    });

    // Attach pass token to input for downstream audit
    (input as any).__byz_pass_token = token;
    return toolFn(input);
  };
}

// ── OpenAI function-calling middleware ────────────────────────────────────────

export interface OpenAIFunctionArgs {
  amount_cents?: number;
  counterparty_id?: string;
  [key: string]: unknown;
}

export function withByzantiumCheckOAI<TArgs extends OpenAIFunctionArgs, TOutput>(
  fn: (args: TArgs) => TOutput | Promise<TOutput>,
  opts: TrustMiddlewareOptions & { actionType: ActionType },
): (args: TArgs) => Promise<TOutput> {
  return withByzantiumCheck(fn as any, opts) as any;
}

// ── LangChain tool wrapper ────────────────────────────────────────────────────

export interface ByzantiumLangChainTool {
  name: string;
  description: string;
  call: (input: string) => Promise<string>;
  _agentDid: string;
  _passToken?: PassToken;
}

/**
 * Wrap a LangChain-style tool string-in/string-out with trust-check.
 * Parses JSON input to extract amount_cents and counterparty_id if present.
 */
export function wrapLangChainTool(
  tool: { name: string; description: string; call: (input: string) => Promise<string> },
  opts: TrustMiddlewareOptions & { actionType: ActionType },
): ByzantiumLangChainTool {
  return {
    name: tool.name,
    description: tool.description,
    _agentDid: opts.agentDid,

    async call(input: string): Promise<string> {
      let parsed: OpenAIFunctionArgs = {};
      try {
        parsed = JSON.parse(input);
      } catch {
        // Non-JSON input — no amount/counterparty to extract
      }

      const token = await opts.client.requirePass({
        agent_did: opts.agentDid,
        action_type: opts.actionType,
        rail_id: opts.railId ?? "custom",
        amount_cents: parsed.amount_cents,
        counterparty: parsed.counterparty_id ? { id: parsed.counterparty_id } : undefined,
      });

      (this as any)._passToken = token;
      return tool.call(input);
    },
  };
}
