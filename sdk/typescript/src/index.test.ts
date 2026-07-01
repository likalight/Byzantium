import { describe, expect, it, vi } from "vitest";
import { ByzantiumClient, ByzantiumTrustError } from "./client.js";

function mockClient(verdict: "PASS" | "FLAG" | "BLOCK", reason?: string) {
  const client = new ByzantiumClient({ baseUrl: "http://localhost:8080", apiKey: "test" });

  const mockFetch = vi.fn().mockResolvedValue({
    ok: verdict === "PASS",
    status: verdict === "PASS" ? 200 : 403,
    json: async () => ({
      verdict: verdict === "PASS"
        ? { verdict: "PASS" }
        : { verdict, reason: reason ?? "test block" },
      token: verdict === "PASS" ? {
        agent_did: "did:byz:test",
        verdict: { verdict: "PASS" },
        mandate_hash: "abc123",
        reputation_threshold_met: true,
        valid_until: new Date(Date.now() + 30000).toISOString(),
        signature: [],
      } : undefined,
      request_id: "req-001",
      checked_at: new Date().toISOString(),
      latency_ms: 15,
    }),
    headers: { get: () => null },
  });

  vi.stubGlobal("fetch", mockFetch);
  return client;
}

describe("ByzantiumClient", () => {
  it("trustCheck returns PASS with token", async () => {
    const client = mockClient("PASS");
    const result = await client.trustCheck({
      agent_did: "did:byz:test",
      action_type: "Payment",
      rail_id: "x402",
      amount_cents: 1000,
    });
    expect(result.verdict.verdict).toBe("PASS");
    expect(result.token).toBeDefined();
  });

  it("requirePass throws ByzantiumTrustError on BLOCK", async () => {
    const client = mockClient("BLOCK", "daily cap exceeded");
    await expect(client.requirePass({
      agent_did: "did:byz:test",
      action_type: "Payment",
      rail_id: "x402",
    })).rejects.toThrow(ByzantiumTrustError);
  });

  it("ByzantiumTrustError carries verdict and reason", async () => {
    const client = mockClient("BLOCK", "counterparty not in whitelist");
    try {
      await client.requirePass({
        agent_did: "did:byz:test",
        action_type: "Payment",
        rail_id: "x402",
      });
    } catch (e) {
      expect(e).toBeInstanceOf(ByzantiumTrustError);
      const err = e as ByzantiumTrustError;
      expect(err.verdict).toBe("BLOCK");
      expect(err.reason).toContain("counterparty");
    }
  });
});
