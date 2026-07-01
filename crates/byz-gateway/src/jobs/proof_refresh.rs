//! Background job: refresh ZK threshold proofs for all active agents.
//!
//! Runs every `config.gateway.proof_refresh_secs` seconds.
//! For each known agent: score → commitment → SP1 proof → Redis cache.
//! The hot-path trust-check only reads from Redis — never generates proofs.

use byz_proof::threshold::{ThresholdProveRequest, ThresholdProver};
use byz_reputation::commitment::ScoreCommitment;

use crate::state::AppState;

pub fn spawn(state: AppState) {
    let interval = std::time::Duration::from_secs(state.config.gateway.proof_refresh_secs);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            run_once(&state).await;
        }
    });
}

async fn run_once(state: &AppState) {
    let threshold = state.config.reputation.default_threshold;

    let agent_dids: Vec<byz_common::AgentDid> = {
        state.reputation.read().await.all_agent_dids()
    };

    if agent_dids.is_empty() {
        return;
    }

    tracing::debug!(count = agent_dids.len(), "proof-refresh: starting batch");
    let mut generated = 0u32;
    let mut skipped  = 0u32;

    for did in &agent_dids {
        let score = {
            let rep = state.reputation.read().await;
            match rep.score(did) {
                Ok(s) => s,
                Err(_) => { skipped += 1; continue; }
            }
        };

        if score.score < threshold {
            skipped += 1;
            continue;
        }

        let commitment = match ScoreCommitment::new(&score) {
            Ok(c)  => c,
            Err(e) => {
                tracing::warn!(did = %did, error = %e, "proof-refresh: commitment failed");
                skipped += 1;
                continue;
            }
        };

        let nonce = match hex::decode(&commitment.nonce_hex) {
            Ok(n)  => n,
            Err(_) => { skipped += 1; continue; }
        };

        let valid_for = (state.config.gateway.proof_refresh_secs * 2).max(120) as i64;
        let req = ThresholdProveRequest {
            commitment_hex: commitment.commitment_hex.clone(),
            threshold,
            score_private: score.score,
            nonce_private: nonce,
            valid_for_secs: valid_for,
        };

        // SP1 proof generation is CPU-heavy — run in blocking thread pool.
        let prove_result = tokio::task::spawn_blocking(move || ThresholdProver::prove(req))
            .await
            .unwrap_or_else(|_| Ok(None));

        let proof_opt = match prove_result {
            Ok(opt) => opt,
            Err(e) => {
                tracing::warn!(did = %did, error = %e, "proof-refresh: proof generation not supported");
                skipped += 1;
                continue;
            }
        };

        if let Some(proof) = proof_opt {
            if let Some(store) = &state.store {
                if let Err(e) = store.proof_cache.set_threshold_proof(did, &proof).await {
                    tracing::warn!(did = %did, error = %e, "proof-refresh: cache write failed");
                }
            }
            generated += 1;
        } else {
            skipped += 1;
        }
    }

    tracing::info!(generated, skipped, total = agent_dids.len(), "proof-refresh: done");
}
