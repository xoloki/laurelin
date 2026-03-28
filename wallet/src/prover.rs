//! Interface to the `laurelin-prover` Go subprocess.
//!
//! The prover binary must be on PATH.  It reads a JSON witness from stdin and
//! writes a proof JSON object to stdout.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::Context;
use ark_bn254::{Fr, G1Affine};
use serde::{Deserialize, Serialize};

use crate::bn254::{fr_to_hex, g1_to_hex};

// ── Proof result ──────────────────────────────────────────────────────────────

/// Decoded output from laurelin-prover.
#[derive(Debug, Clone)]
pub struct ProofBytes {
    pub proof_a: [u8; 64],
    pub proof_b: [u8; 128],
    pub proof_c: [u8; 64],
    pub commitment: [u8; 64],
    pub commit_hash: [u8; 32],
}

#[derive(Deserialize)]
struct RawProofOutput {
    proof_a: String,
    proof_b: String,
    proof_c: String,
    commitment: String,
    commit_hash: String,
}

impl ProofBytes {
    fn from_raw(raw: RawProofOutput) -> anyhow::Result<Self> {
        Ok(ProofBytes {
            proof_a: decode_fixed::<64>(&raw.proof_a, "proof_a")?,
            proof_b: decode_fixed::<128>(&raw.proof_b, "proof_b")?,
            proof_c: decode_fixed::<64>(&raw.proof_c, "proof_c")?,
            commitment: decode_fixed::<64>(&raw.commitment, "commitment")?,
            commit_hash: decode_fixed::<32>(&raw.commit_hash, "commit_hash")?,
        })
    }
}

fn decode_fixed<const N: usize>(s: &str, field: &str) -> anyhow::Result<[u8; N]> {
    let bytes = hex::decode(s).with_context(|| format!("decode hex field {field}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("field {field}: expected {} bytes", N))
}

// ── Witness structs (serialised to JSON for the prover) ───────────────────────

#[derive(Serialize)]
pub struct DepositWitness<'a> {
    pub circuit: &'static str,
    pub pk_path: &'a str,
    pub r: String,
    pub pk: String,
    pub delta_c1: String,
    pub delta_c2: String,
    pub amount: u64,
}

#[derive(Serialize)]
pub struct WithdrawWitness<'a> {
    pub circuit: &'static str,
    pub pk_path: &'a str,
    pub sk: String,
    pub r_new: String,
    pub old_balance: u64,
    pub new_balance: u64,
    pub pk: String,
    pub old_c1: String,
    pub old_c2: String,
    pub new_c1: String,
    pub new_c2: String,
    pub amount: u64,
}

#[derive(Serialize)]
pub struct TransferWitness<'a> {
    pub circuit: &'static str,
    pub pk_path: &'a str,

    // Private witnesses
    pub sk: String,
    pub r_new: String,
    pub r_decoy: String,
    pub r_t: String,
    pub r_recv: String,
    pub b: u64,
    pub v: u64,
    pub bmv: u64,
    pub sender_idx: usize,
    pub recv_idx: usize,

    // Sender ring public inputs
    pub sender_pk_0: String,
    pub sender_pk_1: String,
    pub sender_old_c1_0: String,
    pub sender_old_c1_1: String,
    pub sender_old_c2_0: String,
    pub sender_old_c2_1: String,
    pub sender_new_c1_0: String,
    pub sender_new_c1_1: String,
    pub sender_new_c2_0: String,
    pub sender_new_c2_1: String,

    // Receiver ring public inputs
    pub recv_pk_0: String,
    pub recv_pk_1: String,
    pub recv_delta_c1_0: String,
    pub recv_delta_c2_0: String,
    pub recv_delta_c1_1: String,
    pub recv_delta_c2_1: String,
}

// ── Prover call ───────────────────────────────────────────────────────────────

/// Run `laurelin-prover`, write `witness_json` to its stdin, return proof.
fn call_prover(witness_json: &str) -> anyhow::Result<ProofBytes> {
    let mut child = Command::new("laurelin-prover")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // prover logs/errors visible to user
        .spawn()
        .context("spawn laurelin-prover (is it on PATH?)")?;

    child
        .stdin
        .take()
        .unwrap()
        .write_all(witness_json.as_bytes())
        .context("write witness to laurelin-prover stdin")?;

    let output = child
        .wait_with_output()
        .context("wait for laurelin-prover")?;

    anyhow::ensure!(
        output.status.success(),
        "laurelin-prover exited with status {}",
        output.status
    );

    let raw: RawProofOutput =
        serde_json::from_slice(&output.stdout).context("parse laurelin-prover output JSON")?;
    ProofBytes::from_raw(raw)
}

// ── Public helpers ────────────────────────────────────────────────────────────

/// Prove a deposit.
pub fn prove_deposit(
    pk_path: &str,
    r: &Fr,
    pk: &G1Affine,
    delta_c1: &G1Affine,
    delta_c2: &G1Affine,
    amount: u64,
) -> anyhow::Result<ProofBytes> {
    let w = DepositWitness {
        circuit: "deposit",
        pk_path,
        r: fr_to_hex(r),
        pk: g1_to_hex(pk),
        delta_c1: g1_to_hex(delta_c1),
        delta_c2: g1_to_hex(delta_c2),
        amount,
    };
    call_prover(&serde_json::to_string(&w)?)
}

/// Prove a withdrawal.
#[allow(clippy::too_many_arguments)]
pub fn prove_withdraw(
    pk_path: &str,
    sk: &Fr,
    r_new: &Fr,
    old_balance: u64,
    new_balance: u64,
    pk: &G1Affine,
    old_c1: &G1Affine,
    old_c2: &G1Affine,
    new_c1: &G1Affine,
    new_c2: &G1Affine,
    amount: u64,
) -> anyhow::Result<ProofBytes> {
    let w = WithdrawWitness {
        circuit: "withdraw",
        pk_path,
        sk: fr_to_hex(sk),
        r_new: fr_to_hex(r_new),
        old_balance,
        new_balance,
        pk: g1_to_hex(pk),
        old_c1: g1_to_hex(old_c1),
        old_c2: g1_to_hex(old_c2),
        new_c1: g1_to_hex(new_c1),
        new_c2: g1_to_hex(new_c2),
        amount,
    };
    call_prover(&serde_json::to_string(&w)?)
}

/// Prove a ring transfer.
#[allow(clippy::too_many_arguments)]
pub fn prove_transfer(
    pk_path: &str,
    sk: &Fr,
    r_new: &Fr,
    r_decoy: &Fr,
    r_t: &Fr,
    r_recv: &Fr,
    b: u64,
    v: u64,
    bmv: u64,
    sender_idx: usize,
    recv_idx: usize,
    sender_pks: [&G1Affine; 2],
    sender_old_c1: [&G1Affine; 2],
    sender_old_c2: [&G1Affine; 2],
    sender_new_c1: [&G1Affine; 2],
    sender_new_c2: [&G1Affine; 2],
    recv_pks: [&G1Affine; 2],
    recv_delta_c1: [&G1Affine; 2],
    recv_delta_c2: [&G1Affine; 2],
) -> anyhow::Result<ProofBytes> {
    let w = TransferWitness {
        circuit: "transfer",
        pk_path,
        sk: fr_to_hex(sk),
        r_new: fr_to_hex(r_new),
        r_decoy: fr_to_hex(r_decoy),
        r_t: fr_to_hex(r_t),
        r_recv: fr_to_hex(r_recv),
        b,
        v,
        bmv,
        sender_idx,
        recv_idx,
        sender_pk_0: g1_to_hex(sender_pks[0]),
        sender_pk_1: g1_to_hex(sender_pks[1]),
        sender_old_c1_0: g1_to_hex(sender_old_c1[0]),
        sender_old_c1_1: g1_to_hex(sender_old_c1[1]),
        sender_old_c2_0: g1_to_hex(sender_old_c2[0]),
        sender_old_c2_1: g1_to_hex(sender_old_c2[1]),
        sender_new_c1_0: g1_to_hex(sender_new_c1[0]),
        sender_new_c1_1: g1_to_hex(sender_new_c1[1]),
        sender_new_c2_0: g1_to_hex(sender_new_c2[0]),
        sender_new_c2_1: g1_to_hex(sender_new_c2[1]),
        recv_pk_0: g1_to_hex(recv_pks[0]),
        recv_pk_1: g1_to_hex(recv_pks[1]),
        recv_delta_c1_0: g1_to_hex(recv_delta_c1[0]),
        recv_delta_c2_0: g1_to_hex(recv_delta_c2[0]),
        recv_delta_c1_1: g1_to_hex(recv_delta_c1[1]),
        recv_delta_c2_1: g1_to_hex(recv_delta_c2[1]),
    };
    call_prover(&serde_json::to_string(&w)?)
}
