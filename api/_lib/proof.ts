import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { ParsedInput } from "./decide";
import { deriveSalt, fieldElementFromValue } from "./util";

/**
 * The gatekeeper circuit's own verification-key hash, registered on zkVerify
 * mainnet (served by the platform at /api/circuit-info). Needed when
 * submitting proofs through Kurier; the in-response proof path does not use
 * it, but it is recorded here as the canonical reference.
 */
export const GATEKEEPER_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

export interface ProofBundle {
  proof: unknown;
  public_signals: string[];
}

/**
 * Circuit input semantics — determined experimentally against the official
 * gatekeeper.wasm (witness-calculator probing + constraint tests; the full
 * write-up is in the standalone agent's README "Proof module"):
 *
 *   13 scalar public inputs: decision, amount, maxTransfer, recipient,
 *   conditionRecipient, publicBalance, minimum, expiryBlock, currentBlock,
 *   taskId, registeredVkHash, proofVkHash, salt.
 *
 *   The circuit (template GatekeeperEvaluation) enforces:
 *     decision == 1  <=>  proofVkHash == registeredVkHash
 *                         AND recipient == conditionRecipient
 *                         AND publicBalance >= minimum
 *                         AND amount <= maxTransfer
 *                         AND currentBlock < expiryBlock   (strict)
 *     decision == 0  <=>  at least one of the above fails
 *   taskId and salt are unconstrained binders.
 *
 * Consequences for this module:
 *  - A proof can only be produced when the agent's decision AGREES with the
 *    circuit's evaluation of the envelope facts. Decisions rejected for
 *    agent-side-only reasons (replay, timestamps, finality, malformed input)
 *    while the circuit-level facts are all valid cannot be attested; the
 *    module returns null and the response omits the proof for those tasks.
 *  - Value encodings for hash/address/task-id fields are ASSUMED (see
 *    fieldElementFromValue). They are deterministic and documented, but the
 *    platform's canonical encoding is not published on /build.
 *
 * SERVERLESS ADAPTATION vs the standalone agent:
 *  - The circuit artifacts are loaded ONCE per warm instance as Buffers
 *    (fs.readFileSync) and cached in module scope, then passed to snarkjs
 *    fullProve as Uint8Arrays (verified working with snarkjs 0.7.6's
 *    CommonJS build — see the local harness, which verifies real proofs).
 *  - The files ship with the function via vercel.json `includeFiles`
 *    ("circuits/**") and are resolved from the project root
 *    (process.cwd()/circuits) with fallbacks for the local test layout.
 *  - No prove/verify self-test runs on cold start: it would add ~1-2 s to
 *    the first request for no benefit — the local harness exercises the
 *    exact prove + verify pipeline. runProofSelfTest remains exported for
 *    manual checks only.
 */

interface CircuitBuffers {
  wasm: Buffer;
  zkey: Buffer;
}

let circuitCache: CircuitBuffers | null | undefined;

/** Candidate directories for the circuit artifacts, most specific first. */
function circuitDirCandidates(): string[] {
  const dirs: string[] = [];
  if (process.env.CIRCUITS_DIR) dirs.push(process.env.CIRCUITS_DIR);
  // Vercel: the function runs with the project root as cwd and includeFiles
  // places circuits/ at the project root.
  dirs.push(join(process.cwd(), "circuits"));
  // Local compiled layout: dist/api/_lib/proof.js -> project root is 3 up.
  dirs.push(resolve(__dirname, "..", "..", "..", "circuits"));
  // Fallbacks for other bundling layouts.
  dirs.push(resolve(__dirname, "..", "..", "circuits"));
  dirs.push(resolve(__dirname, "..", "circuits"));
  return dirs;
}

function loadCircuitBuffers(): CircuitBuffers | null {
  if (circuitCache !== undefined) return circuitCache;
  circuitCache = null;

  const wasmOverride = process.env.CIRCUIT_WASM_PATH;
  const zkeyOverride = process.env.CIRCUIT_ZKEY_PATH;
  if (wasmOverride && zkeyOverride && existsSync(wasmOverride) && existsSync(zkeyOverride)) {
    circuitCache = {
      wasm: readFileSync(wasmOverride),
      zkey: readFileSync(zkeyOverride),
    };
    return circuitCache;
  }

  for (const dir of circuitDirCandidates()) {
    const wasm = join(dir, "gatekeeper.wasm");
    const zkey = join(dir, "gatekeeper_final.zkey");
    if (existsSync(wasm) && existsSync(zkey)) {
      circuitCache = { wasm: readFileSync(wasm), zkey: readFileSync(zkey) };
      return circuitCache;
    }
  }
  return null;
}

export function proofsEnabled(): boolean {
  return process.env.PROOF_ENABLED !== "false";
}

/** Build the 13 gatekeeper circuit inputs for a decision over a parsed task. */
export function buildCircuitInputs(
  parsed: ParsedInput,
  decision: 0 | 1,
  taskId: string,
): Record<string, string> {
  const rawSalt = parsed.raw.salt;
  const salt =
    rawSalt !== undefined && rawSalt !== null
      ? fieldElementFromValue(rawSalt)
      : deriveSalt(taskId);
  return {
    decision: String(decision),
    amount: parsed.amount.toString(),
    maxTransfer: parsed.maxTransfer.toString(),
    recipient: fieldElementFromValue(parsed.recipient).toString(),
    conditionRecipient: fieldElementFromValue(parsed.conditionRecipient).toString(),
    publicBalance: parsed.publicBalance.toString(),
    minimum: parsed.minimum.toString(),
    expiryBlock: parsed.expiryBlock.toString(),
    currentBlock: parsed.currentBlock.toString(),
    taskId: fieldElementFromValue(taskId).toString(),
    registeredVkHash: fieldElementFromValue(parsed.registeredVk).toString(),
    proofVkHash: fieldElementFromValue(parsed.proofVk).toString(),
    salt: salt.toString(),
  };
}

/**
 * Generate a real Groth16 proof (snarkjs fullProve) attesting the decision.
 * Returns null — never a fabricated proof — when proofs are disabled, the
 * artifacts are unavailable, or the decision is not circuit-attestable
 * (snarkjs assert failure).
 */
export async function generateDecisionProof(
  parsed: ParsedInput,
  decision: 0 | 1,
  taskId: string,
): Promise<ProofBundle | null> {
  if (!proofsEnabled()) return null;
  const circuits = loadCircuitBuffers();
  if (!circuits) {
    console.error("[proof] circuit artifacts not found; omitting proof");
    return null;
  }
  try {
    const snarkjs = await import("snarkjs");
    const inputs = buildCircuitInputs(parsed, decision, taskId);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      inputs,
      circuits.wasm,
      circuits.zkey,
    );
    return { proof, public_signals: publicSignals };
  } catch (err) {
    console.error(
      "[proof] proof generation failed (decision may not be circuit-attestable):",
      (err as Error).message.split("\n")[0],
    );
    return null;
  }
}

/**
 * Manual sanity check (NOT run automatically in serverless mode — see the
 * module header): prove a synthetic all-valid decision from buffers and
 * verify it against the verification key exported from the zkey.
 */
export async function runProofSelfTest(): Promise<boolean> {
  if (!proofsEnabled()) return false;
  const circuits = loadCircuitBuffers();
  if (!circuits) return false;
  try {
    const snarkjs = await import("snarkjs");
    const inputs: Record<string, string> = {
      decision: "1",
      amount: "50",
      maxTransfer: "100",
      recipient: "7",
      conditionRecipient: "7",
      publicBalance: "1000",
      minimum: "500",
      expiryBlock: "200",
      currentBlock: "150",
      taskId: "1",
      registeredVkHash: "999",
      proofVkHash: "999",
      salt: "1",
    };
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      inputs,
      circuits.wasm,
      circuits.zkey,
    );
    const vk = await snarkjs.zKey.exportVerificationKey(circuits.zkey);
    return await snarkjs.groth16.verify(vk, publicSignals, proof);
  } catch (err) {
    console.error("[proof] self-test failed:", (err as Error).message.split("\n")[0]);
    return false;
  }
}
