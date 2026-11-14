import {
  DecisionResult,
  GatekeeperInput,
  ReasonCode,
  TaskEnvelope,
} from "./types";
import { asString, normalizeId, parseTimestampToSec, toBigIntStrict } from "./util";

/** Gatekeeper input with numeric fields parsed and validated. */
export interface ParsedInput {
  raw: GatekeeperInput;
  proofVk: string;
  registeredVk: string;
  recipient: string;
  conditionRecipient: string;
  proofTx: string;
  publicBalance: bigint;
  minimum: bigint;
  amount: bigint;
  maxTransfer: bigint;
  currentBlock: bigint;
  expiryBlock: bigint;
}

/**
 * Parse and shape-check the envelope's input object. Returns an error
 * reason_code instead of throwing so the caller can fail closed with a
 * deterministic REJECT.
 */
export function parseGatekeeperInput(
  input: GatekeeperInput | undefined,
): { parsed: ParsedInput } | { error: string } {
  if (!input || typeof input !== "object") return { error: ReasonCode.MissingField };

  const proofVk = asString(input.proof_vk);
  const registeredVk = asString(input.registered_vk);
  const recipient = asString(input.recipient);
  const conditionRecipient = asString(input.condition_recipient);
  const proofTx = asString(input.proof_tx);
  if (
    !proofVk?.trim() ||
    !registeredVk?.trim() ||
    !recipient?.trim() ||
    !conditionRecipient?.trim() ||
    !proofTx?.trim()
  ) {
    return { error: ReasonCode.MissingField };
  }

  const publicBalance = toBigIntStrict(input.public_balance);
  const minimum = toBigIntStrict(input.minimum);
  const amount = toBigIntStrict(input.amount);
  const maxTransfer = toBigIntStrict(input.max_transfer);
  const currentBlock = toBigIntStrict(input.current_block);
  const expiryBlock = toBigIntStrict(input.expiry_block);
  if (
    publicBalance === null ||
    minimum === null ||
    amount === null ||
    maxTransfer === null ||
    currentBlock === null ||
    expiryBlock === null
  ) {
    return { error: ReasonCode.InvalidField };
  }

  return {
    parsed: {
      raw: input,
      proofVk: proofVk.trim(),
      registeredVk: registeredVk.trim(),
      recipient: recipient.trim(),
      conditionRecipient: conditionRecipient.trim(),
      proofTx: proofTx.trim(),
      publicBalance,
      minimum,
      amount,
      maxTransfer,
      currentBlock,
      expiryBlock,
    },
  };
}

export interface DecisionContext {
  /** Current time, epoch seconds (injected for determinism in tests). */
  nowSec: number;
  /** True if this proof_tx was already consumed by an earlier task. */
  replaySeen: boolean;
}

export interface Evaluation {
  result: DecisionResult;
  /** Present when the input parsed cleanly (needed to build proof inputs). */
  parsed?: ParsedInput;
}

const reject = (reason_code: string): DecisionResult => ({
  decision: "REJECT",
  reason_code,
});

/**
 * The deterministic Proof Gatekeeper decision function. No LLM, no network,
 * no randomness: the same envelope always yields the same decision.
 *
 * Implements the /build Security checklist, in order:
 *   0. envelope shape + task signature/timestamp sanity (HMAC itself is
 *      verified by the HTTP layer before this runs);
 *   1. proof system is the expected one (when the envelope declares it);
 *   2. the submitted proof's verification reached a finalized state
 *      (when the envelope declares finality);
 *   3. VK matches the key registered for this condition — VK_SUBSTITUTION;
 *   4. public inputs prove the required recipient — RECIPIENT_MISMATCH;
 *   5. public inputs prove the required threshold — INSUFFICIENT_BALANCE;
 *   6. public inputs prove an amount within the action limit — AMOUNT_OVER_MAX;
 *   7. the authorisation has not expired — EXPIRED
 *      (the gatekeeper circuit treats expiry_block as the first invalid
 *      block: approval requires current_block < expiry_block — verified
 *      experimentally against gatekeeper.wasm, see README);
 *   8. the proof reference has not been used by another task — PROOF_REPLAY.
 * APPROVE only when every check passes. Anything unknown fails closed.
 */
export function evaluateTask(envelope: TaskEnvelope, ctx: DecisionContext): Evaluation {
  try {
    // The input object is authoritative; fall back to top-level fields so a
    // flat envelope variant still parses (documented tolerance, README).
    const rawInput = envelope.input ?? (envelope as unknown as GatekeeperInput);
    const parsedOrError = parseGatekeeperInput(rawInput);
    if ("error" in parsedOrError) return { result: reject(parsedOrError.error) };
    const { parsed } = parsedOrError;
    const input = parsed.raw;

    // --- Task timestamp sanity -------------------------------------------
    const issuedAt = parseTimestampToSec(envelope.issued_at ?? inputTimestamp(input));
    const deadlineAt = parseTimestampToSec(envelope.deadline_at ?? inputTimestamp(input, "deadline_at"));
    if (issuedAt === null || deadlineAt === null || deadlineAt <= issuedAt) {
      return { result: reject(ReasonCode.InvalidTimestamp), parsed };
    }
    if (issuedAt > ctx.nowSec + 300) {
      return { result: reject(ReasonCode.IssuedInFuture), parsed };
    }
    if (ctx.nowSec > deadlineAt) {
      return { result: reject(ReasonCode.DeadlinePassed), parsed };
    }

    // --- Checklist 1: expected circuit / proof system ---------------------
    if (
      typeof input.proof_system === "string" &&
      input.proof_system.trim().toLowerCase() !== "groth16"
    ) {
      return { result: reject(ReasonCode.UnsupportedProofSystem), parsed };
    }

    // --- Checklist 2: verification finalized before approval --------------
    if (input.finalized === false) {
      return { result: reject(ReasonCode.NotFinalized), parsed };
    }
    if (
      typeof input.verification_status === "string" &&
      input.verification_status.trim().toLowerCase() !== "finalized"
    ) {
      return { result: reject(ReasonCode.NotFinalized), parsed };
    }

    // --- Checklist 3: VK matches the registered key -----------------------
    if (normalizeId(parsed.proofVk) !== normalizeId(parsed.registeredVk)) {
      return { result: reject(ReasonCode.VkSubstitution), parsed };
    }

    // --- Checklist 4: recipient proven by public inputs -------------------
    if (normalizeId(parsed.recipient) !== normalizeId(parsed.conditionRecipient)) {
      return { result: reject(ReasonCode.RecipientMismatch), parsed };
    }

    // --- Checklist 5: threshold (balance) proven --------------------------
    if (parsed.publicBalance < parsed.minimum) {
      return { result: reject(ReasonCode.InsufficientBalance), parsed };
    }

    // --- Checklist 6: amount within the action limit ----------------------
    if (parsed.amount > parsed.maxTransfer) {
      return { result: reject(ReasonCode.AmountOverMax), parsed };
    }

    // --- Checklist 7: not expired (circuit semantics: strict <) -----------
    if (parsed.currentBlock >= parsed.expiryBlock) {
      return { result: reject(ReasonCode.Expired), parsed };
    }

    // --- Checklist 8: proof reference not replayed ------------------------
    if (ctx.replaySeen) {
      return { result: reject(ReasonCode.ProofReplay), parsed };
    }

    return { result: { decision: "APPROVE", reason_code: ReasonCode.AllChecksPassed }, parsed };
  } catch {
    // Fail closed on any surprise.
    return { result: reject(ReasonCode.InternalError) };
  }
}

function inputTimestamp(input: GatekeeperInput, key: "issued_at" | "deadline_at" = "issued_at"): unknown {
  return (input as unknown as Record<string, unknown>)[key];
}
