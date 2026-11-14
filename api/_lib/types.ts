/**
 * Protocol types for the zkVerify Agent Games — Proof Gatekeeper event.
 * Field names follow the /build specification as captured in the project brief.
 */

export const PREFLIGHT_TYPE = "agent-games.preflight.v1";
export const GATEKEEPER_TASK_TYPE = "agent-games.proof-gatekeeper.v1";

/** The `input` object of a gatekeeper task envelope: the transfer under review. */
export interface GatekeeperInput {
  /** Verification key of the proof attached to the transfer request. */
  proof_vk: string;
  /** Verification key registered for the condition being enforced. */
  registered_vk: string;
  /** Recipient the transfer wants to pay. */
  recipient: string;
  /** Recipient the condition requires. */
  condition_recipient: string;
  /** Publicly proven balance (integer, smallest unit). */
  public_balance: string | number;
  /** Minimum balance the condition requires. */
  minimum: string | number;
  /** Transfer amount requested. */
  amount: string | number;
  /** Maximum transfer the condition allows. */
  max_transfer: string | number;
  /** Current block height. */
  current_block: string | number;
  /** Block height at which the authorisation expires. */
  expiry_block: string | number;
  /** Reference of the submitted proof — must never repeat across tasks. */
  proof_tx: string;
  /** Optional: proof system of the submitted proof (expected "groth16"). */
  proof_system?: string;
  /** Optional: finality flag of the submitted proof's verification. */
  finalized?: boolean;
  /** Optional: finality status string (expected "finalized"). */
  verification_status?: string;
  /** Optional: per-task salt bound into the decision proof. */
  salt?: string | number;
}

export interface TaskEnvelope {
  type: string;
  task_id?: string | number;
  /** ISO-8601 string or epoch seconds/milliseconds. */
  issued_at?: string | number;
  /** ISO-8601 string or epoch seconds/milliseconds. */
  deadline_at?: string | number;
  input?: GatekeeperInput;
}

export type Decision = "APPROVE" | "REJECT";

export interface DecisionResult {
  decision: Decision;
  reason_code: string;
}

/** Reason codes emitted by the deterministic decision function. */
export const ReasonCode = {
  AllChecksPassed: "ALL_CHECKS_PASSED",
  MalformedEnvelope: "MALFORMED_ENVELOPE",
  MissingField: "MISSING_FIELD",
  InvalidField: "INVALID_FIELD",
  InvalidTimestamp: "INVALID_TIMESTAMP",
  IssuedInFuture: "ISSUED_IN_FUTURE",
  DeadlinePassed: "DEADLINE_PASSED",
  UnsupportedProofSystem: "UNSUPPORTED_PROOF_SYSTEM",
  NotFinalized: "NOT_FINALIZED",
  VkSubstitution: "VK_SUBSTITUTION",
  RecipientMismatch: "RECIPIENT_MISMATCH",
  InsufficientBalance: "INSUFFICIENT_BALANCE",
  AmountOverMax: "AMOUNT_OVER_MAX",
  Expired: "EXPIRED",
  ProofReplay: "PROOF_REPLAY",
  UnknownEnvelopeType: "UNKNOWN_ENVELOPE_TYPE",
  InternalError: "INTERNAL_ERROR",
} as const;
