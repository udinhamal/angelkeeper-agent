import { IncomingMessage, ServerResponse } from "node:http";
import { evaluateTask } from "./decide";
import { SIGNATURE_HEADER, signBody, verifySignature } from "./hmac";
import { generateDecisionProof } from "./proof";
import { AgentStore } from "./store";
import {
  GATEKEEPER_TASK_TYPE,
  PREFLIGHT_TYPE,
  ReasonCode,
  TaskEnvelope,
} from "./types";
import { asString } from "./util";

const MAX_BODY_BYTES = 1_000_000;

export interface AgentHandlerOptions {
  /** Platform-issued HMAC secret (AGENT_GAMES_HMAC_SECRET). */
  secret: string;
  store?: AgentStore;
}

/**
 * Warm-instance store: created once per function instance and shared across
 * invocations of that instance. Cold starts begin empty (see store.ts).
 */
let warmStore: AgentStore | undefined;
function getStore(override?: AgentStore): AgentStore {
  if (override) return override;
  if (!warmStore) warmStore = new AgentStore();
  return warmStore;
}

function readRawBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolveBody, rejectBody) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        rejectBody(new Error("body_too_large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolveBody(Buffer.concat(chunks)));
    req.on("error", rejectBody);
  });
}

/**
 * The Proof Gatekeeper request handler — the standalone agent's server.ts
 * logic behind a Vercel function signature (see api/agent.ts):
 *
 *   1. Read the RAW body; verify x-agent-games-signature (HMAC-SHA256 over
 *      the raw bytes) BEFORE parsing JSON. Mismatch -> 401.
 *   2. Preflight envelopes -> { ok: true, protocolVersion: "v1" }.
 *   3. Gatekeeper task envelopes -> deterministic decision (see decide.ts).
 *      Responses are cached per task_id (idempotent retries); every task's
 *      proof_tx is recorded so a later task reusing it is a replay REJECT.
 *   4. Every JSON response is signed with x-agent-games-signature over the
 *      raw response body.
 *
 * GET -> { ok: true } (unsigned liveness probe, same as the standalone
 * service's GET /health).
 * Full request bodies and the secret are never logged.
 */
export async function handleAgentRequest(
  req: IncomingMessage,
  res: ServerResponse,
  options: AgentHandlerOptions,
): Promise<void> {
  const { secret } = options;
  const store = getStore(options.store);

  function sendJson(status: number, body: string): void {
    res.writeHead(status, {
      "content-type": "application/json",
      [SIGNATURE_HEADER]: signBody(secret, body),
    });
    res.end(body);
  }

  async function handleTask(envelope: TaskEnvelope): Promise<void> {
    const startedAt = Date.now();
    const taskId = asString(envelope.task_id);
    if (!taskId) {
      sendJson(
        200,
        JSON.stringify({ decision: "REJECT", reason_code: ReasonCode.MissingField }),
      );
      return;
    }

    // Idempotent retry: return the byte-identical cached response.
    const cached = store.getResponse(taskId);
    if (cached) {
      console.log(`[agent] task ${taskId} -> cached response (idempotent retry)`);
      sendJson(200, cached);
      return;
    }

    const rawInput = envelope.input ?? (envelope as unknown as Record<string, unknown>);
    const proofTx = asString((rawInput as Record<string, unknown>).proof_tx)?.trim() ?? null;

    const evaluation = evaluateTask(envelope, {
      nowSec: Math.floor(Date.now() / 1000),
      replaySeen: proofTx ? store.hasProofTx(proofTx) : false,
    });
    const { decision, reason_code } = evaluation.result;

    const responseObj: Record<string, unknown> = { decision, reason_code };
    if (evaluation.parsed) {
      const proof = await generateDecisionProof(
        evaluation.parsed,
        decision === "APPROVE" ? 1 : 0,
        taskId,
      );
      if (proof) {
        responseObj.proof = proof.proof;
        responseObj.public_signals = proof.public_signals;
      }
    }

    const body = JSON.stringify(responseObj);
    store.recordTask(taskId, proofTx, body);
    console.log(
      `[agent] task ${taskId} -> ${decision} ${reason_code} (${Date.now() - startedAt}ms)`,
    );
    sendJson(200, body);
  }

  try {
    if (req.method === "GET") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    if (req.method !== "POST") {
      sendJson(404, JSON.stringify({ error: "not_found" }));
      return;
    }

    const rawBody = await readRawBody(req);
    const signature = req.headers[SIGNATURE_HEADER];
    if (!verifySignature(secret, rawBody, Array.isArray(signature) ? signature[0] : signature)) {
      sendJson(401, JSON.stringify({ error: "invalid_signature" }));
      return;
    }

    let envelope: TaskEnvelope;
    try {
      envelope = JSON.parse(rawBody.toString("utf8")) as TaskEnvelope;
    } catch {
      sendJson(400, JSON.stringify({ error: "invalid_json" }));
      return;
    }

    if (envelope?.type === PREFLIGHT_TYPE) {
      sendJson(200, JSON.stringify({ ok: true, protocolVersion: "v1" }));
      return;
    }
    if (envelope?.type === GATEKEEPER_TASK_TYPE) {
      await handleTask(envelope);
      return;
    }
    if (typeof envelope?.type === "string") {
      // Unknown task-like envelope: fail closed but stay responsive.
      sendJson(
        200,
        JSON.stringify({ decision: "REJECT", reason_code: ReasonCode.UnknownEnvelopeType }),
      );
      return;
    }
    sendJson(400, JSON.stringify({ error: "missing_type" }));
  } catch (err) {
    console.error("[agent] request failed:", (err as Error).message);
    if (!res.headersSent) {
      try {
        sendJson(
          200,
          JSON.stringify({ decision: "REJECT", reason_code: ReasonCode.InternalError }),
        );
      } catch {
        /* socket already gone */
      }
    }
  }
}
