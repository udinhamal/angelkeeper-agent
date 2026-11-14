/**
 * Idempotency + replay state — SERVERLESS ADAPTATION of agent/src/store.ts.
 *
 * Same semantics as the standalone service:
 * - Responses are cached per task_id: a platform retry of the same task gets
 *   the byte-identical response and is never mistaken for a replay.
 * - Every consumed proof_tx is remembered: a *different* task reusing it is a
 *   replay trap.
 *
 * Difference: state lives ONLY in memory (module scope of the function).
 * STORE_PATH is ignored — serverless filesystems are ephemeral.
 *
 * CAVEAT (see README-VERCEL.md): a cold start (new function instance) begins
 * with an empty store, which reopens the replay window across instances and
 * loses idempotency for retries that land on a fresh instance. Warm
 * invocations of the same instance share this store. This is the accepted
 * free-tier tradeoff; the standalone service with STORE_PATH does not have it.
 */
export class AgentStore {
  private responses = new Map<string, string>();
  private proofTxIndex = new Map<string, string>();

  getResponse(taskId: string): string | undefined {
    return this.responses.get(taskId);
  }

  hasProofTx(proofTx: string): boolean {
    return this.proofTxIndex.has(proofTx);
  }

  recordTask(taskId: string, proofTx: string | null, responseBody: string): void {
    this.responses.set(taskId, responseBody);
    if (proofTx) this.proofTxIndex.set(proofTx, taskId);
  }
}
