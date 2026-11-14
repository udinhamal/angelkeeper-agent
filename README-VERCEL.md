# Proof Gatekeeper Agent — Vercel deployment

The zkVerify Agent Games **Proof Gatekeeper** agent (deterministic
APPROVE/REJECT decisions over HMAC-signed task envelopes, with real local
Groth16 decision proofs via snarkjs) packaged as a **Vercel serverless
function** for the free Hobby tier.

This is a thin adapter over the standalone service in `../agent/` — the
decision logic, HMAC handling, proof inputs and store semantics are the
same code, copied into `api/_lib/` (see "How the adapter works" below).
The standalone README (`../agent/README.md`) documents the protocol, the
full decision checklist and the proof-module research; this file covers
only what is different on Vercel.

**Endpoint after deploy:** `POST https://<project>.vercel.app/api/agent`
(`GET` on the same URL answers `{ "ok": true }` as a health ping.)

---

## Deploy steps (GitHub import, in a browser)

Prerequisites: the contents of this `vercel-app/` folder committed to the
GitHub repo **udinhamal/angelkeeper-agent**, and the agent's HMAC secret
from the Agent Games dashboard (agent settings → **Rotate Secret** — it is
shown exactly once; keep it ready to paste, never commit it anywhere).

1. Go to **https://vercel.com** and choose **Sign Up** (or Log In) →
   **Continue with GitHub**. Authorize Vercel for the GitHub account
   `udinhamal` when GitHub asks.
2. On the Vercel dashboard choose **Add New… → Project**.
3. Under **Import Git Repository**, find **udinhamal/angelkeeper-agent**
   and click **Import**. (If the repo is not listed, use
   *Adjust GitHub App Permissions* / *Configure GitHub App* on that screen
   and grant Vercel access to the repository, then come back.)
4. On the **Configure Project** screen:
   - **Project Name:** e.g. `angelkeeper-agent` (this becomes the
     subdomain: `https://angelkeeper-agent.vercel.app`).
   - **Framework Preset:** **Other**.
   - **Root Directory:** the folder in the repo that contains this
     project's `package.json`, `api/` and `circuits/` —
     - if this folder's contents were committed at the repo root, leave
       the default (`./`);
     - if the folder itself was committed as `vercel-app/`, click **Edit**
       and set the Root Directory to **`vercel-app`**.
   - **Build and Output Settings:** leave everything at the defaults
     (no build command, no output directory — Vercel compiles `api/*.ts`
     functions itself).
   - **Environment Variables:** add one variable:
     - Name: `AGENT_GAMES_HMAC_SECRET`
     - Value: the secret from the dashboard (paste it here, nowhere else)
     - Environments: **Production** (add Preview too if you want preview
       deployments to work).
5. Click **Deploy** and wait for the build to finish (~1 minute).
6. Your endpoint is:
   **`https://<project-name>.vercel.app/api/agent`**
   Sanity check in a browser: opening
   `https://<project-name>.vercel.app/api/agent` shows `{"ok":true}`.
7. Back in the Agent Games dashboard, set this full URL (including
   `/api/agent`) as the agent's endpoint, then run the platform's
   **preflight** check and a **Practice** task from the dashboard.

Redeploys: every push to the repo's production branch redeploys
automatically. To change the secret later, edit the environment variable
in **Project → Settings → Environment Variables** and redeploy
(**Deployments → ⋯ → Redeploy**).

Exact import settings summary:

| Setting | Value |
| --- | --- |
| Repository | `udinhamal/angelkeeper-agent` |
| Framework Preset | **Other** |
| Root Directory | repo root, or `vercel-app` if the project sits in that subfolder |
| Build Command | *(default / none)* |
| Output Directory | *(default / none)* |
| Install Command | *(default — `npm install`)* |
| Environment variable | `AGENT_GAMES_HMAC_SECRET` = platform secret (Production) |
| Node.js version | 20.x or newer (Project Settings → General; `engines` in package.json asks for >= 20) |

---

## How the adapter works

```
platform ── signed JSON POST /api/agent ──▶ api/agent.ts (Vercel function)
                                              │ bodyParser disabled: RAW stream
                                              │ secret from env, per request
                                              ▼
                                    api/_lib/handler.ts
                                              │ 1. verify HMAC over RAW body → 401
                                              │ 2. preflight → { ok, protocolVersion }
                                              │ 3. task → _lib/decide.ts (deterministic)
                                              │         → _lib/proof.ts (snarkjs fullProve)
                                              │         → _lib/store.ts (idempotency/replay)
                                              ◀─ signed JSON response
```

- `api/agent.ts` is the only route. Everything under `api/_lib/` is shared
  logic (files starting with `_` are not routes). `types.ts`, `util.ts`,
  `hmac.ts` and `decide.ts` are byte-identical copies of the standalone
  agent's modules — decision semantics are unchanged, including the strict
  expiry rule (`current_block < expiry_block`; at the boundary block the
  transfer is already EXPIRED).
- `api/_lib/handler.ts` is `server.ts` with `createServer` removed: same
  raw-body reading, signature gate before parsing, routing, idempotency,
  replay check, proof attachment, and response signing.
- `api/_lib/proof.ts` loads `circuits/gatekeeper.wasm` +
  `gatekeeper_final.zkey` once per warm instance as **Buffers**
  (`fs.readFileSync`, resolved from `process.cwd()/circuits` — the project
  root — with fallbacks) and passes the buffers to snarkjs
  `groth16.fullProve`. `vercel.json` sets `includeFiles: "circuits/**"` on
  the `api/agent.ts` function so the artifacts ship inside the function,
  and `maxDuration: 60` so a slow cold start can never be cut off before
  the platform's 60 s deadline (a proof takes ~0.3–1.2 s in local tests).
- No prove/verify self-test runs on cold start (it would only slow the
  first request); the local harness below exercises the full pipeline.

## Local tests

```bash
npm install
npm test   # tsc build + mock req/res harness (no vercel dev, no network)
```

The harness invokes the compiled handler with mock request/response
objects and replays the standalone agent's full matrix: health ping,
preflight, a valid task (its Groth16 proof is verified locally against the
zkey), all five traps (VK_SUBSTITUTION, RECIPIENT_MISMATCH,
INSUFFICIENT_BALANCE, AMOUNT_OVER_MAX, EXPIRED at the boundary block), a
replayed `proof_tx` (REJECT PROOF_REPLAY, proof omitted), an idempotent
retry (byte-identical response), an expired deadline (DEADLINE_PASSED), a
bad signature (401), a `sha256=`-prefixed signature, and a signature check
on every response. Current status: **47/47 checks pass**; valid-task wall
time ≈ 390 ms including the first proof, ≈ 315 ms warm.

## Known caveats (read before relying on this in scored rounds)

1. **In-memory store — cold starts reopen the replay window.**
   Idempotency (per `task_id`) and replay protection (per `proof_tx`) live
   in module-scope memory of one function instance. Warm invocations share
   them; a cold start (new instance) begins empty, so a `proof_tx` replay
   or a retry that lands on a fresh instance is not recognised. `STORE_PATH`
   is ignored (serverless filesystems are ephemeral). The standalone
   service with a persisted `STORE_PATH` does not have this limitation.
2. **HMAC signature encoding is an assumption.** /build documents
   HMAC-SHA256 over the raw body in `x-agent-games-signature` but not its
   encoding. Inbound verification accepts the plain hex digest and
   tolerates a `sha256=` prefix; outbound responses are signed with the
   plain hex digest. If the platform expects the prefixed form when
   *receiving*, flip one line in `api/_lib/hmac.ts` (`signBody`).
3. **Proof field encodings are assumed, not published.** Envelope values
   are mapped to BN128 field elements as: integers/decimal strings as-is
   (mod p); `0x` hex strings (addresses, VK hashes) as integers mod p; any
   other string SHA-256-hashed mod p; `salt` from the envelope when
   present, else deterministically derived from `task_id`. If the platform
   binds public signals with a different encoding, proofs would fail
   verification (−2/task). Decisions do not depend on the proof module;
   setting `PROOF_ENABLED=false` in the environment omits proofs entirely.
4. **Not every decision is circuit-attestable.** Rejects caused by
   agent-side-only checks (replay, timestamps, finality, malformed input)
   while all circuit-level facts are valid cannot be proven in the
   gatekeeper circuit; those responses omit the proof (the platform scores
   a missing/invalid proof −2 for that task). This is inherent to the
   circuit design and identical in the standalone agent.
5. **Secrets** come only from the environment
   (`AGENT_GAMES_HMAC_SECRET`). Without it the function answers
   `500 {"error":"server_misconfigured"}` — it never guesses or logs it.
   Rotate the secret from the platform dashboard if it is ever exposed.
6. **Free-tier behaviour.** Vercel Hobby functions are spun up on demand;
   the first request after idle pays a cold start (circuit load + first
   proof ≈ well under a few seconds — far inside the 60 s deadline).
   Nothing here uses any paid Vercel feature.
