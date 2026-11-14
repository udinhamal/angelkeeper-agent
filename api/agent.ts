import type { VercelRequest, VercelResponse } from "@vercel/node";
import { handleAgentRequest } from "./_lib/handler";

/**
 * Vercel Node function — zkVerify Agent Games, Proof Gatekeeper agent.
 *
 * Registered endpoint: POST https://<project>.vercel.app/api/agent
 *
 * bodyParser is disabled so the handler sees the RAW request stream: the
 * platform signs the exact raw bytes with HMAC-SHA256
 * (x-agent-games-signature), and parsing/re-serialising JSON would break
 * verification. All routing, decision and proof logic lives in ./_lib
 * (adapted 1:1 from the standalone service in ../agent).
 */
export const config = {
  api: { bodyParser: false },
};

export default async function handler(
  req: VercelRequest,
  res: VercelResponse,
): Promise<void> {
  const secret = process.env.AGENT_GAMES_HMAC_SECRET;
  if (!secret) {
    // Fail closed: without the platform secret the function can neither
    // verify inbound signatures nor sign responses. The secret is only ever
    // read from the environment — never hardcoded, never logged.
    res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "server_misconfigured" }));
    return;
  }
  await handleAgentRequest(req, res, { secret });
}
