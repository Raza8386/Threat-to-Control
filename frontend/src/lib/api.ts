import { parseSSE } from "./sse";
import type { ChatEvent, Mode } from "./types";

export const API_URL = (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, "") || "http://localhost:8000";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function errorMessage(res: Response): Promise<string> {
  try {
    const body = await res.json();
    if (typeof body?.detail === "string") return body.detail;
  } catch {
    /* not JSON */
  }
  if (res.status === 429) return "Too many questions. Wait a minute and try again.";
  if (res.status === 503) return "The demo is unavailable right now. Try again later.";
  return `The server returned an error (${res.status}).`;
}

/** POST a question and call onEvent for each streamed event. Resolves when the stream ends. */
export async function streamChat(
  question: string,
  mode: Mode,
  onEvent: (e: ChatEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}/api/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question, mode }),
      signal,
    });
  } catch (err) {
    if ((err as Error).name === "AbortError") throw err;
    throw new ApiError(0, "Can't reach the server. It may be starting up; try again in 30 seconds.");
  }
  if (!res.ok || !res.body) throw new ApiError(res.status, await errorMessage(res));

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const { events, rest } = parseSSE(buffer);
    buffer = rest;
    events.forEach(onEvent);
  }
  const { events } = parseSSE(buffer + "\n\n");
  events.forEach(onEvent);
}

export async function fetchEvalResults(signal?: AbortSignal): Promise<EvalResults | null> {
  const res = await fetch(`${API_URL}/api/eval/results`, { signal });
  if (res.status === 404) return null;
  if (!res.ok) throw new ApiError(res.status, await errorMessage(res));
  return res.json();
}

export interface EvalAnswers {
  model: string;
  faithfulness: number | null;
  citation_accuracy: number | null;
  expected_cited_rate: number | null;
  offtopic_refused: number;
  offtopic_total: number;
  indirect_resisted: number;
  indirect_total: number;
  prompt_leaks: number;
  avg_latency_ms: number | null;
  avg_cost_usd: number | null;
  judged_answers: number;
  errors?: number;
  fallbacks?: number;
}

export interface EvalResults {
  run_at: string;
  golden: Record<string, number>;
  embedder: string | null;
  retrieval: { mode: string; hit_at_5: number; mrr: number; cross_coverage: number | null; n: number }[];
  guardrail: { attacks_blocked: number; attacks_total: number; false_positives: number; normal_total: number } | null;
  answers: EvalAnswers[];
  targets: Record<string, number>;
  gate: Record<string, boolean>;
  gate_passed: boolean;
  failures: { id: string; model?: string; kind: string; detail: string }[];
}
