export type Mode = "hybrid" | "vector" | "bm25";
export type Origin = "attack" | "owasp" | "kev";

export interface Guardrail {
  verdict: "allow" | "block";
  reason: string;
  score?: number;
  layer?: string;
}

export interface Source {
  n: number;
  ref_id: string;
  title: string;
  url: string;
  source: Origin;
  ranks?: { bm25?: number | null; vector?: number | null; id_boost?: boolean };
}

export interface Done {
  latency_ms: number;
  tokens_in: number;
  tokens_out: number;
  cost_usd: number;
  model?: string;
  cited?: number[];
  invalid_citations?: number[];
  blocked?: boolean;
  refused?: boolean;
  withheld?: boolean;
  fallback_from?: string | null;
  truncated?: boolean;
}

export type ChatEvent =
  | { event: "guardrail"; data: Guardrail }
  | { event: "sources"; data: Source[] }
  | { event: "token"; data: { text: string } }
  | { event: "reset"; data: { reason: "refusal" | "withheld" } }
  | { event: "error"; data: { message: string; code?: string } }
  | { event: "done"; data: Done };
