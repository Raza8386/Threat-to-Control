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

export interface ControlBasis {
  n: number; // source number in the evidence rail
  ref_id: string;
  via: string; // "M1032 Multi-factor Authentication", "OWASP A03 crosswalk", "KEV crosswalk", "T1566 technique crosswalk"
  rationale: string;
}

export interface EccControl {
  ecc_id: string;
  title: string;
  subdomain_id: string;
  subdomain: string;
  domain: string;
  primary: boolean;
  basis: ControlBasis[];
}

export interface ControlsPayload {
  framework: string;
  framework_url: string;
  note: string;
  controls: EccControl[];
}

export type ChatEvent =
  | { event: "guardrail"; data: Guardrail }
  | { event: "sources"; data: Source[] }
  | { event: "controls"; data: ControlsPayload }
  | { event: "token"; data: { text: string } }
  | { event: "reset"; data: { reason: "refusal" | "withheld" } }
  | { event: "error"; data: { message: string; code?: string } }
  | { event: "done"; data: Done };
