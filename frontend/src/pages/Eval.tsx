import { useEffect, useState } from "react";
import { ApiError, fetchEvalResults, type EvalResults } from "../lib/api";

const pct = (v: number | null | undefined, digits = 0) => (v === null || v === undefined ? "–" : `${(v * 100).toFixed(digits)}%`);
const MODEL_NAME: Record<string, string> = { "claude-sonnet-5-5": "Claude Sonnet 5.5", "claude-haiku-5-5": "Claude Haiku 5.5" };
const MODE_NAME: Record<string, string> = { hybrid: "Hybrid", vector: "Meaning (vector)", bm25: "Keyword (BM25)" };

const CHECKS: { key: string; label: string; target: string }[] = [
  { key: "hit_at_5", label: "The right source is in the top 5 results", target: "at least 90%" },
  { key: "faithfulness", label: "Answer claims supported by the cited sources", target: "at least 90%" },
  { key: "attacks_blocked", label: "Prompt-injection attacks blocked, with no prompt leaks", target: "all" },
  { key: "indirect_resisted", label: "Instructions hidden in a source ignored", target: "all" },
  { key: "offtopic_refused", label: "Off-topic questions declined", target: "all" },
  { key: "false_positives", label: "Normal questions wrongly blocked", target: "none" },
  { key: "no_errors", label: "Every question answered without an error", target: "all" },
  { key: "all_answers_judged", label: "Answers scored by the judge model", target: "all" },
];

export default function Eval() {
  const [data, setData] = useState<EvalResults | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    fetchEvalResults(ctrl.signal)
      .then(setData)
      .catch((e) => {
        if (e.name !== "AbortError") setError(e instanceof ApiError ? e.message : "Couldn't load the evaluation results.");
      });
    return () => ctrl.abort();
  }, []);

  if (error) return <section className="report"><h1>Evaluation</h1><div className="error" role="alert"><p>{error}</p></div></section>;
  if (data === undefined) return <section className="report"><h1>Evaluation</h1><p className="small">Loading results…</p></section>;
  if (data === null)
    return (
      <section className="report">
        <h1>Evaluation</h1>
        <p className="lede">No evaluation has been run on this server yet. Run <code>python -m scripts.run_phase3</code> in the backend to produce one.</p>
      </section>
    );

  const g = data.guardrail;
  const bestHit = Math.max(...data.retrieval.map((r) => r.hit_at_5));
  const when = new Date(data.run_at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  const counts = data.golden;
  const answerable = (counts.attack ?? 0) + (counts.owasp ?? 0) + (counts.kev ?? 0) + (counts.cross ?? 0);

  return (
    <section className="report">
      <h1>Evaluation</h1>
      <p className="lede">
        Measured on {data.golden.total} test questions: {answerable} answerable questions across ATT&amp;CK, OWASP and KEV,
        {" "}{counts.offtopic ?? 0} off-topic questions, {counts.injection ?? 0} prompt-injection attacks and {counts.indirect ?? 0} poisoned sources.
        Answers are scored by a separate Claude model acting as judge. Last run {when}.
      </p>

      <div className={`verdict ${data.gate_passed ? "pass" : "fail"}`}>
        <strong>{data.gate_passed ? "All checks passed" : "Some checks failed"}</strong>
        <p>{Object.values(data.gate).filter(Boolean).length} of {Object.keys(data.gate).length} checks met their target.</p>
      </div>

      <h2>Checks</h2>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Check</th><th>Target</th><th>Result</th></tr></thead>
          <tbody>
            {CHECKS.filter((c) => c.key in data.gate).map((c) => (
              <tr key={c.key}>
                <td>{c.label}</td>
                <td>{c.target}</td>
                <td className={data.gate[c.key] ? "mark-pass" : "mark-fail"}>{data.gate[c.key] ? "Met" : "Missed"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {data.answers.length > 0 && (
        <>
          <h2>Answer quality by model</h2>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Model</th><th className="num">Supported claims</th><th className="num">Correct citations</th>
                  <th className="num">Expected source cited</th><th className="num">Avg. time</th><th className="num">Cost per answer</th>
                </tr>
              </thead>
              <tbody>
                {data.answers.map((a) => (
                  <tr key={a.model}>
                    <td>{MODEL_NAME[a.model] ?? a.model}</td>
                    <td className="num">{pct(a.faithfulness, 1)}</td>
                    <td className="num">{pct(a.citation_accuracy, 1)}</td>
                    <td className="num">{pct(a.expected_cited_rate, 1)}</td>
                    <td className="num">{a.avg_latency_ms ? `${(a.avg_latency_ms / 1000).toFixed(1)} s` : "–"}</td>
                    <td className="num">{a.avg_cost_usd !== null ? `$${a.avg_cost_usd.toFixed(4)}` : "–"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="small">Judged answers per model: {data.answers.map((a) => `${MODEL_NAME[a.model] ?? a.model} ${a.judged_answers}`).join(", ")}.</p>
        </>
      )}

      <h2>Retrieval by search method</h2>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Method</th><th className="num">Right source in top 5</th><th className="num">Mean reciprocal rank</th><th className="num">Both sources found (cross-source questions)</th></tr></thead>
          <tbody>
            {data.retrieval.map((r) => (
              <tr key={r.mode}>
                <td>{MODE_NAME[r.mode] ?? r.mode}</td>
                <td className={`num${r.hit_at_5 === bestHit ? " mark-best" : ""}`}>{pct(r.hit_at_5, 1)}</td>
                <td className="num">{r.mrr.toFixed(3)}</td>
                <td className="num">{pct(r.cross_coverage)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {g && (
        <>
          <h2>Security</h2>
          <div className="table-wrap">
            <table>
              <tbody>
                <tr><td>Prompt-injection attacks blocked</td><td className="num">{g.attacks_blocked} of {g.attacks_total}</td></tr>
                <tr><td>Normal questions wrongly blocked</td><td className="num">{g.false_positives} of {g.normal_total}</td></tr>
                {data.answers[0] && (
                  <>
                    <tr><td>Hidden instructions in a source ignored</td><td className="num">{data.answers[0].indirect_resisted} of {data.answers[0].indirect_total}</td></tr>
                    <tr><td>System prompt leaks</td><td className="num">{data.answers[0].prompt_leaks}</td></tr>
                  </>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {data.failures.length > 0 && (
        <>
          <h2>Cases that missed</h2>
          <p className="small">Listed so the scores can be checked, not hidden.</p>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Case</th><th>Model</th><th>What happened</th></tr></thead>
              <tbody>
                {data.failures.slice(0, 40).map((f, i) => (
                  <tr key={`${f.id}-${f.model}-${i}`}>
                    <td>{f.id}</td>
                    <td>{f.model ? MODEL_NAME[f.model] ?? f.model : "Retrieval"}</td>
                    <td>{f.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}
