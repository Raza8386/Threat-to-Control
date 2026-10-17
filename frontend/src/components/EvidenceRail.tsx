import { ORIGIN_LABEL } from "../lib/citations";
import type { Source } from "../lib/types";

interface Props {
  sources: Source[];
  cited: number[] | null; // null while the answer is still streaming
  active: number | null;
  blocked?: boolean;
}

function matchNote(s: Source): string {
  const r = s.ranks ?? {};
  if (r.id_boost) return "Matched the ID in your question";
  const parts: string[] = [];
  if (r.bm25) parts.push(`keyword rank ${r.bm25}`);
  if (r.vector) parts.push(`meaning rank ${r.vector}`);
  return parts.length ? `Found by ${parts.join(" and ")}` : "Added to cover this source";
}

/** "T1059.001 Command and Scripting Interpreter: PowerShell (MITRE ATT&CK)" -> "Command and Scripting Interpreter: PowerShell" */
function cleanTitle(s: Source): string {
  return s.title
    .replace(/\s*\((MITRE ATT&CK|OWASP Top 10|CISA KEV)\)$/, "")
    .replace(new RegExp(`^${s.ref_id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*`), "");
}

export default function EvidenceRail({ sources, cited, active, blocked }: Props) {
  return (
    <aside className="rail" aria-label="Evidence">
      <h2>Evidence</h2>
      {sources.length === 0 ? (
        <p className="rail-empty">
          {blocked ? "Blocked questions are not searched." : "The sources used for the answer appear here."}
        </p>
      ) : (
        <ol>
          {sources.map((s) => {
            const uncited = cited !== null && !cited.includes(s.n);
            return (
              <li
                key={s.n}
                id={`exhibit-${s.n}`}
                className={`exhibit ${s.source}${active === s.n ? " active" : ""}${uncited ? " uncited" : ""}`}
              >
                <div className="exhibit-head">
                  <span className="exhibit-n">[{s.n}] {s.ref_id}</span>
                  <span className="exhibit-origin">{ORIGIN_LABEL[s.source]}</span>
                </div>
                <p className="exhibit-title">
                  <a href={s.url} target="_blank" rel="noopener noreferrer">
                    {cleanTitle(s)}
                  </a>
                </p>
                <p className="exhibit-meta">
                  {matchNote(s)}.{uncited ? " Not cited in the answer." : ""}
                </p>
              </li>
            );
          })}
        </ol>
      )}
    </aside>
  );
}
