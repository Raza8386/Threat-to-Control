import { useState } from "react";
import type { ControlsPayload, EccControl, Source } from "../lib/types";

interface Props {
  payload: ControlsPayload;
  sources: Source[];
  onActivate: (n: number | null) => void;
}

const SHOWN = 6;

/** Group a control's basis by reason: "M1032 Multi-factor Authentication" -> [1, 3]. */
export function reasons(c: EccControl): { via: string; ns: number[]; rationale: string }[] {
  const map = new Map<string, { via: string; ns: number[]; rationale: string }>();
  for (const b of c.basis) {
    const r = map.get(b.via) ?? { via: b.via, ns: [], rationale: b.rationale };
    if (!r.ns.includes(b.n)) r.ns.push(b.n);
    map.set(b.via, r);
  }
  return [...map.values()];
}

/** Only an https link from the API becomes clickable. */
const safeUrl = (u: string) => (/^https:\/\//.test(u) ? u : null);

export default function ControlMap({ payload, sources, onActivate }: Props) {
  const [all, setAll] = useState(false);
  const origin = new Map(sources.map((s) => [s.n, s.source]));
  const list = all ? payload.controls : payload.controls.slice(0, SHOWN);
  const url = safeUrl(payload.framework_url);

  return (
    <section className="controls" aria-labelledby="controls-h">
      <h2 id="controls-h">NCA ECC controls that address this</h2>
      {payload.controls.length === 0 ? (
        <p className="small">No NCA ECC-2:2024 control is mapped to these sources.</p>
      ) : (
        <>
          <p className="controls-lede">
            Mapped from the sources through MITRE mitigations and a curated crosswalk, not written by the AI model. Titles are
            paraphrased; check the{" "}
            {url ? (
              <a href={url} target="_blank" rel="noopener noreferrer">official ECC-2:2024 text</a>
            ) : (
              "official ECC-2:2024 text"
            )}{" "}
            before relying on a control.
          </p>
          <ol className="ctl-list">
            {list.map((c) => (
              <li key={c.ecc_id} className="ctl">
                <span className="ctl-id">{c.ecc_id}</span>
                <div>
                  <p className="ctl-title">{c.title}</p>
                  <p className="ctl-path">
                    {c.domain} › {c.subdomain_id} {c.subdomain}
                  </p>
                  <ul className="ctl-why">
                    {reasons(c).map((r) => (
                      <li key={r.via} title={r.rationale}>
                        {r.ns.map((n) => (
                          <button
                            key={n}
                            type="button"
                            className={`cite ${origin.get(n) ?? ""}`}
                            onMouseEnter={() => onActivate(n)}
                            onMouseLeave={() => onActivate(null)}
                            onFocus={() => onActivate(n)}
                            onBlur={() => onActivate(null)}
                            onClick={() => document.getElementById(`exhibit-${n}`)?.scrollIntoView({ block: "nearest", behavior: "smooth" })}
                            aria-label={`Source ${n}`}
                          >
                            {n}
                          </button>
                        ))}{" "}
                        <span>{r.via}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </li>
            ))}
          </ol>
          {payload.controls.length > SHOWN && (
            <button type="button" className="btn quiet small-btn" onClick={() => setAll(!all)}>
              {all ? "Show fewer" : `Show all ${payload.controls.length} controls`}
            </button>
          )}
        </>
      )}
    </section>
  );
}
