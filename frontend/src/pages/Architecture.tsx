export default function Architecture() {
  return (
    <section className="report">
      <h1>How it works</h1>
      <p className="lede">
        Every question goes through the same six steps. The design goal is an answer an auditor can check: every claim
        cites a source, and the system reports its own accuracy on the Evaluation page.
      </p>

      <h2>From question to answer</h2>
      <ol className="pipeline">
        <li><div><h3>Check the question</h3><p>Pattern rules catch obvious prompt-injection attempts at no cost. Questions that look suspicious but unclear go to Claude Haiku for a second opinion. If that check fails, the question is blocked rather than let through.</p></div></li>
        <li><div><h3>Search two ways</h3><p>Keyword search (BM25) finds exact IDs such as T1059.001 or CVE-2021-44228. Meaning search (vector embeddings) finds paraphrased questions. The two rankings are merged with reciprocal rank fusion, and an ID named in the question is pinned first.</p></div></li>
        <li><div><h3>Keep small sources visible</h3><p>The catalog holds about 1,750 CVEs, 700 ATT&amp;CK techniques and 10 OWASP categories. When a smaller source has a strong match that the larger ones crowd out, it keeps one slot.</p></div></li>
        <li><div><h3>Answer from the sources only</h3><p>Claude receives the top six sources as numbered, fenced blocks marked as reference data. It must cite each claim as [n] and say so when the sources don't cover the question. Text inside a source is never followed as an instruction.</p></div></li>
        <li><div><h3>Check the output</h3><p>A hidden marker in the instructions detects any attempt to leak them, and the answer is withheld before it reaches you. If the model's safety system stops an answer partway, the partial text is cleared and a second Claude model answers instead.</p></div></li>
        <li><div><h3>Show the evidence</h3><p>Each citation links to the original ATT&amp;CK, OWASP or NVD page. Sources the answer did not use are shown faded, so you can see what was considered.</p></div></li>
      </ol>

      <h2>Sources</h2>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Source</th><th>What one entry is</th><th>Links to</th></tr></thead>
          <tbody>
            <tr><td>MITRE ATT&amp;CK (Enterprise)</td><td>One technique or sub-technique, with its tactics, platforms, detections and mitigations</td><td>attack.mitre.org</td></tr>
            <tr><td>OWASP Top 10 (2021)</td><td>One risk category, split into sections when long</td><td>owasp.org</td></tr>
            <tr><td>CISA Known Exploited Vulnerabilities</td><td>One CVE, with the required action and due date</td><td>nvd.nist.gov</td></tr>
          </tbody>
        </table>
      </div>

      <h2>Built with</h2>
      <p>
        Python and FastAPI on the server, ChromaDB and rank-bm25 for search, BGE or Voyage embeddings, and the Claude API
        (Sonnet 5.5 and Haiku 5.5) for answers, the injection check and the evaluation judge. The interface is React,
        streaming each answer as it is written.
      </p>

      <h2>Limits</h2>
      <ul>
        <li>It knows only these three sources. Questions about NCA ECC, SAMA or other frameworks are declined until those are added.</li>
        <li>Scores come from a 60-question test set and a model judge. They show how the system behaves, not that it is never wrong.</li>
        <li>Answers explain techniques for defenders; they do not provide attack instructions beyond what the sources describe.</li>
      </ul>
    </section>
  );
}
