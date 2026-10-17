import { NavLink, Route, Routes } from "react-router-dom";
import Chat from "./pages/Chat";
import Eval from "./pages/Eval";
import Architecture from "./pages/Architecture";

export default function App() {
  return (
    <div className="shell">
      <header className="masthead">
        <NavLink to="/" className="wordmark" aria-label="Threat to Control, home">
          <span className="wordmark-tabs" aria-hidden="true"><span /><span /><span /></span>
          <span className="wordmark-name">Threat to Control</span>
        </NavLink>
        <nav className="nav" aria-label="Main">
          <NavLink to="/" end>Ask</NavLink>
          <NavLink to="/eval">Evaluation</NavLink>
          <NavLink to="/how-it-works">How it works</NavLink>
        </nav>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<Chat />} />
          <Route path="/eval" element={<Eval />} />
          <Route path="/how-it-works" element={<Architecture />} />
          <Route path="*" element={<Chat />} />
        </Routes>
      </main>
      <footer className="footer">
        <p>Answers come only from MITRE ATT&amp;CK, the OWASP Top 10 (2021) and the CISA Known Exploited Vulnerabilities catalog. Check the cited source before acting on an answer.</p>
        <p>MITRE ATT&amp;CK® is a registered trademark of The MITRE Corporation. OWASP Top 10 © OWASP Foundation, CC BY-SA 4.0. CISA KEV is in the public domain.</p>
      </footer>
    </div>
  );
}
