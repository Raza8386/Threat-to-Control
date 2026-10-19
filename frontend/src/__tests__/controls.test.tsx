import { describe, expect, it } from "vitest";
import { fireEvent, render } from "@testing-library/react";
import ControlMap, { reasons } from "../components/ControlMap";
import { parseSSE } from "../lib/sse";
import type { ControlsPayload, Source } from "../lib/types";

const sources: Source[] = [
  { n: 1, ref_id: "T1566.001", title: "Spearphishing Attachment", url: "https://attack.mitre.org/techniques/T1566/001", source: "attack" },
  { n: 2, ref_id: "A07:2021", title: "Identification and Authentication Failures", url: "https://owasp.org/", source: "owasp" },
];

const payload = (n = 2, url = "https://cdn.nca.gov.sa/ecc.pdf"): ControlsPayload => ({
  framework: "NCA Essential Cybersecurity Controls (ECC-2:2024)",
  framework_url: url,
  note: "",
  controls: Array.from({ length: n }, (_, i) => ({
    ecc_id: `2-2-3-${i + 1}`,
    title: `Control ${i + 1}`,
    subdomain_id: "2-2",
    subdomain: "Identity and Access Management",
    domain: "Cybersecurity Defense",
    primary: true,
    basis: [
      { n: 1, ref_id: "T1566.001", via: "M1032 Multi-factor Authentication", rationale: "r" },
      { n: 2, ref_id: "A07:2021", via: "M1032 Multi-factor Authentication", rationale: "r" },
      { n: 2, ref_id: "A07:2021", via: "OWASP A07 crosswalk", rationale: "r" },
    ],
  })),
});

describe("controls event", () => {
  it("is parsed from the stream", () => {
    const { events } = parseSSE(`event: controls\ndata: ${JSON.stringify(payload(1))}\n\n`);
    expect(events[0].event).toBe("controls");
  });
});

describe("ControlMap", () => {
  it("groups the trail by reason and colours source chips by origin", () => {
    expect(reasons(payload(1).controls[0]).map((r) => [r.via, r.ns])).toEqual([
      ["M1032 Multi-factor Authentication", [1, 2]],
      ["OWASP A07 crosswalk", [2]],
    ]);
    const { container } = render(<ControlMap payload={payload(1)} sources={sources} onActivate={() => {}} />);
    const chips = container.querySelectorAll("button.cite");
    expect(chips[0].className).toContain("attack");
    expect(chips[1].className).toContain("owasp");
    expect(container.textContent).toContain("2-2-3-1");
    expect(container.textContent).toContain("Cybersecurity Defense › 2-2 Identity and Access Management");
  });

  it("shows six controls, then all on request", () => {
    const { container, getByText } = render(<ControlMap payload={payload(9)} sources={sources} onActivate={() => {}} />);
    expect(container.querySelectorAll(".ctl")).toHaveLength(6);
    fireEvent.click(getByText("Show all 9 controls"));
    expect(container.querySelectorAll(".ctl")).toHaveLength(9);
  });

  it("links the official text only over https", () => {
    const ok = render(<ControlMap payload={payload(1)} sources={sources} onActivate={() => {}} />);
    expect(ok.container.querySelector("a")?.getAttribute("href")).toBe("https://cdn.nca.gov.sa/ecc.pdf");
    const bad = render(<ControlMap payload={payload(1, "javascript:alert(1)")} sources={sources} onActivate={() => {}} />);
    expect(bad.container.querySelector("a")).toBeNull();
  });
});
