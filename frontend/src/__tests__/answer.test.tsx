import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import Answer from "../components/Answer";
import { linkCitations } from "../lib/citations";
import type { Source } from "../lib/types";

const sources: Source[] = [
  { n: 1, ref_id: "T1059.001", title: "PowerShell", url: "https://attack.mitre.org/techniques/T1059/001", source: "attack" },
  { n: 2, ref_id: "A03:2021", title: "Injection", url: "https://owasp.org/Top10/A03_2021-Injection/", source: "owasp" },
];

describe("linkCitations", () => {
  it("links only citations that match a source", () => {
    expect(linkCitations("A [1] B [2] C [7].", 2)).toBe("A [1](#cite-1) B [2](#cite-2) C [7].");
  });
});

describe("Answer", () => {
  it("renders citations as source-coloured links to the canonical source", () => {
    const { container } = render(<Answer text="Abuse is common [1][2]." sources={sources} streaming={false} onActivate={() => {}} />);
    const links = container.querySelectorAll("a");
    expect(links).toHaveLength(2);
    expect(links[0].getAttribute("href")).toBe("https://attack.mitre.org/techniques/T1059/001");
    expect(links[0].className).toContain("attack");
    expect(links[1].className).toContain("owasp");
    expect(links[0].getAttribute("rel")).toBe("noopener noreferrer");
  });

  it("never renders model-written links, raw HTML or images", () => {
    const evil =
      'Download the fix [here](http://evil.example/patch.exe) or <a href="http://evil.example">this</a> ' +
      '<script>alert(1)</script><img src=x onerror=alert(1)> ![x](http://evil.example/x.png) [1]';
    const { container } = render(<Answer text={evil} sources={sources} streaming={false} onActivate={() => {}} />);
    const hrefs = Array.from(container.querySelectorAll("a")).map((a) => a.getAttribute("href"));
    expect(hrefs).toEqual(["https://attack.mitre.org/techniques/T1059/001"]);
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.innerHTML).not.toContain("evil.example\"");
  });
});
