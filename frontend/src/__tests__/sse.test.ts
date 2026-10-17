import { describe, expect, it } from "vitest";
import { parseSSE } from "../lib/sse";

describe("parseSSE", () => {
  it("parses complete events and keeps the partial remainder", () => {
    const buf = 'event: guardrail\ndata: {"verdict":"allow","reason":"ok"}\n\nevent: token\ndata: {"text":"Hel';
    const { events, rest } = parseSSE(buf);
    expect(events).toEqual([{ event: "guardrail", data: { verdict: "allow", reason: "ok" } }]);
    expect(rest).toBe('event: token\ndata: {"text":"Hel');
  });

  it("handles CRLF line endings and the reset event", () => {
    const { events } = parseSSE('event: reset\r\ndata: {"reason":"refusal"}\r\n\r\n');
    expect(events).toEqual([{ event: "reset", data: { reason: "refusal" } }]);
  });

  it("ignores unknown events and malformed JSON", () => {
    const { events } = parseSSE('event: evil\ndata: {"x":1}\n\nevent: token\ndata: {not json}\n\nevent: done\ndata: {"latency_ms":5}\n\n');
    expect(events).toEqual([{ event: "done", data: { latency_ms: 5 } }]);
  });
});
