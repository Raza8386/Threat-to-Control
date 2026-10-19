import type { ChatEvent } from "./types";

const KNOWN = new Set(["guardrail", "sources", "controls", "token", "reset", "error", "done"]);

/**
 * Parse a buffer of server-sent events. Returns the complete events and the unparsed remainder
 * (an event can be split across network chunks). Unknown events and bad JSON are skipped.
 */
export function parseSSE(buffer: string): { events: ChatEvent[]; rest: string } {
  const normalized = buffer.replace(/\r\n/g, "\n");
  const blocks = normalized.split("\n\n");
  const rest = blocks.pop() ?? "";
  const events: ChatEvent[] = [];
  for (const block of blocks) {
    let name = "message";
    const data: string[] = [];
    for (const line of block.split("\n")) {
      if (line.startsWith("event:")) name = line.slice(6).trim();
      else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
    }
    if (!KNOWN.has(name) || data.length === 0) continue;
    try {
      events.push({ event: name, data: JSON.parse(data.join("\n")) } as ChatEvent);
    } catch {
      /* malformed event: ignore */
    }
  }
  return { events, rest };
}
