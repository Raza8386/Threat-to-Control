/**
 * Turn "[n]" citations into markdown links "#cite-n" so the renderer can show them as source chips.
 * Only numbers that match a retrieved source become links; anything else stays as plain text.
 */
export function linkCitations(answer: string, sourceCount: number): string {
  return answer.replace(/\[(\d{1,2})\](?!\()/g, (whole, num: string) => {
    const n = Number(num);
    return n >= 1 && n <= sourceCount ? `[${n}](#cite-${n})` : whole;
  });
}

export function citationNumber(href: string | undefined): number | null {
  const m = /^#cite-(\d{1,2})$/.exec(href ?? "");
  return m ? Number(m[1]) : null;
}

export const ORIGIN_LABEL = { attack: "MITRE ATT&CK", owasp: "OWASP Top 10", kev: "CISA KEV" } as const;
