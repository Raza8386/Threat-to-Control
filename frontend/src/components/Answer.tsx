import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { ReactNode } from "react";
import { citationNumber, linkCitations } from "../lib/citations";
import type { Source } from "../lib/types";

interface Props {
  text: string;
  sources: Source[];
  streaming: boolean;
  onActivate: (n: number | null) => void;
}

/**
 * Renders the model's markdown safely: raw HTML is dropped, images are dropped, and the only links
 * are citation chips that point at the retrieved source's canonical URL. Any other link the model
 * writes is shown as plain text, so a poisoned source cannot plant a clickable link.
 */
export default function Answer({ text, sources, streaming, onActivate }: Props) {
  const md = linkCitations(text, sources.length);
  return (
    <div className={`answer${streaming ? " cursor" : ""}`} aria-live="polite" aria-busy={streaming}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        skipHtml
        components={{
          img: () => null,
          a: ({ href, children }: { href?: string; children?: ReactNode }) => {
            const n = citationNumber(href);
            const src = n ? sources[n - 1] : undefined;
            if (!n || !src) return <span>{children}</span>;
            return (
              <a
                className={`cite ${src.source}`}
                href={src.url}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={`Source ${n}: ${src.ref_id}, opens in a new tab`}
                title={`${src.ref_id} ${src.title}`}
                onMouseEnter={() => onActivate(n)}
                onMouseLeave={() => onActivate(null)}
                onFocus={() => onActivate(n)}
                onBlur={() => onActivate(null)}
              >
                {n}
              </a>
            );
          },
        }}
      >
        {md}
      </ReactMarkdown>
    </div>
  );
}
