"""Markdown section-aware document chunker with hierarchical context prepending."""

import re
from dataclasses import dataclass, field
from uuid import uuid4


@dataclass(frozen=True)
class DocumentChunk:
    """A granular chunk of markdown documentation with contextual hierarchy."""

    id: str
    title: str
    content: str
    heading_path: str
    category: str
    tags: list[str] = field(default_factory=list)
    source_path: str = "unknown.md"


class MarkdownChunker:
    """Splits markdown documents along structural headings (#, ##, ###).

    If an individual section exceeds max_chunk_chars, it applies a sliding window
    with overlap. Each chunk prepends its full heading path to preserve hierarchical context.
    """

    HEADING_REGEX = re.compile(r"^(#{1,6})\s+(.+)$")

    def __init__(self, max_chunk_chars: int = 1500, overlap_chars: int = 200) -> None:
        self.max_chunk_chars = max_chunk_chars
        self.overlap_chars = overlap_chars

    def chunk_document(
        self,
        title: str,
        content: str,
        category: str = "runbook",
        tags: list[str] | None = None,
        source_path: str = "runbook.md",
    ) -> list[DocumentChunk]:
        """Parses markdown into contextual chunks preserving metadata and heading hierarchies."""
        effective_tags = tags or []
        lines = content.splitlines()

        sections: list[tuple[list[str], list[str]]] = []
        current_heading_stack: list[str] = [title]
        current_lines: list[str] = []

        for line in lines:
            heading_match = self.HEADING_REGEX.match(line)
            if heading_match:
                # Flush previous section if it has content
                if current_lines:
                    sections.append((list(current_heading_stack), current_lines))
                    current_lines = []

                level = len(heading_match.group(1))  # 1 for #, 2 for ##, etc.
                heading_text = heading_match.group(2).strip()

                # Adjust heading stack according to heading depth level
                # Level 1 replaces everything after title, level 2 nests under level 1, etc.
                if level == 1:
                    current_heading_stack = [heading_text]
                else:
                    # Truncate stack to level - 1 and append
                    current_heading_stack = current_heading_stack[: level - 1]
                    current_heading_stack.append(heading_text)
            else:
                current_lines.append(line)

        # Flush final accumulated section
        if current_lines:
            sections.append((list(current_heading_stack), current_lines))

        # If no headings existed at all, treat whole text as a single section
        if not sections and content.strip():
            sections.append(([title], lines))

        chunks: list[DocumentChunk] = []

        for stack, sec_lines in sections:
            body = "\n".join(sec_lines).strip()
            if not body:
                continue

            heading_path = " > ".join(stack)

            # If within size threshold, output as a single chunk
            if len(body) <= self.max_chunk_chars:
                contextual_content = f"[{heading_path}]\n{body}"
                chunks.append(
                    DocumentChunk(
                        id=str(uuid4()),
                        title=title,
                        content=contextual_content,
                        heading_path=heading_path,
                        category=category,
                        tags=effective_tags,
                        source_path=source_path,
                    )
                )
            else:
                # Sliding window chunking with overlap for oversized sections
                start = 0
                part = 1
                body_len = len(body)
                while start < body_len:
                    end = min(start + self.max_chunk_chars, body_len)
                    sub_body = body[start:end]
                    contextual_content = f"[{heading_path} (Part {part})]\n{sub_body}"
                    chunks.append(
                        DocumentChunk(
                            id=str(uuid4()),
                            title=title,
                            content=contextual_content,
                            heading_path=f"{heading_path} (Part {part})",
                            category=category,
                            tags=effective_tags,
                            source_path=source_path,
                        )
                    )
                    part += 1
                    if end >= body_len:
                        break
                    start += self.max_chunk_chars - self.overlap_chars

        return chunks
