#!/usr/bin/env python3
"""
noteshelf.py — a compact but feature-rich personal note manager.

Usage (examples):
  python noteshelf.py init --dir ./mynotes
  python noteshelf.py new "My first note" --tags life,ideas
  python noteshelf.py list
  python noteshelf.py show my-first-note
  python noteshelf.py search "neural network"
  python noteshelf.py suggest-tags my-first-note
  python noteshelf.py export-graph graph.dot

This file intentionally contains everything in one file for portability.
"""

from __future__ import annotations
import argparse
import sys
import os
from pathlib import Path
from datetime import datetime
import re
from collections import defaultdict, Counter
import math
import logging
import shutil
import json
import subprocess
from typing import List, Dict, Tuple, Optional

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("noteshelf")

FRONTMATTER_RE = re.compile(r'^---\s*\n(.*?)\n---\s*\n', re.S)
SLUGIFY_RE = re.compile(r'[^\w]+')

def slugify(title: str) -> str:
    slug = SLUGIFY_RE.sub('-', title.strip().lower()).strip('-')
    return slug or "note"

def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec='seconds') + "Z"

class Note:
    """Represents a single markdown note stored on disk."""
    def __init__(self, slug: str, title: str, body: str, tags: List[str]=None, created: str=None, modified: str=None):
        self.slug = slug
        self.title = title
        self.body = body
        self.tags = tags or []
        self.created = created or now_iso()
        self.modified = modified or now_iso()

    @classmethod
    def from_markdown(cls, text: str):
        m = FRONTMATTER_RE.match(text)
        meta = {}
        body = text
        if m:
            meta_text = m.group(1)
            body = text[m.end():]
            for line in meta_text.splitlines():
                if ':' in line:
                    k, v = line.split(':', 1)
                    meta[k.strip()] = v.strip()
        slug = meta.get('slug') or slugify(meta.get('title', ''))
        title = meta.get('title', slug)
        tags = [t.strip() for t in meta.get('tags', '').split(',') if t.strip()]
        created = meta.get('created')
        modified = meta.get('modified')
        return cls(slug=slug, title=title, body=body.strip(), tags=tags, created=created, modified=modified)

    def to_markdown(self) -> str:
        front = [
            '---',
            f"title: {self.title}",
            f"slug: {self.slug}",
            f"tags: {', '.join(self.tags)}",
            f"created: {self.created}",
            f"modified: {now_iso()}",
            '---',
            ''
        ]
        return '\n'.join(front) + self.body + '\n'

    def filename(self) -> str:
        return f"{self.slug}.md"

    def __repr__(self):
        return f"<Note {self.slug} title={self.title!r} tags={self.tags!r}>"

class NoteStore:
    """Handles reading/writing notes in a directory."""
    def __init__(self, path: Path):
        self.path = path
        self.path.mkdir(parents=True, exist_ok=True)
        logger.debug("NoteStore at %s", self.path)

    def list_notes(self) -> List[Note]:
        notes = []
        for p in sorted(self.path.glob('*.md')):
            try:
                text = p.read_text(encoding='utf-8')
                note = Note.from_markdown(text)
                notes.append(note)
            except Exception as e:
                logger.warning("Failed to read %s: %s", p, e)
        return notes

    def get(self, slug: str) -> Optional[Note]:
        p = self.path / f"{slug}.md"
        if not p.exists():
            return None
        return Note.from_markdown(p.read_text(encoding='utf-8'))

    def save(self, note: Note) -> None:
        p = self.path / note.filename()
        p.write_text(note.to_markdown(), encoding='utf-8')
        logger.info("Saved note %s", p)

    def exists(self, slug: str) -> bool:
        return (self.path / f"{slug}.md").exists()

class Indexer:
    """Builds an inverted index and document stats for TF-IDF scoring."""
    TOKEN_RE = re.compile(r"[A-Za-z0-9']{2,}")

    def __init__(self):
        # term -> {doc: count}
        self.inverted: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.doc_lengths: Dict[str, int] = {}
        self.titles: Dict[str, str] = {}
        self.tags: Dict[str, List[str]] = {}

    @staticmethod
    def tokenize(text: str) -> List[str]:
        return [t.lower() for t in Indexer.TOKEN_RE.findall(text)]

    def add(self, note: Note) -> None:
        doc = note.slug
        tokens = self.tokenize(note.title + " " + note.body)
        counts = Counter(tokens)
        for term, c in counts.items():
            self.inverted[term][doc] += c
        self.doc_lengths[doc] = sum(counts.values())
        self.titles[doc] = note.title
        self.tags[doc] = note.tags

    def idf(self, term: str) -> float:
        n_docs = len(self.doc_lengths) or 1
        df = len(self.inverted.get(term, {})) or 0
        # smoothing
        return math.log((1 + n_docs) / (1 + df)) + 1.0

    def score(self, query: str) -> List[Tuple[str, float]]:
        qtokens = self.tokenize(query)
        qcounts = Counter(qtokens)
        scores: Dict[str, float] = defaultdict(float)
        for term, qf in qcounts.items():
            if term not in self.inverted:
                continue
            idf = self.idf(term)
            postings = self.inverted[term]
            for doc, tf in postings.items():
                scores[doc] += (tf * idf * qf)
        # normalize by doc length
        scored = []
        for doc, s in scores.items():
            length = self.doc_lengths.get(doc, 1)
            scored.append((doc, s / math.sqrt(length)))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

class TagSuggester:
    """Simple tag suggestion using top TF terms in a note and existing global tags."""
    def __init__(self, indexer: Indexer):
        self.indexer = indexer

    def suggest(self, note: Note, top_n: int = 5) -> List[str]:
        tokens = Indexer.tokenize(note.title + " " + note.body)
        counts = Counter(tokens)
        common = [t for t, _ in counts.most_common(50)]
        # prefer tokens that are also present as tags in other docs
        candidate_scores = {}
        for token in common:
            # heuristics: ignore stop-ish words
            if len(token) < 3 or token.isdigit():
                continue
            # score: frequency + presence in other docs' tags
            freq = counts[token]
            tag_bonus = sum(1 for tags in self.indexer.tags.values() if token in tags)
            candidate_scores[token] = freq + 2 * tag_bonus
        # pick top N unique
        picked = [t for t, _ in sorted(candidate_scores.items(), key=lambda x: x[1], reverse=True)]
        return [p for p in picked if p not in note.tags][:top_n]

def find_backlinks(notes: List[Note]) -> Dict[str, List[str]]:
    """Detect backlinks: if a note body contains another note's slug or title."""
    mapping: Dict[str, List[str]] = defaultdict(list)
    slug_map = {n.slug: n for n in notes}
    title_map = {n.title.lower(): n for n in notes}
    for n in notes:
        text = (n.title + " " + n.body).lower()
        for candidate in notes:
            if candidate.slug == n.slug:
                continue
            if candidate.slug in text or candidate.title.lower() in text:
                mapping[candidate.slug].append(n.slug)
    return mapping

def export_graph_dot(notes: List[Note], backlinks: Dict[str, List[str]]) -> str:
    """Return a DOT graph string linking notes by backlinks and shared tags."""
    lines = ["digraph notes {", "  rankdir=LR;", "  node [shape=box, style=rounded];"]
    for n in notes:
        label = n.title.replace('"', '\\"')
        lines.append(f'  "{n.slug}" [label="{label}\\n({",".join(n.tags)})"];')
    # backlink edges
    for target, sources in backlinks.items():
        for s in sources:
            lines.append(f'  "{s}" -> "{target}";')
    # tag-cluster edges (thin)
    tag_map = defaultdict(list)
    for n in notes:
        for t in n.tags:
            tag_map[t].append(n.slug)
    for t, slugs in tag_map.items():
        if len(slugs) > 1:
            for a in slugs:
                for b in slugs:
                    if a != b:
                        lines.append(f'  "{a}" -> "{b}" [style=dotted, arrowhead=none, penwidth=0.5];')
    lines.append("}")
    return "\n".join(lines)

# CLI layer
def init_cmd(args):
    store = NoteStore(Path(args.dir))
    readme = Path(args.dir) / "README.md"
    if not readme.exists():
        readme.write_text("# Noteshelf Notes\n\nThis directory contains markdown notes managed by noteshelf.\n", encoding='utf-8')
    logger.info("Initialized notes directory at %s", args.dir)

def new_cmd(args):
    store = NoteStore(Path(args.dir))
    title = args.title
    slug = slugify(title)
    i = 1
    base = slug
    while store.exists(slug):
        i += 1
        slug = f"{base}-{i}"
    tags = [t.strip() for t in (args.tags or "").split(',') if t.strip()]
    body = args.body or f"# {title}\n\nWrite your note here.\n"
    note = Note(slug=slug, title=title, body=body, tags=tags)
    store.save(note)
    print(f"Created note: {slug} -> {store.path / note.filename()}")

def list_cmd(args):
    store = NoteStore(Path(args.dir))
    notes = store.list_notes()
    for n in notes:
        print(f"- {n.slug:20}  {n.title}  [{', '.join(n.tags)}]")

def show_cmd(args):
    store = NoteStore(Path(args.dir))
    note = store.get(args.slug)
    if not note:
        print("Note not found:", args.slug)
        return
    print(f"# {note.title}\n")
    print(f"_slug_: {note.slug}")
    print(f"_tags_: {', '.join(note.tags)}")
    print(f"_created_: {note.created}")
    print(f"_modified_: {note.modified}\n")
    print(note.body)

def search_cmd(args):
    store = NoteStore(Path(args.dir))
    notes = store.list_notes()
    idx = Indexer()
    for n in notes:
        idx.add(n)
    results = idx.score(args.query)
    if not results:
        print("No results.")
        return
    for slug, score in results[: args.limit]:
        title = idx.titles.get(slug, slug)
        print(f"{slug:20}  {title}  (score={score:.3f})")

def tags_cmd(args):
    store = NoteStore(Path(args.dir))
    notes = store.list_notes()
    tag_counts = Counter()
    for n in notes:
        tag_counts.update(n.tags)
    for tag, cnt in tag_counts.most_common():
        print(f"{tag:15} {cnt}")

def suggest_cmd(args):
    store = NoteStore(Path(args.dir))
    notes = store.list_notes()
    idx = Indexer()
    for n in notes:
        idx.add(n)
    suggester = TagSuggester(idx)
    note = store.get(args.slug)
    if not note:
        print("Note not found:", args.slug)
        return
    suggestions = suggester.suggest(note)
    print("Suggestions:", ", ".join(suggestions) if suggestions else "(none)")

def export_graph_cmd(args):
    store = NoteStore(Path(args.dir))
    notes = store.list_notes()
    backlinks = find_backlinks(notes)
    dot = export_graph_dot(notes, backlinks)
    Path(args.out).write_text(dot, encoding='utf-8')
    print("Wrote graph to", args.out)
    print("Render with: dot -Tpng -o graph.png", args.out)

def repl_cmd(args):
    store = NoteStore(Path(args.dir))
    print("Entering noteshelf interactive REPL. Type 'help' for commands. Ctrl-D to exit.")
    idx = None
    notes = store.list_notes()
    while True:
        try:
            line = input("noteshelf> ").strip()
        except EOFError:
            print()
            break
        if not line:
            continue
        parts = line.split(maxsplit=1)
        cmd = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""
        if cmd in ("q", "quit", "exit"):
            break
        if cmd in ("ls", "list"):
            for n in store.list_notes():
                print(f"- {n.slug:20} {n.title}")
        elif cmd == "show":
            slug = rest
            show_cmd(argparse.Namespace(dir=args.dir, slug=slug))
        elif cmd == "search":
            query = rest
            search_cmd(argparse.Namespace(dir=args.dir, query=query, limit=10))
        elif cmd == "new":
            title = rest or input("Title: ")
            new_cmd(argparse.Namespace(dir=args.dir, title=title, tags="", body=None))
        elif cmd in ("help", "?"):
            print("Commands: list, show <slug>, search <query>, new <title>, quit")
        else:
            print("Unknown:", cmd)

def parse_args(argv):
    p = argparse.ArgumentParser(prog="noteshelf", description="Noteshelf — simple markdown note manager")
    sub = p.add_subparsers(dest="cmd", required=True)

    a_init = sub.add_parser("init")
    a_init.add_argument("--dir", default="notes", help="notes directory")
    a_init.set_defaults(func=init_cmd)

    a_new = sub.add_parser("new")
    a_new.add_argument("title", help="note title")
    a_new.add_argument("--tags", help="comma separated tags", default="")
    a_new.add_argument("--body", help="initial body text", default=None)
    a_new.add_argument("--dir", default="notes")
    a_new.set_defaults(func=new_cmd)

    a_list = sub.add_parser("list")
    a_list.add_argument("--dir", default="notes")
    a_list.set_defaults(func=list_cmd)

    a_show = sub.add_parser("show")
    a_show.add_argument("slug", help="note slug")
    a_show.add_argument("--dir", default="notes")
    a_show.set_defaults(func=show_cmd)

    a_search = sub.add_parser("search")
    a_search.add_argument("query", help="search query")
    a_search.add_argument("--limit", type=int, default=10)
    a_search.add_argument("--dir", default="notes")
    a_search.set_defaults(func=search_cmd)

    a_tags = sub.add_parser("tags")
    a_tags.add_argument("--dir", default="notes")
    a_tags.set_defaults(func=tags_cmd)

    a_suggest = sub.add_parser("suggest-tags")
    a_suggest.add_argument("slug", help="note slug")
    a_suggest.add_argument("--dir", default="notes")
    a_suggest.set_defaults(func=suggest_cmd)

    a_export = sub.add_parser("export-graph")
    a_export.add_argument("out", help="output dot filename")
    a_export.add_argument("--dir", default="notes")
    a_export.set_defaults(func=export_graph_cmd)

    a_repl = sub.add_parser("repl")
    a_repl.add_argument("--dir", default="notes")
    a_repl.set_defaults(func=repl_cmd)

    return p.parse_args(argv)

def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    args = parse_args(argv)
    try:
        args.func(args)
    except Exception as e:
        logger.exception("Error: %s", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
