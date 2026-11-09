#!/usr/bin/env python3
"""Generate a standalone searchable website from GAMES.md."""

import argparse
import json
import re
from pathlib import Path
from typing import List, Tuple


Game = Tuple[str, str, str, str, str]
GAME_LINE_RE = re.compile(
    r"^- \*\*(.*?)\*\* - `([^`]+)` - version `([^`]+)` - `([^`]+)`"
    r"(?: - `([^`]+)`)?$"
)


def parse_args() -> argparse.Namespace:
    script_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(
        description="Generate a standalone searchable website from GAMES.md."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=script_root,
        help="Repository root containing GAMES.md and the website template.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output HTML path. Defaults to <root>/index.html.",
    )
    return parser.parse_args()


def read_games(markdown_path: Path) -> List[Game]:
    games = []
    for line_number, line in enumerate(
        markdown_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.startswith("- **"):
            continue
        match = GAME_LINE_RE.fullmatch(line)
        if not match:
            raise RuntimeError(
                f"Unrecognized game entry at {markdown_path}:{line_number}"
            )
        name, title_id, version, file_type, process = match.groups()
        games.append((name, title_id, version, file_type, process or "eboot.bin"))
    return games


def main() -> None:
    args = parse_args()
    root = args.root.resolve()
    markdown_path = root / "GAMES.md"
    template_path = root / ".ci" / "game-catalog-template.html"
    output_path = (args.output or root / "index.html").resolve()

    games = read_games(markdown_path)
    template = template_path.read_text(encoding="utf-8")
    placeholder = "__GAME_DATA__"
    if template.count(placeholder) != 1:
        raise RuntimeError(f"Expected exactly one {placeholder} in {template_path}")

    game_data = json.dumps(games, ensure_ascii=False).replace("<", "\\u003c")
    output_path.write_text(
        template.replace(placeholder, game_data),
        encoding="utf-8",
    )
    print(f"Wrote {output_path} with {len(games)} game/version entries.")


if __name__ == "__main__":
    main()
