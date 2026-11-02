#!/usr/bin/env python3
"""Generate a Markdown game catalog from JSON, mc4 and shn cheat files."""

import argparse
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


def parse_args() -> argparse.Namespace:
    script_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(
        description="Generate a Markdown list of games from JSON, MC4, and SHN cheat files."
    )
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=script_root,
        help="Repository root containing the JSON files.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Output Markdown path. Defaults to <root>/GAMES.md.",
    )
    return parser.parse_args()


Game = Tuple[str, str, str, str, str]
FILE_NAME_RE = re.compile(
    r"(?P<id>[A-Z]{4}\d+)_"
    r"(?P<version>\d+[._]\d+)(?:_(?P<process>.*?))?"
    r"\s*\.(?P<extension>json|shn|mc4)(?:\.xml)?$",
    re.IGNORECASE,
)


def read_games(root: Path, output: Path) -> List[Game]:
    games: set[Game] = set()
    json_files = sorted(path for path in root.rglob("*.json") if path.resolve() != output.resolve())
    names_by_id: Dict[str, str] = {}

    for path in json_files:
        try:
            with path.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(f"Could not read {path}: {error}") from error

        if not isinstance(data, dict):
            raise RuntimeError(f"{path} does not contain a JSON object")

        title_id = data.get("id")
        name = data.get("name")
        version = data.get("version")
        process = data.get("process", "")
        if not isinstance(title_id, str) or not title_id:
            raise RuntimeError(f"{path} is missing a non-empty string 'id'")
        if not isinstance(name, str) or not name:
            raise RuntimeError(f"{path} is missing a non-empty string 'name'")
        if not isinstance(version, str) or not version:
            raise RuntimeError(f"{path} is missing a non-empty string 'version'")
        if not isinstance(process, str):
            raise RuntimeError(f"{path} has an invalid 'process' value")

        names_by_id[title_id.upper()] = name
        games.add((name, title_id, version, process, "JSON"))

    for extension in ("*.shn", "*.mc4", "*.mc4.xml", "*.MC4"):
        for path in sorted(root.rglob(extension)):
            if path.resolve() == output.resolve():
                continue
            match = FILE_NAME_RE.match(path.name)
            if not match:
                raise RuntimeError(f"Could not identify title/version in {path}")

            title_id = match.group("id").upper()
            version = match.group("version").replace("_", ".")
            process = match.group("process") or "eboot.bin"
            file_type = match.group("extension").upper()
            name = names_by_id.get(title_id, title_id)

            if path.suffix.lower() == ".xml":
                try:
                    attributes = ET.parse(path).getroot().attrib
                except (OSError, ET.ParseError) as error:
                    raise RuntimeError(f"Could not read {path}: {error}") from error
                name = attributes.get("Game", name).strip()
                title_id = attributes.get("Cusa", title_id).strip().upper()
                version = attributes.get("Version", version).strip()
                process = attributes.get("Process", process).strip()

            games.add((name, title_id, version, process, file_type))

    return sorted(games, key=lambda game: (game[0].casefold(), game[1], game[2], game[3], game[4]))


def markdown_lines(games: List[Game]) -> Iterable[str]:
    yield "# Available Games"
    yield ""
    yield (
        f"This catalog lists {len(games)} unique game/version entries from "
        "the JSON, MC4, and SHN cheat files in this repository."
    )
    yield ""

    for name, title_id, version, process, file_type in games:
        process_suffix = f" - `{process}`" if process and process != "eboot.bin" else ""
        yield f"- **{name}** - `{title_id}` - version `{version}` - `{file_type}`{process_suffix}"


def main() -> None:
    args = parse_args()
    root = args.root.resolve()
    output = (args.output or root / "GAMES.md").resolve()
    games = read_games(root, output)

    output.write_text(
        "\n".join(markdown_lines(games)) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {output} with {len(games)} game/version entries.")


if __name__ == "__main__":
    main()
