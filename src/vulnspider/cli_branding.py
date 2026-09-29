"""Pure, capability-aware VulnSpider terminal branding."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping, TextIO


TAGLINE = "LOCAL-FIRST · EVIDENCE-DRIVEN · AUTHORIZED TARGETS ONLY"
ASCII_TAGLINE = "LOCAL-FIRST | EVIDENCE-DRIVEN | AUTHORIZED TARGETS ONLY"
TEAM_NAME = "TEAM SPIDER-MAN"
MIN_WIDE_WIDTH = 76


class ColorMode(StrEnum):
    NONE = "none"
    ANSI16 = "ansi16"
    ANSI256 = "ansi256"
    TRUECOLOR = "truecolor"


@dataclass(frozen=True, slots=True)
class BannerCapabilities:
    width: int
    is_tty: bool
    color_mode: ColorMode
    unicode: bool
    term_dumb: bool = False
    hidden: bool = False


_GLYPHS = {
    "V": ("█   █", "█   █", "█   █", " █ █ ", "  █  "),
    "U": ("█   █", "█   █", "█   █", "█   █", " ███ "),
    "L": ("█    ", "█    ", "█    ", "█    ", "█████"),
    "N": ("█   █", "██  █", "█ █ █", "█  ██", "█   █"),
    "S": (" ████", "█    ", " ███ ", "    █", "████ "),
    "P": ("████ ", "█   █", "████ ", "█    ", "█    "),
    "I": ("█████", "  █  ", "  █  ", "  █  ", "█████"),
    "D": ("████ ", "█   █", "█   █", "█   █", "████ "),
    "E": ("█████", "█    ", "████ ", "█    ", "█████"),
    "R": ("████ ", "█   █", "████ ", "█  █ ", "█   █"),
}
_WORD = "VULNSPIDER"
_TRUECOLOR = (
    "30;90;230",
    "35;105;245",
    "40;120;255",
    "50;135;255",
    "225;25;45",
    "235;30;45",
    "245;35;45",
    "255;40;50",
    "255;50;55",
    "255;60;60",
)
_ANSI256 = (27, 27, 33, 33, 196, 196, 196, 203, 203, 203)
_ANSI16 = (94, 94, 94, 94, 91, 91, 91, 91, 91, 91)

# Braille cells provide a 32 x 48 silhouette in only 16 terminal columns:
# four articulated leg pairs, a small cephalothorax, and an oval abdomen.
# The ASCII silhouette preserves the same anatomy without Unicode glyphs.
_SPIDER = (
    ("⢠⠀⠀⠀⠀⡐⠁⠀⠀⠈⢂⠀⠀⠀⠀⡄", "     /    \\     "),
    ("⠀⣆⠀⠀⢸⠀⠀⠀⠀⠀⠀⡇⠀⠀⣰⠀", " |   |    |   | "),
    ("⠀⠘⡄⠀⢸⡀⠀⠀⠀⠀⢀⡇⠀⢠⠃⠀", "  \\  |    |  /  "),
    ("⠀⠀⠹⢦⣈⢷⡀⣀⣀⢀⡾⣁⡴⠏⠀⠀", "   \\_\\ oo /_/   "),
    ("⠀⠀⠀⠀⠙⠻⣷⣿⣿⣾⠟⠋⠀⠀⠀⠀", "     \\(@@)/     "),
    ("⠀⠀⠀⣀⣤⡴⣞⣿⣿⣳⢦⣤⣀⠀⠀⠀", "   __/(##)\\__   "),
    ("⠀⢀⡞⠉⠀⣰⣿⣿⣿⣿⣆⠀⠉⢳⡀⠀", "  /  /####\\  \\  "),
    ("⢠⠏⠀⠀⢰⢏⣿⣿⣿⣿⡹⡆⠀⠀⠹⡄", " /  /######\\  \\ "),
    ("⠘⠀⠀⠀⢸⠀⣿⣿⣿⣿⠀⡇⠀⠀⠀⠃", "|   |######|   |"),
    ("⠇⠀⠀⠀⢸⠀⠹⣿⣿⠏⠀⡇⠀⠀⠀⠸", "|   | #### |   |"),
    ("⠀⠀⠀⠀⠀⠆⠀⠀⠀⠀⠰⠀⠀⠀⠀⠀", "     \\    /     "),
    ("⠀⠀⠀⠀⠀⠘⡀⠀⠀⢀⠃⠀⠀⠀⠀⠀", "      \\  /      "),
)


def detect_capabilities(
    stream: TextIO,
    *,
    environ: Mapping[str, str] | None = None,
    hidden: bool = False,
    width: int | None = None,
) -> BannerCapabilities:
    env = os.environ if environ is None else environ
    is_tty = bool(getattr(stream, "isatty", lambda: False)())
    resolved_width = width or shutil.get_terminal_size((100, 24)).columns
    term = env.get("TERM", "")
    term_dumb = term.casefold() == "dumb"
    no_color = "NO_COLOR" in env
    if not is_tty or no_color:
        mode = ColorMode.NONE
    elif env.get("COLORTERM", "").casefold() in {"truecolor", "24bit"}:
        mode = ColorMode.TRUECOLOR
    elif "256color" in term.casefold():
        mode = ColorMode.ANSI256
    else:
        mode = ColorMode.ANSI16
    encoding = (getattr(stream, "encoding", None) or "").lower()
    unicode_ok = "utf" in encoding or encoding == ""
    return BannerCapabilities(
        width=max(1, resolved_width),
        is_tty=is_tty,
        color_mode=mode,
        unicode=unicode_ok,
        term_dumb=term_dumb,
        hidden=hidden,
    )


def render_banner(capabilities: BannerCapabilities) -> str:
    """Render a wide wordmark or a compact fallback; return empty off-TTY."""

    if capabilities.hidden or not capabilities.is_tty:
        return ""
    if capabilities.term_dumb or capabilities.width < MIN_WIDE_WIDTH:
        spider = "🕷 " if capabilities.unicode else ""
        return f"{spider}VULNSPIDER\n"

    rows: list[str] = []
    for row_index, motif in enumerate(_SPIDER):
        spider = motif[0 if capabilities.unicode else 1]
        pieces = [_paint(spider, 6, capabilities.color_mode)]
        if row_index == 2:
            pieces.append(_paint(TEAM_NAME, "silver", capabilities.color_mode))
        if not 4 <= row_index < 9:
            rows.append(" ".join(pieces).rstrip())
            continue
        for letter_index, letter in enumerate(_WORD):
            glyph = _GLYPHS[letter][row_index - 4]
            if not capabilities.unicode:
                glyph = glyph.replace("█", "#")
            pieces.append(
                _paint(
                    glyph,
                    letter_index,
                    capabilities.color_mode,
                )
            )
        rows.append(" ".join(pieces).rstrip())
    tagline = TAGLINE if capabilities.unicode else ASCII_TAGLINE
    rows.append(_paint(tagline, "silver", capabilities.color_mode))
    return "\n".join(rows) + "\n"


def write_banner(stream: TextIO, capabilities: BannerCapabilities) -> bool:
    rendered = render_banner(capabilities)
    if not rendered:
        return False
    stream.write(rendered)
    stream.flush()
    return True


def _paint(text: str, tone: int | str, mode: ColorMode) -> str:
    if mode == ColorMode.NONE:
        return text
    if tone == "silver":
        if mode == ColorMode.TRUECOLOR:
            code = "38;2;229;231;235"
        elif mode == ColorMode.ANSI256:
            code = "38;5;254"
        else:
            code = "97"
    else:
        index = int(tone)
        if mode == ColorMode.TRUECOLOR:
            code = f"38;2;{_TRUECOLOR[index]}"
        elif mode == ColorMode.ANSI256:
            code = f"38;5;{_ANSI256[index]}"
        else:
            code = str(_ANSI16[index])
    return f"\x1b[{code}m{text}\x1b[0m"
