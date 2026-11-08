import os
import sys

from rich.console import Console
from rich.panel import Panel

console = Console()


def read_key() -> str:
    """Read exactly one key without needing Enter. Works in screen/SSH and on Windows."""
    if os.name == "nt":
        try:
            import msvcrt

            # Piped/non-console stdin (CI, scripts): read a line instead.
            if not sys.stdin.isatty():
                line = sys.stdin.readline()
                return line.strip()[:1].lower() if line else "q"

            ch = msvcrt.getwch()
            if ch in ("\x00", "\xe0"):
                ch = msvcrt.getwch()
                return {"H": "up", "P": "down", "K": "up", "M": "down"}.get(ch, "")
            return ch.lower()
        except Exception:
            try:
                line = input()
                return line.strip()[:1].lower() if line else "q"
            except EOFError:
                return "q"

    try:
        import termios
        import tty

        fd = sys.stdin.fileno()
        if not os.isatty(fd):
            line = input().strip()
            return line[:1].lower()

        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            ch = os.read(fd, 1).decode("utf-8", errors="ignore")
            if ch == "\x1b":
                import select
                seq = b""
                while len(seq) < 2 and select.select([fd], [], [], 0.02)[0]:
                    seq += os.read(fd, 1)
                ch = {"[A": "up", "[B": "down", "[C": "right", "[D": "left"}.get(
                    seq.decode("ascii", errors="ignore"), ""
                )
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        return ch.lower()
    except Exception:
        try:
            return input().strip()[:1].lower()
        except EOFError:
            return "q"


def read_block(prompt_text: str = "", end_marker: str = "") -> str:
    """Read a multi-line paste until a blank line (or the end marker)."""
    console.print(prompt_text or "[dim]Paste text. Finish with a blank line:[/]")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if end_marker and line.strip() == end_marker:
            break
        if not line.strip():
            if lines:
                break
            continue
        lines.append(line)
    return "\n".join(lines)


def choose_device() -> str:
    """Ask whether to use the mobile or PC layout. Also supports --mobile / --pc / VOLUME_UI."""
    argv = [a.lower() for a in sys.argv]
    forced = (os.getenv("VOLUME_UI") or "").strip().lower()
    if "--mobile" in argv:
        forced = "mobile"
    elif "--pc" in argv:
        forced = "pc"

    if forced in ("mobile", "pc"):
        return forced

    if not sys.stdin.isatty():
        return "mobile" if console.size.width < 100 else "pc"

    console.print(Panel(
        "[bold green]VOLUME[/]\n\n"
        "[bold]1[/]  Mobile layout  (compact, phone friendly)\n"
        "[bold]2[/]  PC layout      (full dashboard)\n"
        "[dim]Press Enter for auto-detect[/]",
        title="[bold green]CHOOSE DEVICE[/]",
        border_style="green",
    ))
    while True:
        console.print("[bold green]device>[/] ", end="")
        console.file.flush()
        key = read_key()
        console.print()
        if key == "1":
            return "mobile"
        if key == "2":
            return "pc"
        if key in ("\r", "\n", ""):
            return "mobile" if console.size.width < 100 else "pc"
        console.print("[yellow]Press 1 for Mobile, 2 for PC, or Enter for auto.[/]")
