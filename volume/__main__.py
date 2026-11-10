"""Run VOLUME.

Local terminals get the interactive console. A Render web service starts this
package with no TTY, so boot the FastAPI app there instead of failing the CLI's
license check (which would exit with status 2 and never bind a port).
"""

import os


def _web_mode() -> bool:
    """Render web services set RENDER/RENDER_SERVICE_ID; the local CLI does not."""
    return bool(os.environ.get("RENDER") or os.environ.get("RENDER_SERVICE_ID"))


def main() -> int:
    if _web_mode():
        import uvicorn

        port = int(os.environ.get("PORT") or "10000")
        uvicorn.run("api.main:app", host="0.0.0.0", port=port)
        return 0

    from volume.main import main as cli

    return cli()


if __name__ == "__main__":
    raise SystemExit(main())
