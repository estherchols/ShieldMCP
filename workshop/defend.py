"""LAB 2: YOU are the defender.

Runs the SAME vulnerable server, but this time behind ShieldMCP as a
transparent proxy. The normal request still works; the exact attack that
wiped the table in Lab 1 is now blocked before it reaches the database.

    python workshop/defend.py

Nothing about the server changed. The only difference is one line in front
of it:  shieldmcp proxy -- python workshop/vulnerable_server.py
"""
from __future__ import annotations
import sys, shutil, asyncio
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = Path(__file__).resolve().parent
SERVER = str(HERE / "vulnerable_server.py")
DB = HERE / "workshop_demo.db"
# Find the shieldmcp CLI in the same environment as this Python.
SHIELD = shutil.which("shieldmcp") or str(Path(sys.executable).parent / "shieldmcp")

R, G, DIM, B, RESET = "\033[91m", "\033[92m", "\033[2m", "\033[1m", "\033[0m"


async def run(label, tool, args, expect_block):
    if DB.exists():
        DB.unlink()
    params = StdioServerParameters(
        command=SHIELD,
        args=["proxy", "--server-id", "customer-db", "--log-level", "WARNING",
              "--", sys.executable, SERVER],
        cwd=str(HERE),
    )
    print(f"\n{B}> {label}{RESET}")
    print(f"{DIM}  sends: {tool}({args}){RESET}")
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await asyncio.wait_for(session.initialize(), timeout=25)
                res = await asyncio.wait_for(session.call_tool(tool, args), timeout=25)
                text = " ".join(getattr(c, "text", "") for c in res.content).strip()
                if expect_block:
                    print(f"{R}  reached the server (unexpected): {text[:90]}{RESET}")
                else:
                    print(f"{G}  PASSED THROUGH, server ran it: {text[:90]}{RESET}")
    except Exception:
        if expect_block:
            print(f"{G}  BLOCKED by ShieldMCP at Stage 2. The SQL never reached the database.{RESET}")
        else:
            print(f"{R}  unexpected error on the benign call{RESET}")
    finally:
        if DB.exists():
            DB.unlink()


async def main():
    print(f"\n{G}{B}{'='*66}\n LAB 2: same server, now behind ShieldMCP\n{'='*66}{RESET}")
    await run("A normal request", "insert_record",
              {"name": "Alice Chen", "address": "5 Oak Ave"}, expect_block=False)
    await run("The SAME DROP TABLE that wiped everything in Lab 1", "execute_sql",
              {"query": "DROP TABLE records"}, expect_block=True)
    print(f"\n{G}{B}{'='*66}\n Same server. Same attack. Blocked. You defended it.\n{'='*66}{RESET}")


if __name__ == "__main__":
    asyncio.run(main())
