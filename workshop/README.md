# Workshop lab: attack an MCP server, then defend it with ShieldMCP

A hands-on lab. You will attack a real (deliberately vulnerable) MCP server,
defend the same server with ShieldMCP, then make ShieldMCP a little stronger
and open your first pull request. No AI, no API keys, fully offline.

## Setup (once)

```bash
# 1. Fork this repo on GitHub (top-right Fork button), then clone YOUR fork:
git clone https://github.com/<your-username>/ShieldMCP.git
cd ShieldMCP
git checkout workshop-lab

# 2. Install into an isolated environment:
python3 -m venv .venv
source .venv/bin/activate      # your prompt now shows (.venv)
pip install -e .
```

Check it worked:

```bash
shieldmcp --help
```

## Lab 1: be the attacker (see the vulnerability)

```bash
python workshop/attack.py
```

You just watched a real MCP server leak every customer record and then destroy
its whole table, using nothing but tool calls. Open `workshop/attack.py`, change
the query on the line marked `ATTACK 2`, and run it again to see what else you
can do.

## Lab 2: be the defender (see the protection)

```bash
python workshop/defend.py
```

Same server, unchanged. This time ShieldMCP sits in front of it as a proxy. The
normal request still works; the exact `DROP TABLE` that wiped everything in Lab 1
is now blocked before it reaches the database. In production that is one line:

```bash
shieldmcp proxy -- python workshop/vulnerable_server.py
```

## Lab 3: make it stronger, open a PR

1. Launch the interactive playground:
   ```bash
   shieldmcp demo
   ```
   Open the printed address, click **Try your own input**, and write a tool
   description or response that is clearly malicious but slips through.

2. Add a rule that catches it. Open `src/shieldmcp/stage1/semantic.py` and add
   your phrase to `DIRECTIVE_KEYWORDS` (one line):
   ```python
       "exfiltrate to",   # your bypass phrase
   ```

3. Prove it with a test. Create `tests/unit/test_<yourname>_rule.py`:
   ```python
   from shieldmcp.stage1.semantic import DIRECTIVE_KEYWORDS
   def test_my_rule():
       assert "exfiltrate to" in DIRECTIVE_KEYWORDS
   ```
   Run it:
   ```bash
   python -m pytest tests/unit/test_<yourname>_rule.py -q
   ```

4. Open the pull request:
   ```bash
   git checkout -b add-detection-rule
   git add -A
   git commit -m "Add detection rule for <the attack you caught>"
   git push origin add-detection-rule
   ```
   GitHub prints a link to open the PR. Raise your hand when it is open.

Thank you for making an open security tool a little stronger. That is the point.
