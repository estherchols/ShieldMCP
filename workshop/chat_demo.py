"""Workshop chat demo: a real customer-support assistant that looks up
customers by name. Its lookup tool is vulnerable to SQL injection. Type a
normal name and it helps you; type a SQL trick into the name and it leaks or
destroys the whole database. Flip ShieldMCP on and the attacks get blocked
while normal lookups still work. No AI key, offline.

    python workshop/chat_demo.py
    open http://127.0.0.1:8090
"""
from __future__ import annotations
import sqlite3
from pathlib import Path
from aiohttp import web

from shieldmcp.core.pipeline import ShieldPipeline
from shieldmcp.core.config import ShieldMCPConfig

DB = str(Path(__file__).parent / "chat_demo.db")
SEED = [
    ("Alice Chen", "5 Oak Ave, Dublin CA", "alice@example.com"),
    ("Bob Diaz", "12 Pine St, Fremont CA", "bob@example.com"),
    ("Priya Rao", "88 Lake Blvd, San Jose CA", "priya@example.com"),
]


def reset_db():
    Path(DB).unlink(missing_ok=True)
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE records (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, address TEXT, email TEXT)")
    c.executemany("INSERT INTO records (name, address, email) VALUES (?,?,?)", SEED)
    c.commit(); c.close()


def db_state():
    try:
        c = sqlite3.connect(DB)
        rows = c.execute("SELECT id, name, address, email FROM records").fetchall()
        c.close()
        return {"alive": True, "rows": rows}
    except Exception:
        return {"alive": False, "rows": []}


def count_customers():
    try:
        c = sqlite3.connect(DB)
        n = c.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        c.close()
        return n
    except Exception:
        return 0


def lookup_customer(name: str):
    """VULNERABLE on purpose: the name is glued into SQL with an f-string."""
    query = f"SELECT id, name, address, email FROM records WHERE name = '{name}'"
    c = sqlite3.connect(DB)
    try:
        try:
            rows = c.execute(query).fetchall()
            c.commit()
            return {"ok": True, "rows": rows}
        except (sqlite3.Warning, sqlite3.ProgrammingError):
            # multi-statement injection, e.g.  x'; DROP TABLE records; --
            c.executescript(query)
            c.commit()
            return {"ok": True, "rows": [], "destructive": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        c.close()


pipeline: ShieldPipeline | None = None


async def api_chat(request: web.Request):
    global pipeline
    body = await request.json()
    msg = (body.get("query") or "").strip()
    shield = bool(body.get("shield"))
    low = msg.lower()

    if not msg:
        return web.json_response({"kind": "assistant", "text": "Type a customer name to look them up."})

    # Friendly canned intents so it feels like a real assistant (safe, no DB query text).
    if low in ("hi", "hello", "hey", "help", "help me"):
        return web.json_response({"kind": "assistant",
            "text": "Hi! I'm the Acme support assistant. Give me a customer's name and I'll pull up their account. For example, try Alice Chen."})
    if "how many" in low or low.startswith("count"):
        return web.json_response({"kind": "assistant",
            "text": f"We currently have {count_customers()} customers in the system."})

    # Everything else is treated as a customer NAME and looked up (the vulnerable tool).
    if shield:
        assert pipeline is not None
        _, alerts = await pipeline.process_tool_call("support-bot", "lookup_customer", {"name": msg})
        blocked = [a for a in alerts if a.action.value in ("block", "quarantine")]
        if blocked:
            return web.json_response({
                "kind": "blocked",
                "stage": "Stage 2 (parameters)",
                "reason": blocked[0].message,
                "state": db_state(),
            })

    r = lookup_customer(msg)
    if not r["ok"]:
        return web.json_response({"kind": "assistant", "text": f"Sorry, something went wrong: {r['error']}", "state": db_state()})
    if r.get("destructive"):
        return web.json_response({"kind": "destroyed", "state": db_state()})
    rows = r["rows"]
    exposed = len(rows) > 1
    return web.json_response({
        "kind": "lookup",
        "rows": rows,
        "exposed": exposed,
        "name": msg,
        "state": db_state(),
    })


async def api_state(request: web.Request):
    return web.json_response(db_state())


async def api_reset(request: web.Request):
    reset_db()
    return web.json_response(db_state())


async def index(request: web.Request):
    return web.Response(text=HTML, content_type="text/html")


async def on_start(app):
    global pipeline
    reset_db()
    pipeline = ShieldPipeline(ShieldMCPConfig())
    await pipeline.initialize()


HTML = r"""<!doctype html><html><head><meta charset="utf-8"><title>Acme Support Assistant</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 :root{--bg:#0f0f16;--panel:#1a1a24;--line:#2a2a38;--fg:#ececf4;--mut:#9a9ab0;--acc:#7c6cff;--red:#ff5d6c;--grn:#43d69a;--blue:#3d7dff}
 *{box-sizing:border-box}body{margin:0;font-family:-apple-system,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--fg)}
 header{display:flex;align-items:center;gap:14px;padding:14px 22px;border-bottom:1px solid var(--line);background:var(--panel)}
 header h1{font-size:18px;margin:0;font-weight:700}header .sub{color:var(--mut);font-size:13px}
 .spacer{flex:1}
 .toggle{display:flex;align-items:center;gap:10px}
 .switch{position:relative;width:60px;height:30px;border-radius:20px;background:#555;cursor:pointer;transition:.2s;border:none}
 .switch.on{background:var(--grn)}
 .knob{position:absolute;top:3px;left:3px;width:24px;height:24px;border-radius:50%;background:#fff;transition:.2s}
 .switch.on .knob{left:33px}
 .shield-label{font-weight:700;font-size:15px}.shield-label.off{color:var(--red)}.shield-label.on{color:var(--grn)}
 .wrap{display:grid;grid-template-columns:1.3fr 1fr;height:calc(100vh - 62px)}
 .chat{display:flex;flex-direction:column;border-right:1px solid var(--line);min-width:0}
 .msgs{flex:1;overflow-y:auto;padding:20px;display:flex;flex-direction:column;gap:14px}
 .row{display:flex}.row.me{justify-content:flex-end}
 .bub{max-width:80%;padding:11px 15px;border-radius:16px;font-size:15px;line-height:1.5;white-space:pre-wrap;word-break:break-word}
 .me .bub{background:var(--blue);color:#fff;border-bottom-right-radius:4px}
 .bot .bub{background:#23233150;border:1px solid var(--line);border-bottom-left-radius:4px}
 .bot .bub.blocked{border-color:var(--grn);background:#16351f}
 .bot .bub.destroyed{border-color:var(--red);background:#3a1620}
 .bot .bub.exposed{border-color:var(--red);background:#2a1622}
 .bub .tag{display:block;font-size:11px;font-weight:800;letter-spacing:.5px;margin-bottom:5px}
 .tag.g{color:var(--grn)}.tag.r{color:var(--red)}.tag.m{color:var(--mut)}
 .rec{font-family:'SF Mono',Menlo,monospace;font-size:13px;background:#00000030;border-radius:8px;padding:7px 10px;margin-top:6px}
 .composer{border-top:1px solid var(--line);padding:14px 18px;background:var(--panel)}
 .quick{display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap}
 .quick button{background:transparent;border:1px solid var(--line);color:var(--mut);padding:6px 11px;border-radius:20px;font-size:12px;cursor:pointer;font-family:'SF Mono',Menlo,monospace}
 .quick button.evil{border-color:#5a2030;color:#ff9db0}
 .quick button:hover{border-color:var(--acc);color:var(--fg)}
 .inrow{display:flex;gap:10px}
 .inrow input{flex:1;background:#0f0f16;border:1px solid var(--line);color:var(--fg);padding:12px 14px;border-radius:10px;font-size:15px}
 .inrow input:focus{outline:none;border-color:var(--acc)}
 .inrow button.send{background:var(--acc);border:none;color:#fff;padding:0 20px;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer}
 .db{padding:20px;overflow-y:auto;background:#12121a;min-width:0}
 .db h2{font-size:14px;margin:0 0 4px;display:flex;align-items:center;gap:8px}
 .db .hint{color:var(--mut);font-size:12px;margin:0 0 14px}
 table{width:100%;border-collapse:collapse;font-size:12.5px}
 th,td{border:1px solid var(--line);padding:7px 9px;text-align:left}
 th{background:#20202c;color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
 td{font-family:'SF Mono',Menlo,monospace;word-break:break-word}
 .gone{margin-top:24px;text-align:center;color:var(--red);font-size:17px;font-weight:700}
 .gone .big{font-size:44px;display:block;margin-bottom:8px}
 .reset{margin-top:16px;background:transparent;border:1px solid var(--line);color:var(--mut);padding:8px 14px;border-radius:8px;cursor:pointer;font-size:13px}
 .reset:hover{border-color:var(--acc);color:var(--fg)}
 .pill{font-size:11px;padding:2px 8px;border-radius:10px;font-weight:700}
 .pill.live{background:#16351f;color:var(--grn)}.pill.dead{background:#3a1620;color:var(--red)}
</style></head><body>
<header>
  <h1>&#128100; Acme Support Assistant</h1>
  <span class="sub">looks up customer accounts</span>
  <div class="spacer"></div>
  <div class="toggle">
    <span class="shield-label off" id="slabel">&#128737; ShieldMCP: OFF</span>
    <button class="switch" id="switch" onclick="toggleShield()"><span class="knob"></span></button>
  </div>
</header>
<div class="wrap">
  <div class="chat">
    <div class="msgs" id="msgs"></div>
    <div class="composer">
      <div class="quick">
        <button onclick="quick('Alice Chen')">Alice Chen</button>
        <button onclick="quick('how many customers do we have?')">how many customers?</button>
        <button class="evil" onclick="quick(&quot;' OR '1'='1&quot;)">&#128520; ' OR '1'='1</button>
        <button class="evil" onclick="quick(&quot;x'; DROP TABLE records; --&quot;)">&#128520; drop table</button>
      </div>
      <div class="inrow">
        <input id="q" placeholder="Type a customer name..." onkeydown="if(event.key==='Enter')send()">
        <button class="send" onclick="send()">Send</button>
      </div>
    </div>
  </div>
  <div class="db">
    <h2>&#128202; Customer Database <span class="pill live" id="pill">LIVE</span></h2>
    <p class="hint">Private data. The assistant should never expose all of this at once.</p>
    <div id="dbview"></div>
    <button class="reset" onclick="resetDb()">&#8635; Reset database</button>
  </div>
</div>
<script>
let shield=false;
function toggleShield(){shield=!shield;
  document.getElementById('switch').classList.toggle('on',shield);
  const l=document.getElementById('slabel');
  l.textContent=(shield?'\u{1F6E1} ShieldMCP: ON':'\u{1F6E1} ShieldMCP: OFF');
  l.className='shield-label '+(shield?'on':'off');
}
function quick(t){document.getElementById('q').value=t;send();}
function esc(s){return (s+'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function add(side,html,cls){const m=document.getElementById('msgs');const r=document.createElement('div');
  r.className='row '+side;const b=document.createElement('div');b.className='bub'+(cls?' '+cls:'');b.innerHTML=html;
  r.appendChild(b);m.appendChild(r);m.scrollTop=m.scrollHeight;}
function recCard(row){return '<div class="rec">name: '+esc(row[1])+'<br>address: '+esc(row[2])+'<br>email: '+esc(row[3])+'</div>';}
async function send(){
  const inp=document.getElementById('q');const q=inp.value.trim();if(!q)return;inp.value='';
  add('me','<code>'+esc(q)+'</code>');
  const res=await fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:q,shield:shield})});
  const d=await res.json();
  if(d.kind==='assistant'){add('bot','<span class="tag m">ASSISTANT</span>'+esc(d.text));}
  else if(d.kind==='blocked'){add('bot','<span class="tag g">\u{1F6E1} SHIELDMCP BLOCKED &middot; '+esc(d.stage)+'</span>'+esc(d.reason)+'<br><br>That request was not a real name. It never reached the database.','blocked');}
  else if(d.kind==='destroyed'){add('bot','<span class="tag r">\u{1F4A5} REQUEST RAN</span>The lookup ran your injected command. The customer table has been dropped.','destroyed');}
  else if(d.kind==='lookup'){
    if(d.rows.length===0){add('bot','<span class="tag m">ASSISTANT</span>No customer found named "'+esc(d.name)+'".');}
    else if(d.exposed){add('bot','<span class="tag r">⚠ DATA EXPOSED &middot; '+d.rows.length+' records</span>You asked for one customer, but the injection returned <b>every</b> customer:'+d.rows.map(recCard).join(''),'exposed');}
    else{add('bot','<span class="tag m">ASSISTANT</span>Here is the account you asked for:'+recCard(d.rows[0]));}
  }
  if(d.state) renderDb(d.state);
}
function renderDb(s){
  const v=document.getElementById('dbview');const pill=document.getElementById('pill');
  if(!s.alive){pill.textContent='DESTROYED';pill.className='pill dead';
    v.innerHTML='<div class="gone"><span class="big">&#128165;</span>Table dropped.<br>All customer data is gone.</div>';return;}
  pill.textContent='LIVE';pill.className='pill live';
  let h='<table><tr><th>id</th><th>name</th><th>address</th><th>email</th></tr>';
  s.rows.forEach(r=>{h+='<tr><td>'+r[0]+'</td><td>'+esc(r[1])+'</td><td>'+esc(r[2])+'</td><td>'+esc(r[3])+'</td></tr>';});
  h+='</table>';v.innerHTML=h;
}
async function resetDb(){const r=await fetch('/api/reset',{method:'POST'});renderDb(await r.json());
  document.getElementById('msgs').innerHTML='';greet();}
function greet(){add('bot','<span class="tag m">ASSISTANT</span>Hi! I\'m the Acme support assistant. Give me a customer\'s name and I\'ll pull up their account. Try Alice Chen.');}
async function load(){const r=await fetch('/api/state');renderDb(await r.json());greet();}
load();
</script></body></html>"""


def main():
    app = web.Application()
    app.on_startup.append(on_start)
    app.add_routes([
        web.get("/", index),
        web.get("/api/state", api_state),
        web.post("/api/chat", api_chat),
        web.post("/api/reset", api_reset),
    ])
    print("\n  Acme Support Assistant demo at  http://127.0.0.1:8090\n  Ctrl+C to stop.\n")
    web.run_app(app, host="127.0.0.1", port=8090, print=None)


if __name__ == "__main__":
    main()
