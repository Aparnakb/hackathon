"""Brightloop Subscription Management System - FastAPI + SQLite."""
import sqlite3, os, hashlib, secrets, re, json, datetime as dt, calendar
from fastapi import Path, FastAPI, Depends, HTTPException, Header, Body
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
import jwt

DB = os.environ.get("DB_PATH", "brightloop.db")
SECRET = os.environ.get("JWT_SECRET", "change-me-in-production")
app = FastAPI(title="Brightloop Subscription Management")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN('admin','staff','customer')), reset_token TEXT, reset_expires TEXT);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT NOT NULL, type TEXT, sales_price REAL NOT NULL, cost_price REAL DEFAULT 0, notes TEXT);
CREATE TABLE IF NOT EXISTS variants(id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL REFERENCES products(id), attribute TEXT, value TEXT, extra_price REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS plans(id INTEGER PRIMARY KEY, name TEXT NOT NULL, price REAL NOT NULL, billing_period TEXT NOT NULL CHECK(billing_period IN('daily','weekly','monthly','yearly')),
  min_qty INTEGER DEFAULT 1, start_date TEXT, end_date TEXT, auto_close INTEGER DEFAULT 0, closable INTEGER DEFAULT 0, pausable INTEGER DEFAULT 0, renewable INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS taxes(id INTEGER PRIMARY KEY, name TEXT NOT NULL, rate REAL NOT NULL);
CREATE TABLE IF NOT EXISTS discounts(id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN('fixed','percent')), value REAL NOT NULL,
  min_purchase REAL DEFAULT 0, min_qty INTEGER DEFAULT 0, start_date TEXT, end_date TEXT, usage_limit INTEGER, used INTEGER DEFAULT 0, product_id INTEGER);
CREATE TABLE IF NOT EXISTS templates(id INTEGER PRIMARY KEY, name TEXT NOT NULL, plan_id INTEGER, validity_days INTEGER DEFAULT 30, lines TEXT DEFAULT '[]');
CREATE TABLE IF NOT EXISTS subscriptions(id INTEGER PRIMARY KEY, number TEXT UNIQUE, customer_id INTEGER NOT NULL REFERENCES users(id), plan_id INTEGER NOT NULL REFERENCES plans(id),
  start_date TEXT, expiry_date TEXT, payment_terms INTEGER DEFAULT 15, status TEXT DEFAULT 'Draft', next_invoice_date TEXT, discount_id INTEGER, quote_valid_until TEXT);
CREATE TABLE IF NOT EXISTS sub_lines(id INTEGER PRIMARY KEY, subscription_id INTEGER NOT NULL REFERENCES subscriptions(id), product_id INTEGER, variant_id INTEGER, qty INTEGER DEFAULT 1, unit_price REAL, tax_id INTEGER);
CREATE TABLE IF NOT EXISTS invoices(id INTEGER PRIMARY KEY, number TEXT UNIQUE, subscription_id INTEGER NOT NULL, customer_id INTEGER NOT NULL, period_start TEXT, period_end TEXT,
  status TEXT DEFAULT 'Draft', subtotal REAL, discount REAL, tax REAL, total REAL, due_date TEXT, sent_at TEXT, created_at TEXT, UNIQUE(subscription_id, period_start));
CREATE TABLE IF NOT EXISTS invoice_lines(id INTEGER PRIMARY KEY, invoice_id INTEGER NOT NULL REFERENCES invoices(id), description TEXT, qty INTEGER, unit_price REAL, tax_rate REAL, amount REAL);
CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY, invoice_id INTEGER NOT NULL REFERENCES invoices(id), method TEXT NOT NULL, amount REAL NOT NULL, date TEXT NOT NULL, note TEXT);
CREATE INDEX IF NOT EXISTS ix_sub_status ON subscriptions(status, next_invoice_date);
CREATE INDEX IF NOT EXISTS ix_sub_cust ON subscriptions(customer_id);
CREATE INDEX IF NOT EXISTS ix_inv_status ON invoices(status, due_date);
CREATE INDEX IF NOT EXISTS ix_inv_cust ON invoices(customer_id);
CREATE INDEX IF NOT EXISTS ix_pay_inv ON payments(invoice_id);
"""

def conn():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON"); c.execute("PRAGMA journal_mode=WAL"); return c

def q(sql, a=(), c=None):
    own = c is None; c = c or conn()
    cur = c.execute(sql, a)
    out = [dict(r) for r in cur.fetchall()] if cur.description else cur.lastrowid
    if own: c.commit(); c.close()
    return out

def one(sql, a=(), c=None):
    r = q(sql, a, c); return r[0] if r else None

def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex()

def check_pw(pw, h):
    return secrets.compare_digest(hash_pw(pw, h.split("$")[0]), h)

def valid_pw(pw):
    return (len(pw) > 8 and re.search("[A-Z]", pw) and re.search("[a-z]", pw) and re.search(r"[^A-Za-z0-9]", pw))

@app.on_event("startup")
def startup():
    c = conn(); c.executescript(SCHEMA)
    if not one("SELECT 1 FROM users WHERE role='admin'", c=c):
        q("INSERT INTO users(name,email,password_hash,role) VALUES('Admin','admin@brightloop.com',?,'admin')", (hash_pw("Admin@12345"),), c)
    c.commit(); c.close()

# ---------- auth ----------
def user(authorization: str = Header(None)):
    try:
        data = jwt.decode((authorization or "").replace("Bearer ", ""), SECRET, algorithms=["HS256"])
        return {"id": data["id"], "role": data["role"]}
    except Exception:
        raise HTTPException(401, "Not authenticated")

def need(*roles):
    def dep(u=Depends(user)):
        if u["role"] not in roles: raise HTTPException(403, "Not allowed for your role")
        return u
    return dep
ADMIN, TEAM = need("admin"), need("admin", "staff")

def token(u): return jwt.encode({"id": u["id"], "role": u["role"], "exp": dt.datetime.utcnow() + dt.timedelta(hours=12)}, SECRET)

@app.post("/api/auth/register")
def register(b: dict = Body(...)):
    email = (b.get("email") or "").strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email): raise HTTPException(400, "Enter a valid email")
    if not valid_pw(b.get("password", "")): raise HTTPException(400, "Password needs 9+ characters with an uppercase letter, a lowercase letter and a special character")
    if one("SELECT 1 FROM users WHERE email=?", (email,)): raise HTTPException(409, "This email already has an account")
    uid = q("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'customer')", (b.get("name", ""), email, hash_pw(b["password"])))
    return {"token": token({"id": uid, "role": "customer"}), "role": "customer"}

@app.post("/api/auth/login")
def login(b: dict = Body(...)):
    u = one("SELECT * FROM users WHERE email=?", ((b.get("email") or "").lower(),))
    if not u or not check_pw(b.get("password", ""), u["password_hash"]): raise HTTPException(401, "Wrong email or password")
    return {"token": token(u), "role": u["role"], "name": u["name"]}

@app.post("/api/auth/forgot")
def forgot(b: dict = Body(...)):
    u = one("SELECT id,email FROM users WHERE email=?", ((b.get("email") or "").lower(),))
    if u:
        t = secrets.token_urlsafe(24)
        q("UPDATE users SET reset_token=?, reset_expires=? WHERE id=?", (t, (dt.datetime.utcnow() + dt.timedelta(hours=1)).isoformat(), u["id"]))
        send_email(u["email"], "Reset your Brightloop password", f"Reset link: {os.environ.get('BASE_URL','http://localhost:8000')}/?reset={t}")
    return {"message": "If that email is registered, a reset link has been sent."}

@app.post("/api/auth/reset")
def reset(b: dict = Body(...)):
    u = one("SELECT * FROM users WHERE reset_token=?", (b.get("token", ""),))
    if not u or u["reset_expires"] < dt.datetime.utcnow().isoformat(): raise HTTPException(400, "Reset link is invalid or expired")
    if not valid_pw(b.get("password", "")): raise HTTPException(400, "Password does not meet the rules")
    q("UPDATE users SET password_hash=?, reset_token=NULL WHERE id=?", (hash_pw(b["password"]), u["id"]))
    return {"message": "Password updated"}

def send_email(to, subject, body):
    """Uses SMTP if SMTP_HOST is set, otherwise prints (demo mode)."""
    host = os.environ.get("SMTP_HOST")
    if not host: print(f"\n[EMAIL to {to}] {subject}\n{body}\n"); return
    import smtplib; from email.message import EmailMessage
    m = EmailMessage(); m["To"], m["Subject"], m["From"] = to, subject, os.environ.get("SMTP_FROM", "billing@brightloop.com"); m.set_content(body)
    with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", 587))) as s:
        s.starttls(); s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"]); s.send_message(m)

@app.post("/api/staff")
def add_staff(b: dict = Body(...), u=Depends(ADMIN)):
    if not valid_pw(b.get("password", "")): raise HTTPException(400, "Password does not meet the rules")
    try: uid = q("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'staff')", (b.get("name"), b["email"].lower(), hash_pw(b["password"])))
    except sqlite3.IntegrityError: raise HTTPException(409, "This email already has an account")
    return {"id": uid}

@app.get("/api/customers")
def customers(u=Depends(TEAM)): return q("SELECT id,name,email FROM users WHERE role='customer' ORDER BY name")

# ---------- subscriptions ----------
def add_period(d, period, n=1):
    if period == "daily": return d + dt.timedelta(days=n)
    if period == "weekly": return d + dt.timedelta(weeks=n)
    m = d.month - 1 + (n if period == "monthly" else 12 * n)
    y, m = d.year + m // 12, m % 12 + 1
    return d.replace(year=y, month=m, day=min(d.day, calendar.monthrange(y, m)[1]))

def D(s): return dt.date.fromisoformat(s)
FLOW = {"quote": ("Draft", "Quotation"), "confirm": ("Quotation", "Confirmed"), "activate": ("Confirmed", "Active")}

@app.post("/api/subscriptions")
def new_sub(b: dict = Body(...), u=Depends(TEAM)):
    plan = one("SELECT * FROM plans WHERE id=?", (b.get("plan_id"),))
    if not plan: raise HTTPException(400, "Choose a plan")
    lines, valid_until = b.get("lines") or [], None
    if b.get("template_id"):
        t = one("SELECT * FROM templates WHERE id=?", (b["template_id"],))
        if t: lines = lines or json.loads(t["lines"]); valid_until = (dt.date.today() + dt.timedelta(days=t["validity_days"])).isoformat()
    start = b.get("start_date") or dt.date.today().isoformat()
    expiry = b.get("expiry_date") or plan["end_date"] or add_period(D(start), "yearly").isoformat()
    c = conn()
    try:
        sid = q("INSERT INTO subscriptions(customer_id,plan_id,start_date,expiry_date,payment_terms,quote_valid_until,discount_id) VALUES(?,?,?,?,?,?,?)",
                (b["customer_id"], plan["id"], start, expiry, b.get("payment_terms", 15), valid_until, b.get("discount_id")), c)
        q("UPDATE subscriptions SET number=? WHERE id=?", (f"SUB-{sid:06d}", sid), c)
        for l in lines:
            if int(l.get("qty", 1)) < plan["min_qty"]: raise HTTPException(400, f"Minimum quantity for this plan is {plan['min_qty']}")
            p = one("SELECT sales_price FROM products WHERE id=?", (l["product_id"],), c)
            v = one("SELECT extra_price FROM variants WHERE id=?", (l.get("variant_id"),), c) if l.get("variant_id") else None
            q("INSERT INTO sub_lines(subscription_id,product_id,variant_id,qty,unit_price,tax_id) VALUES(?,?,?,?,?,?)",
              (sid, l["product_id"], l.get("variant_id"), l.get("qty", 1), p["sales_price"] + (v["extra_price"] if v else 0), l.get("tax_id")), c)
        c.commit()
    except HTTPException: c.rollback(); raise
    finally: c.close()
    return {"id": sid, "number": f"SUB-{sid:06d}"}

@app.post("/api/subscriptions/{sid}/{action}")
def sub_action(sid: int, action: str, u=Depends(TEAM)):
    s = one("SELECT s.*, p.billing_period, p.closable, p.pausable, p.renewable FROM subscriptions s JOIN plans p ON p.id=s.plan_id WHERE s.id=?", (sid,))
    if not s: raise HTTPException(404)
    st, new = s["status"], None
    if action in FLOW:
        if st != FLOW[action][0]: raise HTTPException(400, f"Cannot {action} from {st}")
        new = FLOW[action][1]
        if action == "activate": q("UPDATE subscriptions SET next_invoice_date=start_date WHERE id=?", (sid,))
    elif action == "close" and st in ("Active", "Paused"):
        if not s["closable"]: raise HTTPException(400, "This plan cannot be closed early")
        new = "Closed"
    elif action == "pause" and st == "Active":
        if not s["pausable"]: raise HTTPException(400, "This plan cannot be paused")
        new = "Paused"
    elif action == "resume" and st == "Paused": new = "Active"
    elif action == "renew" and st in ("Active", "Closed"):
        if not s["renewable"]: raise HTTPException(400, "This plan cannot be renewed")
        q("UPDATE subscriptions SET expiry_date=? WHERE id=?", (add_period(D(s["expiry_date"]), s["billing_period"], 12 if s["billing_period"] == "monthly" else 1).isoformat(), sid))
        new = "Active"
    else: raise HTTPException(400, f"Cannot {action} a {st} subscription")
    q("UPDATE subscriptions SET status=? WHERE id=?", (new, sid)); return {"status": new}

@app.get("/api/subscriptions/view/list")
def list_subs(status: str = None, customer_id: int = None, limit: int = 50, offset: int = 0, u=Depends(user)):
    w, a = [], []
    if u["role"] == "customer": w.append("s.customer_id=?"); a.append(u["id"])
    elif customer_id: w.append("s.customer_id=?"); a.append(customer_id)
    if status: w.append("s.status=?"); a.append(status)
    sql = "SELECT s.*, u.name customer_name, u.email, p.name plan_name FROM subscriptions s JOIN users u ON u.id=s.customer_id JOIN plans p ON p.id=s.plan_id"
    return q(sql + (" WHERE " + " AND ".join(w) if w else "") + " ORDER BY s.id DESC LIMIT ? OFFSET ?", a + [min(limit, 200), offset])

@app.get("/api/subscriptions/{sid}/lines")
def sub_lines(sid: int, u=Depends(user)):
    s = one("SELECT customer_id FROM subscriptions WHERE id=?", (sid,))
    if not s or (u["role"] == "customer" and s["customer_id"] != u["id"]): raise HTTPException(404)
    return q("SELECT l.*, p.name product, t.rate tax_rate, l.qty*l.unit_price amount FROM sub_lines l JOIN products p ON p.id=l.product_id LEFT JOIN taxes t ON t.id=l.tax_id WHERE subscription_id=?", (sid,))

# ---------- invoices ----------
def discount_amt(d, base, qty):
    if base < d["min_purchase"] or qty < d["min_qty"]: return 0
    return min(base, base * d["value"] / 100 if d["kind"] == "percent" else d["value"])

def active_discounts(c, today):
    return q("SELECT * FROM discounts WHERE (start_date IS NULL OR start_date<=?) AND (end_date IS NULL OR end_date>=?) AND (usage_limit IS NULL OR used<usage_limit)", (today, today), c)

def build_invoice(c, s, today):
    """Create one invoice for the next period of subscription s. UNIQUE(subscription_id, period_start) stops double billing."""
    ps = D(s["next_invoice_date"]); pe = add_period(ps, s["billing_period"])
    lines = q("SELECT l.*, p.name, t.rate FROM sub_lines l JOIN products p ON p.id=l.product_id LEFT JOIN taxes t ON t.id=l.tax_id WHERE subscription_id=?", (s["id"],), c)
    ds, used = active_discounts(c, today), []
    sub = sum(l["qty"] * l["unit_price"] for l in lines); disc = 0; taxable = []
    for l in lines:
        amt = l["qty"] * l["unit_price"]; ld = 0
        for d in ds:
            if d["product_id"] == l["product_id"]:
                x = discount_amt(d, amt, l["qty"]); 
                if x: ld += x; used.append(d["id"])
        disc += ld; taxable.append((amt - ld, l["rate"] or 0))
    for d in ds:
        if d["id"] == s["discount_id"]:
            x = discount_amt(d, sub - disc, sum(l["qty"] for l in lines))
            if x: disc += x; used.append(d["id"])
    net = sub - disc; ratio = net / (sum(t[0] for t in taxable) or 1)
    tax = round(sum(a * r / 100 for a, r in taxable) * ratio, 2)
    iid = q("INSERT INTO invoices(subscription_id,customer_id,period_start,period_end,status,subtotal,discount,tax,total,due_date,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (s["id"], s["customer_id"], ps.isoformat(), pe.isoformat(), "Draft", round(sub, 2), round(disc, 2), tax, round(net + tax, 2),
             (dt.date.today() + dt.timedelta(days=s["payment_terms"])).isoformat(), today), c)
    q("UPDATE invoices SET number=? WHERE id=?", (f"INV-{iid:06d}", iid), c)
    for l in lines: q("INSERT INTO invoice_lines(invoice_id,description,qty,unit_price,tax_rate,amount) VALUES(?,?,?,?,?,?)", (iid, l["name"], l["qty"], l["unit_price"], l["rate"] or 0, l["qty"] * l["unit_price"]), c)
    for d in used: q("UPDATE discounts SET used=used+1 WHERE id=?", (d,), c)
    q("UPDATE subscriptions SET next_invoice_date=? WHERE id=?", (pe.isoformat(), s["id"]), c)
    return iid

@app.post("/api/invoices/generate")
def generate(u=Depends(TEAM)):
    today = dt.date.today().isoformat(); c = conn(); made = 0
    q("UPDATE subscriptions SET status='Closed' WHERE status='Active' AND expiry_date<? AND plan_id IN(SELECT id FROM plans WHERE auto_close=1)", (today,), c)
    due = q("SELECT s.*, p.billing_period FROM subscriptions s JOIN plans p ON p.id=s.plan_id WHERE s.status='Active' AND s.next_invoice_date<=? AND s.next_invoice_date<=s.expiry_date", (today,), c)
    for s in due:
        while s["next_invoice_date"] <= today and s["next_invoice_date"] <= s["expiry_date"]:  # catches up on missed periods
            try: build_invoice(c, s, today); made += 1
            except sqlite3.IntegrityError: c.rollback(); break
            s["next_invoice_date"] = one("SELECT next_invoice_date n FROM subscriptions WHERE id=?", (s["id"],), c)["n"]
    c.commit(); c.close(); return {"created": made}

@app.get("/api/invoices/view/list")
def list_inv(status: str = None, overdue: bool = False, customer_id: int = None, date_from: str = None, date_to: str = None, limit: int = 50, offset: int = 0, u=Depends(user)):
    w, a = [], []
    if u["role"] == "customer": w.append("i.customer_id=?"); a.append(u["id"])
    elif customer_id: w.append("i.customer_id=?"); a.append(customer_id)
    if status: w.append("i.status=?"); a.append(status)
    if overdue: w.append("i.status='Confirmed' AND i.due_date<?"); a.append(dt.date.today().isoformat())
    if date_from: w.append("i.created_at>=?"); a.append(date_from)
    if date_to: w.append("i.created_at<=?"); a.append(date_to)
    sql = ("SELECT i.*, u.name customer_name, COALESCE((SELECT SUM(amount) FROM payments WHERE invoice_id=i.id),0) paid FROM invoices i JOIN users u ON u.id=i.customer_id"
           + (" WHERE " + " AND ".join(w) if w else "") + " ORDER BY i.id DESC LIMIT ? OFFSET ?")
    rows = q(sql, a + [min(limit, 200), offset])
    for r in rows: r["balance"] = round(r["total"] - r["paid"], 2)
    return rows

@app.post("/api/invoices/{iid}/{action}")
def inv_action(iid: int, action: str, u=Depends(TEAM)):
    i = one("SELECT i.*, u.email FROM invoices i JOIN users u ON u.id=i.customer_id WHERE i.id=?", (iid,))
    if not i: raise HTTPException(404)
    if action == "confirm" and i["status"] == "Draft": q("UPDATE invoices SET status='Confirmed' WHERE id=?", (iid,))
    elif action == "cancel" and i["status"] in ("Draft", "Confirmed"): q("UPDATE invoices SET status='Cancelled' WHERE id=?", (iid,))
    elif action == "send" and i["status"] != "Cancelled":
        send_email(i["email"], f"Invoice {i['number']}", f"Total {i['total']} due {i['due_date']}."); q("UPDATE invoices SET sent_at=? WHERE id=?", (dt.datetime.now().isoformat(), iid))
    else: raise HTTPException(400, f"Cannot {action} an invoice that is {i['status']}")
    return {"ok": True}

@app.get("/api/invoices/{iid}/print", response_class=HTMLResponse)
def print_inv(iid: int, u=Depends(user)):
    i = one("SELECT i.*, u.name cname, u.email FROM invoices i JOIN users u ON u.id=i.customer_id WHERE i.id=?", (iid,))
    if not i or (u["role"] == "customer" and i["customer_id"] != u["id"]): raise HTTPException(404)
    rows = "".join(f"<tr><td>{l['description']}</td><td>{l['qty']}</td><td>{l['unit_price']:.2f}</td><td>{l['tax_rate']}%</td><td>{l['amount']:.2f}</td></tr>" for l in q("SELECT * FROM invoice_lines WHERE invoice_id=?", (iid,)))
    return f"""<html><body style="font-family:sans-serif;max-width:700px;margin:2rem auto"><h1>Invoice {i['number']}</h1><p>{i['cname']} ({i['email']})<br>Period {i['period_start']} to {i['period_end']} · Due {i['due_date']} · {i['status']}</p>
<table width=100% border=1 cellspacing=0 cellpadding=6><tr><th>Product</th><th>Qty</th><th>Unit</th><th>Tax</th><th>Amount</th></tr>{rows}</table>
<p>Subtotal {i['subtotal']:.2f}<br>Discount -{i['discount']:.2f}<br>Tax {i['tax']:.2f}<br><b>Total {i['total']:.2f}</b></p><script>print()</script></body></html>"""

# ---------- payments ----------
@app.post("/api/payments")
def pay(b: dict = Body(...), u=Depends(TEAM)):
    i = one("SELECT * FROM invoices WHERE id=?", (b.get("invoice_id"),))
    if not i or i["status"] not in ("Confirmed",): raise HTTPException(400, "Payments can only be recorded against confirmed invoices")
    amt = float(b.get("amount", 0))
    paid = one("SELECT COALESCE(SUM(amount),0) s FROM payments WHERE invoice_id=?", (i["id"],))["s"]
    if amt <= 0 or amt > round(i["total"] - paid, 2) + 0.001: raise HTTPException(400, "Amount must be more than 0 and no more than the balance due")
    pid = q("INSERT INTO payments(invoice_id,method,amount,date,note) VALUES(?,?,?,?,?)", (i["id"], b.get("method", "Bank transfer"), amt, b.get("date") or dt.date.today().isoformat(), b.get("note")))
    if paid + amt >= i["total"] - 0.001: q("UPDATE invoices SET status='Paid' WHERE id=?", (i["id"],))
    return {"id": pid}

@app.get("/api/payments/view/list")
def list_pay(limit: int = 100, u=Depends(TEAM)):
    return q("SELECT p.*, i.number invoice FROM payments p JOIN invoices i ON i.id=p.invoice_id ORDER BY p.id DESC LIMIT ?", (min(limit, 500),))

# ---------- dashboard ----------
@app.get("/api/dashboard")
def dashboard(date_from: str = "0000-01-01", date_to: str = "9999-12-31", u=Depends(TEAM)):
    today = dt.date.today().isoformat()
    mrr = one("""SELECT COALESCE(SUM(l.qty*l.unit_price*CASE p.billing_period WHEN 'daily' THEN 30 WHEN 'weekly' THEN 4.33 WHEN 'monthly' THEN 1 ELSE 1/12.0 END),0) v
                 FROM subscriptions s JOIN plans p ON p.id=s.plan_id JOIN sub_lines l ON l.subscription_id=s.id WHERE s.status='Active'""")["v"]
    return {
        "subscriptions_by_status": q("SELECT status, COUNT(*) n FROM subscriptions GROUP BY status"),
        "active_subscriptions": one("SELECT COUNT(*) n FROM subscriptions WHERE status='Active'")["n"],
        "monthly_recurring_revenue": round(mrr, 2),
        "revenue_collected": one("SELECT COALESCE(SUM(amount),0) v FROM payments WHERE date BETWEEN ? AND ?", (date_from, date_to))["v"],
        "outstanding": round(one("SELECT COALESCE(SUM(total),0)-COALESCE((SELECT SUM(p.amount) FROM payments p JOIN invoices i2 ON i2.id=p.invoice_id WHERE i2.status='Confirmed'),0) v FROM invoices WHERE status='Confirmed'")["v"], 2),
        "overdue_count": one("SELECT COUNT(*) n FROM invoices WHERE status='Confirmed' AND due_date<?", (today,))["n"],
        "overdue_invoices": q("SELECT i.number, i.total, i.due_date, u.name customer FROM invoices i JOIN users u ON u.id=i.customer_id WHERE i.status='Confirmed' AND i.due_date<? ORDER BY i.due_date LIMIT 50", (today,)),
        "payments_by_method": q("SELECT method, SUM(amount) total FROM payments WHERE date BETWEEN ? AND ? GROUP BY method", (date_from, date_to)),
    }

# ---------- admin-managed catalog (generic CRUD) ----------
CFG = {
 "products": ["name", "type", "sales_price", "cost_price", "notes"],
 "variants": ["product_id", "attribute", "value", "extra_price"],
 "plans": ["name", "price", "billing_period", "min_qty", "start_date", "end_date", "auto_close", "closable", "pausable", "renewable"],
 "taxes": ["name", "rate"],
 "discounts": ["name", "kind", "value", "min_purchase", "min_qty", "start_date", "end_date", "usage_limit", "product_id"],
 "templates": ["name", "plan_id", "validity_days", "lines"],
}
def cols(t, b):
    if t not in CFG: raise HTTPException(404, "Unknown resource")
    return {k: (json.dumps(v) if isinstance(v, (list, dict)) else v) for k, v in b.items() if k in CFG[t]}

@app.get("/api/{t}")
def list_(t: str = Path(..., pattern="^(products|variants|plans|taxes|discounts|templates)$"), u=Depends(user)):
    if t not in CFG: raise HTTPException(404)
    return q(f"SELECT * FROM {t} ORDER BY id DESC LIMIT 500")

@app.post("/api/{t}")
def create(t: str = Path(..., pattern="^(products|variants|plans|taxes|discounts|templates)$"), b: dict = Body(...), u=Depends(TEAM)):
    d = cols(t, b)
    if u["role"] != "admin" and t != "templates": raise HTTPException(403, "Only the admin can change this")
    try: return {"id": q(f"INSERT INTO {t}({','.join(d)}) VALUES({','.join('?'*len(d))})", list(d.values()))}
    except sqlite3.IntegrityError as e: raise HTTPException(400, str(e))

@app.put("/api/{t}/{i}")
def update(i: int, b: dict = Body(...), t: str = Path(..., pattern="^(products|variants|plans|taxes|discounts|templates)$"), u=Depends(ADMIN)):
    d = cols(t, b); q(f"UPDATE {t} SET {','.join(k+'=?' for k in d)} WHERE id=?", list(d.values()) + [i]); return {"ok": True}

@app.delete("/api/{t}/{i}")
def delete(i: int, t: str = Path(..., pattern="^(products|variants|plans|taxes|discounts|templates)$"), u=Depends(ADMIN)):
    cols(t, {})
    try: q(f"DELETE FROM {t} WHERE id=?", (i,))
    except sqlite3.IntegrityError: raise HTTPException(409, "Still in use")
    return {"ok": True}


app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static"), html=True), name="static")
