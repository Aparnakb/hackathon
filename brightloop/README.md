# Brightloop Subscription Management System
FastAPI + SQLite backend, single-page UI. Run:
```
pip install -r requirements.txt
uvicorn main:app --reload      # open http://localhost:8000
```
Seeded admin: `admin@brightloop.com` / `Admin@12345` (change it). API docs: `/docs`.
Set `JWT_SECRET`, and `SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASS/SMTP_FROM` for real email (otherwise emails print to the console).

Roles: admin (everything, creates staff/discounts/plans), staff (subscriptions, invoices, payments, quote templates), customer (own subscriptions/invoices only).
Subscription flow: Draft -> Quotation -> Confirmed -> Active -> Closed. Invoice flow: Draft -> Confirmed -> Paid.
No double billing: `UNIQUE(subscription_id, period_start)` on invoices. Indexes on status/due-date/customer keep lists fast.
