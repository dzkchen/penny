# Penny Planted App

This deterministic local target contains Penny's P0 vulnerabilities:

- A client-visible Supabase-style service-role key in `frontend/src/supabaseClient.ts`.
- A committed fake payment secret in `frontend/src/api.ts`.
- A permissive RLS-style policy in `policies/private_notes.sql`.
- A mock Supabase REST endpoint at `GET /rest/v1/private_notes`.
- A BOLA-style order endpoint at `GET /api/orders/<id>`.

Run it locally:

```bash
python planted-app/server/app.py
```

Then scan it:

```bash
python -m penny run ./planted-app --target http://127.0.0.1:8787
```
