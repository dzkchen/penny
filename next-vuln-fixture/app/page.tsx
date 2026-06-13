export default function HomePage() {
  return (
    <main>
      <h1>Next Vulnerability Fixture</h1>
      <p>
        This app is intentionally insecure and exists only as a local audit target for Penny and
        other reviewers.
      </p>
      <h2>Seed users</h2>
      <ul>
        <li>`alice@example.com` / `alice123`</li>
        <li>`bob@example.com` / `bob123`</li>
      </ul>
      <h2>Useful routes</h2>
      <ul>
        <li>`POST /api/auth/login` with `{ "email": "...", "password": "..." }`</li>
        <li>`GET /api/orders/o2` after logging in as Alice</li>
        <li>`POST /api/orders/o2/cancel` after logging in as Alice</li>
        <li>`POST /api/account/email` with `{ "email": "new@example.com" }`</li>
        <li>`POST /api/admin/promote` with `{ "targetUserId": "u2" }` and header `x-user-role: admin`</li>
      </ul>
    </main>
  );
}
