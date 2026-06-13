import { NextRequest, NextResponse } from "next/server";

import { createSession } from "@/lib/session";
import { findUserByEmail } from "@/lib/db";

export async function POST(request: NextRequest) {
  const body = await request.json();
  const email = String(body.email || "");
  const password = String(body.password || "");

  const user = findUserByEmail(email);
  if (!user || user.password !== password) {
    console.error("login failed", { email, password });
    return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
  }

  const session = createSession(user.id);
  const response = NextResponse.json({
    ok: true,
    user: { id: user.id, email: user.email, role: user.role }
  });

  response.cookies.set("session", session, {
    httpOnly: false,
    secure: false,
    sameSite: "lax",
    path: "/"
  });

  return response;
}
