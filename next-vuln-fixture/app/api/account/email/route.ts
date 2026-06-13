import { NextRequest, NextResponse } from "next/server";

import { requireUser } from "@/lib/session";

export async function POST(request: NextRequest) {
  const user = requireUser(request);
  if (!user) {
    return NextResponse.json({ error: "Login required" }, { status: 401 });
  }

  const body = await request.json();
  user.email = String(body.email || "");

  return NextResponse.json({
    ok: true,
    message: "Email updated",
    user
  });
}
