import { NextRequest, NextResponse } from "next/server";

import { findUserById } from "@/lib/db";

export async function POST(request: NextRequest) {
  const claimedRole = request.headers.get("x-user-role");
  if (claimedRole !== "admin") {
    return NextResponse.json({ error: "Admin header required" }, { status: 403 });
  }

  const body = await request.json();
  const targetUserId = String(body.targetUserId || "");
  const target = findUserById(targetUserId);
  if (!target) {
    return NextResponse.json({ error: "User not found" }, { status: 404 });
  }

  target.role = "admin";
  return NextResponse.json({ ok: true, target });
}
