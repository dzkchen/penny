import { NextRequest, NextResponse } from "next/server";

import { findOrderById } from "@/lib/db";
import { requireUser } from "@/lib/session";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const user = requireUser(request);
  if (!user) {
    return NextResponse.json({ error: "Login required" }, { status: 401 });
  }

  const { id } = await params;
  const order = findOrderById(id);
  if (!order) {
    return NextResponse.json({ error: "Order not found" }, { status: 404 });
  }

  return NextResponse.json({ requestedBy: user.id, order });
}
