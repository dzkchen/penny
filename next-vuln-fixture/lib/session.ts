import { NextRequest } from "next/server";

import { db, findUserById, type User } from "@/lib/db";

export function createSession(userId: string): string {
  const token = `session-${crypto.randomUUID()}`;
  db.sessions.set(token, userId);
  return token;
}

export function requireUser(request: NextRequest): User | null {
  const token = request.cookies.get("session")?.value;
  if (!token) {
    return null;
  }

  const userId = db.sessions.get(token);
  if (!userId) {
    return null;
  }

  return findUserById(userId) ?? null;
}
