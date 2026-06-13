export type User = {
  id: string;
  email: string;
  password: string;
  role: "user" | "admin";
};

export type Order = {
  id: string;
  ownerId: string;
  item: string;
  status: "open" | "cancelled";
};

export const db = {
  users: [
    { id: "u1", email: "alice@example.com", password: "alice123", role: "user" },
    { id: "u2", email: "bob@example.com", password: "bob123", role: "user" },
    { id: "u3", email: "ops@example.com", password: "admin123", role: "admin" }
  ] satisfies User[],
  orders: [
    { id: "o1", ownerId: "u1", item: "Garden Trowel", status: "open" },
    { id: "o2", ownerId: "u2", item: "Rose Seeds", status: "open" }
  ] satisfies Order[],
  sessions: new Map<string, string>()
};

export function findUserByEmail(email: string): User | undefined {
  return db.users.find((user) => user.email === email);
}

export function findUserById(id: string): User | undefined {
  return db.users.find((user) => user.id === id);
}

export function findOrderById(id: string): Order | undefined {
  return db.orders.find((order) => order.id === id);
}
