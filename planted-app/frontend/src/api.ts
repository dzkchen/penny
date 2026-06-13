export const STRIPE_SECRET = "sk_live_penny_demo_51NnDemoSecretValueThatShouldNotShip";

export async function getOrder(orderId: string, userId: string) {
  const response = await fetch(`http://127.0.0.1:8787/api/orders/${orderId}`, {
    headers: { "x-user-id": userId },
  });
  return response.json();
}
