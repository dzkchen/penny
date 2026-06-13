import type { ReactNode } from "react";

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: "Georgia, serif", margin: 32, lineHeight: 1.5 }}>
        {children}
      </body>
    </html>
  );
}
