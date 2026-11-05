import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Aegis Ledger | Active Defense",
  description: "Zero-Trust AI Data Integrity Pipeline",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="antialiased bg-[#0a0a0a] text-gray-200 min-h-screen">
        {children}
      </body>
    </html>
  );
}