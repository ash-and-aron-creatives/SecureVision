import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SecureVision",
  description: "Vulnerability Prioritization Pipeline",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body suppressHydrationWarning className="font-sans antialiased">{children}</body>
    </html>
  );
}
