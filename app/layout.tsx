import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Web Vulnerability Control Mapping",
  description:
    "Educational reference mapping common web vulnerabilities to risk, governance controls, and frameworks (OWASP, NIST, ISO 27001).",
};
 
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
