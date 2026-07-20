import type { Metadata } from "next";
import "./globals.css";
import { AppFrame } from "@/components/layout/app-frame";

// Fonts are vendored locally (deployment contract): no build-time fetch from
// Google Fonts, so the image builds fully offline / air-gapped and reproducibly.
// The typeface comes from a local system stack defined on `--font-geist-sans`
// in globals.css. To pin an exact bundled face, drop woff2 files into
// `src/app/fonts/` and swap this for `next/font/local` — the CSS variable name
// stays the same, so nothing else changes.

export const metadata: Metadata = {
  title: "BYOC",
  description: "AI-powered cybersecurity platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="font-sans antialiased">
        <AppFrame>{children}</AppFrame>
      </body>
    </html>
  );
}
