"use client";

import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

const glossary: Record<string, string> = {
  CVE: "Common Vulnerabilities and Exposures — a standardized ID for known security issues",
  TLS: "Transport Layer Security — encryption protocol that protects data sent over the internet",
  RDP: "Remote Desktop Protocol — allows remote access to a computer's desktop",
  PHI: "Protected Health Information — any health data that can identify a patient",
  HIPAA: "Health Insurance Portability and Accountability Act — federal law protecting patient data",
  "PCI-DSS": "Payment Card Industry Data Security Standard — rules for handling credit card data",
  MFA: "Multi-Factor Authentication — requires two or more ways to verify your identity",
  SSO: "Single Sign-On — log in once to access multiple systems",
  SQL: "Structured Query Language — language used to communicate with databases",
  "SQL Injection": "An attack where malicious code is inserted into database queries to steal or modify data",
  SSL: "Secure Sockets Layer — older encryption protocol for internet security (replaced by TLS)",
  "SHA-256": "A secure hashing algorithm used to verify data integrity and encrypt information",
  "SHA-1": "An older, less secure hashing algorithm that is no longer recommended",
  CSR: "Certificate Signing Request — a file sent to a certificate authority to get an SSL certificate",
  CA: "Certificate Authority — a trusted organization that issues SSL certificates",
  VPN: "Virtual Private Network — creates a secure, encrypted connection over the internet",
  ePHI: "Electronic Protected Health Information — PHI stored or transmitted electronically",
  "Port 3389": "The default network port used by Remote Desktop Protocol (RDP)",
  Firewall: "A security system that monitors and controls incoming and outgoing network traffic",
  Patch: "A software update that fixes security vulnerabilities or bugs",
};

export function TechTerm({
  term,
  children,
}: {
  term: string;
  children: React.ReactNode;
}) {
  const explanation = glossary[term];
  if (!explanation) return <>{children}</>;

  return (
    <TooltipProvider delayDuration={200}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="cursor-help border-b border-dotted border-muted-foreground/50">
            {children}
          </span>
        </TooltipTrigger>
        <TooltipContent
          side="top"
          className="max-w-xs text-sm"
        >
          <p className="font-medium">{term}</p>
          <p className="mt-0.5 text-sm text-muted-foreground">{explanation}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
