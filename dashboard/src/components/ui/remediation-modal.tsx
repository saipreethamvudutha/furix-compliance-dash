"use client";

import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Bot, Clock, RotateCcw, AlertTriangle, Shield, Database, Monitor } from "lucide-react";

interface RemediationModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  system: string;
  steps: string[];
  downtime: string;
  risk: string;
  reversible: boolean;
  affectedLabel?: string;
  bestTime?: string;
}

export function RemediationModal({
  open,
  onClose,
  title,
  system,
  steps,
  downtime,
  risk,
  reversible,
  affectedLabel,
  bestTime = "After business hours",
}: RemediationModalProps) {
  const [hasScrolledToBottom, setHasScrolledToBottom] = useState(false);

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Bot className="h-5 w-5 text-[#805ad5]" />
            Proposed Fix: {title}
          </DialogTitle>
          <DialogDescription>
            Review the remediation plan before approving
          </DialogDescription>
        </DialogHeader>

        <div
          className="max-h-[60vh] space-y-4 overflow-y-auto pr-2"
          onScroll={(e) => {
            const el = e.currentTarget;
            if (el.scrollTop + el.clientHeight >= el.scrollHeight - 20) {
              setHasScrolledToBottom(true);
            }
          }}
        >
          {/* Steps */}
          <div>
            <p className="text-sm font-semibold">What will happen:</p>
            <ol className="mt-2 list-inside list-decimal space-y-1.5 text-sm text-muted-foreground">
              {steps.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ol>
          </div>

          {/* Details Grid */}
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-lg border p-3">
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Monitor className="h-4 w-4" />
                Affected System
              </div>
              <p className="mt-1 text-sm font-medium">{system}</p>
            </div>
            <div className="rounded-lg border p-3">
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Clock className="h-4 w-4" />
                Expected Downtime
              </div>
              <p className="mt-1 text-sm font-medium">{downtime}</p>
            </div>
            <div className="rounded-lg border p-3">
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Shield className="h-4 w-4" />
                Best Time
              </div>
              <p className="mt-1 text-sm font-medium">{bestTime}</p>
            </div>
            <div className="rounded-lg border p-3">
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <RotateCcw className="h-4 w-4" />
                Reversible
              </div>
              <p className="mt-1 text-sm font-medium">
                {reversible ? "Yes (can roll back)" : "No"}
              </p>
            </div>
          </div>

          {/* Risk Assessment Bars */}
          <div className="space-y-2">
            <p className="text-sm font-semibold">Risk Assessment:</p>
            <RiskBar label="Downtime Risk" level={downtime === "None" ? 0 : downtime.includes("2 min") || downtime.includes("5 min") ? 1 : 2} />
            <RiskBar label="Data Risk" level={0} />
            <RiskBar label="Reversibility" level={reversible ? 0 : 2} inverted />
            <RiskBar label="Business Impact" level={risk === "Low" ? 1 : risk === "Medium" ? 2 : 3} />
          </div>

          {/* Warning */}
          {affectedLabel && (
            <div className="flex items-start gap-2 rounded-lg border border-[#d69e2e]/30 bg-[#fffff0] p-3">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[#d69e2e]" />
              <p className="text-sm text-[#744210]">
                This will briefly interrupt your {affectedLabel}
              </p>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="flex gap-2 border-t pt-4">
          <Button size="sm" className="flex-1">
            Schedule for Tonight
          </Button>
          <Button size="sm" variant="default" className="flex-1 bg-[#38a169] hover:bg-[#2f855a]">
            Apply Now
          </Button>
          <Button size="sm" variant="outline" className="flex-1" onClick={onClose}>
            I&apos;ll Handle This Myself
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function RiskBar({
  label,
  level,
  inverted = false,
}: {
  label: string;
  level: number;
  inverted?: boolean;
}) {
  const actualLevel = inverted ? 3 - level : level;
  const colors = ["#38a169", "#68d391", "#d69e2e", "#c53030"];
  const labels = inverted
    ? ["Fully reversible", "Mostly reversible", "Partially reversible", "Not reversible"]
    : ["None expected", "Minimal", "Moderate", "Significant"];

  return (
    <div className="flex items-center gap-3 text-sm">
      <span className="w-32 shrink-0 text-muted-foreground">{label}:</span>
      <div className="flex flex-1 gap-1">
        {[0, 1, 2, 3].map((i) => (
          <div
            key={i}
            className="h-2 flex-1 rounded-full"
            style={{
              backgroundColor: i <= actualLevel ? colors[actualLevel] : "#e2e8f0",
            }}
          />
        ))}
      </div>
      <span className="w-32 shrink-0 text-right text-muted-foreground">
        {labels[actualLevel]}
      </span>
    </div>
  );
}
