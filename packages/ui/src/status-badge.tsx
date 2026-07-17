import type { ReactNode } from "react";

export type StatusTone = "busy" | "neutral" | "offline" | "ready";

export interface StatusBadgeProps {
  children: ReactNode;
  tone?: StatusTone;
  className?: string;
}

export function StatusBadge({
  children,
  className = "",
  tone = "neutral",
}: StatusBadgeProps) {
  return (
    <span className={`ui-status ui-status--${tone} ${className}`.trim()}>
      <span aria-hidden="true" className="ui-status__dot" />
      {children}
    </span>
  );
}
