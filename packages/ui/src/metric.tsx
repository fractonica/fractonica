import type { ReactNode } from "react";

export interface MetricProps {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
  className?: string;
}

export function Metric({ className = "", detail, label, value }: MetricProps) {
  return (
    <div className={`ui-metric ${className}`.trim()}>
      <span className="ui-metric__label">{label}</span>
      <strong className="ui-metric__value">{value}</strong>
      {detail ? <span className="ui-metric__detail">{detail}</span> : null}
    </div>
  );
}
