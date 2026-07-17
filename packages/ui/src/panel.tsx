import type { HTMLAttributes, ReactNode } from "react";

export interface PanelProps extends HTMLAttributes<HTMLElement> {
  children: ReactNode;
  eyebrow?: string;
  title?: string;
}

export function Panel({
  children,
  className = "",
  eyebrow,
  title,
  ...props
}: PanelProps) {
  return (
    <section className={`ui-panel ${className}`.trim()} {...props}>
      {eyebrow || title ? (
        <header className="ui-panel__header">
          {eyebrow ? <span className="ui-panel__eyebrow">{eyebrow}</span> : null}
          {title ? <h2 className="ui-panel__title">{title}</h2> : null}
        </header>
      ) : null}
      {children}
    </section>
  );
}
