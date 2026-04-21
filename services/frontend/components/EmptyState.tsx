type EmptyStateProps = {
  icon?: React.ReactNode;
  title: string;
  description: string;
  action?: React.ReactNode;
  className?: string;
};

export function EmptyState({ icon, title, description, action, className = '' }: EmptyStateProps) {
  return (
    <div
      className={`relative overflow-hidden rounded-[2rem] border border-[var(--border)] bg-[rgba(255,255,255,0.92)] px-6 py-16 text-center animate-in shadow-[var(--shadow-soft)] ${className}`}
      role="status"
    >
      <div className="pointer-events-none absolute -left-10 top-8 h-28 w-28 rounded-full bg-cyan-300/10 blur-2xl" />
      <div className="pointer-events-none absolute -right-8 bottom-10 h-24 w-24 rounded-full bg-emerald-300/12 blur-2xl" />
      <div className="pointer-events-none absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-cyan-200/60 to-transparent" />

      {icon && (
        <div className="mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-[1.2rem] border border-cyan-300/18 bg-cyan-300/[0.08] text-[var(--cyan-strong)]">
          {icon}
        </div>
      )}
      <h2 className="text-2xl tracking-[-0.03em] text-[var(--text)]">{title}</h2>
      <p className="mx-auto mt-3 max-w-md text-sm leading-7 text-[var(--text-muted)]">
        {description}
      </p>
      {action && <div className="mt-6">{action}</div>}
    </div>
  );
}

export function ApiDownHint() {
  return (
    <p className="mt-3 text-xs leading-6 text-[var(--muted)]">
      If the API is unreachable, make sure the service is running and then refresh this view.
    </p>
  );
}
