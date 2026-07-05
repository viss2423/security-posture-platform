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
      className={`relative overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--surface)] px-6 py-14 text-center animate-in shadow-[var(--shadow-soft)] ${className}`}
      role="status"
    >
      <div className="pointer-events-none absolute -left-10 top-8 h-28 w-28 rounded-full bg-cyan-300/[0.06] blur-2xl" />
      <div className="pointer-events-none absolute -right-8 bottom-10 h-24 w-24 rounded-full bg-emerald-300/[0.07] blur-2xl" />
      <div className="pointer-events-none absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-[var(--accent)]/45 to-transparent" />

      {icon && (
        <div className="mx-auto mb-5 flex h-14 w-14 items-center justify-center rounded-xl border border-[var(--accent-ring)] bg-[var(--accent-dim)] text-[var(--accent)]">
          {icon}
        </div>
      )}
      <h2 className="text-xl font-semibold tracking-tight text-[var(--text-strong)]">
        {title}
      </h2>
      <p className="mx-auto mt-3 max-w-md text-sm leading-6 text-[var(--text-muted)]">
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
