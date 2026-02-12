'use client';

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
      className={`rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)] py-16 px-6 text-center animate-in ${className}`}
      role="status"
    >
      {icon && <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--bg)]">{icon}</div>}
      <h2 className="text-lg font-semibold text-[var(--text)]">{title}</h2>
      <p className="mt-2 mx-auto max-w-sm text-sm text-[var(--muted)]">{description}</p>
      {action && <div className="mt-6">{action}</div>}
    </div>
  );
}

export function ApiDownHint() {
  return (
    <p className="mt-3 text-xs text-[var(--muted)]">
      If the API is unreachable, ensure the API service is running and refresh the page.
    </p>
  );
}
