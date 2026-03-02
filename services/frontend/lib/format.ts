/** Format ISO date/time string in user's local timezone. */
export function formatDateTime(iso: string | null | undefined): string {
  if (iso == null || iso === '') return '–';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '–';
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'short',
    timeStyle: 'short',
  }).format(d);
}
