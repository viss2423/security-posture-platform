'use client';

import * as Dialog from '@radix-ui/react-dialog';
import { Command } from 'cmdk';
import { ArrowRight, Compass, Search, Sparkles } from 'lucide-react';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useMemo, useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { getVisibleNavGroups } from '@/lib/navigation';

export default function CommandPalette({
  showTrigger = true,
}: {
  showTrigger?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const router = useRouter();
  const pathname = usePathname();
  const { user } = useAuth();
  const role = user?.role ?? 'viewer';

  const groups = useMemo(() => getVisibleNavGroups(role), [role]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setOpen((value) => !value);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      {showTrigger && (
        <Dialog.Trigger asChild>
          <button
            type="button"
            className="group inline-flex items-center gap-2 rounded-[1rem] border border-[var(--border)] bg-[var(--surface-soft)] px-3 py-2 text-sm text-[var(--text-muted)] transition hover:border-[var(--accent)]/30 hover:text-[var(--text)]"
          >
            <Search size={15} className="text-[var(--accent)] transition group-hover:scale-110" />
            Jump anywhere
            <kbd className="hidden rounded-md border border-[var(--accent)]/20 bg-[var(--accent-dim)] px-1.5 py-0.5 text-[11px] font-semibold text-[var(--accent)] sm:inline">
              Ctrl K
            </kbd>
          </button>
        </Dialog.Trigger>
      )}
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-[80] bg-[rgba(7,11,18,0.72)] backdrop-blur-md" />
        <Dialog.Content className="fixed left-1/2 top-[7%] z-[90] w-[min(94vw,52rem)] -translate-x-1/2 overflow-hidden rounded-[2rem] border border-[var(--border)] bg-[var(--surface-elevated)] shadow-[0_40px_90px_-30px_rgba(0,0,0,0.8)] focus:outline-none">
          <Dialog.Title className="sr-only">Command Palette</Dialog.Title>
          <Dialog.Description className="sr-only">
            Search and jump to any SecPlat page.
          </Dialog.Description>

          <Command className="max-h-[78vh] overflow-hidden">
            <div className="border-b border-[var(--border)] px-4 py-4">
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <span className="inline-flex items-center gap-1.5 rounded-full border border-cyan-300/18 bg-cyan-300/08 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--cyan-strong)]">
                  <Sparkles size={10} />
                  Search-first
                </span>
                <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-300/18 bg-emerald-300/08 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--green)]">
                  <Compass size={10} />
                  Route jump
                </span>
              </div>
              <div className="flex items-center gap-2 rounded-[1rem] border border-[var(--border)] bg-[var(--surface-soft)] px-3">
                <Search size={16} className="text-[var(--muted)]" />
                <Command.Input
                  autoFocus
                  placeholder="Search pages, workflows, reports, and controls..."
                  className="w-full bg-transparent py-3 text-sm text-[var(--text)] outline-none placeholder:text-[var(--muted)]"
                />
              </div>
            </div>

            <Command.List className="max-h-[58vh] overflow-y-auto p-3">
              <Command.Empty className="rounded-[1.15rem] border border-[var(--border)] bg-[var(--surface-soft)] px-4 py-8 text-center text-sm text-[var(--muted)]">
                No matching commands.
              </Command.Empty>
              {groups.map((group) => (
                <Command.Group
                  key={group.title}
                  heading={group.title}
                  className="mb-3 [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:pb-2 [&_[cmdk-group-heading]]:pt-1 [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-[0.2em] [&_[cmdk-group-heading]]:text-[var(--muted)]"
                >
                  {group.items.map((item) => (
                    <Command.Item
                      key={item.href}
                      value={`${item.label} ${item.description} ${item.href}`}
                      onSelect={() => {
                        router.push(item.href);
                        setOpen(false);
                      }}
                      className="group relative mb-1.5 flex cursor-pointer items-center justify-between overflow-hidden rounded-[1.1rem] border border-transparent bg-transparent px-3 py-3 text-sm text-[var(--text-muted)] outline-none transition data-[selected=true]:border-cyan-300/18 data-[selected=true]:bg-[rgba(22,142,196,0.08)] data-[selected=true]:text-[var(--text)]"
                    >
                      <span className="pointer-events-none absolute inset-y-2 left-1.5 w-[2px] rounded-full bg-transparent group-data-[selected=true]:bg-[linear-gradient(180deg,#168ec4,#1fb7a6)]" />
                      <div className="relative">
                        <p className="font-medium">{item.label}</p>
                        <p className="text-xs leading-5 text-[var(--muted)] group-data-[selected=true]:text-[var(--text-muted)]/90">
                          {item.description}
                        </p>
                      </div>
                      <ArrowRight
                        size={14}
                        className="text-[var(--muted)] group-data-[selected=true]:text-[var(--cyan-strong)]"
                      />
                    </Command.Item>
                  ))}
                </Command.Group>
              ))}
            </Command.List>
          </Command>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
