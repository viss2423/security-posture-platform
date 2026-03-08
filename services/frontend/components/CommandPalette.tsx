'use client';

import * as Dialog from '@radix-ui/react-dialog';
import { Command } from 'cmdk';
import { ArrowRight, Search } from 'lucide-react';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useMemo, useState } from 'react';
import { getVisibleNavGroups } from '@/lib/navigation';

export default function CommandPalette({ isAdmin }: { isAdmin: boolean }) {
  const [open, setOpen] = useState(false);
  const router = useRouter();
  const pathname = usePathname();

  const groups = useMemo(() => getVisibleNavGroups(isAdmin), [isAdmin]);

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
      <Dialog.Trigger asChild>
        <button
          type="button"
          className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text-muted)] transition hover:border-cyan-300/40 hover:bg-cyan-300/[0.08] hover:text-[var(--text)]"
        >
          <Search size={15} />
          Search
          <kbd className="hidden rounded-md border border-[var(--border)] bg-[var(--surface-elevated)] px-1.5 py-0.5 text-[11px] font-semibold text-[var(--muted)] sm:inline">
            Ctrl K
          </kbd>
        </button>
      </Dialog.Trigger>
      <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-[80] bg-black/65 backdrop-blur-sm" />
          <Dialog.Content className="fixed left-1/2 top-[8%] z-[90] w-[min(92vw,46rem)] -translate-x-1/2 overflow-hidden rounded-2xl border border-[var(--border)] bg-[linear-gradient(180deg,rgba(16,32,54,0.96),rgba(9,20,35,0.92))] shadow-2xl shadow-black/55 focus:outline-none">
          <Dialog.Title className="sr-only">Command Palette</Dialog.Title>
          <Dialog.Description className="sr-only">Search and jump to any security workspace page.</Dialog.Description>
          <Command className="max-h-[70vh] overflow-hidden">
            <div className="flex items-center gap-2 border-b border-[var(--border)] px-3">
              <Search size={16} className="text-[var(--muted)]" />
              <Command.Input
                autoFocus
                placeholder="Search pages, workflows, and controls..."
                className="w-full bg-transparent py-3 text-sm text-[var(--text)] outline-none placeholder:text-[var(--muted)]"
              />
            </div>
            <Command.List className="max-h-[56vh] overflow-y-auto p-2">
              <Command.Empty className="px-3 py-6 text-sm text-[var(--muted)]">No matching commands.</Command.Empty>
              {groups.map((group) => (
                <Command.Group
                  key={group.title}
                  heading={group.title}
                  className="[&_[cmdk-group-heading]]:px-3 [&_[cmdk-group-heading]]:py-2 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-[0.12em] [&_[cmdk-group-heading]]:text-[var(--muted)]"
                >
                  {group.items.map((item) => (
                    <Command.Item
                      key={item.href}
                      value={`${item.label} ${item.description} ${item.href}`}
                      onSelect={() => {
                        router.push(item.href);
                        setOpen(false);
                      }}
                      className="group flex cursor-pointer items-center justify-between rounded-xl px-3 py-2.5 text-sm text-[var(--text-muted)] outline-none transition data-[selected=true]:bg-cyan-300/16 data-[selected=true]:text-[var(--text)]"
                    >
                      <div>
                        <p className="font-medium">{item.label}</p>
                        <p className="text-xs text-[var(--muted)] group-data-[selected=true]:text-[var(--text-muted)]/90">
                          {item.description}
                        </p>
                      </div>
                      <ArrowRight size={14} className="text-[var(--muted)] group-data-[selected=true]:text-cyan-100" />
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
