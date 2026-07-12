'use client';

import {
  useEffect,
  useRef,
  useState,
  useSyncExternalStore,
  type CSSProperties,
  type MouseEvent,
  type ReactNode,
} from 'react';
import {
  animate,
  motion,
  useInView,
  useMotionValue,
  useMotionValueEvent,
  useReducedMotion,
  useScroll,
  useSpring,
  useTransform,
  type MotionValue,
} from 'framer-motion';
import {
  ArrowRight,
  Bell,
  BrainCircuit,
  Bug,
  CheckCircle,
  ChevronDown,
  Cpu,
  FileCheck,
  FileDown,
  Gamepad2,
  Github,
  Linkedin,
  Mail,
  Menu,
  Pause,
  Play,
  Scale,
  Shield,
  Sparkles,
  Swords,
  X,
  Zap,
} from 'lucide-react';

const USE_CASES = [
  {
    id: 'founders',
    label: 'Leaders & Founders',
    shortLabel: 'Leaders',
    icon: FileCheck,
    heading: 'Understand risk and build trust without adding more tools',
    body:
      'Get a clear view of security gaps, ownership, and compliance evidence in one place. Start with a read-only GitHub scan, then grow into the wider security operations platform when you need it.',
    bullets: [
      'See the issues that matter most, not another list of raw alerts',
      'Turn technical findings into downloadable SOC 2 evidence',
      'Open source and self-hostable, with no platform lock-in',
    ],
    cta: 'See the evidence experience',
    href: '#soc2-demo',
  },
  {
    id: 'teams',
    label: 'Security Teams',
    shortLabel: 'Security',
    icon: Shield,
    heading: 'Move from scattered signals to a repeatable response workflow',
    body:
      'Bring posture findings, network telemetry, alerts, incidents, and automation into one operating view. AI adds context and prioritisation while people keep control of important decisions.',
    bullets: [
      'Prioritise by exploitability, asset criticality, and threat context',
      'Track incidents, ownership, and SLA timers from one workspace',
      'Automate safely with policy-as-code, approvals, and rollback',
    ],
    cta: 'Sign in to the security workspace',
    href: '/login',
  },
  {
    id: 'hiring',
    label: 'Technical Evaluators',
    shortLabel: 'Technical',
    icon: Cpu,
    heading: 'Evaluate a real, end-to-end security platform',
    body:
      'Inspect the architecture, run the stack locally, or explore how the services work together. SecPlat is a working open-source product, not a static interface concept.',
    bullets: [
      'Next.js, FastAPI, PostgreSQL, workers, and Kubernetes',
      'OIDC SSO, RBAC, audit trails, and production-style observability',
      'ML risk scoring, an attack graph, cyber range, and detection lab',
    ],
    cta: 'Explore the source code',
    href: 'https://github.com/viss2423/security-posture-platform',
  },
] as const;

const PIPELINE_STEPS = [
  {
    icon: Github,
    label: 'Connect GitHub',
    detail: 'Connect an organisation with a read-only token. SecPlat cannot change repositories or settings.',
    cta: 'Start from the platform',
    href: '/login',
  },
  {
    icon: Zap,
    label: 'Run a scan',
    detail: 'Check 2FA, branch protection, secret scanning, and Dependabot across the selected repositories.',
    cta: 'Watch the sample scan',
    href: '#terminal-demo',
  },
  {
    icon: FileCheck,
    label: 'Get evidence',
    detail: 'Translate technical findings into plain evidence, mapped to the relevant SOC 2 control and status.',
    cta: 'Explore the evidence',
    href: '#soc2-demo',
  },
  {
    icon: FileDown,
    label: 'Download PDF',
    detail: 'Share an auditor-friendly report with evidence tables, control results, and practical remediation.',
    cta: 'Sign in to download reports',
    href: '/login',
  },
] as const;

const TERMINAL_LINES = [
  { text: '$ secplat scan --source github --org acme-corp', color: 'var(--accent)' },
  { text: 'Authenticating with GitHub (read-only PAT)...', color: 'var(--text-muted)' },
  { text: 'Authenticated as acme-corp (ORG)', color: 'var(--green)' },
  { text: 'Scanning org 2FA enforcement...', color: 'var(--text-muted)' },
  { text: '  OK 2FA is enforced for all members', color: 'var(--green)' },
  { text: 'Scanning 12 repositories...', color: 'var(--text-muted)' },
  { text: '  FAIL acme-corp/api: branch protection off', color: 'var(--red)' },
  { text: '  FAIL acme-corp/web: Dependabot alerts disabled', color: 'var(--red)' },
  { text: '  OK Secret scanning enabled on 10/12 repos', color: 'var(--green)' },
  { text: 'Mapping findings to SOC 2 controls...', color: 'var(--text-muted)' },
  { text: 'Generating PDF evidence report...', color: 'var(--text-muted)' },
  { text: 'Report saved: acme-corp-soc2-evidence-report.pdf', color: 'var(--accent)' },
  { text: 'Done. 3 controls evaluated. 1 PASS, 2 FAIL.', color: 'var(--green)' },
] as const;

const SOC2_CONTROLS = [
  {
    id: 'cc6.1',
    control: 'CC6.1',
    name: 'Logical and Physical Access Controls',
    status: 'PASS',
    checks: ['org_2fa', 'secret_scanning'],
    evidence:
      'Organization enforces 2FA. Secret scanning is enabled on all repositories.',
  },
  {
    id: 'cc7.1',
    control: 'CC7.1',
    name: 'Vulnerability Detection',
    status: 'FAIL',
    checks: ['dependabot_alerts'],
    evidence:
      'Dependabot alerts are disabled. Enable them in repository security settings.',
  },
  {
    id: 'cc8.1',
    control: 'CC8.1',
    name: 'Change Management',
    status: 'FAIL',
    checks: ['branch_protection'],
    evidence:
      'Main has no protection rule configured. Require pull-request review before merge.',
  },
] as const;

const FEATURES = [
  {
    icon: Bell,
    title: 'Alert Triage',
    desc: 'Bring alerts into one queue and add AI-assisted context while keeping human review in the loop.',
    href: '/login',
  },
  {
    icon: Bug,
    title: 'Risk Scoring',
    desc: 'Rank findings by exploitability, business criticality, and current threat intelligence.',
    href: '/login',
  },
  {
    icon: Swords,
    title: 'Attack Simulation',
    desc: 'Validate controls with port scans, brute-force scenarios, and web tests in a safe sandbox.',
    href: '/login',
  },
  {
    icon: Scale,
    title: 'Policy-as-Code',
    desc: 'Define security rules as versioned YAML with approvals, evaluation history, and rollback.',
    href: '/login',
  },
  {
    icon: BrainCircuit,
    title: 'ML Risk Engine',
    desc: 'Learn from triage decisions, explain risk predictions, and monitor model drift over time.',
    href: '/login',
  },
  {
    icon: Gamepad2,
    title: 'Cyber Range',
    desc: 'Run guided security drills that generate realistic signals and incidents inside the platform.',
    href: '/login',
  },
] as const;

function useCountSpring(target: number, inView: boolean) {
  const spring = useSpring(0, { stiffness: 80, damping: 20 });

  useEffect(() => {
    if (inView) {
      spring.set(target);
    }
  }, [inView, spring, target]);

  return spring;
}

function useHydratedReducedMotion() {
  const shouldReduceMotion = useReducedMotion();
  const isHydrated = useSyncExternalStore(
    () => () => undefined,
    () => true,
    () => false,
  );

  return isHydrated && Boolean(shouldReduceMotion);
}

function Reveal({
  children,
  className = '',
}: {
  children: ReactNode;
  className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: '-80px' });
  const shouldReduceMotion = useHydratedReducedMotion();

  return (
    <motion.div
      ref={ref}
      initial={shouldReduceMotion ? false : { opacity: 0, y: 40 }}
      animate={
        shouldReduceMotion || inView ? { opacity: 1, y: 0 } : { opacity: 0, y: 40 }
      }
      transition={{ duration: 0.6, ease: [0.25, 0.1, 0.25, 1] }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

function AnimatedCount({
  value,
  suffix = '',
}: {
  value: MotionValue<number>;
  suffix?: string;
}) {
  const [display, setDisplay] = useState(() => Math.round(value.get()));

  useMotionValueEvent(value, 'change', (latest) => {
    setDisplay(Math.round(latest));
  });

  return (
    <>
      {display}
      {suffix}
    </>
  );
}

function TiltCard({
  children,
  className = '',
}: {
  children: ReactNode;
  className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const shouldReduceMotion = useHydratedReducedMotion();
  const x = useMotionValue(0);
  const y = useMotionValue(0);
  const rotateX = useSpring(useTransform(y, [-0.5, 0.5], [8, -8]), {
    stiffness: 120,
    damping: 20,
  });
  const rotateY = useSpring(useTransform(x, [-0.5, 0.5], [-8, 8]), {
    stiffness: 120,
    damping: 20,
  });
  const glowX = useTransform(x, [-0.5, 0.5], ['0%', '100%']);
  const glowY = useTransform(y, [-0.5, 0.5], ['0%', '100%']);

  const handleMouseMove = (event: MouseEvent<HTMLDivElement>) => {
    if (!ref.current || shouldReduceMotion) {
      return;
    }

    const rect = ref.current.getBoundingClientRect();
    x.set((event.clientX - rect.left) / rect.width - 0.5);
    y.set((event.clientY - rect.top) / rect.height - 0.5);
  };

  const handleMouseLeave = () => {
    x.set(0);
    y.set(0);
  };

  const glowStyle = {
    opacity: shouldReduceMotion ? 0.08 : 0.15,
    background:
      'radial-gradient(circle at var(--x, 50%) var(--y, 50%), var(--accent) 0%, transparent 60%)',
    '--x': glowX,
    '--y': glowY,
  } as CSSProperties;

  return (
    <motion.div
      ref={ref}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      style={
        shouldReduceMotion
          ? undefined
          : {
              rotateX,
              rotateY,
              transformStyle: 'preserve-3d',
              perspective: 1000,
            }
      }
      className={`relative overflow-hidden ${className}`}
    >
      <div
        className="pointer-events-none absolute inset-0 rounded-[inherit] transition-opacity duration-300"
        style={glowStyle}
      />
      {children}
    </motion.div>
  );
}

function AnimatedBg() {
  const shouldReduceMotion = useHydratedReducedMotion();
  const { scrollYProgress } = useScroll();
  const bgY = useTransform(scrollYProgress, [0, 1], ['0%', '30%']);
  const gridY = useTransform(scrollYProgress, [0, 1], [0, 80]);
  const glowScale = useTransform(scrollYProgress, [0, 1], [1, 1.14]);

  const glowStyle = {
    scale: shouldReduceMotion ? 1 : glowScale,
    backgroundImage:
      'radial-gradient(ellipse 80% 40% at 50% var(--y), rgba(34,211,238,0.08), transparent 60%), radial-gradient(ellipse 50% 30% at 85% 90%, rgba(52,211,153,0.04), transparent)',
    '--y': shouldReduceMotion ? '10%' : bgY,
  } as CSSProperties;

  return (
    <>
      <motion.div
        className="pointer-events-none fixed inset-0 -z-10 opacity-30"
        style={glowStyle}
      />
      <motion.div
        className="pointer-events-none fixed inset-0 -z-20 opacity-35"
        style={{
          y: shouldReduceMotion ? 0 : gridY,
          maskImage: 'radial-gradient(circle at center, black, transparent 82%)',
        }}
      >
        <div
          className="h-full w-full"
          style={{
            backgroundImage:
              'linear-gradient(rgba(148,163,184,0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.08) 1px, transparent 1px)',
            backgroundSize: '54px 54px',
          }}
        />
      </motion.div>
    </>
  );
}

function ScanTerminal() {
  const shouldReduceMotion = useHydratedReducedMotion();
  const [runNumber, setRunNumber] = useState(0);
  const [progress, setProgress] = useState(0);
  const started = runNumber > 0;
  const complete = progress >= TERMINAL_LINES.length;

  useEffect(() => {
    if (!started) {
      return;
    }

    if (shouldReduceMotion) {
      setProgress(TERMINAL_LINES.length);
      return;
    }

    setProgress(0);
    const controls = animate(0, TERMINAL_LINES.length, {
      duration: 4.8,
      ease: 'linear',
      onUpdate: (value) => setProgress(value),
    });

    return () => controls.stop();
  }, [runNumber, shouldReduceMotion, started]);

  const visibleLines = Math.floor(progress);
  const cursorVisible = started && visibleLines < TERMINAL_LINES.length;

  return (
    <motion.div
      initial={shouldReduceMotion ? false : { opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-40px' }}
      transition={{ duration: 0.5 }}
      className="overflow-hidden rounded-2xl border border-[var(--border)] bg-[#0a0d14] shadow-[var(--shadow-heavy)]"
    >
      <div className="flex items-center gap-2 border-b border-[var(--border)] bg-[var(--surface-elevated)]/40 px-4 py-2.5">
        <div className="flex gap-1.5">
          <div className="h-3 w-3 rounded-full bg-[var(--red)]/70" />
          <div className="h-3 w-3 rounded-full bg-[var(--amber)]/70" />
          <div className="h-3 w-3 rounded-full bg-[var(--green)]/70" />
        </div>
        <span className="ml-2 font-mono text-[11px] text-[var(--text-subtle)]">
          secplat scan - zsh
        </span>
        {(!started || complete) && (
          <button
            type="button"
            onClick={() => setRunNumber((current) => current + 1)}
            className="ml-auto inline-flex items-center gap-1.5 rounded-md bg-[var(--accent)]/20 px-2.5 py-1 text-[11px] font-semibold text-[var(--accent)] transition hover:bg-[var(--accent)]/30"
          >
            <Play className="h-3 w-3" />
            {complete ? 'Run again' : 'Run scan'}
          </button>
        )}
        {cursorVisible && (
          <span className="ml-auto inline-flex items-center gap-1 text-[10px] text-[var(--amber)]">
            <motion.span
              animate={{ opacity: [1, 0.4, 1] }}
              transition={{ repeat: Infinity, duration: 1.2 }}
            >
              .
            </motion.span>
            running
          </span>
        )}
        {complete && (
          <span className="text-[10px] text-[var(--green)]">complete</span>
        )}
      </div>
      <div className="min-h-[280px] overflow-x-auto p-4 font-mono text-[13px] leading-relaxed sm:p-5">
        {TERMINAL_LINES.slice(0, visibleLines).map((line) => (
          <motion.div
            key={line.text}
            initial={shouldReduceMotion ? false : { opacity: 0, x: -4 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.15 }}
            className="whitespace-pre"
            style={{ color: line.color }}
          >
            {line.text}
          </motion.div>
        ))}
        {cursorVisible && (
          <motion.span
            animate={{ opacity: [1, 0] }}
            transition={{ repeat: Infinity, duration: 0.8 }}
            className="ml-0.5 inline-block h-[14px] w-2 align-middle bg-[var(--accent)]"
          />
        )}
        {!started && (
          <motion.span
            animate={{ opacity: [1, 0] }}
            transition={{ repeat: Infinity, duration: 0.8 }}
            className="inline-block h-[14px] w-2 align-middle bg-[var(--accent)]"
          />
        )}
      </div>
    </motion.div>
  );
}

function NavBar() {
  const [scrolled, setScrolled] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const { scrollYProgress } = useScroll();

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 10);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <motion.nav
      initial={{ y: -60 }}
      animate={{ y: 0 }}
      transition={{ duration: 0.5, ease: [0.25, 0.1, 0.25, 1] }}
      className={`fixed inset-x-0 top-0 z-50 transition-all duration-300 ${
        menuOpen
          ? 'border-b border-[var(--border)] bg-[var(--bg)] shadow-[var(--shadow-heavy)]'
          : scrolled
            ? 'border-b border-[var(--border)] bg-[var(--bg)]/90 backdrop-blur-xl'
          : 'border-b border-transparent bg-transparent'
      }`}
    >
      <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4 sm:px-6">
        <a href="#top" className="flex items-center gap-2.5" aria-label="SecPlat home">
          <div className="relative">
            <Shield className="h-5 w-5 text-[var(--accent)]" />
            <motion.span
              animate={{ opacity: [0.2, 0.5, 0.2], scale: [1, 1.3, 1] }}
              transition={{ repeat: Infinity, duration: 2.5, ease: 'easeInOut' }}
              className="absolute inset-0 rounded-full bg-[var(--accent)]/20 blur-md"
            />
          </div>
          <span className="text-sm font-semibold tracking-tight text-[var(--text-strong)]">
            SecPlat
          </span>
        </a>
        <div className="hidden items-center gap-6 md:flex">
          <a
            href="#terminal-demo"
            className="text-xs font-medium text-[var(--text-muted)] transition hover:text-[var(--text)]"
          >
            Demo
          </a>
          <a
            href="#how-it-works"
            className="text-xs font-medium text-[var(--text-muted)] transition hover:text-[var(--text)]"
          >
            How it works
          </a>
          <a
            href="#audiences"
            className="text-xs font-medium text-[var(--text-muted)] transition hover:text-[var(--text)]"
          >
            Use cases
          </a>
          <a
            href="#capabilities"
            className="text-xs font-medium text-[var(--text-muted)] transition hover:text-[var(--text)]"
          >
            Capabilities
          </a>
        </div>
        <div className="flex items-center gap-3">
          <a
            href="https://github.com/viss2423/security-posture-platform"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="View SecPlat on GitHub"
            className="hidden items-center gap-1.5 rounded-lg px-3 py-1.5 text-[13px] font-medium text-[var(--text-muted)] transition hover:text-[var(--text)] lg:inline-flex"
          >
            <Github className="h-4 w-4" />
            <span>GitHub</span>
          </a>
          <a
            href="/login"
            className="rounded-lg bg-[var(--accent)] px-3.5 py-1.5 text-[13px] font-semibold text-[#07090e] shadow-[0_0_15px_rgba(34,211,238,0.2)] transition hover:-translate-y-0.5 hover:brightness-110 active:translate-y-0"
          >
            Open platform
          </a>
          <button
            type="button"
            aria-label={menuOpen ? 'Close navigation' : 'Open navigation'}
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen((current) => !current)}
            className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-[var(--border)] text-[var(--text-muted)] transition hover:border-[var(--border-strong)] hover:text-[var(--text)] md:hidden"
          >
            {menuOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>
        </div>
      </div>
      {menuOpen && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          transition={{ duration: 0.22 }}
          className="border-t border-[var(--line-faint)] bg-[var(--bg)] md:hidden"
        >
          <div className="mx-auto grid max-w-6xl grid-cols-2 gap-2 px-4 py-3">
            {[
              { label: 'Demo', href: '#terminal-demo' },
              { label: 'How it works', href: '#how-it-works' },
              { label: 'Use cases', href: '#audiences' },
              { label: 'Capabilities', href: '#capabilities' },
              { label: 'Contact', href: '#contact' },
            ].map((item) => (
              <a
                key={item.href}
                href={item.href}
                onClick={() => setMenuOpen(false)}
                className="rounded-lg border border-transparent px-3 py-2.5 text-sm font-medium text-[var(--text-muted)] transition hover:border-[var(--border)] hover:bg-[var(--surface)]/60 hover:text-[var(--text)]"
              >
                {item.label}
              </a>
            ))}
            <a
              href="https://github.com/viss2423/security-posture-platform"
              target="_blank"
              rel="noopener noreferrer"
              onClick={() => setMenuOpen(false)}
              className="col-span-2 inline-flex items-center justify-center gap-2 rounded-lg border border-[var(--border)] px-3 py-2.5 text-sm font-medium text-[var(--text-muted)] transition hover:border-[var(--border-strong)] hover:text-[var(--text)]"
            >
              <Github className="h-4 w-4" />
              Explore on GitHub
            </a>
          </div>
        </motion.div>
      )}
      <motion.div
        aria-hidden="true"
        style={{ scaleX: scrollYProgress, transformOrigin: '0% 50%' }}
        className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-[var(--accent)] via-[var(--green)] to-[var(--accent)]"
      />
    </motion.nav>
  );
}

function Hero() {
  const ref = useRef<HTMLElement>(null);
  const shouldReduceMotion = useHydratedReducedMotion();
  const inView = useInView(ref, { once: true, margin: '-100px' });
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ['start start', 'end start'],
  });
  const badgeY = useTransform(scrollYProgress, [0, 1], [0, shouldReduceMotion ? 0 : -16]);
  const cardY = useTransform(scrollYProgress, [0, 1], [0, shouldReduceMotion ? 0 : -24]);
  const cap0 = useCountSpring(0, inView);
  const cap1 = useCountSpring(1, inView);
  const cap30 = useCountSpring(30, inView);
  const cap3 = useCountSpring(3, inView);

  const stats = [
    {
      value: cap1,
      suffix: '',
      label: 'Read-only token',
      icon: Github,
      href: '#terminal-demo',
      external: false,
    },
    {
      value: cap30,
      suffix: 's',
      label: 'To first scan',
      icon: Zap,
      href: '#terminal-demo',
      external: false,
    },
    {
      value: cap3,
      suffix: '',
      label: 'SOC 2 controls',
      icon: FileCheck,
      href: '#soc2-demo',
      external: false,
    },
    {
      value: cap0,
      suffix: '',
      label: 'Vendor access needed',
      icon: Shield,
      href: '#trust',
      external: false,
    },
  ];

  return (
    <section
      id="top"
      ref={ref}
      className="relative scroll-mt-20 overflow-hidden pb-6 pt-28 sm:pb-0 sm:pt-44"
    >
      <AnimatedBg />
      <div className="relative mx-auto max-w-4xl px-4 text-center sm:px-6">
        <motion.a
          href="https://github.com/viss2423/security-posture-platform"
          target="_blank"
          rel="noopener noreferrer"
          initial={shouldReduceMotion ? false : { opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          style={{ y: badgeY }}
          className="mb-6 inline-flex items-center gap-2 rounded-full border border-[var(--border)] bg-[var(--surface-elevated)]/60 px-4 py-1.5 text-xs font-medium text-[var(--accent)] transition hover:border-[var(--border-strong)] hover:bg-[var(--surface-elevated)]"
        >
          <span className="relative flex h-2 w-2">
            <motion.span
              animate={{ opacity: [0.4, 0, 0.4], scale: [1, 1.8, 1] }}
              transition={{ repeat: Infinity, duration: 1.8 }}
              className="absolute inset-0 rounded-full bg-[var(--accent)]"
            />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-[var(--accent)]" />
          </span>
          Open-source platform
          <ArrowRight className="h-3 w-3" />
        </motion.a>

        <motion.h1
          initial={shouldReduceMotion ? false : { opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1, ease: [0.25, 0.1, 0.25, 1] }}
          className="text-[2.15rem] font-extrabold leading-[1.08] tracking-tight text-[var(--text-strong)] [text-wrap:balance] sm:text-5xl lg:text-6xl"
        >
          Know what is exposed.
          <br />
          <span className="text-gradient">Prove what is protected.</span>
          <br />
          Act on what matters.
        </motion.h1>

        <motion.p
          initial={shouldReduceMotion ? false : { opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="mx-auto mt-5 max-w-xl text-base leading-relaxed text-[var(--text-muted)] sm:text-lg"
        >
          SecPlat brings security posture, threat signals, risk scoring, incident
          response, automation, and SOC 2 evidence into one open-source workspace.
        </motion.p>

        <motion.div
          initial={shouldReduceMotion ? false : { opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.3 }}
          className="mt-8 flex flex-wrap items-center justify-center gap-3"
        >
          <a
            href="#terminal-demo"
            className="inline-flex items-center gap-2 rounded-xl bg-[var(--accent)] px-5 py-3 text-sm font-semibold text-[#07090e] shadow-[0_0_30px_rgba(34,211,238,0.2)] transition hover:-translate-y-0.5 hover:brightness-110 active:translate-y-0"
          >
            <Play className="h-4 w-4" />
            See a 30-second scan
            <ArrowRight className="h-4 w-4" />
          </a>
          <a
            href="/login"
            className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] px-5 py-3 text-sm font-medium text-[var(--text-muted)] transition hover:-translate-y-0.5 hover:border-[var(--border-strong)] hover:text-[var(--text)] active:translate-y-0"
          >
            <Shield className="h-4 w-4" />
            Open the platform
          </a>
        </motion.div>

        <motion.div
          initial={shouldReduceMotion ? false : { opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 0.4 }}
          className="mt-5 flex flex-wrap items-center justify-center gap-x-5 gap-y-2 text-[11px] text-[var(--text-muted)]"
        >
          <span>Read-only connectors</span>
          <span>Self-hostable</span>
          <span>Human-in-the-loop AI</span>
        </motion.div>

        <motion.div style={{ y: cardY }} className="mt-14">
          <TiltCard className="rounded-3xl border border-[var(--border)] bg-[var(--surface)]/50 p-5 shadow-[var(--shadow-soft)] backdrop-blur-sm sm:p-7">
            <div
              className="pointer-events-none absolute inset-0"
              style={{
                background:
                  'radial-gradient(circle at top right, rgba(34,211,238,0.12), transparent 32%), linear-gradient(180deg, rgba(255,255,255,0.06), transparent 45%)',
              }}
            />
            <div className="relative">
              <div className="mb-5 flex flex-col items-start justify-between gap-3 text-left sm:flex-row sm:items-center">
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-[var(--accent)]">
                    Live Platform Snapshot
                  </p>
                  <p className="mt-1 text-sm text-[var(--text-muted)]">
                    Connect a read-only GitHub token and get a SOC 2 evidence report in
                    under a minute.
                  </p>
                </div>
                <div className="inline-flex items-center gap-2 rounded-full border border-[var(--border)] bg-[var(--surface-elevated)]/50 px-3 py-1 text-[10px] uppercase tracking-[0.2em] text-[var(--text-subtle)]">
                  <span className="dot-online" />
                  Live
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                {stats.map((stat, index) => (
                  <motion.a
                    key={stat.label}
                    href={stat.href}
                    target={stat.external ? '_blank' : undefined}
                    rel={stat.external ? 'noopener noreferrer' : undefined}
                    initial={shouldReduceMotion ? false : { opacity: 0, y: 12 }}
                    animate={inView ? { opacity: 1, y: 0 } : { opacity: 0, y: 12 }}
                    transition={{ duration: 0.4, delay: 0.4 + index * 0.08 }}
                    whileHover={shouldReduceMotion ? undefined : { y: -3 }}
                    className="group rounded-2xl border border-[var(--line-faint)] bg-[var(--surface-soft)]/40 p-4 text-center transition-colors hover:border-[var(--border-strong)] hover:bg-[var(--surface-soft)]/70"
                  >
                    <stat.icon className="mx-auto mb-2 h-5 w-5 text-[var(--accent)] opacity-70 transition-transform group-hover:scale-110" />
                    <div className="text-3xl font-bold tabular-nums text-[var(--text-strong)]">
                      <AnimatedCount value={stat.value} suffix={stat.suffix} />
                    </div>
                    <div className="mt-0.5 inline-flex items-center gap-1 text-xs text-[var(--text-subtle)] group-hover:text-[var(--text-muted)]">
                      {stat.label}
                      <ArrowRight className="h-2.5 w-2.5 opacity-0 transition-opacity group-hover:opacity-100" />
                    </div>
                  </motion.a>
                ))}
              </div>
            </div>
          </TiltCard>
        </motion.div>
      </div>
    </section>
  );
}

function PipelineVisual() {
  const [activeStep, setActiveStep] = useState(0);
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    if (paused) {
      return;
    }

    const timer = setInterval(() => {
      setActiveStep((current) => (current + 1) % PIPELINE_STEPS.length);
    }, 2500);

    return () => clearInterval(timer);
  }, [paused]);

  return (
    <Reveal>
      <section id="how-it-works" className="scroll-mt-16 py-14 sm:py-16">
        <div className="mx-auto max-w-4xl px-4 sm:px-6">
          <div className="mb-8 text-center">
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-[var(--border)] bg-[var(--surface-elevated)]/40 px-3 py-1 text-[11px] text-[var(--accent)]">
              <Sparkles className="h-3 w-3" />
              HOW IT WORKS
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-[var(--text-strong)] sm:text-3xl">
              From source data to useful evidence
            </h2>
            <p className="mt-2 text-sm text-[var(--text-muted)]">
              Four understandable steps, one read-only connection. Click a step to
              explore the flow.
            </p>
          </div>

          <motion.div
            initial={{ opacity: 0, scale: 0.98 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="relative overflow-hidden rounded-3xl border border-[var(--border)] bg-[var(--surface)]/40 p-6 sm:p-10"
          >
            <div className="mb-8 flex items-center justify-between">
              {PIPELINE_STEPS.map((step, index) => (
                <div
                  key={step.label}
                  className={`flex items-start gap-0 ${index < PIPELINE_STEPS.length - 1 ? 'flex-1' : 'flex-none'}`}
                >
                  <button
                    type="button"
                    aria-label={`Show step ${index + 1}: ${step.label}`}
                    aria-pressed={index === activeStep}
                    onClick={() => {
                      setActiveStep(index);
                      setPaused(true);
                    }}
                    className={`flex flex-col items-center gap-2 rounded-2xl outline-none transition-all duration-500 focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:ring-offset-4 focus-visible:ring-offset-[var(--bg)] ${
                      index <= activeStep ? 'opacity-100' : 'opacity-30'
                    }`}
                  >
                    <motion.div
                      animate={index === activeStep ? { scale: [1, 1.05, 1] } : {}}
                      transition={{
                        repeat: activeStep === index ? Infinity : 0,
                        duration: 2,
                        ease: 'easeInOut',
                      }}
                      className={`flex h-14 w-14 items-center justify-center rounded-2xl transition-all duration-500 ${
                        index === activeStep
                          ? 'bg-[var(--accent)] text-[#07090e] shadow-[0_0_24px_rgba(34,211,238,0.4)]'
                          : index < activeStep
                            ? 'bg-[var(--green-dim)] text-[var(--green)] ring-1 ring-[var(--green-ring)]'
                            : 'bg-[var(--surface-elevated)] text-[var(--muted)]'
                      }`}
                    >
                      <step.icon className="h-6 w-6" />
                    </motion.div>
                    <span className="hidden text-[11px] font-medium text-[var(--text-muted)] sm:block">
                      {step.label}
                    </span>
                  </button>
                  {index < PIPELINE_STEPS.length - 1 && (
                    <div className="mx-2 mt-[27px] h-[2px] flex-1 overflow-hidden rounded-full bg-[var(--surface-elevated)]">
                      <motion.div
                        animate={{
                          width:
                            index < activeStep ? '100%' : index === activeStep ? '50%' : '0%',
                        }}
                        transition={{ duration: 0.7 }}
                        className="h-full rounded-full bg-gradient-to-r from-[var(--accent)] to-[var(--green)]"
                      />
                    </div>
                  )}
                </div>
              ))}
            </div>

            <div className="flex min-h-[90px] flex-col justify-center text-center transition-all duration-500">
              <div className="mx-auto mb-3 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-[var(--accent-dim)] ring-1 ring-[var(--accent-ring)]">
                {(() => {
                  const Icon = PIPELINE_STEPS[activeStep].icon;
                  return <Icon className="h-6 w-6 text-[var(--accent)]" />;
                })()}
              </div>
              <h3 className="text-lg font-semibold text-[var(--text-strong)]">
                {PIPELINE_STEPS[activeStep].label}
              </h3>
              <p className="mx-auto mt-1 max-w-md text-sm text-[var(--text-muted)]">
                {PIPELINE_STEPS[activeStep].detail}
              </p>
              <a
                href={PIPELINE_STEPS[activeStep].href}
                className="mx-auto mt-4 inline-flex items-center gap-1.5 text-xs font-semibold text-[var(--accent)] transition hover:text-[var(--text-strong)]"
              >
                {PIPELINE_STEPS[activeStep].cta}
                <ArrowRight className="h-3 w-3" />
              </a>
            </div>

            <div className="mt-6 text-center">
              <button
                type="button"
                onClick={() => setPaused((value) => !value)}
                className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--text-muted)] transition hover:border-[var(--border-strong)] hover:text-[var(--text)]"
              >
                {paused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
                {paused ? 'Resume' : 'Pause auto-play'}
              </button>
            </div>
          </motion.div>
        </div>
      </section>
    </Reveal>
  );
}

function UseCaseTabs() {
  const [active, setActive] = useState<(typeof USE_CASES)[number]['id']>(USE_CASES[0].id);
  const activeUseCase = USE_CASES.find((useCase) => useCase.id === active) ?? USE_CASES[0];
  const ActiveIcon = activeUseCase.icon;
  const external = activeUseCase.href.startsWith('http');

  return (
    <Reveal>
      <section id="audiences" className="scroll-mt-16 py-14 sm:py-16">
        <div className="mx-auto max-w-4xl px-4 sm:px-6">
          <div className="mb-8 text-center">
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-[var(--border)] bg-[var(--surface-elevated)]/40 px-3 py-1 text-[11px] text-[var(--accent)]">
              <Sparkles className="h-3 w-3" />
              BUILT FOR
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-[var(--text-strong)] sm:text-3xl">
              Useful at every level of the conversation
            </h2>
            <p className="mx-auto mt-2 max-w-xl text-sm text-[var(--text-muted)]">
              Start with the outcome you care about. The same platform can support
              leadership decisions, day-to-day security work, and technical evaluation.
            </p>
          </div>

          <div className="mb-8 text-center">
            <div
              role="tablist"
              aria-label="Choose an audience"
              className="grid w-full grid-cols-3 rounded-xl border border-[var(--border)] bg-[var(--surface)]/40 p-1 sm:inline-flex sm:w-auto"
            >
              {USE_CASES.map((useCase) => (
                <button
                  key={useCase.id}
                  id={`audience-tab-${useCase.id}`}
                  type="button"
                  role="tab"
                  aria-selected={active === useCase.id}
                  aria-controls={`audience-panel-${useCase.id}`}
                  onClick={() => setActive(useCase.id)}
                  className={`rounded-lg px-2 py-2.5 text-xs font-medium outline-none transition-all focus-visible:ring-2 focus-visible:ring-[var(--accent)] sm:px-4 sm:py-2 sm:text-sm ${
                    active === useCase.id
                      ? 'bg-[var(--accent)] text-[#07090e] shadow-[var(--shadow-glow-accent)]'
                      : 'text-[var(--text-muted)] hover:text-[var(--text)]'
                  }`}
                >
                  <span className="sm:hidden">{useCase.shortLabel}</span>
                  <span className="hidden sm:inline">{useCase.label}</span>
                </button>
              ))}
            </div>
          </div>

          <motion.div
            key={activeUseCase.id}
            id={`audience-panel-${activeUseCase.id}`}
            role="tabpanel"
            aria-labelledby={`audience-tab-${activeUseCase.id}`}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.35 }}
            className="rounded-3xl border border-[var(--border)] bg-[var(--surface)]/40 p-6 sm:p-10"
          >
            <div className="flex flex-col items-start gap-5 sm:flex-row">
              <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-[var(--accent-dim)] ring-1 ring-[var(--accent-ring)] sm:h-14 sm:w-14">
                <ActiveIcon className="h-7 w-7 text-[var(--accent)]" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-[var(--text-strong)]">
                  {activeUseCase.heading}
                </h3>
                <p className="mt-3 max-w-2xl text-sm leading-relaxed text-[var(--text-muted)]">
                  {activeUseCase.body}
                </p>
                <ul className="mt-5 space-y-2">
                  {activeUseCase.bullets.map((bullet) => (
                    <li
                      key={bullet}
                      className="flex items-start gap-2.5 text-sm text-[var(--text-muted)]"
                    >
                      <CheckCircle className="mt-0.5 h-4 w-4 shrink-0 text-[var(--green)]" />
                      {bullet}
                    </li>
                  ))}
                </ul>
                <a
                  href={activeUseCase.href}
                  target={external ? '_blank' : undefined}
                  rel={external ? 'noopener noreferrer' : undefined}
                  className="mt-6 inline-flex w-full items-center justify-center gap-2 rounded-lg border border-[var(--border)] px-4 py-2.5 text-sm font-semibold text-[var(--accent)] transition hover:-translate-y-0.5 hover:border-[var(--border-strong)] hover:bg-[var(--surface-elevated)]/50 sm:w-auto sm:justify-start"
                >
                  {activeUseCase.cta}
                  <ArrowRight className="h-3.5 w-3.5" />
                </a>
              </div>
            </div>
          </motion.div>
        </div>
      </section>
    </Reveal>
  );
}

function Soc2DemoCard() {
  const [expandedCheck, setExpandedCheck] = useState<string | null>(null);
  const [controlFilter, setControlFilter] = useState<'ALL' | 'PASS' | 'FAIL'>('ALL');
  const visibleControls = SOC2_CONTROLS.filter(
    (control) => controlFilter === 'ALL' || control.status === controlFilter,
  );
  const reportStats = [
    { value: '3', label: 'All controls', filter: 'ALL', color: 'var(--text)' },
    { value: '1', label: 'Passing', filter: 'PASS', color: 'var(--green)' },
    { value: '2', label: 'Needs action', filter: 'FAIL', color: 'var(--red)' },
  ] as const;

  return (
    <Reveal>
      <section
        id="soc2-demo"
        className="scroll-mt-16 border-y border-[var(--line-faint)] bg-[var(--surface)]/10 py-14 sm:py-16"
      >
        <div className="mx-auto max-w-lg px-4 sm:px-6">
          <div className="mb-8 text-center">
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-[var(--border)] bg-[var(--surface-elevated)]/40 px-3 py-1 text-[11px] text-[var(--accent)]">
              <Sparkles className="h-3 w-3" />
              INTERACTIVE DEMO
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-[var(--text-strong)] sm:text-3xl">
              Your SOC 2 report
            </h2>
            <p className="mt-2 text-sm text-[var(--text-muted)]">
              A simple example of how technical checks become evidence a client,
              auditor, or teammate can understand.
            </p>
          </div>

          <TiltCard className="space-y-4 rounded-3xl border border-[var(--border)] bg-[var(--surface)]/60 p-6 shadow-[var(--shadow-soft)] transition-shadow duration-500 hover:shadow-[var(--shadow-glow-accent)]">
            <div className="flex items-center justify-between border-b border-[var(--line-faint)] pb-4">
              <div>
                <p className="text-sm font-bold text-[var(--text-strong)]">SOC 2 Evidence Report</p>
                <p className="mt-0.5 text-[10px] text-[var(--text-subtle)]">
                  Generated from GitHub Posture Connector
                </p>
              </div>
              <motion.span
                initial={{ scale: 0 }}
                whileInView={{ scale: 1 }}
                viewport={{ once: true }}
                transition={{ type: 'spring', stiffness: 250, delay: 0.2 }}
                className="rounded-md bg-[var(--red-dim)] px-3 py-1 text-[11px] font-bold uppercase text-[var(--red)]"
              >
                FAIL
              </motion.span>
            </div>

            <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--surface-elevated)]">
              <motion.div
                initial={{ width: 0 }}
                whileInView={{ width: '33%' }}
                viewport={{ once: true }}
                transition={{ duration: 1, delay: 0.3, ease: 'easeOut' }}
                className="h-full rounded-full"
                style={{ background: 'linear-gradient(90deg, var(--green), var(--red))' }}
              />
            </div>

            <div className="grid grid-cols-3 gap-2 text-center">
              {reportStats.map((stat) => (
                <button
                  key={stat.label}
                  type="button"
                  aria-pressed={controlFilter === stat.filter}
                  onClick={() => {
                    setControlFilter(stat.filter);
                    setExpandedCheck(null);
                  }}
                  className={`rounded-lg border p-2 transition-all ${
                    controlFilter === stat.filter
                      ? 'border-[var(--border-strong)] bg-[var(--surface-soft)] shadow-[var(--shadow-soft)]'
                      : 'border-transparent bg-[var(--surface-soft)]/50 hover:border-[var(--border)] hover:bg-[var(--surface-soft)]'
                  }`}
                >
                  <div className="text-lg font-bold" style={{ color: stat.color }}>
                    {stat.value}
                  </div>
                  <div className="text-[10px] text-[var(--muted)]">{stat.label}</div>
                </button>
              ))}
            </div>

            <div className="space-y-2 pt-2">
              {visibleControls.map((control) => (
                <motion.button
                  key={control.id}
                  type="button"
                  aria-expanded={expandedCheck === control.id}
                  aria-controls={`${control.id}-evidence`}
                  onClick={() =>
                    setExpandedCheck((current) =>
                      current === control.id ? null : control.id,
                    )
                  }
                  whileHover={{ scale: 1.01 }}
                  whileTap={{ scale: 0.99 }}
                  className={`w-full rounded-xl border border-[var(--line-faint)] p-4 text-left transition-all duration-300 ${
                    expandedCheck === control.id
                      ? 'border-[var(--border-strong)] bg-[var(--surface-soft)]/60 shadow-[var(--shadow-soft)]'
                      : 'bg-[var(--surface-soft)]/30 hover:border-[var(--border-strong)] hover:bg-[var(--surface-soft)]/50'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className="rounded-md bg-[var(--accent-dim)] px-2 py-0.5 font-mono text-[11px] font-bold text-[var(--accent)]">
                        {control.control}
                      </span>
                      <span className="text-sm font-semibold text-[var(--text)]">
                        {control.name}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span
                        className={`rounded px-2 py-0.5 text-[10px] font-semibold ${
                          control.status === 'PASS'
                            ? 'bg-[var(--green-dim)] text-[var(--green)]'
                            : 'bg-[var(--red-dim)] text-[var(--red)]'
                        }`}
                      >
                        {control.status}
                      </span>
                      <ChevronDown
                        className={`h-3 w-3 text-[var(--text-subtle)] transition-transform duration-300 ${
                          expandedCheck === control.id ? 'rotate-180' : ''
                        }`}
                      />
                    </div>
                  </div>
                  {expandedCheck === control.id && (
                    <motion.div
                      id={`${control.id}-evidence`}
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      transition={{ duration: 0.3 }}
                      className="mt-3 border-t border-[var(--line-faint)] pt-3"
                    >
                      <div className="mb-2 flex flex-wrap gap-1.5">
                        {control.checks.map((check) => (
                          <span
                            key={check}
                            className="rounded bg-[var(--surface-elevated)] px-2 py-0.5 font-mono text-[10px] text-[var(--accent)]"
                          >
                            {check}
                          </span>
                        ))}
                      </div>
                      <p className="text-xs leading-relaxed text-[var(--text-muted)]">
                        {control.evidence}
                      </p>
                      <div className="mt-2 flex items-center gap-1.5">
                        <span className="dot-online" />
                        <span className="text-[10px] text-[var(--green)]">
                          Evidence collected from live scan
                        </span>
                      </div>
                    </motion.div>
                  )}
                </motion.button>
              ))}
            </div>

            <div className="border-t border-[var(--line-faint)] pt-3 text-center">
              <p className="text-[10px] text-[var(--text-subtle)]">
                Control pass rate: 33% - 1 PASS / 2 NEED ACTION - downloadable PDF
              </p>
              <a
                href="/login"
                className="mt-3 inline-flex items-center gap-1.5 text-xs font-semibold text-[var(--accent)] transition hover:text-[var(--text-strong)]"
              >
                Sign in to open reports
                <ArrowRight className="h-3 w-3" />
              </a>
            </div>
          </TiltCard>
        </div>
      </section>
    </Reveal>
  );
}

function FeatureGrid() {
  return (
    <Reveal>
      <section id="capabilities" className="scroll-mt-16 py-14 sm:py-16">
        <div className="mx-auto max-w-5xl px-4 sm:px-6">
          <div className="mb-8 text-center">
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-[var(--border)] bg-[var(--surface-elevated)]/40 px-3 py-1 text-[11px] text-[var(--accent)]">
              <Sparkles className="h-3 w-3" />
              UNDER THE HOOD
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-[var(--text-strong)] sm:text-3xl">
              Start focused. Expand when you need to.
            </h2>
            <p className="mx-auto mt-2 max-w-xl text-sm text-[var(--text-muted)]">
              SecPlat connects the core jobs of a modern security programme without
              forcing every team to use every module.
            </p>
          </div>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map((feature, index) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: index * 0.05 }}
                whileHover={{ y: -4, scale: 1.02 }}
                className="group flex items-start gap-4 rounded-2xl border border-[var(--border)] bg-[var(--surface)]/40 p-5 outline-none transition-all duration-300 hover:border-[var(--border-strong)] hover:bg-[var(--surface)]/70 hover:shadow-[var(--shadow-soft)]"
              >
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-dim)] ring-1 ring-[var(--accent-ring)] transition-all group-hover:bg-[var(--accent)]/20 group-hover:ring-[var(--accent)]/50">
                  <feature.icon className="h-5 w-5 text-[var(--accent)] transition-transform group-hover:scale-110" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-semibold text-[var(--text)]">
                      {feature.title}
                    </h3>
                  </div>
                  <p className="mt-1 text-xs leading-relaxed text-[var(--text-muted)]">
                    {feature.desc}
                  </p>
                  <span className="mt-2 inline-block rounded border border-[var(--line-faint)] bg-[var(--surface-elevated)]/40 px-1.5 py-0.5 text-[10px] text-[var(--text-subtle)] group-hover:border-[var(--border)] group-hover:text-[var(--text-muted)]">
                    In platform
                  </span>
                </div>
              </motion.div>
            ))}
          </div>

          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            transition={{ delay: 0.4 }}
            className="mt-8 text-center"
          >
            <a
              href="https://github.com/viss2423/security-posture-platform"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-lg border border-[var(--border)] px-4 py-2 text-sm font-medium text-[var(--text-muted)] transition hover:border-[var(--border-strong)] hover:text-[var(--text)]"
            >
              <Github className="h-4 w-4" />
              Explore the full codebase
              <ArrowRight className="h-3 w-3" />
            </a>
          </motion.div>
        </div>
      </section>
    </Reveal>
  );
}

function Contact() {
  return (
    <Reveal>
      <section
        id="contact"
        className="scroll-mt-16 border-t border-[var(--line-faint)] bg-[var(--surface)]/10 py-14 sm:py-16"
      >
        <div className="mx-auto max-w-2xl px-4 text-center sm:px-6">
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ type: 'spring', stiffness: 200 }}
            className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-[var(--accent-dim)] ring-1 ring-[var(--accent-ring)]"
          >
            <Mail className="h-6 w-6 text-[var(--accent)]" />
          </motion.div>
          <h2 className="text-2xl font-bold tracking-tight text-[var(--text-strong)] sm:text-3xl">
            See whether SecPlat fits your next step
          </h2>
          <p className="mx-auto mt-3 max-w-md text-sm leading-relaxed text-[var(--text-muted)]">
            Evaluate the product, discuss a deployment, review the engineering, or
            collaborate on the open-source project. Start with whichever conversation
            matters to you.
          </p>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <a
              href="mailto:vishal.ireland2423@gmail.com"
              className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 px-5 py-2.5 text-sm font-medium text-[var(--text)] transition hover:border-[var(--border-strong)] hover:bg-[var(--surface-elevated)]/70"
            >
              <Mail className="h-4 w-4 text-[var(--accent)]" />
              Start a conversation
            </a>
            <a
              href="https://github.com/viss2423/security-posture-platform"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 px-5 py-2.5 text-sm font-medium text-[var(--text)] transition hover:border-[var(--border-strong)] hover:bg-[var(--surface-elevated)]/70"
            >
              <Github className="h-4 w-4 text-[var(--accent)]" />
              GitHub
            </a>
            <a
              href="https://www.linkedin.com/in/vishalb6401"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 px-5 py-2.5 text-sm font-medium text-[var(--text)] transition hover:border-[var(--border-strong)] hover:bg-[var(--surface-elevated)]/70"
            >
              <Linkedin className="h-4 w-4 text-[var(--accent)]" />
              LinkedIn
            </a>
          </div>
        </div>
      </section>
    </Reveal>
  );
}

function Footer() {
  return (
    <footer className="border-t border-[var(--border)] py-8">
      <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-3 px-4 sm:flex-row sm:px-6">
        <a
          href="#top"
          className="inline-flex items-center gap-2 text-xs font-semibold text-[var(--text-muted)] transition hover:text-[var(--text)]"
        >
          <Shield className="h-3.5 w-3.5 text-[var(--accent)]" />
          SecPlat
        </a>
        <div className="flex items-center gap-4 text-xs text-[var(--text-subtle)]">
          <a href="#how-it-works" className="transition hover:text-[var(--text)]">
            How it works
          </a>
          <a href="#capabilities" className="transition hover:text-[var(--text)]">
            Capabilities
          </a>
          <a href="#contact" className="transition hover:text-[var(--text)]">
            Contact
          </a>
        </div>
        <p className="text-xs text-[var(--text-subtle)]">
          &copy; {new Date().getFullYear()} SecPlat. Open-source security posture platform.
        </p>
      </div>
    </footer>
  );
}

function TerminalDemoSection() {
  return (
    <Reveal>
      <section
        id="terminal-demo"
        className="scroll-mt-16 border-y border-[var(--line-faint)] bg-[var(--surface)]/10 py-14 sm:py-16"
      >
        <div className="mx-auto max-w-2xl px-4 sm:px-6">
          <div className="mb-8 text-center">
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-[var(--border)] bg-[var(--surface-elevated)]/40 px-3 py-1 text-[11px] text-[var(--accent)]">
              <Sparkles className="h-3 w-3" />
              LIVE SIMULATION
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-[var(--text-strong)] sm:text-3xl">
              See it in action
            </h2>
            <p className="mt-2 text-sm text-[var(--text-muted)]">
              This is what happens when you run a GitHub posture scan. Hit
              <span className="font-semibold text-[var(--accent)]"> Run </span>
              to watch.
            </p>
          </div>
          <ScanTerminal />
        </div>
      </section>
    </Reveal>
  );
}

function ClosingCta() {
  return (
    <Reveal>
      <section className="py-14 sm:py-16">
        <div className="mx-auto max-w-2xl px-4 text-center sm:px-6">
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="rounded-3xl border border-[var(--border)] bg-[var(--surface)]/40 p-8 sm:p-12"
          >
            <h2 className="text-2xl font-bold tracking-tight text-[var(--text-strong)] sm:text-3xl">
              Ready to try it?
            </h2>
            <p className="mx-auto mt-3 max-w-md text-sm leading-relaxed text-[var(--text-muted)]">
              Connect a read-only GitHub token and get an auditor-ready SOC 2 report
              in under a minute. No infrastructure, no commitment.
            </p>
            <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
              <a
                href="/login"
                className="inline-flex items-center gap-2 rounded-xl bg-[var(--accent)] px-5 py-3 text-sm font-semibold text-[#07090e] shadow-[0_0_30px_rgba(34,211,238,0.2)] transition hover:-translate-y-0.5 hover:brightness-110 active:translate-y-0"
              >
                <Shield className="h-4 w-4" />
                Open the platform
                <ArrowRight className="h-4 w-4" />
              </a>
              <a
                href="#terminal-demo"
                className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] px-5 py-3 text-sm font-medium text-[var(--text-muted)] transition hover:-translate-y-0.5 hover:border-[var(--border-strong)] hover:text-[var(--text)] active:translate-y-0"
              >
                <Play className="h-4 w-4" />
                Watch the demo again
              </a>
            </div>
          </motion.div>
        </div>
      </section>
    </Reveal>
  );
}

function TrustStrip() {
  return (
    <section
      id="trust"
      className="border-y border-[var(--line-faint)] bg-[var(--surface)]/10 py-10"
    >
      <div className="mx-auto flex max-w-4xl flex-wrap items-center justify-center gap-x-8 gap-y-4 px-4 text-xs text-[var(--text-subtle)] sm:px-6">
        <span className="inline-flex items-center gap-2">
          <Github className="h-3.5 w-3.5 text-[var(--accent)]" />
          Open source — read every line
        </span>
        <span className="inline-flex items-center gap-2">
          <Cpu className="h-3.5 w-3.5 text-[var(--accent)]" />
          Self-hosted — your data stays with you
        </span>
        <span className="inline-flex items-center gap-2">
          <CheckCircle className="h-3.5 w-3.5 text-[var(--green)]" />
          Read-only connectors — cannot modify your repos
        </span>
      </div>
    </section>
  );
}

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-[var(--bg)]">
      <NavBar />
      <Hero />
      <TerminalDemoSection />
      <PipelineVisual />
      <Soc2DemoCard />
      <UseCaseTabs />
      <FeatureGrid />
      <ClosingCta />
      <TrustStrip />
      <Contact />
      <Footer />
    </div>
  );
}
