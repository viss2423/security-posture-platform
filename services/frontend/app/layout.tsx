import type { Metadata } from 'next';
import { Instrument_Sans, JetBrains_Mono } from 'next/font/google';
import './globals.css';

const instrumentSans = Instrument_Sans({
  subsets: ['latin'],
  variable: '--font-sans',
  display: 'swap',
});
const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'SecPlat — Open-Source Security Posture & SOC 2 Compliance',
  description:
    'Run a read-only GitHub scan and get an auditor-ready SOC 2 evidence report in under a minute. Open-source platform with risk scoring, alert triage, attack simulation, and policy-as-code.',
  openGraph: {
    title: 'SecPlat — Open-Source Security Posture & SOC 2 Compliance',
    description:
      'Run a read-only GitHub scan and get an auditor-ready SOC 2 evidence report in under a minute.',
    url: 'https://207-180-216-252.sslip.io/',
    siteName: 'SecPlat',
    type: 'website',
    images: [
      {
        url: 'https://github.com/viss2423.png',
        width: 460,
        height: 460,
        alt: 'SecPlat — Open-Source Security Posture & SOC 2 Compliance',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'SecPlat — Open-Source Security Posture & SOC 2 Compliance',
    description:
      'Run a read-only GitHub scan and get an auditor-ready SOC 2 evidence report in under a minute.',
    images: ['https://github.com/viss2423.png'],
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      data-scroll-behavior="smooth"
      className={`${instrumentSans.variable} ${jetbrainsMono.variable}`}
    >
      <body className="font-sans antialiased text-[var(--text)] selection:bg-[var(--selection-bg)] selection:text-[var(--selection-text)]">
        {children}
      </body>
    </html>
  );
}
