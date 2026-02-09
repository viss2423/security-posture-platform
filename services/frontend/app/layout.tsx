import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'SecPlat – Security Posture',
  description: 'Security posture and asset overview',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
