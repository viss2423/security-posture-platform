import { redirect } from 'next/navigation';
import { getServerSession } from '@/lib/session';

export default async function Home() {
  const user = await getServerSession();
  redirect(user ? '/overview' : '/login');
}
