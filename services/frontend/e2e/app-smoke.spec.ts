import { test, expect } from '@playwright/test';
import { startMockApiServer } from './mockApiServer';

let apiServer: Awaited<ReturnType<typeof startMockApiServer>>;

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
  apiServer = await startMockApiServer(4010);
});

test.afterAll(async () => {
  await apiServer.close();
});

test('login, onboarding, findings, incidents, and automation approval flows all work', async ({
  page,
}) => {
  await page.goto('/login');
  await page.getByLabel(/username/i).fill('admin');
  await page.getByLabel(/password/i).fill('admin');
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/overview/, { timeout: 15000 });

  await page.goto('/onboarding');
  await expect(
    page.getByRole('heading', { name: /launch your account in one guided flow/i, level: 1 })
  ).toBeVisible();

  await page.getByRole('button', { name: /^create asset$/i }).click();
  await expect(page.getByText(/asset onboarding-edge-gateway created/i)).toBeVisible();

  await page.getByRole('button', { name: /ingest sample telemetry/i }).click();
  await expect(page.getByText(/telemetry ingested for onboarding-edge-gateway/i)).toBeVisible();

  await page.getByRole('button', { name: /enable baseline detection/i }).click();
  await expect(page.getByText(/matched 1 event\(s\) over 168h/i)).toBeVisible();

  await page.getByRole('button', { name: /create first incident/i }).click();
  await expect(page.getByText(/incident 2000 is ready for triage/i)).toBeVisible();

  await page.goto('/incidents');
  await expect(
    page.getByRole('heading', { name: /incident response/i, level: 1 })
  ).toBeVisible();
  await expect(page.getByText(/onboarding incident for onboarding-edge-gateway/i).first()).toBeVisible();

  await page.goto('/findings');
  await expect(page.getByRole('heading', { name: /risk review/i, level: 1 })).toBeVisible();
  await expect(page.getByText(/image user should not be root/i)).toBeVisible();

  await page.goto('/automation');
  await expect(
    page.getByRole('heading', { name: /workflow builder/i, level: 1 })
  ).toBeVisible();
  await page.getByRole('button', { name: /^approve$/i }).first().click();
  await expect(page.getByText(/approval 501 approved/i)).toBeVisible();
});
