# SecPlat landing page

The public marketing site for SecPlat — a standalone **static** site (Vite +
React) that reuses the product's landing component. It builds to plain
HTML/CSS/JS with **no server runtime**, so it hosts free on Cloudflare Pages (or
any static host) and can't be broken by the main app's backend or Next.js
version.

## Local development

```bash
cd landing
npm install
npm run dev        # http://localhost:3010
```

## Build

```bash
npm run build      # type-checks, then outputs static files to ./dist
npm run preview    # serve the built ./dist locally
```

## Where the "Open the platform" buttons point

By default (no config) the sign-in / "open the platform" CTAs link to the GitHub
repo, so visitors can self-host. Once you deploy the actual app (e.g. on your
Oracle Cloud VM), set a build-time env var so the buttons point at it:

```bash
VITE_APP_URL=https://app.yourdomain.com npm run build
# CTAs now link to https://app.yourdomain.com/login
```

In Cloudflare Pages, set `VITE_APP_URL` under **Settings → Environment variables**.

## Deploy free on Cloudflare Pages (recommended)

No secrets, no credit card, no GitHub Action needed — connect the repo once in the
dashboard:

1. Cloudflare dashboard → **Workers & Pages → Create → Pages → Connect to Git**.
2. Pick this repository.
3. Build settings:
   - **Framework preset:** `None`
   - **Root directory:** `landing`
   - **Build command:** `npm install && npm run build`
   - **Build output directory:** `dist`
4. (Optional) Add `VITE_APP_URL` under environment variables.
5. **Save and Deploy.**

Cloudflare gives you a free `*.pages.dev` URL and rebuilds automatically on every
push to `main`. Add a custom domain later under the project's **Custom domains**
tab (also free).

> This site is intentionally *not* wired into the repo's GitHub Actions, because
> the dashboard "connect repo" flow is simpler and needs no stored secrets.

## Keeping it in sync

`src/LandingPage.tsx` is a copy of `services/frontend/app/LandingPage.tsx`. If you
change the product's landing component, mirror visual changes here. The only
intentional difference is the configurable `VITE_APP_URL` link target.
