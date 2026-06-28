import type { KnipConfig } from "knip";

const config: KnipConfig = {
  // Next.js plugin auto-detects App Router entries, pages, and API routes.
  ignore: [".next/**", "node_modules/**"],
  ignoreDependencies: [
    // eslint-config-next is a direct dep (needed for eslint flat config),
    // but knip may flag it because no import references it by name.
    "eslint-config-next",
  ],
};

export default config;
