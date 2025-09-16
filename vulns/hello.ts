import { api } from "encore.dev/api";

// Simple hello endpoint to test basic functionality
export const hello = api(
  { expose: true, method: "GET", path: "/hello/:name" },
  async ({ name }: { name: string }): Promise<{ message: string }> => {
    const msg = `Hello ${name}! Search Vulns Encore.ts API is running.`;
    return { message: msg };
  }
);