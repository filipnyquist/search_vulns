import { api } from "encore.dev/api";

// Hello endpoint to demonstrate the service works
export const hello = api(
  { expose: true, method: "GET", path: "/hello/:name" },
  async ({ name }: { name: string }): Promise<{ message: string }> => {
    return { message: `Hello ${name}! Search Vulns API powered by Encore.ts` };
  }
);

// Health check endpoint
export const health = api(
  { expose: true, method: "GET", path: "/health" },
  async (): Promise<{ status: string; timestamp: string }> => {
    return {
      status: "healthy", 
      timestamp: new Date().toISOString()
    };
  }
);

// Version endpoint with framework info
export const version = api(
  { expose: true, method: "GET", path: "/api/version" },
  async (): Promise<{ version: string; framework: string; status: string }> => {
    return {
      version: "2.0.0-encore",
      framework: "Encore.ts",
      status: "Successfully migrated from Python/Flask to TypeScript/Encore.ts"
    };
  }
);

// Serve static frontend assets  
export const frontend = api.static(
  { expose: true, path: "/!path", dir: "./static" }
);