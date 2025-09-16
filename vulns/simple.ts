import { api } from "encore.dev/api";

// Basic health check endpoint
export const health = api(
  { expose: true, method: "GET", path: "/health" },
  async (): Promise<{ status: string; timestamp: string }> => {
    return {
      status: "healthy",
      timestamp: new Date().toISOString()
    };
  }
);

// Simple version endpoint
export const version = api(
  { expose: true, method: "GET", path: "/api/version" },
  async (): Promise<{ version: string; framework: string }> => {
    return {
      version: "2.0.0-encore",
      framework: "Encore.ts"
    };
  }
);