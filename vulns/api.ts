import { api, APIError, ErrCode, Query } from "encore.dev/api";
import { vulnDb, productDb } from "./database";
import { searchVulnerabilities, searchProductIds, formatVulnerabilityOutput } from "./search";
import { validateQuery, sanitizeQuery } from "./validation";

// Types for API requests and responses
export interface SearchRequest {
  query: Query<string>;
  "ignore-general-product-vulns"?: Query<boolean>;
  "include-single-version-vulns"?: Query<boolean>;
  "include-patched"?: Query<boolean>;
  "use-created-product-ids"?: Query<boolean>;
  "is-good-product-id"?: Query<boolean>;
}

export interface ProductIdSuggestionsRequest {
  query: Query<string>;
}

export interface Vulnerability {
  id: string;
  description: string;
  cvss: number;
  cvss_ver: string;
  published: string;
  cisa_known_exploited?: boolean;
  exploits?: string[];
  aliases: Record<string, string>;
  match_reason?: string;
  is_patched?: boolean;
}

export interface ProductIdSuggestion {
  cpe: string;
  score: number;
}

export interface SearchVulnsResponse {
  vulns: Record<string, Vulnerability>;
  product_ids: Record<string, string[]>;
  pot_product_ids: Record<string, ProductIdSuggestion[]>;
}

export interface ProductIdSuggestionsResponse {
  [key: string]: ProductIdSuggestion[];
}

export interface VersionResponse {
  version: string;
  last_db_update_ts: number;
  last_db_update: string;
}

// Main vulnerability search endpoint
export const searchVulns = api(
  { expose: true, method: "GET", path: "/api/search-vulns" },
  async (req: SearchRequest): Promise<SearchVulnsResponse> => {
    // Validate and sanitize query
    if (!req.query) {
      throw new APIError(ErrCode.InvalidArgument, "No query provided");
    }

    const query = sanitizeQuery(req.query);
    validateQuery(query);

    // Set up search parameters with defaults
    const ignoreGeneralProductVulns = req["ignore-general-product-vulns"] ?? false;
    const includeSingleVersionVulns = req["include-single-version-vulns"] ?? false;
    const includePatched = req["include-patched"] ?? false;
    const useCreatedProductIds = req["use-created-product-ids"] ?? false;
    const isGoodProductId = req["is-good-product-id"] ?? true;

    try {
      // Search for vulnerabilities
      const result = await searchVulnerabilities(
        query,
        {
          ignoreGeneralProductVulns,
          includeSingleVersionVulns,
          includePatched,
          useCreatedProductIds,
          isGoodProductId
        },
        vulnDb,
        productDb
      );

      return result;
    } catch (error) {
      throw new APIError(ErrCode.Internal, `Search failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
);

// Product ID suggestions endpoint
export const productIdSuggestions = api(
  { expose: true, method: "GET", path: "/api/product-id-suggestions" },
  async (req: ProductIdSuggestionsRequest): Promise<ProductIdSuggestionsResponse> => {
    if (!req.query) {
      throw new APIError(ErrCode.InvalidArgument, "No query provided");
    }

    const query = sanitizeQuery(req.query);
    validateQuery(query);

    try {
      const suggestions = await searchProductIds(query, productDb);
      return suggestions;
    } catch (error) {
      throw new APIError(ErrCode.Internal, `Product ID search failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
);

// Version information endpoint
export const version = api(
  { expose: true, method: "GET", path: "/api/version" },
  async (): Promise<VersionResponse> => {
    try {
      // Get last update timestamp from vulnerability database
      const result = await vulnDb.queryRow<{ UTCTimestamp: Date }>`
        SELECT UTCTimestamp FROM meta_last_data_update;
      `;

      if (!result) {
        throw new Error("Unable to retrieve database update timestamp");
      }

      const lastUpdate = result.UTCTimestamp;
      
      return {
        version: "2.0.0-encore", // Updated version for the Encore.ts implementation
        last_db_update_ts: Math.floor(lastUpdate.getTime() / 1000),
        last_db_update: lastUpdate.toUTCString()
      };
    } catch (error) {
      throw new APIError(ErrCode.Internal, `Failed to get version info: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
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