import { SQLDatabase } from "encore.dev/storage/sqldb";
import type { SearchVulnsResponse, ProductIdSuggestionsResponse, Vulnerability, ProductIdSuggestion } from "./api";

export interface SearchOptions {
  ignoreGeneralProductVulns: boolean;
  includeSingleVersionVulns: boolean;
  includePatched: boolean;
  useCreatedProductIds: boolean;
  isGoodProductId: boolean;
}

// Cache for search results - in production this should be Redis or similar
const searchCache = new Map<string, any>();
const productIdCache = new Map<string, any>();

export async function searchVulnerabilities(
  query: string,
  options: SearchOptions,
  vulnDb: SQLDatabase,
  productDb: SQLDatabase
): Promise<SearchVulnsResponse> {
  // Create cache key
  const cacheKey = `${query}:${JSON.stringify(options)}`;
  
  // Check cache first
  if (searchCache.has(cacheKey)) {
    return searchCache.get(cacheKey);
  }

  // Search for product IDs first
  const productIds = await findProductIds(query, productDb, options.isGoodProductId);
  const potentialProductIds = await findPotentialProductIds(query, productDb);

  // Search for vulnerabilities based on product IDs
  const vulnerabilities = await findVulnerabilities(
    query,
    productIds,
    options,
    vulnDb
  );

  const result: SearchVulnsResponse = {
    vulns: vulnerabilities,
    product_ids: productIds,
    pot_product_ids: potentialProductIds
  };

  // Cache the result
  searchCache.set(cacheKey, result);
  
  // Clear cache after 5 minutes to prevent memory issues
  setTimeout(() => searchCache.delete(cacheKey), 5 * 60 * 1000);

  return result;
}

export async function searchProductIds(
  query: string,
  productDb: SQLDatabase
): Promise<ProductIdSuggestionsResponse> {
  const cacheKey = `productids:${query.toLowerCase()}`;
  
  if (productIdCache.has(cacheKey)) {
    return productIdCache.get(cacheKey);
  }

  const suggestions = await findPotentialProductIds(query, productDb);
  
  productIdCache.set(cacheKey, suggestions);
  setTimeout(() => productIdCache.delete(cacheKey), 5 * 60 * 1000);
  
  return suggestions;
}

async function findProductIds(
  query: string,
  productDb: SQLDatabase,
  isGoodProductId: boolean
): Promise<Record<string, string[]>> {
  const productIds: Record<string, string[]> = {};

  try {
    // If it's already a CPE string, use it directly
    if (query.startsWith('cpe:2.3:')) {
      productIds.cpe = [query];
      return productIds;
    }

    // Search for matching CPEs in the product database
    // This is a simplified version - the original Python code has more complex logic
    const cpeResults = await productDb.query<{ cpe: string; score: number }>`
      SELECT cpe_name as cpe, 1.0 as score
      FROM cpe_search_results 
      WHERE LOWER(product_name) LIKE LOWER(${'%' + query + '%'})
      ORDER BY score DESC
      LIMIT 10
    `;

    const cpes: string[] = [];
    for await (const row of cpeResults) {
      cpes.push(row.cpe);
    }

    if (cpes.length > 0) {
      productIds.cpe = cpes;
    }

    return productIds;
  } catch (error) {
    console.error('Error finding product IDs:', error);
    return productIds;
  }
}

async function findPotentialProductIds(
  query: string,
  productDb: SQLDatabase
): Promise<Record<string, ProductIdSuggestion[]>> {
  const potentialIds: Record<string, ProductIdSuggestion[]> = {};

  try {
    // Search for potential CPE matches with similarity scores
    const cpeResults = await productDb.query<{ cpe: string; score: number }>`
      SELECT cpe_name as cpe, similarity_score as score
      FROM cpe_search_suggestions 
      WHERE LOWER(product_name) LIKE LOWER(${'%' + query + '%'})
      ORDER BY score DESC
      LIMIT 20
    `;

    const cpeSuggestions: ProductIdSuggestion[] = [];
    for await (const row of cpeResults) {
      cpeSuggestions.push({ cpe: row.cpe, score: row.score });
    }

    if (cpeSuggestions.length > 0) {
      potentialIds.cpe = cpeSuggestions;
    }

    return potentialIds;
  } catch (error) {
    console.error('Error finding potential product IDs:', error);
    return potentialIds;
  }
}

async function findVulnerabilities(
  query: string,
  productIds: Record<string, string[]>,
  options: SearchOptions,
  vulnDb: SQLDatabase
): Promise<Record<string, Vulnerability>> {
  const vulnerabilities: Record<string, Vulnerability> = {};

  try {
    // If we have CPE product IDs, search for vulnerabilities
    const cpes = productIds.cpe || [];
    if (cpes.length === 0) {
      return vulnerabilities;
    }

    // Search for vulnerabilities matching the CPEs
    const vulnResults = await vulnDb.query<{
      vuln_id: string;
      description: string;
      cvss_score: number;
      cvss_version: string;
      published_date: string;
      cisa_exploited: boolean;
      exploit_links: string;
      aliases: string;
      match_reason: string;
      is_patched: boolean;
    }>`
      SELECT DISTINCT
        v.vuln_id,
        v.description,
        v.cvss_score,
        v.cvss_version,
        v.published_date,
        v.cisa_known_exploited as cisa_exploited,
        v.exploit_links,
        v.aliases,
        vm.match_reason,
        v.is_patched
      FROM vulnerabilities v
      JOIN vulnerability_matches vm ON v.vuln_id = vm.vuln_id
      WHERE vm.cpe_pattern = ANY(${cpes})
      ORDER BY v.cvss_score DESC
    `;

    for await (const row of vulnResults) {
      // Apply filtering based on options
      if (options.ignoreGeneralProductVulns && row.match_reason === 'GENERAL_PRODUCT_UNCERTAIN') {
        continue;
      }
      
      if (!options.includeSingleVersionVulns && row.match_reason === 'SINGLE_HIGHER_VERSION') {
        continue;
      }
      
      if (!options.includePatched && row.is_patched) {
        continue;
      }

      // Parse exploit links
      const exploits = row.exploit_links ? 
        row.exploit_links.split(',').map((link: string) => link.trim()).filter((link: string) => link) : 
        [];

      // Parse aliases
      const aliases = row.aliases ? JSON.parse(row.aliases) : {};

      vulnerabilities[row.vuln_id] = {
        id: row.vuln_id,
        description: row.description,
        cvss: row.cvss_score,
        cvss_ver: row.cvss_version,
        published: row.published_date,
        cisa_known_exploited: row.cisa_exploited,
        exploits: exploits.length > 0 ? exploits : undefined,
        aliases,
        match_reason: row.match_reason,
        is_patched: row.is_patched
      };
    }

    return vulnerabilities;
  } catch (error) {
    console.error('Error finding vulnerabilities:', error);
    return vulnerabilities;
  }
}

export function formatVulnerabilityOutput(vulnerabilities: Record<string, Vulnerability>): string {
  let output = '';
  
  // Sort vulnerabilities by CVSS score (highest first)
  const sortedVulns = Object.entries(vulnerabilities)
    .sort(([, a], [, b]) => b.cvss - a.cvss);

  for (const [vulnId, vuln] of sortedVulns) {
    output += `${vuln.id} (CVSSv${vuln.cvss_ver}/${vuln.cvss})`;
    
    if (vuln.cisa_known_exploited) {
      output += ' (Actively exploited)';
    }
    
    output += `: ${vuln.description}\n`;
    
    if (vuln.exploits && vuln.exploits.length > 0) {
      output += `Exploits:  ${vuln.exploits[0]}\n`;
      for (let i = 1; i < vuln.exploits.length; i++) {
        output += `${''.padStart('Exploits:  '.length)}${vuln.exploits[i]}\n`;
      }
    }
    
    output += `Reference: ${Object.values(vuln.aliases)[0] || 'N/A'}`;
    output += `, ${vuln.published.split(' ')[0]}\n\n`;
  }
  
  return output;
}