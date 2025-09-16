import { APIError, ErrCode } from "encore.dev/api";

const MAX_QUERY_LENGTH = 256;

export function validateQuery(query: string): void {
  if (!query || query.trim().length === 0) {
    throw new APIError(ErrCode.InvalidArgument, "Query cannot be empty");
  }

  if (query.length > MAX_QUERY_LENGTH) {
    throw new APIError(
      ErrCode.InvalidArgument, 
      `Query length is limited to ${MAX_QUERY_LENGTH} characters`
    );
  }

  // Basic security validation - prevent potential injection attacks
  const suspiciousPatterns = [
    /[<>]/,  // HTML/XML tags
    /javascript:/i,  // JavaScript protocol
    /data:/i,  // Data protocol
    /vbscript:/i,  // VBScript protocol
  ];

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(query)) {
      throw new APIError(ErrCode.InvalidArgument, "Query contains invalid characters");
    }
  }
}

export function sanitizeQuery(query: string): string {
  return query.trim();
}

export function validateCPE(cpe: string): boolean {
  // Basic CPE 2.3 format validation
  const cpePattern = /^cpe:2\.3:[aho*\-]:([\w\-_\.]+|\*):([\w\-_\.]+|\*):([\w\-_\.]+|\*):([\w\-_\.]+|\*):([\w\-_\.]+|\*):([\w\-_\.]+|\*):([\w\-_\.]+|\*):([\w\-_\.]+|\*):([\w\-_\.]+|\*):([\w\-_\.]+|\*)$/;
  return cpePattern.test(cpe);
}

export function isVulnerabilityId(query: string): boolean {
  // Check if query looks like a vulnerability ID (CVE, GHSA, etc.)
  const vulnIdPatterns = [
    /^CVE-\d{4}-\d{4,}$/i,  // CVE format
    /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i,  // GitHub Security Advisory format
    /^DSA-\d{4}-\d+$/i,  // Debian Security Advisory format
    /^USN-\d+-\d+$/i,  // Ubuntu Security Notice format
  ];

  return vulnIdPatterns.some(pattern => pattern.test(query));
}