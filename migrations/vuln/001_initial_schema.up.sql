-- Migration for vulnerability database schema
CREATE TABLE IF NOT EXISTS meta_last_data_update (
    UTCTimestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id VARCHAR(50) PRIMARY KEY,
    description TEXT NOT NULL,
    cvss_score DECIMAL(3,1),
    cvss_version VARCHAR(10),
    published_date VARCHAR(50),
    cisa_known_exploited BOOLEAN DEFAULT FALSE,
    exploit_links TEXT,
    aliases JSONB,
    is_patched BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vulnerability_matches (
    id SERIAL PRIMARY KEY,
    vuln_id VARCHAR(50) REFERENCES vulnerabilities(vuln_id),
    cpe_pattern VARCHAR(500),
    match_reason VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vuln_matches_cpe ON vulnerability_matches(cpe_pattern);
CREATE INDEX IF NOT EXISTS idx_vuln_matches_vuln_id ON vulnerability_matches(vuln_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss ON vulnerabilities(cvss_score DESC);

-- Insert initial timestamp
INSERT INTO meta_last_data_update (UTCTimestamp) 
VALUES (NOW()) 
ON CONFLICT DO NOTHING;