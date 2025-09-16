-- Migration for product database schema  
CREATE TABLE IF NOT EXISTS cpe_search_results (
    id SERIAL PRIMARY KEY,
    product_name VARCHAR(500),
    cpe_name VARCHAR(500),
    vendor VARCHAR(200),
    product VARCHAR(200),
    version VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cpe_search_suggestions (
    id SERIAL PRIMARY KEY,
    product_name VARCHAR(500),
    cpe_name VARCHAR(500),
    similarity_score DECIMAL(4,3),
    vendor VARCHAR(200),
    product VARCHAR(200),
    version VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cpe_results_product ON cpe_search_results(LOWER(product_name));
CREATE INDEX IF NOT EXISTS idx_cpe_suggestions_product ON cpe_search_suggestions(LOWER(product_name));
CREATE INDEX IF NOT EXISTS idx_cpe_suggestions_score ON cpe_search_suggestions(similarity_score DESC);