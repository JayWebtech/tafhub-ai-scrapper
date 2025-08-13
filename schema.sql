-- Create tables for web scraper jobs and results

-- Jobs table to store job metadata
CREATE TABLE IF NOT EXISTS jobs (
    id UUID PRIMARY KEY,
    url TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    max_pages INTEGER NOT NULL DEFAULT 10,
    max_depth INTEGER NOT NULL DEFAULT 2,
    delay_ms INTEGER NOT NULL DEFAULT 1000,
    follow_external_links BOOLEAN NOT NULL DEFAULT false,
    pages_scraped INTEGER NOT NULL DEFAULT 0,
    total_links_found INTEGER NOT NULL DEFAULT 0,
    current_url TEXT,
    error TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Scraped data table to store the actual scraped content
CREATE TABLE IF NOT EXISTS scraped_data (
    id SERIAL PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    title TEXT,
    text_content JSONB NOT NULL, -- Store text content as JSON array
    links JSONB NOT NULL,        -- Store links as JSON array
    images JSONB NOT NULL,       -- Store image URLs as JSON array
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at);
CREATE INDEX IF NOT EXISTS idx_scraped_data_job_id ON scraped_data(job_id);
CREATE INDEX IF NOT EXISTS idx_scraped_data_url ON scraped_data(url);

-- Function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to automatically update updated_at
CREATE TRIGGER update_jobs_updated_at 
    BEFORE UPDATE ON jobs 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();
