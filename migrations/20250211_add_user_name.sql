-- Migration: Add name column to users table
-- Date: 2025-02-11

-- Add name column to users table (nullable to support existing users)
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS name TEXT;

