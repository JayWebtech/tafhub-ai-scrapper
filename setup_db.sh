#!/bin/bash

# Setup script for PostgreSQL database

echo "🚀 Setting up PostgreSQL database for web scraper..."

# Check if PostgreSQL is running
if ! pg_isready -q; then
    echo "❌ PostgreSQL is not running. Please start PostgreSQL first."
    exit 1
fi

# Create database if it doesn't exist
echo "📦 Creating database 'scrapper'..."
createdb -U postgres scrapper 2>/dev/null || echo "Database 'scrapper' already exists"

# Apply schema
echo "🔧 Applying database schema..."
psql -U postgres -d scrapper -f schema.sql

echo "✅ Database setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Set DATABASE_URL environment variable (optional):"
echo "   export DATABASE_URL='postgresql://postgres:password@localhost/scrapper'"
echo "2. Run the scraper: cargo run"
echo ""
echo "🔗 Default connection: postgresql://localhost/scrapper"
