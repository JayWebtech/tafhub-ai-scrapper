#!/bin/bash

echo "🧪 Testing PostgreSQL database connection..."

# Test if PostgreSQL is running
if ! pg_isready -q; then
    echo "❌ PostgreSQL is not running. Please start it first:"
    echo "   brew services start postgresql  # macOS"
    echo "   sudo systemctl start postgresql  # Linux"
    exit 1
fi

echo "✅ PostgreSQL is running"

# Test database connection
if psql -U postgres -d scrapper -c "SELECT 1;" >/dev/null 2>&1; then
    echo "✅ Database 'scrapper' exists and is accessible"
else
    echo "❌ Database 'scrapper' not found or not accessible"
    echo "   Run ./setup_db.sh first"
    exit 1
fi

# Test if tables exist
if psql -U postgres -d scrapper -c "SELECT COUNT(*) FROM jobs;" >/dev/null 2>&1; then
    echo "✅ Table 'jobs' exists"
else
    echo "❌ Table 'jobs' not found"
    echo "   Run ./setup_db.sh first"
    exit 1
fi

if psql -U postgres -d scrapper -c "SELECT COUNT(*) FROM scraped_data;" >/dev/null 2>&1; then
    echo "✅ Table 'scraped_data' exists"
else
    echo "❌ Table 'scraped_data' not found"
    echo "   Run ./setup_db.sh first"
    exit 1
fi

echo ""
echo "🎉 Database test successful! You can now run:"
echo "   cargo run"
