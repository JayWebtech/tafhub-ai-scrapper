# Web Scraper API with PostgreSQL

A robust web scraping API built with Rust, Axum, and PostgreSQL for persistent data storage.

## Features

- **Persistent Storage**: All scraping jobs and results stored in PostgreSQL
- **Async Processing**: Background job processing with real-time status updates
- **RESTful API**: Clean HTTP endpoints for job management
- **Scalable**: Can handle multiple concurrent scraping jobs
- **Progress Tracking**: Real-time progress updates during scraping

## Prerequisites

- Rust (latest stable)
- PostgreSQL (running locally or remotely)
- Cargo

## Setup

### 1. Database Setup

```bash
# Make sure PostgreSQL is running
brew services start postgresql  # macOS
# or
sudo systemctl start postgresql  # Linux

# Run the setup script
./setup_db.sh
```

### 2. Environment Variables (Optional)

```bash
export DATABASE_URL="postgresql://username:password@localhost/scrapper"
```

Default connection: `postgresql://localhost/scrapper`

### 3. Build and Run

```bash
cargo build
cargo run
```

The API will start on `http://localhost:3000`

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/scrape` | Start a new scraping job |
| `GET` | `/jobs` | List all jobs |
| `GET` | `/jobs/:id` | Get job status |
| `GET` | `/jobs/:id/results` | Get scraping results |
| `DELETE` | `/jobs/:id` | Delete a job |

## Usage Example

### Start Scraping

```bash
curl -X POST http://localhost:3000/scrape \
  -H 'Content-Type: application/json' \
  -d '{
    "url": "https://example.com",
    "config": {
      "max_pages": 50,
      "max_depth": 3,
      "delay_ms": 1000,
      "follow_external_links": false
    }
  }'
```

Response:
```json
{
  "job_id": "8df27924-1716-426b-acb0-1a99e562df76",
  "status": "started",
  "message": "Scraping job started for URL: https://example.com"
}
```

### Check Job Status

```bash
curl http://localhost:3000/jobs/8df27924-1716-426b-acb0-1a99e562df76
```

### Get Results

```bash
curl http://localhost:3000/jobs/8df27924-1716-426b-acb0-1a99e562df76/results
```

## Database Schema

The application uses two main tables:

- **`jobs`**: Stores job metadata, status, and progress
- **`scraped_data`**: Stores the actual scraped content (URLs, titles, links, images, text)

## Benefits of PostgreSQL Storage

1. **Persistence**: Data survives server restarts
2. **Scalability**: Can handle thousands of jobs
3. **Querying**: Advanced filtering and search capabilities
4. **Backup**: Easy database backup and recovery
5. **Multi-user**: Safe concurrent access from multiple users

## Configuration

Default scraping limits:
- Max pages: 100 (configurable)
- Max depth: 5 levels (configurable)
- Delay: 500ms minimum between requests
- Concurrent requests: 3

## Troubleshooting

### Database Connection Issues

```bash
# Check if PostgreSQL is running
pg_isready

# Test connection
psql -U postgres -d scrapper -c "SELECT 1;"
```

### Common Issues

1. **Port already in use**: Change port in `main.rs` or kill existing process
2. **Database connection failed**: Check PostgreSQL status and connection string
3. **Permission denied**: Ensure proper database user permissions

## Development

```bash
# Run with logging
RUST_LOG=debug cargo run

# Run tests
cargo test

# Check for issues
cargo clippy
```
