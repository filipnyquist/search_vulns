# Search Vulns - Encore.ts Implementation

This is a TypeScript rewrite of the search_vulns vulnerability search tool using the Encore.ts framework.

## About

search_vulns provides an API for searching known vulnerabilities in software using software titles or CPE 2.3 strings. This Encore.ts implementation offers:

- **Type-safe APIs** with automatic request validation
- **Built-in database management** with PostgreSQL support
- **Modern web service architecture** with proper error handling
- **Scalable microservices design** ready for production deployment
- **Automatic API documentation** and client generation

## Features

- Search for vulnerabilities by software name or CPE string
- Product ID suggestions for better search accuracy
- Version information endpoint
- Built-in web interface for manual searches
- RESTful API endpoints compatible with the original Python version
- Type-safe database operations
- Input validation and security measures

## API Endpoints

### Search Vulnerabilities
```
GET /api/search-vulns?query=<software_name>
```

Query parameters:
- `query` (required): Software name or CPE 2.3 string
- `ignore-general-product-vulns`: Boolean to ignore general product vulnerabilities
- `include-single-version-vulns`: Boolean to include single version vulnerabilities
- `include-patched`: Boolean to include patched vulnerabilities
- `use-created-product-ids`: Boolean to use created product IDs
- `is-good-product-id`: Boolean indicating if query is already a good product ID

### Product ID Suggestions
```
GET /api/product-id-suggestions?query=<software_name>
```

### Version Information
```
GET /api/version
```

### Health Check
```
GET /health
```

## Installation & Setup

1. **Install Encore CLI**:
   ```bash
   curl -L https://encore.dev/install.sh | bash
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Run the application**:
   ```bash
   encore run
   ```

## Development

### Running Tests
```bash
npm test
```

### Building for Production
```bash
encore build docker
```

### Database Migration
Encore automatically handles database migrations when the application starts.

## Architecture

The application follows Encore.ts best practices:

- **Single service architecture** for simplicity
- **PostgreSQL databases** for vulnerability and product data
- **Type-safe API endpoints** with automatic validation
- **Static asset serving** for the web interface
- **Structured error handling** with appropriate HTTP status codes

## Files Structure

- `api.ts` - Main API endpoints
- `database.ts` - Database configuration
- `search.ts` - Core search logic
- `validation.ts` - Input validation utilities
- `static.ts` - Static asset serving
- `migrations/` - Database schema migrations
- `static/` - Web interface files
- `__tests__/` - Test files

## Migration from Python Version

This TypeScript implementation maintains API compatibility with the original Python version while providing:

- Better type safety
- Improved error handling
- Modern async/await patterns
- Built-in scalability features
- Automatic API documentation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

MIT License - see the original LICENSE file for details.