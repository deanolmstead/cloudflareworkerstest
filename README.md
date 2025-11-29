# Cloudflare Workers Authentication Test

A simple authentication system using Cloudflare Workers with a frontend HTML/CSS/JS interface.

## Project Structure

```
.
├── index.html       # Frontend HTML
├── styles.css       # Frontend styling
├── script.js        # Frontend JavaScript
├── package.json     # Dependencies
├── wrangler.toml    # Cloudflare Workers config
└── src/
    └── index.ts     # Worker backend code
```

## Getting Started

### Prerequisites

- Node.js and npm
- Wrangler CLI (`npm install -g wrangler`)
- Cloudflare account

### Installation

```bash
npm install
```

### Development

```bash
wrangler dev
```

This will start a local development server at `http://localhost:8787`

### Deployment

```bash
wrangler deploy
```

## Test Credentials

The following test credentials are available:

| Email | Password | Name |
|-------|----------|------|
| test@example.com | password123 | Test User |
| demo@example.com | demo123 | Demo User |

## API Endpoints

### POST /api/login
Login with email and password

**Request:**
```json
{
  "email": "test@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "id": "user_1234567890",
  "email": "test@example.com",
  "name": "Test User"
}
```

### GET /api/verify
Verify current authentication status

**Response:**
```json
{
  "id": "user_1234567890",
  "email": "test@example.com",
  "name": "Test User"
}
```

### POST /api/logout
Logout and clear session

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

## Features

- ✓ Email/password authentication
- ✓ Secure HTTP-only cookies
- ✓ Session management
- ✓ Clean, responsive UI
- ✓ Error handling
- ✓ Auto-check authentication on page load

## Notes

- This is a demonstration project. In production, you should:
  - Use a real database instead of in-memory storage
  - Hash passwords using bcrypt or similar
  - Use Cloudflare KV or Workers KV for session storage
  - Implement rate limiting
  - Add CSRF protection
  - Use HTTPS only
  - Implement proper error handling and logging

## License

MIT
