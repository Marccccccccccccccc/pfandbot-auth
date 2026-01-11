# PfandBot Auth - Multi-Account Microsoft Authentication Proxy

A Rust-based authentication proxy that allows managing multiple Microsoft accounts for Minecraft, with built-in support for Meteor Client and other Minecraft clients.

Readme made by Claude im to lazy
## Features

- **Multiple Account Support**: Store and manage multiple Microsoft accounts
- **Token Caching**: Tokens are cached for 23 hours per account (persisted to disk)
- **Meteor Client Compatible**: Works with Meteor Client without code modifications
- **Universal Client Support**: Yggdrasil-style API endpoints work with most Minecraft clients
- **CLI Management**: Easy-to-use command-line interface for configuration
- **Secure API Keys**: Generate and manage API keys via JSON config

## Quick Start

### 1. Initial Setup (Interactive)

```bash
cargo build --release
./target/release/pfandbot-auth setup
```

This will guide you through:
- Setting bind address and port
- Generating or setting an API key
- Adding your first account

### 2. Run the Server

```bash
./target/release/pfandbot-auth
# or
./target/release/pfandbot-auth start
# or with custom port
./target/release/pfandbot-auth start --port 8080
```

## CLI Commands

```bash
# Interactive setup
pfandbot-auth setup

# Add a new account
pfandbot-auth add-account

# List all configured accounts
pfandbot-auth list-accounts

# Generate a new API key
pfandbot-auth generate-key

# Start the server
pfandbot-auth start [--port <PORT>]
```

## Configuration Files

### `config.json`
```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 3000
  },
  "api_keys": [
    "your-secret-api-key-here"
  ]
}
```

### `accounts.json`
```json
[
  {
    "email": "your_email1@example.com",
    "display_name": "Main Account"
  },
  {
    "email": "your_email2@example.com",
    "display_name": "Alt Account"
  }
]
```

## Usage with Meteor Client

When the server starts, you'll see which accounts are loaded:

```
Loaded 3 account(s):
  [0] Main Account (your_email1@example.com)
  [1] Alt Account (your_email2@example.com)
  [2] Bot Account (your_email3@example.com)
```

### In Meteor Client:

1. Go to the account settings/add account section
2. Select "Custom Server" or "Auth Server" option
3. Fill in the fields:
   - **Username/Email**: Enter the account number (e.g., `0` for first account, `1` for second, etc.)
   - **Password**: Enter your API key (e.g., `your-secret-key-1`)
   - **Server**: Enter `http://localhost:3000` (or your server address)

### Account Selection

- To use the **first account** (index 0): Username = `0`
- To use the **second account** (index 1): Username = `1`
- To use the **third account** (index 2): Username = `2`

## HTTP API Usage

You can also use the HTTP API directly:

```bash
# Get token for account 0
curl "http://localhost:3000/token?key=your-secret-key-1&account=0"

# Get token for account 1
curl "http://localhost:3000/token?key=your-secret-key-1&account=1"

# Response format
{
  "access_token": "eyJ...",
  "uuid": "069a79f4-44e9-4726-a5be-fca90e38aaf5",
  "username": "PlayerName"
}
```

## First-Time Authentication

On the **first request for each account**, a browser window will open for Microsoft authentication:
1. Sign in with the Microsoft account
2. Authorize Minecraft access
3. The token will be cached for future use

Subsequent requests will use the cached token until it expires (23 hours).

## Manual Configuration

If you prefer to create config files manually instead of using `setup`:

1. Create `config.json` with your settings
2. Create `accounts.json` with your Microsoft accounts
3. Run `pfandbot-auth start`

## Security Notes

- **Keep your API keys secret** - They're in `config.json`
- **Keep your accounts safe** - `accounts.json` contains email addresses
- **Token cache** - `token_cache.json` contains valid access tokens
- All sensitive files are in `.gitignore` by default
- Consider using HTTPS in production (currently uses HTTP)
- The default bind address `0.0.0.0:3000` exposes the server on all interfaces
- For production use, consider adding rate limiting and additional security measures

## Troubleshooting

### "Invalid credentials" error in Meteor
- Make sure you're using the correct account number (0, 1, 2, etc.)
- Verify your API key matches what's in the code
- Check the server is running (`http://localhost:3000`)

### "Account not found" error
- Verify the account number exists in your `accounts.json`
- Remember: accounts are zero-indexed (first account is 0, not 1)

### Browser doesn't open for authentication
- Check that the Microsoft account email is correct in `accounts.json`
- Ensure you have a browser installed and accessible
- Check the console for error messages

## Architecture

- **Axum**: Web framework
- **Azalea-auth**: Microsoft authentication handling
- **Tokio**: Async runtime
- **Serde**: JSON serialization

The server implements two authentication methods:
1. Simple HTTP GET endpoint (`/token`) for direct API access
2. Yggdrasil-style POST endpoint (`/api/yggdrasil/authserver/authenticate`) for Minecraft client compatibility
