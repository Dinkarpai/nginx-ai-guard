# Nginx AI Guard

AI-assisted Nginx intrusion prevention daemon.

## Features

- Real-time Nginx log monitoring
- Threat scoring engine
- OpenAI-assisted classification
- Temporary IP blocking
- AI decision cache
- Whitelist support
- Dry-run testing mode
- Local Nginx testing support
- Environment variable support using `python-dotenv`

## Requirements

- Python 3
- Nginx
- OpenAI API key
- UFW (optional)

## Install

```bash
pip3 install -r requirements.txt
```

## Environment Setup

Create a `.env` file from the example:

```bash
cp .env.example .env
```

Add your OpenAI API key:

```env
OPENAI_API_KEY=your_openai_api_key_here
```

The project automatically loads environment variables using `python-dotenv`.

Do not commit `.env`.

## Configure

Edit:

```python
config.py
```

Example macOS Homebrew Nginx log paths:

```python
LOG_FILE = "/opt/homebrew/var/log/nginx/access.log"
ERROR_LOG = "/opt/homebrew/var/log/nginx/error.log"
```

Example Linux Nginx log paths:

```python
LOG_FILE = "/var/log/nginx/access.log"
ERROR_LOG = "/var/log/nginx/error.log"
```

Important:

```python
DRY_RUN = True
```

during testing.

## Run

```bash
python3 guard.py
```

## Example Detection Flow

- Low risk → allow
- Medium risk → OpenAI review
- High risk → temporary block

## Detection Examples

The daemon currently detects suspicious requests such as:

- `/.env`
- `/wp-admin`
- `/phpmyadmin`
- `/.git`
- suspicious scanners/bots
- excessive request bursts
- repeated error responses

## AI Classification

Medium-risk traffic is reviewed using OpenAI.

The system:
- minimizes API usage
- uses AI decision caching
- avoids repeated requests for identical traffic patterns

## Firewall Blocking

Blocking is handled using UFW:

```bash
sudo ufw deny from <ip>
```

In `DRY_RUN = True`, no real firewall rules are applied.

## Local Testing

Example local tests:

```bash
curl http://localhost:8080/
curl http://localhost:8080/.env
curl http://localhost:8080/wp-admin
curl http://localhost:8080/.git/config
```

## Current Status

Current version is an MVP / prototype focused on:
- AI-assisted log analysis
- adaptive threat scoring
- automated firewall orchestration
- real-time Nginx monitoring

## WARNING

Do not disable `DRY_RUN` on production until fully tested.