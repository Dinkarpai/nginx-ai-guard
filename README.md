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

## Requirements

- Python 3
- Nginx
- OpenAI API key
- UFW (optional)

## Install

```bash
pip3 install -r requirements.txt
```

## Configure

Edit:

```python
config.py
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

## WARNING

Do not disable DRY_RUN on production until fully tested.
