LOG_FILE = "/opt/homebrew/var/log/nginx/access.log"
ERROR_LOG = "/opt/homebrew/var/log/nginx/error.log"

DRY_RUN = True
BLOCK_DURATION = 900

WHITELIST = {
    "127.0.0.1",
    "::1",
}

BAD_PATHS = [
    "/.env",
    "/wp-admin",
    "/phpmyadmin",
    "/admin",
    "/config.php",
    "/.git",
]

BAD_AGENTS = [
    "python-requests",
    "sqlmap",
    "nikto",
    "masscan",
    "nmap",
]