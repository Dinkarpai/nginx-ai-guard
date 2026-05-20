import re
import time
import subprocess
from openai import OpenAI
from collections import defaultdict, deque

from config import (
    LOG_FILE,
    ERROR_LOG,
    DRY_RUN,
    BLOCK_DURATION,
    WHITELIST,
    BAD_PATHS,
    BAD_AGENTS,
)

ip_events = defaultdict(lambda: deque(maxlen=100))
blocked_ips = {}

ai_cache = {}
AI_CACHE_TTL = 600  # 10 minutes

client = OpenAI()


def parse_nginx_line(line):
    pattern = r'(?P<ip>\S+) .* "(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" (?P<status>\d+) .* "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"'

    match = re.match(pattern, line)

    if not match:
        return None

    data = match.groupdict()
    data["status"] = int(data["status"])

    return data


def unblock_ip(ip):

    if DRY_RUN:
        print(f"[DRY RUN] Would unblock {ip}")
        blocked_ips.pop(ip, None)
        return

    subprocess.run(
        ["sudo", "ufw", "delete", "deny", "from", ip],
        check=False
    )

    print(f"[UNBLOCKED] {ip}")

    blocked_ips.pop(ip, None)


def block_ip(ip, reason):

    if ip in WHITELIST:
        print(f"[WHITELISTED] Skipping {ip}")
        return

    current_time = time.time()

    if ip in blocked_ips:

        expiry = blocked_ips[ip]

        if current_time < expiry:
            return
        else:
            unblock_ip(ip)

    expiry_time = current_time + BLOCK_DURATION

    if DRY_RUN:

        print(
            f"[DRY RUN] Would block {ip} "
            f"for {BLOCK_DURATION}s | Reason: {reason}"
        )

        blocked_ips[ip] = expiry_time
        return

    subprocess.run(
        ["sudo", "ufw", "deny", "from", ip],
        check=False
    )

    print(
        f"[BLOCKED] {ip} "
        f"for {BLOCK_DURATION}s | Reason: {reason}"
    )

    blocked_ips[ip] = expiry_time


def cleanup_expired_blocks():

    current_time = time.time()

    expired_ips = [
        ip for ip, expiry in blocked_ips.items()
        if current_time >= expiry
    ]

    for ip in expired_ips:
        unblock_ip(ip)


def is_suspicious(event):

    ip = event["ip"]
    path = event["path"].lower()
    agent = event["agent"].lower()
    status = event["status"]

    score = 0
    reasons = []

    if any(bad in path for bad in BAD_PATHS):
        score += 50
        reasons.append(f"Bad path: {path}")

    if any(bad in agent for bad in BAD_AGENTS):
        score += 40
        reasons.append(f"Bad agent: {agent}")

    ip_events[ip].append({
        "time": time.time(),
        "path": path,
        "status": status,
        "agent": agent,
    })

    recent = [
        e for e in ip_events[ip]
        if time.time() - e["time"] <= 60
    ]

    error_count = sum(
        1 for e in recent
        if e["status"] in [401, 403, 404, 429]
    )

    if len(recent) >= 20:
        score += 30
        reasons.append(
            f"High request rate: {len(recent)} requests/min"
        )

    if error_count >= 5:
        score += 30
        reasons.append(
            f"High error count: {error_count} errors/min"
        )

    if score >= 70:
        return True, " | ".join(reasons)

    if 40 <= score < 70:
        return False, (
            f"Medium risk ({score}) | "
            f"{' | '.join(reasons)}"
        )

    return False, f"Low risk ({score})"


def make_ai_cache_key(event):

    return (
        event["ip"],
        event["method"],
        event["path"],
        event["status"],
        event["agent"],
    )


def ask_openai(event, reason):

    cache_key = make_ai_cache_key(event)
    current_time = time.time()

    if cache_key in ai_cache:

        cached_decision, expiry = ai_cache[cache_key]

        if current_time < expiry:
            print(f"[AI CACHE] Reusing decision: {cached_decision}")
            return cached_decision

    prompt = f"""
Classify this Nginx request.

IP: {event["ip"]}
Method: {event["method"]}
Path: {event["path"]}
Status: {event["status"]}
User-Agent: {event["agent"]}
Rule result: {reason}

Return only one word:
SAFE
SUSPICIOUS
MALICIOUS
"""

    response = client.responses.create(
        model="gpt-5.4-nano",
        input=prompt,
        store=False,
    )

    decision = response.output_text.strip().upper()

    ai_cache[cache_key] = (
        decision,
        time.time() + AI_CACHE_TTL
    )

    return decision


def follow_log(file_path):

    with open(file_path, "r") as file:

        file.seek(0, 2)

        while True:

            line = file.readline()

            cleanup_expired_blocks()

            if not line:
                time.sleep(0.5)
                continue

            event = parse_nginx_line(line.strip())

            if not event:
                continue

            suspicious, reason = is_suspicious(event)

            if suspicious:

                block_ip(event["ip"], reason)

            else:

                if reason.startswith("Medium risk"):

                    ai_decision = ask_openai(event, reason)

                    print(
                        f"[AI REVIEW] "
                        f"{event['ip']} → "
                        f"{ai_decision} | {reason}"
                    )

                    if ai_decision == "MALICIOUS":

                        block_ip(
                            event["ip"],
                            f"AI classified as malicious | {reason}"
                        )

                else:

                    print(
                        f"[OK] "
                        f"{event['ip']} "
                        f"{event['method']} "
                        f"{event['path']} "
                        f"{event['status']} | {reason}"
                    )


if __name__ == "__main__":

    print("Starting Nginx AI Guard MVP...")
    print(f"Watching: {LOG_FILE}")
    print(f"Dry run mode: {DRY_RUN}")

    follow_log(LOG_FILE)