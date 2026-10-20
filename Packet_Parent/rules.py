"""Pure domain classification and rule evaluation; no database or I/O."""
import datetime as dt
import hashlib
from collections import Counter, defaultdict

from sessions import day_bounds, estimate_sessions

CATEGORIES = {
    'Education': ['khanacademy.org', 'wikipedia.org', 'duolingo.com', 'coursera.org', 'edx.org', 'byjus.com', 'classroom.google.com'],
    'Entertainment': ['youtube.com', 'googlevideo.com', 'netflix.com', 'nflxvideo.net', 'spotify.com', 'twitch.tv', 'hotstar.com'],
    'Gaming': ['roblox.com', 'rbxcdn.com', 'steampowered.com', 'steamcontent.com', 'epicgames.com', 'minecraft.net', 'xboxlive.com'],
    'Social': ['instagram.com', 'facebook.com', 'discord.com', 'discord.gg', 'reddit.com', 'snapchat.com', 'tiktok.com', 'whatsapp.com'],
}

def matches(domain, root):
    """Match a domain and its subdomains on label boundaries."""
    return bool(domain and root and (domain == root or domain.endswith('.' + root)))


def category(domain):
    """Classify visible domains using the local category list."""
    for name, roots in CATEGORIES.items():
        if any(matches(domain, root) for root in roots):
            return name
    return 'Unknown'


def window_contains(minute, start, end):
    """Test a local minute against an optional overnight window."""
    a = int(start[:2]) * 60 + int(start[3:])
    b = int(end[:2]) * 60 + int(end[3:])
    if a == b:
        return True
    return a <= minute < b if a < b else minute >= a or minute < b


def active(row, settings):
    """Apply background-domain exclusions to payload activity."""
    return row['active'] and not any(matches(row['domain'], root) for root in settings['ignored_domains'])


def evaluate_rules(rows, rules, settings):
    """Return deterministic alerts for sorted observations without mutating inputs."""
    tz = dt.timezone(dt.timedelta(minutes=settings['utc_offset']))
    output, times = {}, defaultdict(list)
    for row in rows:
        local = dt.datetime.fromtimestamp(row['timestamp'], tz)
        day, minute = local.date().isoformat(), local.hour * 60 + local.minute
        if active(row, settings):
            times[(row['source'], row['device_ip'])].extend([row.get('first_ts', row['timestamp']), row.get('last_ts', row['timestamp'])])
        for rule in rules:
            if rule['kind'] == 'budget' or (rule['device_ip'] and rule['device_ip'] != row['device_ip']):
                continue
            if rule['kind'] == 'hours':
                hit = active(row, settings) and not window_contains(minute, rule['start'], rule['end'])
                reason = f"Observed internet traffic outside {rule['start']}–{rule['end']}."
            else:
                hit = matches(row['domain'], rule['target']) if rule['kind'] == 'domain' else row['category'] == rule['target']
                if rule['start']:
                    hit = hit and window_contains(minute, rule['start'], rule['end'])
                reason = f"Observed {row['domain']} matched the {rule['kind']} rule: {rule['target']}."
            if not hit:
                continue
            key = hashlib.sha256(f"{row['source']}|{rule['id']}|{row['device_ip']}|{day}|{row['domain'] or row['remote_ip']}".encode()).hexdigest()[:24]
            if key in output:
                output[key]['count'] += row.get('packets', 1)
                output[key]['last_seen'] = max(output[key]['last_seen'], row.get('last_ts', row['timestamp']))
            else:
                output[key] = dict(id=key, rule_id=rule['id'], device_ip=row['device_ip'], day=day,
                    timestamp=row.get('first_ts', row['timestamp']), last_seen=row.get('last_ts', row['timestamp']), domain=row['domain'] or row['remote_ip'],
                    title=rule['name'], reason=reason, evidence=row['evidence'], count=row.get('packets', 1), source=row['source'])
    for (source, ip), timestamps in times.items():
        totals, lasts = Counter(), {}
        for start, end in estimate_sessions(timestamps, settings['idle_seconds']):
            cursor = start
            while cursor < end:
                day = dt.datetime.fromtimestamp(cursor, tz).date().isoformat()
                _, boundary = day_bounds(day, settings['utc_offset'])
                stop = min(end, boundary)
                totals[day] += stop - cursor
                lasts[day] = stop
                cursor = stop
        for rule in rules:
            if rule['kind'] != 'budget' or (rule['device_ip'] and rule['device_ip'] != ip):
                continue
            for day, seconds in totals.items():
                if seconds <= rule['minutes'] * 60:
                    continue
                key = hashlib.sha256(f"{source}|{rule['id']}|{ip}|{day}|budget".encode()).hexdigest()[:24]
                output[key] = dict(id=key, rule_id=rule['id'], device_ip=ip, day=day, timestamp=lasts[day], last_seen=lasts[day], domain='',
                    title=rule['name'], reason=f"Estimated internet-active time is {seconds / 60:.1f} minutes; daily limit is {rule['minutes']} minutes.",
                    evidence='Payload activity sessions; background exclusions applied', count=1, source=source)
    return list(output.values())
