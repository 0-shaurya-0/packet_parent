"""Pure session estimation and fixed-offset local-day boundaries."""
import datetime as dt


def estimate_sessions(timestamps, idle=120):
    """Group activity without appending an idle tail."""
    times = sorted(set(timestamps))
    if not times:
        return []
    sessions, start, last = [], times[0], times[0]
    for value in times[1:]:
        if value - last > idle:
            sessions.append((start, last))
            start = value
        last = value
    sessions.append((start, last))
    return sessions


def day_bounds(day, offset):
    """Return the UTC timestamps bounding a fixed-offset local day."""
    tz = dt.timezone(dt.timedelta(minutes=offset))
    start = dt.datetime.combine(dt.date.fromisoformat(day), dt.time(), tz).timestamp()
    return start, start + 86400


