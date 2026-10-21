"""Versioned, local domain catalog. Add explicit suffixes and bump the version."""
from domain_names import matches

CATALOG_VERSION = 1

# Keep category names CSS-safe. Unknown remains the compatibility category;
# the service view presents unmatched identified destinations as Other websites.
CATEGORY_DOMAINS = {
    'Education': ('khanacademy.org', 'wikipedia.org', 'duolingo.com', 'coursera.org',
                  'edx.org', 'byjus.com', 'classroom.google.com'),
    'Entertainment': ('youtube.com', 'googlevideo.com', 'netflix.com', 'nflxvideo.net',
                      'spotify.com', 'twitch.tv', 'hotstar.com'),
    'Gaming': ('roblox.com', 'rbxcdn.com', 'steampowered.com', 'steamcontent.com',
               'epicgames.com', 'minecraft.net', 'xboxlive.com'),
    'Social': ('instagram.com', 'facebook.com', 'discord.com', 'discord.gg',
               'reddit.com', 'snapchat.com', 'tiktok.com', 'whatsapp.com'),
    'Productivity': (),
    'AI': (),
}

SERVICES = (
    {'service': 'YouTube', 'category': 'Entertainment',
     'suffixes': ('youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com', 'ggpht.com')},
    {'service': 'Microsoft Teams & Office', 'category': 'Productivity',
     'suffixes': ('teams.microsoft.com', 'teams.cloud.microsoft', 'office.com', 'office.net',
                  'officeapps.live.com', 'onecdn.static.microsoft', 'sharepoint.com',
                  'graph.microsoft.com', 'login.live.com', 'login.microsoftonline.com', 'live.com')},
    {'service': 'ChatGPT', 'category': 'AI', 'suffixes': ('chatgpt.com', 'openai.com')},
    # Do not label Docs, Drive, Classroom or every google.com subdomain as Search.
    {'service': 'Google Search', 'category': 'Productivity',
     'exact': ('google.com', 'www.google.com')},
)

NOISE = {
    'ads': ('doubleclick.net', 'googleadservices.com', 'googlesyndication.com',
            'ogads-pa.clients6.google.com'),
    'telemetry': ('events.data.microsoft.com', 'monitor.azure.com', 'vortex.data.microsoft.com'),
    'system': ('windowsupdate.com', 'update.microsoft.com', 'time.windows.com',
               'pool.ntp.org', 'time.google.com', 'time.cloudflare.com', 'time.apple.com',
               'msftconnecttest.com', 'msftncsi.com', 'captive.apple.com',
               'connectivitycheck.gstatic.com', 'connectivitycheck.android.com',
               'detectportal.firefox.com'),
}


def classify(domain):
    """Return service, category and positive noise classification for a hostname."""
    domain = (domain or '').strip().lower().rstrip('.')
    result = {'service': None, 'category': 'Unknown', 'noise': None}
    for name, suffixes in CATEGORY_DOMAINS.items():
        if any(matches(domain, suffix) for suffix in suffixes):
            result['category'] = name
            break
    for entry in SERVICES:
        if domain in entry.get('exact', ()) or any(matches(domain, suffix) for suffix in entry.get('suffixes', ())):
            result['service'] = entry['service']
            result['category'] = entry['category']
            break
    for kind, suffixes in NOISE.items():
        if any(matches(domain, suffix) for suffix in suffixes):
            result['noise'] = kind
            break
    return result
