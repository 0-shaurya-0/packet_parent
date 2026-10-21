"""Domain label-boundary matching shared by the catalog and rules."""


def matches(domain, root):
    """Match a domain or subdomain, never an unrelated suffix lookalike."""
    return bool(domain and root and (domain == root or domain.endswith('.' + root)))
