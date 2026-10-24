"""CVE feed: vulnerability data for the software you run, matched against its versions.

    catalog   which products exist and where their vulnerabilities are published
    sources   fetchers for GitHub advisories, OSV, NVD, CISA KEV and EPSS
    matching  "is version X affected by this vulnerability?" (pure version logic)
    feed      sync, subjects (scanned instances and watchlist entries), alerts

Everything is deterministic: a vulnerability affects a subject when the
subject's version falls into a published affected range.
"""
