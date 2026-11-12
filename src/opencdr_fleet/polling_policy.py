"""Cadence for health/configuration observation; detection delivery is separate."""

import math
import os

from .models import FleetError


def intervals():
    try:
        poll = int(os.getenv("POLL_INTERVAL_MINUTES", "1"))
        refresh = int(os.getenv("FULL_REFRESH_MINUTES", "60"))
        retention = int(os.getenv("SNAPSHOT_RETENTION_HOURS", "24"))
        if not 1 <= poll <= 60 or not poll <= refresh <= 1440 or not 2 <= retention <= 168:
            raise ValueError
    except ValueError:
        raise FleetError("invalid_polling_configuration", 503) from None
    return poll * 60, refresh * 60, retention * 3600


def stale_after_seconds():
    return max(180, intervals()[0] * 3, int(os.getenv("STALE_AFTER_SECONDS", "180")))


def monthly_requests(full_count, *, generation_supported):
    poll, refresh, retention = intervals()
    month = 31 * 86400
    if not generation_supported:
        return math.ceil(month / poll) * full_count
    # Refresh at the first poll after the configured age, or before cache expiry.
    effective = min(refresh, retention - 3600)
    full_cadence = math.ceil(effective / poll) * poll
    return math.ceil(month / poll) + max(0, full_count - 1) * math.ceil(month / full_cadence)
