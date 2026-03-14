"""Constants for pyopnsense."""

from typing import Any

from dateutil.tz import gettz

# Default timeout, in seconds, for HTTP/XMLRPC requests.
DEFAULT_REQUEST_TIMEOUT_SECONDS = 60
# Shared cache time-to-live, in seconds, for plugin and endpoint availability state.
DEFAULT_CACHE_TTL_SECONDS = 6 * 60 * 60

# Mapping of ambiguous timezone abbreviations to explicit IANA timezones.
AMBIGUOUS_TZINFOS: dict[str, Any] = {
    "ACST": gettz("Australia/Darwin"),  # Australian Central Standard Time
    "ACT": gettz("America/Rio_Branco"),  # Acre Time (Brazil)
    "AEST": gettz("Australia/Sydney"),  # Australian Eastern Standard Time
    "AST": gettz("America/Halifax"),  # Atlantic Standard Time (Caribbean/Canada)
    "AWST": gettz("Australia/Perth"),  # Australian Western Standard Time
    "BST": gettz("Europe/London"),  # British Summer Time
    "CET": gettz("Europe/Paris"),  # Central European Time
    "CST": gettz("America/Chicago"),  # Central Standard Time (North America)
    "EET": gettz("Europe/Bucharest"),  # Eastern European Time
    "EST": gettz("America/New_York"),  # Eastern Standard Time (North America)
    "HST": gettz("Pacific/Honolulu"),  # Hawaii-Aleutian Standard Time
    "IST": gettz("Asia/Kolkata"),  # Indian Standard Time
    "MST": gettz("America/Denver"),  # Mountain Standard Time (North America)
    "NZST": gettz("Pacific/Auckland"),  # New Zealand Standard Time
    "PST": gettz("America/Los_Angeles"),  # Pacific Standard Time (North America)
}
