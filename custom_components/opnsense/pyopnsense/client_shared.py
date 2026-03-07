"""Shared imports/constants for pyopnsense client method modules."""

"""pyopnsense to manage OPNsense from HA."""
from abc import ABC
import asyncio
from collections.abc import Callable, MutableMapping
from datetime import datetime, timedelta, timezone
from functools import partial
import inspect
import ipaddress
import json
import logging
import re
import socket
import ssl
import traceback
from typing import Any
from urllib.parse import quote, quote_plus, urlparse
import xmlrpc.client
import aiohttp
import awesomeversion
from dateutil.parser import ParserError, UnknownTimezoneWarning, parse
from .const import AMBIGUOUS_TZINFOS
from .helpers import (
    DEFAULT_TIMEOUT,
    dict_get,
    get_ip_key,
    human_friendly_duration,
    log_errors as _log_errors,
    timestamp_to_datetime,
    try_to_float,
    try_to_int,
    wireguard_is_connected,
    xmlrpc_timeout as _xmlrpc_timeout,
)
_LOGGER: logging.Logger = logging.getLogger(__name__)
FIRMWARE_CHECK_INTERVAL = timedelta(hours=12)
FIRMWARE_INFO_PATH = "/api/core/firmware/info"
FIRMWARE_STATUS_PATH = "/api/core/firmware/status"
class VoucherServerError(Exception):
    """Error from Voucher Server."""

__all__ = [name for name in globals() if not name.startswith("__")]
