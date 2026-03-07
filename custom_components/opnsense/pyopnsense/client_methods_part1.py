"""Method definitions for OPNsenseClient (part 1)."""

from .client_shared import *

def __init__(
    self,
    url: str,
    username: str,
    password: str,
    session: aiohttp.ClientSession,
    opts: MutableMapping[str, Any] | None = None,
    initial: bool = False,
    name: str = "OPNsense",
) -> None:
    """Initialize the OPNsense client.

    Parameters
    ----------
    url : str
        Base URL of the OPNsense instance.
    username : str
        API username used for authentication.
    password : str
        API password used for authentication.
    session : aiohttp.ClientSession
        Shared aiohttp client session used for HTTP requests.
    opts : MutableMapping[str, Any] | None
        Optional connection options (for example verify_ssl). Defaults to None.
    initial : bool
        Whether the call runs during initial setup/validation. Defaults to False.
    name : str
        Human-friendly name used in logs and identifiers. Defaults to 'OPNsense'.

    """

    self._username: str = username
    self._password: str = password
    self._name: str = name

    self._opts: MutableMapping[str, Any] = opts or {}
    self._verify_ssl: bool = self._opts.get("verify_ssl", True)
    parts = urlparse(url.rstrip("/"))
    self._url: str = f"{parts.scheme}://{parts.netloc}"
    self._xmlrpc_url: str = (
        f"{parts.scheme}://{quote_plus(username)}:{quote_plus(password)}@{parts.netloc}"
    )
    self._scheme: str = parts.scheme
    self._session: aiohttp.ClientSession = session
    self._initial = initial
    self._firmware_version: str | None = None
    self._use_snake_case: bool = True
    self._xmlrpc_query_count = 0
    self._rest_api_query_count = 0
    self._request_queue: asyncio.Queue = asyncio.Queue()
    self._queue_monitor = asyncio.create_task(self._monitor_queue())
    self._workers = []
    self._max_workers = 2  # Number of parallel workers to process the queue

    for _ in range(self._max_workers):
        self._workers.append(asyncio.create_task(self._process_queue()))

    try:
        self._loop = asyncio.get_running_loop()
    except RuntimeError:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

@property
def name(self) -> str:
    """Return the name of the client.

    Returns
    -------
    str
    Configured client display name.


    """
    return self._name

async def reset_query_counts(self) -> None:
    """Reset REST and XMLRPC query counters to zero."""
    self._xmlrpc_query_count = 0
    self._rest_api_query_count = 0

async def get_query_counts(self) -> tuple:
    """Return current REST and XMLRPC query counts.

    Returns
    -------
    tuple
    Two-item tuple containing REST query count and XMLRPC query count.


    """
    return self._rest_api_query_count, self._xmlrpc_query_count

def _get_proxy(self) -> xmlrpc.client.ServerProxy:
    """Create an XMLRPC server proxy for the configured OPNsense host.

    Returns
    -------
    xmlrpc.client.ServerProxy
    XMLRPC ServerProxy configured for this client instance.


    """
    # https://docs.python.org/3/library/xmlrpc.client.html#module-xmlrpc.client
    # https://stackoverflow.com/questions/30461969/disable-default-certificate-verification-in-python-2-7-9
    context = None

    if self._scheme == "https" and not self._verify_ssl:
        context = ssl._create_unverified_context()  # noqa: SLF001

    # set to True if necessary during development
    verbose = False

    return xmlrpc.client.ServerProxy(
        f"{self._xmlrpc_url}/xmlrpc.php", context=context, verbose=verbose
    )

@_xmlrpc_timeout
async def _restore_config_section(
    self, section_name: str, data: MutableMapping[str, Any]
) -> None:
    """Restore a specific configuration section via XMLRPC.

    Parameters
    ----------
    section_name : str
        Configuration section name to restore.
    data : MutableMapping[str, Any]
        Input mapping used to build the request payload.

    """
    params = {section_name: data}
    proxy_method = partial(self._get_proxy().opnsense.restore_config_section, params)
    await self._loop.run_in_executor(None, proxy_method)

@_xmlrpc_timeout
async def _exec_php(self, script: str) -> MutableMapping[str, Any]:
    """Execute a PHP snippet through XMLRPC and decode the JSON payload.

    Parameters
    ----------
    script : str
        PHP script source executed through XMLRPC.

    Returns
    -------
    MutableMapping[str, Any]
    JSON-decoded response mapping returned by the PHP helper, or an empty mapping on failure.


    """
    self._xmlrpc_query_count += 1
    script = rf"""
ini_set('display_errors', 0);

{script}

// wrapping this in json_encode and then unwrapping in python prevents funny XMLRPC NULL encoding errors
// https://github.com/travisghansen/hass-pfsense/issues/35
$toreturn_real = $toreturn;
$toreturn = [];
$toreturn["real"] = json_encode($toreturn_real);
"""
    try:
        response = await self._loop.run_in_executor(
            None, self._get_proxy().opnsense.exec_php, script
        )
        if not isinstance(response, MutableMapping):
            return {}
        if response.get("real"):
            return json.loads(response.get("real", ""))
    except TypeError as e:
        stack = inspect.stack()
        calling_function = stack[1].function.strip("_") if len(stack) > 1 else "Unknown"
        _LOGGER.error(
            "Invalid data returned from exec_php for %s. %s: %s. Called from %s",
            calling_function,
            type(e).__name__,
            e,
            calling_function,
        )
    except xmlrpc.client.Fault as e:
        stack = inspect.stack()
        calling_function = stack[1].function.strip("_") if len(stack) > 1 else "Unknown"
        _LOGGER.error(
            "Error running exec_php script for %s. %s: %s. Ensure the 'os-homeassistant-maxit' plugin has been installed on OPNsense",
            calling_function,
            type(e).__name__,
            e,
        )
    except socket.gaierror as e:
        stack = inspect.stack()
        calling_function = stack[1].function.strip("_") if len(stack) > 1 else "Unknown"
        _LOGGER.warning(
            "Connection Error running exec_php script for %s. %s: %s. Will retry",
            calling_function,
            type(e).__name__,
            e,
        )
    except ssl.SSLError as e:
        stack = inspect.stack()
        calling_function = stack[1].function.strip("_") if len(stack) > 1 else "Unknown"
        _LOGGER.warning(
            "SSL Connection Error running exec_php script for %s. %s: %s. Will retry",
            calling_function,
            type(e).__name__,
            e,
        )
    return {}

@_log_errors
async def get_host_firmware_version(self) -> None | str:
    """Return the OPNsense Firmware version.

    Returns
    -------
    None | str
    Normalized get host firmware version data returned by OPNsense APIs.


    """
    firmware: str | None = None
    for path in (FIRMWARE_INFO_PATH, FIRMWARE_STATUS_PATH):
        candidate = await self._extract_firmware_version_from_path(path)
        if candidate:
            firmware = candidate
            break
    self._firmware_version = firmware
    return firmware

async def _extract_firmware_version_from_path(self, path: str) -> str | None:
    """Fetch and normalize firmware version information from a firmware endpoint.

    Parameters
    ----------
    path : str
        API endpoint path to call on the OPNsense host.

    Returns
    -------
    str | None
    Result produced by this method.


    """
    data = await self._safe_dict_get(path)
    firmware = dict_get(data, "product.product_version")
    if firmware and awesomeversion.AwesomeVersion(firmware).valid:
        _LOGGER.debug("[get_host_firmware_version] firmware: %s", firmware)
        return firmware

    series = dict_get(data, "product.product_series")
    candidate = series or firmware
    if candidate and firmware and firmware != candidate:
        _LOGGER.debug(
            "[get_host_firmware_version] firmware: %s not valid SemVer, using %s",
            firmware,
            candidate,
        )
    return candidate

async def set_use_snake_case(self, initial: bool = False) -> None:
    """Set whether to use snake_case or camelCase for API calls.

    Parameters
    ----------
    initial : bool
        Whether the call runs during initial setup/validation. Defaults to False.

    """
    if self._firmware_version is None:
        await self.get_host_firmware_version()

    self._use_snake_case = True
    try:
        if awesomeversion.AwesomeVersion(
            self._firmware_version
        ) < awesomeversion.AwesomeVersion("25.7"):
            _LOGGER.debug("Using camelCase for OPNsense < 25.7")
            self._use_snake_case = False
        else:
            _LOGGER.debug("Using snake_case for OPNsense >= 25.7")
    except (
        awesomeversion.exceptions.AwesomeVersionCompareException,
        TypeError,
        ValueError,
    ) as e:
        _LOGGER.error(
            "Error comparing firmware version %s. Using snake_case by default",
            self._firmware_version,
        )
        if initial:
            raise UnknownFirmware from e

async def is_plugin_installed(self) -> bool:
    """Retun whether OPNsense plugin is installed or not.

    Returns
    -------
    bool
    Result produced by this method.


    """
    firmware_info = await self._safe_dict_get("/api/core/firmware/info")
    if not isinstance(firmware_info.get("package"), list):
        return False
    for pkg in firmware_info.get("package", []):
        if pkg.get("name") == "os-homeassistant-maxit" and pkg.get("installed") == "1":
            return True
    return False

async def _get_from_stream(self, path: str) -> MutableMapping[str, Any]:
    """Queue a streaming GET request and return the parsed payload.

    Parameters
    ----------
    path : str
        API endpoint path to call on the OPNsense host.

    Returns
    -------
    MutableMapping[str, Any]
    Queued streaming-response payload parsed into a mapping.


    """
    try:
        caller = inspect.stack()[1].function
    except (IndexError, AttributeError):
        caller = "Unknown"
    future = self._loop.create_future()
    await self._request_queue.put(("get_from_stream", path, None, future, caller))
    return await future

async def _get(self, path: str) -> MutableMapping[str, Any] | list | None:
    """Queue a GET request and return the result.

    Parameters
    ----------
    path : str
        API endpoint path to call on the OPNsense host.

    Returns
    -------
    MutableMapping[str, Any] | list | None
    Decoded JSON payload from a queued GET request, or None when request/parse fails.


    """
    try:
        caller = inspect.stack()[1].function
    except (IndexError, AttributeError):
        caller = "Unknown"
    future = self._loop.create_future()
    await self._request_queue.put(("get", path, None, future, caller))
    return await future

async def _post(
    self, path: str, payload: MutableMapping[str, Any] | None = None
) -> MutableMapping[str, Any] | list | None:
    """Queue a POST request and return the result.

    Parameters
    ----------
    path : str
        API endpoint path to call on the OPNsense host.
    payload : MutableMapping[str, Any] | None
        JSON payload body sent with the API request. Defaults to None.

    Returns
    -------
    MutableMapping[str, Any] | list | None
    Decoded JSON payload from a queued POST request, or None when request/parse fails.


    """
    try:
        caller = inspect.stack()[1].function
    except (IndexError, AttributeError):
        caller = "Unknown"
    future = self._loop.create_future()
    await self._request_queue.put(("post", path, payload, future, caller))
    return await future

async def _process_queue(self) -> None:
    """Continuously process queued API requests and resolve waiting futures."""
    while True:
        method, path, payload, future, caller = await self._request_queue.get()
        try:
            if method == "get_from_stream":
                result: Any = await self._do_get_from_stream(path, caller)
                if future is not None and not future.done():
                    future.set_result(result)
            elif method == "get":
                result = await self._do_get(path, caller)
                if future is not None and not future.done():
                    future.set_result(result)
            elif method == "post":
                result = await self._do_post(path, payload, caller)
                if future is not None and not future.done():
                    future.set_result(result)
            else:
                _LOGGER.error("Unknown method to add to Queue: %s", method)
                if future is not None and not future.done():
                    future.set_exception(
                        RuntimeError(f"Unknown method to add to Queue: {method}")
                    )
        except Exception as e:  # noqa: BLE001
            _LOGGER.error(
                "Exception in request queue processor (called by %s). %s: %s",
                caller,
                type(e).__name__,
                e,
            )
            if future is not None and not future.done():
                future.set_exception(e)
        await asyncio.sleep(0.3)

async def _monitor_queue(self) -> None:
    """Periodically log request queue backlog size for diagnostics."""
    while True:
        try:
            queue_size = self._request_queue.qsize()
            if queue_size > 0:
                _LOGGER.debug("OPNsense API queue backlog: %d tasks", queue_size)
        except Exception as e:  # noqa: BLE001
            _LOGGER.error("Error monitoring queue size. %s: %s", type(e).__name__, e)
        await asyncio.sleep(10)

async def _do_get_from_stream(
    self, path: str, caller: str = "Unknown"
) -> MutableMapping[str, Any]:
    """Execute a streaming GET request immediately.

    Parameters
    ----------
    path : str
        API endpoint path to call on the OPNsense host.
    caller : str
        Name of the calling method used for log context. Defaults to 'Unknown'.

    Returns
    -------
    MutableMapping[str, Any]
    Result produced by this method.


    """
    self._rest_api_query_count += 1
    url: str = f"{self._url}{path}"
    _LOGGER.debug("[get_from_stream] url: %s", url)
    try:
        async with self._session.get(
            url,
            auth=aiohttp.BasicAuth(self._username, self._password),
            timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
            ssl=self._verify_ssl,
        ) as response:
            _LOGGER.debug(
                "[get_from_stream] Response %s: %s",
                response.status,
                response.reason,
            )

            if response.ok:
                buffer = ""
                message_count = 0

                async for chunk in response.content.iter_chunked(1024):
                    buffer += chunk.decode("utf-8")
                    # _LOGGER.debug("[get_from_stream] buffer: %s", buffer)

                    if "\n\n" in buffer:
                        message, buffer = buffer.split("\n\n", 1)
                        lines = message.splitlines()
                        for line in lines:
                            if line.startswith("data:"):
                                message_count += 1
                                if message_count == 2:
                                    response_str: str = line[len("data:") :].strip()
                                    response_json = json.loads(response_str)
                                    _LOGGER.debug(
                                        "[get_from_stream] response_json (%s): %s",
                                        type(response_json).__name__,
                                        response_json,
                                    )
                                    return (
                                        response_json
                                        if isinstance(response_json, MutableMapping)
                                        else {}
                                    )  # Exit after processing the second message
                                _LOGGER.debug(
                                    "[get_from_stream] Ignored message %s: %s",
                                    message_count,
                                    line,
                                )
                            else:
                                _LOGGER.debug("[get_from_stream] Unparsed: %s", line)
            else:
                if response.status == 403:
                    _LOGGER.error(
                        "Permission Error in do_get_from_stream (called by %s). Path: %s. Ensure the OPNsense user connected to HA has appropriate access. Recommend full admin access",
                        caller,
                        url,
                    )
                else:
                    _LOGGER.error(
                        "Error in do_get_from_stream (called by %s). Path: %s. Response %s: %s",
                        caller,
                        url,
                        response.status,
                        response.reason,
                    )
                if self._initial:
                    raise aiohttp.ClientResponseError(
                        request_info=response.request_info,
                        history=response.history,
                        status=response.status,
                        message=f"HTTP Status Error: {response.status} {response.reason}",
                        headers=response.headers,
                    )
    except aiohttp.ClientError as e:
        _LOGGER.error("Client error. %s: %s", type(e).__name__, e)
        if self._initial:
            raise

    return {}

async def _do_get(
    self, path: str, caller: str = "Unknown"
) -> MutableMapping[str, Any] | list | None:
    """Execute a GET request immediately without queueing.

    Parameters
    ----------
    path : str
        API endpoint path to call on the OPNsense host.
    caller : str
        Name of the calling method used for log context. Defaults to 'Unknown'.

    Returns
    -------
    MutableMapping[str, Any] | list | None
    Decoded JSON payload from an immediate GET request, or None when request/parse fails.


    """
    # /api/<module>/<controller>/<command>/[<param1>/[<param2>/...]]
    self._rest_api_query_count += 1
    url: str = f"{self._url}{path}"
    _LOGGER.debug("[get] url: %s", url)
    try:
        async with self._session.get(
            url,
            auth=aiohttp.BasicAuth(self._username, self._password),
            timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
            ssl=self._verify_ssl,
        ) as response:
            _LOGGER.debug("[get] Response %s: %s", response.status, response.reason)
            if response.ok:
                return await response.json(content_type=None)
            if response.status == 403:
                _LOGGER.error(
                    "Permission Error in do_get (called by %s). Path: %s. Ensure the OPNsense user connected to HA has appropriate access. Recommend full admin access",
                    caller,
                    url,
                )
            else:
                _LOGGER.error(
                    "Error in do_get (called by %s). Path: %s. Response %s: %s",
                    caller,
                    url,
                    response.status,
                    response.reason,
                )
            if self._initial:
                raise aiohttp.ClientResponseError(
                    request_info=response.request_info,
                    history=response.history,
                    status=response.status,
                    message=f"HTTP Status Error: {response.status} {response.reason}",
                    headers=response.headers,
                )
    except aiohttp.ClientError as e:
        _LOGGER.error("Client error. %s: %s", type(e).__name__, e)
        if self._initial:
            raise

    return None

async def _safe_dict_get(self, path: str) -> MutableMapping[str, Any]:
    """Fetch data from the given path, ensuring the result is a dict.

    Parameters
    ----------
    path : str
        API endpoint path to call on the OPNsense host.

    Returns
    -------
    MutableMapping[str, Any]
    Dictionary payload from the GET request, or an empty mapping if the response is not a dictionary.


    """
    result = await self._get(path=path)
    return result if isinstance(result, MutableMapping) else {}

async def _safe_list_get(self, path: str) -> list:
    """Fetch data from the given path, ensuring the result is a list.

    Parameters
    ----------
    path : str
        API endpoint path to call on the OPNsense host.

    Returns
    -------
    list
    List payload from the GET request, or an empty list if the response is not a list.


    """
    result = await self._get(path=path)
    return result if isinstance(result, list) else []

async def _do_post(
    self, path: str, payload: MutableMapping[str, Any] | None = None, caller: str = "Unknown"
) -> MutableMapping[str, Any] | list | None:
    """Execute a POST request immediately without queueing.

    Parameters
    ----------
    path : str
        API endpoint path to call on the OPNsense host.
    payload : MutableMapping[str, Any] | None
        JSON payload body sent with the API request. Defaults to None.
    caller : str
        Name of the calling method used for log context. Defaults to 'Unknown'.

    Returns
    -------
    MutableMapping[str, Any] | list | None
    Decoded JSON payload from an immediate POST request, or None when request/parse fails.


    """
    self._rest_api_query_count += 1
    url: str = f"{self._url}{path}"
    _LOGGER.debug("[post] url: %s", url)
    _LOGGER.debug("[post] payload: %s", payload)
    try:
        async with self._session.post(
            url,
            json=payload,
            auth=aiohttp.BasicAuth(self._username, self._password),
            timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
            ssl=self._verify_ssl,
        ) as response:
            _LOGGER.debug("[post] Response %s: %s", response.status, response.reason)
            if response.ok:
                response_json: MutableMapping[str, Any] | list = await response.json(
                    content_type=None
                )
                return response_json
            if response.status == 403:
                _LOGGER.error(
                    "Permission Error in do_post (called by %s). Path: %s. Ensure the OPNsense user connected to HA has appropriate access. Recommend full admin access",
                    caller,
                    url,
                )
            else:
                _LOGGER.error(
                    "Error in do_post (called by %s). Path: %s. Response %s: %s",
                    caller,
                    url,
                    response.status,
                    response.reason,
                )
            if self._initial:
                raise aiohttp.ClientResponseError(
                    request_info=response.request_info,
                    history=response.history,
                    status=response.status,
                    message=f"HTTP Status Error: {response.status} {response.reason}",
                    headers=response.headers,
                )
    except aiohttp.ClientError as e:
        _LOGGER.error("Client error. %s: %s", type(e).__name__, e)
        if self._initial:
            raise

    return None

async def _safe_dict_post(
    self, path: str, payload: MutableMapping[str, Any] | None = None
) -> MutableMapping[str, Any]:
    """Fetch data from the given path, ensuring the result is a dict.

    Parameters
    ----------
    path : str
        API endpoint path to call on the OPNsense host.
    payload : MutableMapping[str, Any] | None
        JSON payload body sent with the API request. Defaults to None.

    Returns
    -------
    MutableMapping[str, Any]
    Dictionary payload from the POST request, or an empty mapping if the response is not a dictionary.


    """
    result = await self._post(path=path, payload=payload)
    return result if isinstance(result, MutableMapping) else {}

__all__ = [
    "__init__",
    "name",
    "reset_query_counts",
    "get_query_counts",
    "_get_proxy",
    "_restore_config_section",
    "_exec_php",
    "get_host_firmware_version",
    "_extract_firmware_version_from_path",
    "set_use_snake_case",
    "is_plugin_installed",
    "_get_from_stream",
    "_get",
    "_post",
    "_process_queue",
    "_monitor_queue",
    "_do_get_from_stream",
    "_do_get",
    "_safe_dict_get",
    "_safe_list_get",
    "_do_post",
    "_safe_dict_post",
]
