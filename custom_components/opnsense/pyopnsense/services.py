"""Service management methods for OPNsenseClient."""

from collections.abc import MutableMapping
from urllib.parse import quote

from ._typing import PyOPNsenseClientProtocol
from .helpers import _LOGGER, _log_errors


class ServicesMixin(PyOPNsenseClientProtocol):
    """Service management methods for OPNsenseClient."""

    @_log_errors
    async def get_services(self) -> list:
        """Get the list of OPNsense services.

        Returns
        -------
        list
            Parsed services payload returned by OPNsense APIs.

        """
        response = await self._safe_dict_get("/api/core/service/search")
        services: list = response.get("rows") or []
        if not isinstance(services, list):
            services = []
        normalized_services: list = []
        for service in services:
            if not isinstance(service, MutableMapping):
                continue
            running = service.get("running", 0)
            try:
                is_running = int(running) == 1
            except (TypeError, ValueError):
                is_running = str(running) == "1"
            service["status"] = is_running
            normalized_services.append(service)
        return normalized_services

    @_log_errors
    async def get_service_is_running(self, service: str) -> bool:
        """Return if the OPNsense service is running.

        Parameters
        ----------
        service : str
            Service name or identifier recognized by OPNsense.

        Returns
        -------
        bool
            ``True`` when the named service is reported as running.

        """
        services: list = await self.get_services()
        if services is None or not isinstance(services, list):
            return False
        for svc in services:
            if (svc.get("name", None) == service or svc.get("id", None) == service) and svc.get(
                "status", False
            ):
                return True
        return False

    async def _manage_service(self, action: str, service: str) -> bool:
        """Run a service control action for a named service.

        Parameters
        ----------
        action : str
            Service action to perform (start, stop, restart, etc.).
        service : str
            Service name or identifier recognized by OPNsense.

        Returns
        -------
        bool
            ``True`` when the service action reports success.

        """
        if not service:
            return False
        encoded_service = quote(service, safe="")
        api_addr: str = f"/api/core/service/{action}/{encoded_service}"
        response = await self._safe_dict_post(api_addr)
        _LOGGER.debug("[%s_service] service: %s, response: %s", action, service, response)
        return response.get("result", "failed") == "ok"

    @_log_errors
    async def start_service(self, service: str) -> bool:
        """Start an OPNsense service.

        Parameters
        ----------
        service : str
            Service name or identifier recognized by OPNsense.

        Returns
        -------
        bool
            ``True`` when OPNsense reports the requested action succeeded.

        """
        return await self._manage_service("start", service)

    @_log_errors
    async def stop_service(self, service: str) -> bool:
        """Stop an OPNsense service.

        Parameters
        ----------
        service : str
            Service name or identifier recognized by OPNsense.

        Returns
        -------
        bool
            ``True`` when OPNsense reports the requested action succeeded.

        """
        return await self._manage_service("stop", service)

    @_log_errors
    async def restart_service(self, service: str) -> bool:
        """Restart an OPNsense service.

        Parameters
        ----------
        service : str
            Service name or identifier recognized by OPNsense.

        Returns
        -------
        bool
            ``True`` when OPNsense reports the requested action succeeded.

        """
        return await self._manage_service("restart", service)

    @_log_errors
    async def restart_service_if_running(self, service: str) -> bool:
        """Restart an OPNsense service only when it is currently running.

        Parameters
        ----------
        service : str
            Service name or identifier recognized by OPNsense.

        Returns
        -------
        bool
            ``True`` when no restart is required or when restart succeeds.

        """
        if await self.get_service_is_running(service):
            return await self.restart_service(service)
        return True
