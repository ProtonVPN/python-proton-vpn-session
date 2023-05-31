"""
Copyright (c) 2023 Proton AG

This file is part of Proton VPN.

Proton VPN is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton VPN is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

from proton.vpn import logging
from proton.vpn.session.dataclasses import (
    VPNCertificate, VPNSessions, VPNSettings, VPNLocation
)

if TYPE_CHECKING:
    from proton.vpn.session import VPNSession

logger = logging.getLogger(__name__)


class VPNAccountFetcher:
    """
    Fetches PROTON VPN user account information.
    """
    def __init__(self, session: "VPNSession" = None):
        self._session = session

    async def fetch_vpn_info(self) -> VPNSettings:
        """Fetches client VPN information."""
        route = "/vpn"
        logger.info(f"'{route}'", category="api", event="request")
        response = await self._session.async_api_request(route, no_condition_check=True)
        logger.info(f"'{route}'", category="api", event="response")
        return VPNSettings.from_dict(response)

    async def fetch_certificate(
        self, client_public_key, cert_duration_in_minutes: int = 1440, features=None
    ) -> VPNCertificate:
        """
        Fetches a certificated signed by the API server to authenticate against VPN servers.
        """
        json_req = {
            "ClientPublicKey": client_public_key,
            "Duration": f"{cert_duration_in_minutes} min"
        }
        if features:
            json_req["Features"] = features

        route = "/vpn/v1/certificate"
        logger.info(f"'{route}'", category="api", event="request")
        response = await self._session.async_api_request(
            route,
            jsondata=json_req,
            no_condition_check=True
        )
        logger.info(f"'{route}'", category="api", event="response")

        return VPNCertificate.from_dict(response)

    async def fetch_active_sessions(self) -> VPNSessions:
        """
        Fetches information about active VPN sessions.
        """
        route = "/vpn/sessions"
        logger.info(f"'{route}'", category="api", event="request")
        response = await self._session.async_api_request(route)
        logger.info(f"'{route}'", category="api", event="response")
        return VPNSessions.from_dict(response)

    async def fetch_location(self) -> VPNLocation:
        """Fetches information about the physical location the VPN client is connected from."""
        route = "/vpn/location"
        logger.info(f"'{route}'", category="api", event="request")
        response = await self._session.async_api_request(
            route, no_condition_check=True
        )
        logger.info(f"'{route}'", category="api", event="response")
        return VPNLocation.from_dict(response)
