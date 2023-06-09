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
from dataclasses import dataclass
from pathlib import Path
import random
from typing import List, Optional, TYPE_CHECKING
import time

from proton.utils.environment import VPNExecutionEnvironment

from proton.vpn.session.cache import CacheFile
from proton.vpn.session.exceptions import ClientConfigDecodeError
from proton.vpn.session.utils import rest_api_request

if TYPE_CHECKING:
    from proton.vpn.session import VPNSession

DEFAULT_CLIENT_CONFIG = {
    "OpenVPNConfig": {
        "DefaultPorts": {
            "UDP": [80, 51820, 4569, 1194, 5060],
            "TCP": [443, 7770, 8443]
        }
    },
    "HolesIPs": ["62.112.9.168", "104.245.144.186"],
    "ServerRefreshInterval": 10,
    "FeatureFlags": {
        "NetShield": 0,
        "GuestHoles": 0,
        "ServerRefresh": 1,
        "StreamingServicesLogos": 1,
        "PortForwarding": 0,
        "ModerateNAT": 1,
        "SafeMode": 0,
        "StartConnectOnBoot": 1,
        "PollNotificationAPI": 1,
        "VpnAccelerator": 1,
        "SmartReconnect": 1,
        "PromoCode": 0,
        "WireGuardTls": 1
    }
}


@dataclass
class OpenVPNPorts:
    """Dataclass for openvpn ports.
    These ports are mainly used for establishing VPN connections.
    """
    udp: List
    tcp: List

    @staticmethod
    def from_dict(openvpn_ports: dict) -> OpenVPNPorts:
        """Creates OpenVPNPorts object from data."""
        # The lists are copied to avoid side effects if the dict is modified.
        return OpenVPNPorts(
            openvpn_ports["UDP"].copy(),
            openvpn_ports["TCP"].copy()
        )


@dataclass
class FeatureFlags:  # pylint: disable=R0902
    """Dataclass for feature flags ports.

    Flags are important since they can let us know which feature are enabled
    or disabled. Also certain feature flags dependent on user tier.
    """
    netshield: bool
    guest_holes: bool
    server_refresh: bool
    streaming_services_logos: bool
    port_forwarding: bool
    moderate_nat: bool
    safe_mode: bool
    start_connect_on_boot: bool
    poll_notification_api: bool
    vpn_accelerator: bool
    smart_reconnect: bool
    promo_code: bool
    wireguard_tls: bool

    @staticmethod
    def from_dict(feature_flags: dict) -> FeatureFlags:
        """Creates FeatureFlags object from data."""
        return FeatureFlags(
            feature_flags["NetShield"],
            feature_flags["GuestHoles"],
            feature_flags["ServerRefresh"],
            feature_flags["StreamingServicesLogos"],
            feature_flags["PortForwarding"],
            feature_flags["ModerateNAT"],
            feature_flags["SafeMode"],
            feature_flags["StartConnectOnBoot"],
            feature_flags["PollNotificationAPI"],
            feature_flags["VpnAccelerator"],
            feature_flags["SmartReconnect"],
            feature_flags["PromoCode"],
            feature_flags["WireGuardTls"]
        )


class ClientConfig:
    """
    General configuration used to connect to VPN servers.
    """

    REFRESH_INTERVAL = 3 * 60 * 60  # 3 hours
    REFRESH_RANDOMNESS = 0.22  # +/- 22%

    def __init__(
        self, openvpn_ports, holes_ips,
        server_refresh_interval, feature_flags,
        expiration_time
    ):  # pylint: disable=R0913
        self.openvpn_ports = openvpn_ports
        self.holes_ips = holes_ips
        self.server_refresh_interval = server_refresh_interval
        self.feature_flags = feature_flags
        self.expiration_time = expiration_time

    @classmethod
    def from_dict(cls, apidata: dict) -> ClientConfig:
        """Creates ClientConfig object from data."""
        try:
            openvpn_ports = apidata["OpenVPNConfig"]["DefaultPorts"]
            holes_ips = apidata["HolesIPs"]
            server_refresh_interval = apidata["ServerRefreshInterval"]
            feature_flags = apidata["FeatureFlags"]
            expiration_time = float(apidata.get("ExpirationTime", cls.get_expiration_time()))

            return ClientConfig(
                # No need to copy openvpn_ports, OpenVPNPorts takes care of it.
                OpenVPNPorts.from_dict(openvpn_ports),
                # We copy the holes_ips list to avoid side effects if it's modified.
                holes_ips.copy(),
                server_refresh_interval,
                FeatureFlags.from_dict(feature_flags),
                expiration_time
            )
        except (KeyError, ValueError) as error:
            raise ClientConfigDecodeError(
                "Error parsing client configuration."
            ) from error

    @staticmethod
    def default() -> ClientConfig:
        """":returns: the default client configuration."""
        return ClientConfig.from_dict(DEFAULT_CLIENT_CONFIG)

    @property
    def is_expired(self) -> bool:
        """Returns if data has expired"""
        current_time = time.time()
        return current_time > self.expiration_time

    @property
    def seconds_until_expiration(self) -> float:
        """
        Amount of seconds left until the client configuration is considered
        outdated and should be fetched again from the REST API.
        """
        seconds_left = self.expiration_time - time.time()
        return seconds_left if seconds_left > 0 else 0

    @classmethod
    def _generate_random_component(cls):
        # 1 +/- 0.22*random
        return 1 + cls.REFRESH_RANDOMNESS * (2 * random.random() - 1)

    @classmethod
    def get_refresh_interval_in_seconds(cls):
        return cls.REFRESH_INTERVAL * cls._generate_random_component()

    @classmethod
    def get_expiration_time(cls, start_time: int = None):
        start_time = start_time if start_time is not None else time.time()
        return start_time + cls.get_refresh_interval_in_seconds()


class ClientConfigFetcher:
    """
    Fetches and caches the client configuration from Proton's REST API.
    """
    ROUTE = "/vpn/clientconfig"
    CACHE_PATH = Path(VPNExecutionEnvironment().path_cache) / "clientconfig.json"

    def __init__(self, session: "VPNSession"):
        """
        :param session: session used to retrieve the client configuration.
        """
        self._session = session
        self._client_config = None
        self._cache_file = CacheFile(self.CACHE_PATH)

    def clear_cache(self):
        """Discards the cache, if existing."""
        self._client_config = None
        self._cache_file.remove()

    async def fetch(self) -> ClientConfig:
        """
        Fetches the client configuration from the REST API.
        :returns: the fetched client configuration.
        """
        response = await rest_api_request(
            self._session,
            self.ROUTE,
            no_condition_check=True
        )
        response["ExpirationTime"] = ClientConfig.get_expiration_time()
        self._cache_file.save(response)
        self._client_config = ClientConfig.from_dict(response)
        return self._client_config

    def load_from_cache(self) -> ClientConfig:
        """
        Loads the client configuration from persistence.
        :returns: the persisted client configuration. If no persistence
            was found then the default client configuration is returned.

        """
        cache = self._cache_file.load() if self._cache_file.exists else None
        self._client_config = ClientConfig.from_dict(cache) if cache else ClientConfig.default()
        return self._client_config
