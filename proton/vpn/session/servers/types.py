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
import random
from enum import IntFlag
from typing import List, Dict

from proton.vpn.session.exceptions import ServerNotFoundError
from proton.vpn.session.servers.country_codes import get_country_name_by_code


class TierEnum(IntFlag):
    FREE = 0
    PLUS = 2
    PM = 3


class ServerFeatureEnum(IntFlag):
    """
    A Class representing the Server features as encoded in the feature flags field of the API:
    """
    SECURE_CORE = 1 << 0  # 1
    TOR = 1 << 1  # 2
    P2P = 1 << 2  # 4
    STREAMING = 1 << 3  # 8
    IPV6 = 1 << 4  # 16


class PhysicalServer:
    """
    A physical server instance contains the network information
    to initiate a VPN connection to the server.
    """

    def __init__(self, data: Dict):
        self._data = data

    @property
    def id(self):
        return self._data.get("ID")

    @property
    def entry_ip(self):
        return self._data.get("EntryIP")

    @property
    def exit_ip(self):
        return self._data.get("ExitIP")

    @property
    def domain(self):
        return self._data.get("Domain")

    @property
    def enabled(self):
        return self._data.get("Status") == 1

    @property
    def generation(self):
        return self._data.get("Generation")

    @property
    def label(self):
        return self._data.get("Label")

    @property
    def services_down_reason(self):
        return self._data.get("ServicesDownReason")

    @property
    def x25519_pk(self) -> str:
        """ X25519 public key of the physical available as a base64 encoded string.
        """
        return self._data.get("X25519PublicKey")

    def __repr__(self):
        if self.label != '':
            return 'PhysicalServer<{}+b:{}>'.format(self.domain, self.label)
        else:
            return 'PhysicalServer<{}>'.format(self.domain)


class LogicalServer:
    """
    Abstraction of a VPN server.

    One logical servers abstract one or more
    PhysicalServer instances away.
    """

    def __init__(self, data: Dict):
        self._data = data

    def update(self, server_load: ServerLoad):
        if self.id != server_load.id:
            raise ValueError(
                "The id of the logical server does not match the one of "
                "the server load object"
            )

        self._data["Load"] = server_load.load
        self._data["Score"] = server_load.score
        self._data["Status"] = 1 if server_load.enabled else 0

    @property
    def id(self):
        return self._data.get("ID")

    # Score, load and status can be modified (needed to update loads)
    @property
    def load(self) -> int:
        return self._data.get("Load")

    @property
    def score(self) -> float:
        return self._data.get("Score")

    @property
    def enabled(self) -> bool:
        return self._data.get("Status") == 1 and any(
            x.enabled for x in self.physical_servers
        )

    # Every other propriety is readonly
    @property
    def name(self) -> str:
        """ Name of the logical, example : CH#10 """
        return self._data.get("Name")

    @property
    def entry_country(self) -> str:
        """ 2 letter country code entry """
        return self._data.get("EntryCountry")

    @property
    def exit_country(self) -> str:
        """ 2 letter country code exit """
        return self._data.get("ExitCountry")

    @property
    def exit_country_name(self) -> str:
        """Full name of the exit country (e.g. Argentina)."""
        return get_country_name_by_code(self.exit_country)

    @property
    def host_country(self) -> str:
        """ 2 letter country code host """
        return self._data.get("HostCountry")

    @property
    def features(self) -> List[ServerFeatureEnum]:
        """ List of features supported by this Logical
        """
        return self.__unpack_bitmap_features(self._data.get("Features", 0))

    def __unpack_bitmap_features(self, server_value):
        server_features = [
            feature_enum
            for feature_enum
            in ServerFeatureEnum
            if (server_value & feature_enum) != 0
        ]
        return server_features

    @property
    def region(self):
        return self._data.get("Region")

    @property
    def city(self) -> str:
        return self._data.get("City")

    @property
    def tier(self) -> int:
        return TierEnum(int(self._data.get("Tier")))

    @property
    def latitude(self) -> float:
        return self._data.get("Location", {}).get("Lat")

    @property
    def longitude(self) -> float:
        return self._data.get("Location", {}).get("Long")

    @property
    def data(self):
        return self._data.copy()

    @property
    def physical_servers(self) -> List[PhysicalServer]:
        """ Get all the physicals of supporting a logical
        """
        return [PhysicalServer(x) for x in self._data.get("Servers", [])]

    def get_random_physical_server(self) -> PhysicalServer:
        """ Get a random `enabled` physical linked to this logical
        """
        enabled_servers = [x for x in self.physical_servers if x.enabled]
        if len(enabled_servers) == 0:
            raise ServerNotFoundError("No physical servers could be found")

        return random.choice(enabled_servers)

    def to_dict(self) -> Dict:
        """Converts this object to a dictionary for serialization purposes."""
        return self._data

    def __repr__(self):
        return 'LogicalServer<{}>'.format(self._data.get("Name", "??"))


class ServerLoad:
    """
    Contains data about logical servers to be updated frequently.
    """

    def __init__(self, data: Dict):
        self._data = data

    @property
    def id(self):
        return self._data.get("ID")

    # Score, load and status can be modified (needed to update loads)
    @property
    def load(self) -> int:
        return self._data.get("Load")

    @property
    def score(self) -> float:
        return self._data.get("Score")

    @property
    def enabled(self) -> bool:
        return self._data.get("Status") == 1

    def __str__(self):
        return str(self._data)
