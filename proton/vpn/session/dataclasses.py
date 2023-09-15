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

from dataclasses import dataclass, fields, asdict
import json
from typing import List


# pylint: disable=invalid-name


@dataclass
class LoginResult:  # pylint: disable=missing-class-docstring
    success: bool
    authenticated: bool
    twofa_required: bool


class Serializable:  # pylint: disable=missing-class-docstring
    def to_json(self) -> str:  # pylint: disable=missing-function-docstring
        return json.dumps(asdict(self))

    def to_dict(self) -> dict:  # pylint: disable=missing-function-docstring
        return asdict(self)

    @classmethod
    def from_dict(cls, dict_data: dict) -> 'Serializable':  # noqa: E501 pylint: disable=missing-function-docstring
        return cls._deserialize(dict_data)

    @classmethod
    def from_json(cls, data: str) -> 'Serializable':  # pylint: disable=missing-function-docstring
        dict_data = json.loads(data)
        return cls._deserialize(dict_data)

    @staticmethod
    def _deserialize(dict_data: dict) -> 'Serializable':
        raise NotImplementedError


@dataclass
class VPNInfo(Serializable):  # pylint: disable=too-many-instance-attributes
    """ Same object structure as the one coming from the API"""
    ExpirationTime: int
    Name: str
    Password: str
    GroupID: str
    Status: int
    PlanName: str
    PlanTitle: str
    MaxTier: int
    """ Maximum tier value that this account can vpn connect to """
    MaxConnect: int
    """ Maximum number of simultaneaous session on the infrastructure"""
    Groups: List[str]
    """ List of groups that this account belongs to """
    NeedConnectionAllocation: bool

    @staticmethod
    def _deserialize(dict_data: dict) -> VPNInfo:
        return VPNInfo(**dict_data)


@dataclass
class VPNSettings(Serializable):  # pylint: disable=too-many-instance-attributes
    """ Same object structure as the one coming from the API"""
    VPN: VPNInfo
    Services: int
    Subscribed: int
    Delinquent: int
    """ Encode the deliquent status of the account """
    HasPaymentMethod: int
    Credit: int
    Currency: str
    Warnings: List[str]

    @staticmethod
    def _deserialize(dict_data: dict) -> VPNSettings:
        __vpn_settings_fields = [v.name for v in fields(VPNSettings) if v.name != 'VPN']
        return VPNSettings(
            VPNInfo.from_dict(dict_data['VPN']),
            **{name: dict_data[name] for name in __vpn_settings_fields}
        )


@dataclass
class VPNCertificate(Serializable):  # pylint: disable=too-many-instance-attributes
    """ Same object structure coming from the API """
    SerialNumber: str
    ClientKeyFingerprint: str
    ClientKey: str
    """ Client public key used to ask for this certificate in PEM format. """
    Certificate: str
    """ Certificate value in PEM format. Contains the features requested at fetch time"""
    ExpirationTime: int
    RefreshTime: int
    Mode: str
    DeviceName: str
    ServerPublicKeyMode: str
    ServerPublicKey: str

    @staticmethod
    def _deserialize(dict_data: dict) -> VPNCertificate:
        __fields = [v.name for v in fields(VPNCertificate)]
        return VPNCertificate(**{name: dict_data[name] for name in __fields})


@dataclass
class APIVPNSession(Serializable):  # pylint: disable=missing-class-docstring
    SessionID: str
    ExitIP: str
    Protocol: str

    @staticmethod
    def _deserialize(dict_data: dict) -> APIVPNSession:
        __fields = [v.name for v in fields(APIVPNSession)]
        return APIVPNSession(**{name: dict_data[name] for name in __fields})


@dataclass
class VPNSessions(Serializable):
    """ The list of active VPN session of an account on the infra """
    Sessions: List[APIVPNSession]

    def __len__(self):
        return len(self.Sessions)

    @staticmethod
    def _deserialize(dict_data: dict) -> VPNSessions:
        session_list = [APIVPNSession.from_dict(value) for value in dict_data['Sessions']]
        return VPNSessions(Sessions=session_list)


@dataclass
class VPNLocation(Serializable):
    """Data about the physical location the VPN client runs from."""
    IP: str
    Lat: float
    Long: float
    Country: str
    ISP: str

    @staticmethod
    def _deserialize(dict_data: dict) -> VPNLocation:
        """
        Builds a Location object from a dict containing the parsed
        JSON response returned by the API.
        """
        return VPNLocation(
            IP=dict_data["IP"],
            Lat=dict_data["Lat"],
            Long=dict_data["Long"],
            Country=dict_data["Country"],
            ISP=dict_data["ISP"]
        )
