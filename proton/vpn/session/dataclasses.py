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
from dataclasses import dataclass, fields, asdict
import json
from typing import List


@dataclass
class LoginResult:
    success: bool
    authenticated: bool
    twofa_required: bool


class Serializable:
    def to_json(self) -> str:
        return json.dumps(asdict(self))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, dict_data: dict) -> 'Serializable':
        return cls._deserialize(dict_data)

    @classmethod
    def from_json(cls, data: str) -> 'Serializable':
        dict_data = json.loads(data)
        return cls._deserialize(dict_data)

    @staticmethod
    def _deserialize(dict_data: dict) -> 'Serializable':
        raise NotImplementedError


@dataclass
class VPNInfo(Serializable):
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


@dataclass
class VPNSettings(Serializable):
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
    def _deserialize(dict_data: dict) -> 'VPNSettings':
        __vpn_settings_fields = [v.name for v in fields(VPNSettings) if v.name != 'VPN']
        return VPNSettings(VPNInfo(**dict_data['VPN']), **{name: dict_data[name] for name in __vpn_settings_fields})


@dataclass
class VPNCertificate(Serializable):
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
    def _deserialize(dict_data: dict) -> 'VPNCertificate':
        __fields = [v.name for v in fields(VPNCertificate)]
        return VPNCertificate(**{name: dict_data[name] for name in __fields})


@dataclass
class VPNSecrets(Serializable):
    """ Asymmetric crypto secrets generated locally by the client to :

        - connect to the VPN service
        - ask for a certificate to the API with the corresponding public key.

    """
    wireguard_privatekey: str
    """Wireguard private key encoded in base64. To be added locally by the user. The API route is not providing it"""
    openvpn_privatekey: str
    """OpenVPN private key in PEM format. To be added locally by the user. The API is not providing it"""
    ed25519_privatekey: str
    """Private key in ed25519 base64 format. used to check fingerprints"""

    @staticmethod
    def _deserialize(dict_data: dict) -> 'VPNSecrets':
        __fields = [v.name for v in fields(VPNSecrets)]
        return VPNSecrets(**{name: dict_data[name] for name in __fields})


@dataclass
class APIVPNSession(Serializable):
    SessionID: str
    ExitIP: str
    Protocol: str

    @staticmethod
    def _deserialize(dict_data: dict) -> 'APIVPNSession':
        __fields = [v.name for v in fields(APIVPNSession)]
        return APIVPNSession(**{name: dict_data[name] for name in __fields})


@dataclass
class VPNSessions(Serializable):
    """ The list of active VPN session of an account on the infra """
    Sessions: List[APIVPNSession]

    def __len__(self):
        return len(self.Sessions)

    @staticmethod
    def _deserialize(dict_data: dict) -> 'VPNSessions':
        session_list = [APIVPNSession.from_dict(value) for value in dict_data['Sessions']]
        return VPNSessions(Sessions=session_list)


@dataclass
class VPNCertCredentials(Serializable):
    """
        A Tuple object containing API certificate and user secrets
    """
    api_certificate: VPNCertificate
    secrets: VPNSecrets

    @staticmethod
    def from_dict(cert_raw_data: dict, secrets_raw_data: dict) -> 'VPNCertCredentials':
        """ Helper function ton build a VPNCertCredential object from raw data
            :return: a :class:`VPNCertCredentials` object
        """
        return VPNCertCredentials(
            VPNCertificate.from_dict(cert_raw_data),
            VPNSecrets.from_dict(secrets_raw_data)
        )
