from dataclasses import dataclass, fields, asdict
from proton.sso import ProtonSSO
from typing import NamedTuple, Union
from .key_mgr import KeyHandler
import json

class Serializable:
    def to_json(self) -> str:
        return json.dumps(asdict(self))
    
    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls,dict_data:dict) -> 'Serializable' :
        return cls._deserialize(dict_data)

    @classmethod
    def from_json(cls,data:str) -> 'Serializable' :
        dict_data = json.loads(data)
        return cls._deserialize(dict_data)
    
    @staticmethod
    def _deserialize(dict_data:dict) -> 'Serializable' :
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
    MaxConnect: int
    Groups: list
    NeedConnectionAllocation: bool

@dataclass
class VPNSettings(Serializable):
    """ Same object structure as the one coming from the API"""
    VPN:VPNInfo
    Services: int
    Subscribed: int
    Delinquent: int
    HasPaymentMethod: int
    Credit: int
    Currency: str
    Warnings: list

    @staticmethod
    def _deserialize(dict_data:dict) -> 'VPNSettings' :
        __vpn_settings_fields=[v.name for v in fields(VPNSettings) if v.name != 'VPN']
        return VPNSettings(VPNInfo(**dict_data['VPN']),**{name:dict_data[name] for name in __vpn_settings_fields} )

@dataclass
class VPNCertificate(Serializable):
    """ Same object structure coming from the API, except for `wireguard_privatekey` field"""
    SerialNumber: str
    ClientKeyFingerprint: str
    ClientKey: str
    Certificate: str
    ExpirationTime: int
    RefreshTime: int
    Mode: str
    DeviceName: str
    ServerPublicKeyMode: str
    ServerPublicKey: str
    wireguard_privatekey: str 
    """To be added locally by the user. The API route is not providing it"""


    def _deserialize(dict_data:dict) -> 'VPNCertificate' :
        __fields=[v.name for v in fields(VPNCertificate)]
        return VPNCertificate(**{name:dict_data[name] for name in __fields})


class VPNSettingsFetcher:
    """ Helper class to retrieve a :class:`VPNSettings` object from the API. If
        can be initialized directly with the raw data coming from the API, or
        provided with a Proton session object.
    """
    ROUTE='/vpn'

    def __init__(self, _raw_data: dict=None, session=None ):
        self._session=session
        self._raw_data=_raw_data

    def _fetch_raw_data(self) -> None:
        self._raw_data = self._session.api_request(VPNSettingsFetcher.ROUTE)

    def fetch(self) -> 'VPNSettings':
        """ Return a :class:`VPNSettings` from a local cache or fetch it
            from the API if not available.
        """
        if self._raw_data is None:
            self._fetch_raw_data()
        return VPNSettings.from_dict(self._raw_data)

class VPNCertificateFetcher:
    """ Helper class to retrieve a :class:`VPNCertificate` object from the API. Same
        use as :class:`VPNSettingsFetcher`. This class also generates a private/public key pair
        locally at initialization time that will be available in the :class:`VPNCertificate` dataclass.
    """
    ROUTE='/vpn/v1/certificate'

    def __init__(self, _raw_data: dict =None, cert_duration: int = 1440, features=None, session=None):
        self._keys=KeyHandler()
        self._cert_duration = str(cert_duration) + " min"
        self._session = session
        self._features = features
        self._raw_data=_raw_data
    
    def _fetch_raw_data(self) -> None:
        json_req = {"ClientPublicKey": self._keys.ed25519_pk_pem,
                    "Duration": self._cert_duration
                    }
        if self._features:
            json_req["Features"] = self._features
        self._raw_data=self._session.api_request(VPNCertificateFetcher.ROUTE, jsondata=json_req)
        self._raw_data["wireguard_privatekey"] = self._keys.x25519_sk_str

    def fetch(self) -> 'VPNCertificate':
        """ Return a :class:`VPNCertificate` from a local cache or fetch it
            from the API if not available.
        """
        if self._raw_data is None:
            self._fetch_raw_data()
        return VPNCertificate.from_dict(self._raw_data)