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
    """ Maximum tier value that this account can vpn connect to """
    MaxConnect: int
    """ Maximum number of simultaneaous session on the infrastructure"""
    Groups: list
    """ List of groups that this account belongs to """
    NeedConnectionAllocation: bool

@dataclass
class VPNSettings(Serializable):
    """ Same object structure as the one coming from the API"""
    VPN:VPNInfo
    Services: int
    Subscribed: int
    Delinquent: int
    """ Encode the deliquent status of the account """
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
    def _deserialize(dict_data:dict) -> 'VPNCertificate' :
        __fields=[v.name for v in fields(VPNCertificate)]
        return VPNCertificate(**{name:dict_data[name] for name in __fields})

@dataclass
class VPNSecrets(Serializable):
    """ Asymmetric crypto secrets generated locally by the client to :

        - connect to the VPN service
        - ask for a certificate to the API with the corresponding public key.

    """
    wireguard_privatekey: str
    """Wireguard private key encoded in base64. To be added locally by the user. The API route is not providing it"""
    openvpn_privatekey:str
    """OpenVPN private key in PEM format. To be added locally by the user. The API is not providing it"""

    @staticmethod
    def _deserialize(dict_data:dict) -> 'VPNSecrets' :
        __fields=[v.name for v in fields(VPNSecrets)]
        return VPNSecrets(**{name:dict_data[name] for name in __fields})

@dataclass
class VPNSession(Serializable):
    SessionID: str
    ExitIP: str
    Protocol: str

    @staticmethod
    def _deserialize(dict_data:dict) -> 'VPNSession' :
        __fields=[v.name for v in fields(VPNSession)]
        return VPNSession(**{name:dict_data[name] for name in __fields})

@dataclass
class VPNSessions(Serializable):
    """ The list of active VPN session of an account on the infra """
    Sessions: list[VPNSession]

    def __len__(self):
        return len(self.Sessions)

    @staticmethod
    def _deserialize(dict_data:dict) -> 'VPNSessions' :
        session_list= [ VPNSession.from_dict(value) for value in dict_data['Sessions'] ]
        return VPNSessions(Sessions=session_list)

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


class VPNCertCredentials(NamedTuple):
    """
        A Tuple object containing API certificate and user secrets
    """
    api_certificate: VPNCertificate
    secrets: VPNSecrets

    @staticmethod
    def from_dict(cert_raw_data:dict, secrets_raw_data:dict) -> 'VPNCertCredentials' :
        """ Helper function ton build a VPNCertCredential object from raw data
            :return: a :class:`VPNCertCredentials` object
        """
        return VPNCertCredentials(VPNCertificate.from_dict(cert_raw_data),VPNSecrets.from_dict(secrets_raw_data))


class VPNCertCredentialsFetcher:
    """ Helper class to retrieve a :class:`VPNCertCredentials` object from the API. Same
        use as :class:`VPNSettingsFetcher`. This class also generates a private/public key pair
        locally at initialization time that will be available in the :class:`VPNCertCredentials`.
    """
    ROUTE='/vpn/v1/certificate'

    def __init__(self, _raw_data: dict =None, cert_duration: int = 1440, features=None, session=None):
        # This will generate a new set key!
        self._keys=KeyHandler()
        self._cert_duration = str(cert_duration) + " min"
        self._session = session
        self._features = features
        self._raw_api_cert_data=_raw_data
    
    def _fetch_raw_data(self) -> None:
        json_req = {"ClientPublicKey": self._keys.ed25519_pk_pem,
                    "Duration": self._cert_duration
                    }
        if self._features:
            json_req["Features"] = self._features
        self._raw_api_cert_data=self._session.api_request(VPNCertCredentialsFetcher.ROUTE, jsondata=json_req)

    def fetch(self) -> 'VPNCertCredentials':
        """ Return a :class:`VPNCertificate` from a local cache or fetch it
            from the API if not available.
        """
        if self._raw_api_cert_data is None:
            self._fetch_raw_data()
        return VPNCertCredentials(
                                  VPNCertificate.from_dict(self._raw_api_cert_data),
                                  VPNSecrets(wireguard_privatekey=self._keys.x25519_sk_str,
                                  openvpn_privatekey=self._keys.ed25519_sk_pem)
                                 )

class VPNSessionsFetcher:
    """ Helper class to retrieve a :class:`VPNSessions` object from the API. If
        can be initialized directly with the raw data coming from the API, or
        provided with a Proton session object.
    """
    ROUTE='/vpn/sessions'

    def __init__(self, _raw_data: dict=None, session=None ):
        self._session=session
        self._raw_data=_raw_data

    def _fetch_raw_data(self) -> None:
        self._raw_data = self._session.api_request(VPNSessionsFetcher.ROUTE)

    def fetch(self) -> 'VPNSessions':
        """ Return a :class:`VPNSessions` from a local cache or fetch it
            from the API if not available.
        """
        if self._raw_data is None:
            self._fetch_raw_data()
        return VPNSessions.from_dict(self._raw_data)