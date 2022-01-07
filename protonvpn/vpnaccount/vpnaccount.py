
import base64
from dataclasses import dataclass, fields
from proton.session.api import Session
from typing import NamedTuple, Union

#Dataclass is a python 3.7 feature
@dataclass
class VPNSettings:
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
class VPNPlan:
    Services: int
    Subscribed: int
    Delinquent: int
    HasPaymentMethod: int
    Credit: int
    Currency: str
    Warnings: list

class VPNUserPass(NamedTuple):
    username: str
    password: str


class VPNAccountReloadVPNData(Exception):
    """ VPN Account information are empty or not available and should be filled with
        fresh user information coming from the API by calling :meth:`VPNAccount.reload_vpn_data`
    """

class VPNAccount:
    """
        Wrapper that provides helpers to a persistent offline access to /vpn backend route data fields
        retrieved from the API (a keyring typically).

        - If the keyring does not contain such data, the user will be informed with :exc:`VPNAccountReloadVPNData`
          Exception and will need to reload the data  with a with a :data:`dict` (see :meth:`reload_vpn_data`)

        - If the data is available through the keyring, it will be used as an off-line cache.
    """

    def __init__(self, username:str):
        """
        :param user_name: username handle for the persistent account
        """
        self._vpn_plan=None
        self._vpn_settings=None
        self._keyringname=self.__keyring_key_name(username)
        # Load info from the keyring
        keyring = self._keyring
        try:
            api_vpn_data=keyring[self._keyringname]
            self.reload_vpn_data(api_vpn_data)
        except KeyError:
            pass

    # FIXME : taken from proton.sso, should we use those fonction the same way for accounts ?
    def __encode_name(self, account_name) -> str:
        """Helper function to convert an account_name into a safe alphanumeric string.

        :param account_name: normalized account_name
        :type account_name: str
        :return: base32 encoded string, without padding.
        :rtype: str
        """
        return base64.b32encode(account_name.encode('utf8')).decode('ascii').rstrip('=').lower()

    def __keyring_key_name(self, account_name : str) -> str:
        """Helper function to get the keyring key for account_name

        :param account_name: normalized account_name
        :type account_name: str
        :return: keyring key
        :rtype: str
        """
        return f'proton-vpnaccount-{self.__encode_name(account_name)}'

    @property
    def _keyring(self) -> "KeyringBackend":
        """Shortcut to get the default keyring backend

        :return: an instance of the default KeyringBackend
        :rtype: KeyringBackend
        """
        from proton.loader import Loader
        return Loader.get('keyring')()

    def reload_vpn_data(self, api_vpn_data: dict) -> None:
        """ helper to reload vpn data from a dict directly translated from the API call /vpn to the API.
        fields names are supposed to be the same as the field in the Json answer from the API, currently :

          .. code-block::

                {
                "Code": 1000,

                "VPN": {
                    "ExpirationTime": 1,
                    "Name": "test",
                    "Password": "passwordtest",
                    "GroupID": "testgroup",
                    "Status": 1,
                    "PlanName": "free",
                    "PlanTitle": null,
                    "MaxTier": 0,
                    "MaxConnect": 2,
                    "Groups": [
                    "vpnfree"
                    ],
                },
                "Services": 5,
                "Subscribed": 0,
                "Delinquent": 0,
                "HasPaymentMethod": 1,
                "Credit": 17091,
                "Currency": "EUR",
                "Warnings": []
                }

        :raises: KeyError : if a field from the dataclass does not exist in the dict, check your
         interface with the API of the format of api_vpn_data.
        """
        __account_fields=[v.name for v in fields(VPNPlan)]
        __vpn_settings_fields=[v.name for v in fields(VPNSettings)]
        self._vpn_plan=VPNPlan(*[api_vpn_data[name] for name in __account_fields])
        self._vpn_settings=VPNSettings(*[api_vpn_data['VPN'][name] for name in __vpn_settings_fields])
        # save info to the keyring
        try:
            keyring = self._keyring
            keyring[self._keyringname]=api_vpn_data
        except KeyError:
            pass

    def clear(self) -> None:
        """ Erase any VPNAccount data available in the Keyring.
        """
        keyring = self._keyring
        try:
            del keyring[self._keyringname]
        except KeyError:
            pass

    def get_username_and_password(self) -> VPNUserPass:
        """
        :raises VPNAccountReloadVPNData: : :class:`VPNAccount` must be re-populated with `reload_vpn_data`
        :return: :class:`VPNUserPass` usable credentials to login on ProtonVPN.
        """
        # VPN user and password are in vpn settings object as we simply 
        # cache what's coming from the API.
        if self._vpn_settings is not None:
            return VPNUserPass(self._vpn_settings.Name, self._vpn_settings.Password)
        else:
            raise VPNAccountReloadVPNData

    @property
    def max_tier(self) -> int:
        """
        :raises VPNAccountReloadVPNData:
        :return: int the Maxtier Value of the acccount.
        """
        if self._vpn_settings is not None:
            return self._vpn_settings.MaxTier
        else:
            raise VPNAccountReloadVPNData

