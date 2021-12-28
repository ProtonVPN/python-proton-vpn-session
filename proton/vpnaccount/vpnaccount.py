#Dataclass is a python 3.7 feature
from dataclasses import dataclass, fields

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

class VPNAccountReloadVPNData(Exception):
    """
        VPN Account information are empty or not available and should be filled with 
        fresh user information coming from the API by calling reload_vpn_data
    """

class VPNAccount:
    KEYRING_NAME = "vpnaccount0"
    """
        Wrapper that provides helpers to a persistent offline access to /vpn backend route fields retrieved 
        from the API using the keyring.
        - If the keyring does not contain such info, the user will be informed with an 
          exception and will need to reload the data.
        - If the Info are available through the Keyring, it will be used as an off-line cache.
    """

    def __init__(self):
        self._vpn_plan=None
        self._vpn_settings=None
        # Load info from the keyring
        keyring = self._keyring
        try:
            api_vpn_data=keyring[VPNAccount.KEYRING_NAME]
            self.reload_vpn_data(api_vpn_data)
        except KeyError:
            pass

    @property
    def _keyring(self) -> "KeyringBackend":
        """Shortcut to get the default keyring backend

        :return: an instance of the default KeyringBackend
        :rtype: KeyringBackend
        """
        from proton.loader import Loader
        return Loader.get('keyring')()

    def reload_vpn_data(self, api_vpn_data: dict) -> None:
        """ Reload vpn data from a dict directly translated from the API call /vpn to the API.
        fields names are supposed to be the same as the field in the Json answer from the API.

        :raises KeyError : if a field from the dataclass does not exist in the dict, check your
         interface with the API.
        """
        __account_fields=[v.name for v in fields(VPNPlan)]
        __vpn_settings_fields=[v.name for v in fields(VPNSettings)]
        self._vpn_plan=VPNPlan(*[api_vpn_data[name] for name in __account_fields])
        self._vpn_settings=VPNSettings(*[api_vpn_data['VPN'][name] for name in __vpn_settings_fields])
        # save info to the keyring
        try:
            keyring = self._keyring
            keyring[VPNAccount.KEYRING_NAME]=api_vpn_data
        except KeyError:
            pass

    @property
    def vpn_username(self) -> str:
        """
        :raises VPNAccountReloadVPNData: Keyring is empty and should be re-populated
        :return: vpn username to use for user/password authentication on the VPN Infra
        """
        if self._vpn_settings is not None:
            return self._vpn_settings.Name
        else:
            raise VPNAccountReloadVPNData

    @property
    def vpn_password(self) -> str:
        """
        :raises VPNAccountReloadVPNData: Keyring is empty and should be re-populated
        :return: vpn password to use for user/password authentication on the VPN Infra
        """
        if self._vpn_settings is not None:
            return self._vpn_settings.Password
        else:
            raise VPNAccountReloadVPNData

    @property
    def max_tier(self) -> int:
        if self._vpn_settings is not None:
            return self._vpn_settings.MaxTier
        else:
            raise VPNAccountReloadVPNData

