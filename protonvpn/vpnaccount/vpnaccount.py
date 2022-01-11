
import base64
from dataclasses import dataclass, fields
from proton.session.api import Session
from typing import NamedTuple, Union
from .api_data import VPNSettings, VPNCertificate, VPNSession
from datetime import datetime
from typing import Sequence

class VPNUserPass(NamedTuple):
    username: str
    password: str


class VPNAccountReloadVPNData(Exception):
    """ VPN Account information are empty or not available and should be filled with
        fresh user information coming from the API by calling :meth:`VPNAccount.reload_vpn_settings`
    """
class VPNCertificateReload(Exception):
    """ VPN Certificate data not available and should be reloaded by calling  :meth:`VPNAccount.reload_certificate`
    """

class VPNAccount:
    """
        Wrapper that provides helpers to a persistent offline keyring access to user account information available from
        Proton API :

            - ProtonVPN settings and plan data fields.
            - ProtonVPN X509 certificates signed by the API.
            - Wireguard private key.

        - If the keyring does not contain such data, the user will be informed with :exc:`VPNAccountReloadVPNData` for
          VPN settings or :exc:`VPNCertificateReload` for X509 certificate and wireguard key. In that case, the client
          code  will need to reload the data  with a with :meth:`reload_vpn_settings` or :meth:`reload_certificate`
          respectively.

        - If the data is available through the keyring, it will be used as an off-line cache.

        Simple example of retry strategy :

        .. code-block::

            from proton.sso import ProtonSSO
            from protonvpn.vpnaccount import VPNAccount

            default_account_name=sso.sessions[0]
            account=VPNAccount(default_account_name)
            try:
                b64_wg_key=account.get_client_private_wg_key()
            except VPNCertificateReload:
                f = VPNCertificateFetcher(session=sso.get_session(proton_username))
                account.reload_certificate(f.fetch())
                b64_wg_key=account.get_client_private_wg_key()




    """

    def __init__(self, username:str):
        """
        :param user_name: username handle for the persistent account
        """
        self._vpn_plan=None
        self._vpn_settings=None
        self._vpn_certificate=None
        self._keyring_settings_name=self.__keyring_key_name(username+"_settings")
        self._keyring_certificate_name=self.__keyring_key_name(username+"_cert")
        # Load info from the keyring
        keyring = self._keyring
        try:
            api_vpn_data=keyring[self._keyring_settings_name]
            self.reload_vpn_settings(VPNSettings.from_dict(api_vpn_data))
        except KeyError:
            pass
        try:
            cert_data=keyring[self._keyring_certificate_name]
            self.reload_certificate(VPNCertificate.from_dict(cert_data))
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

    def reload_certificate(self, api_vpn_data: 'VPNCertificate') -> None:
        """ Refresh VPN account data from a :class:`api_data.VPNCertificate` object.
            See the helper :class:`api_data.VPNCertificateFetcher` to provide this
            object.
        """
        keyring = self._keyring
        keyring[self._keyring_certificate_name]=api_vpn_data.to_dict()
        self._vpn_certificate = api_vpn_data   

    def reload_vpn_settings(self, api_vpn_data: 'VPNSettings') -> None:
        """ Reload vpn data from :class:`api_data.VPNSettings` object.
            See the helper :class:`api_data.VPNSettingsFetcher` to provide
            this object.
        """
        keyring = self._keyring
        keyring[self._keyring_settings_name]=api_vpn_data.to_dict()
        self._vpn_settings = api_vpn_data

    def clear(self) -> None:
        """ Erase any VPNAccount data available in the Keyring (certificates, private keys, vpn settings)
        """
        keyring = self._keyring
        try:
            del keyring[self._keyring_settings_name]
            del keyring[self._keyring_certificate_name]
        except KeyError:
            pass

    def get_client_certificate(self) -> VPNCertificate:
        """ X509 client certificate, can be used to connect to the local agent.

            :raises VPNCertificateReload: : :class:`VPNAccount` must be re-populated with :meth:`reload_certificate`
            :return: :class:`api_data.VPNCertificate`
        """
        if self._vpn_certificate is not None:
            refresh_date = datetime.fromtimestamp(self._vpn_certificate.RefreshTime)
            if datetime.now() < refresh_date:
                return self._vpn_certificate
            else:
                raise VPNCertificateReload
        else:
            raise VPNCertificateReload

    def get_client_private_wg_key(self) -> str:
        """ Get the wireguard private key in base64 format, directly usable in a wireguard configuration file. This key
            is tighed to the Proton :class:`api_data.VPNCertificate` obtained from the API. If the corresponding certificate is 
            expired an :exc:`VPNCertificateReload` will also be trigged to the user.

            :raises VPNCertificateReload: : :class:`VPNAccount` must be re-populated with :meth:`reload_certificate`
            :return: `str`: Wireguard private key in base64 format.
        """
        if self._vpn_certificate is not None:
            refresh_date = datetime.fromtimestamp(self._vpn_certificate.RefreshTime)
            if datetime.now() < refresh_date:
                return self._vpn_certificate.wireguard_privatekey
            else:
                raise VPNCertificateReload
        else:
            raise VPNCertificateReload

    def get_username_and_password(self) -> VPNUserPass:
        """
        :raises VPNAccountReloadVPNData: : :class:`VPNAccount` must be re-populated with `reload_vpn_settings`
        :return: :class:`VPNUserPass` usable credentials to login on ProtonVPN.
        """
        # VPN user and password are in vpn settings object as we simply 
        # cache what's coming from the API.
        if self._vpn_settings is not None:
            return VPNUserPass(self._vpn_settings.VPN.Name, self._vpn_settings.VPN.Password)
        else:
            raise VPNAccountReloadVPNData

    @property
    def max_tier(self) -> int:
        """
        :raises VPNAccountReloadVPNData:
        :return: int `Maxtier` value of the acccount from :class:`api_data.VPNInfo`
        """
        if self._vpn_settings is not None:
            return self._vpn_settings.VPN.MaxTier
        else:
            raise VPNAccountReloadVPNData

    @property
    def max_connections(self) -> int:
        """
        :raises VPNAccountReloadVPNData:
        :return: int the `MaxConnect` value of the acccount from :class:`api_data.VPNInfo`
        """
        if self._vpn_settings is not None:
            return self._vpn_settings.VPN.MaxConnect
        else:
            raise VPNAccountReloadVPNData

    @property
    def delinquent(self) -> bool:
        """
        :raises VPNAccountReloadVPNData:
        :return: bool if the account is deliquent, based the value from :class:`api_data.VPNSettings`
        """
        if self._vpn_settings is not None:
            return True if self._vpn_settings.Delinquent > 2 else False
        else:
            raise VPNAccountReloadVPNData

    def get_vpn_sessions(self) -> Sequence['VPNSession']:
        """
        :return: the list of active VPN session of the user on the infra
        """
        raise NotImplementedError
