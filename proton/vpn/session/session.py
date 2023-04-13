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
import base64
from typing import NamedTuple, Optional

from proton.session import Session
from proton.vpn.session.account import VPNAccount
from proton.vpn.session.api_fetchers import VPNCertCredentialsFetcher, VPNSettingsFetcher
from proton.vpn.session.dataclasses import LoginResult
from proton.vpn.session.exceptions import (VPNCertificateExpiredError,
                                           VPNCertificateNeedRefreshError,
                                           VPNCertificateNotAvailableError)
from proton.vpn.session.pubkeycredentials import VPNPubkeyCredentials


class VPNUserPassCredentials(NamedTuple):
    """ Class responsible to hold vpn user/password credentials for authentication
    """
    username: str
    password: str


class VPNSession(Session):
    """
        Augmented Session that provides helpers to a persistent offline keyring access to user account information available from
        Proton API :

            - ProtonVPN settings and plan data fields.
            - ProtonVPN X509 certificates signed by the API.
            - Wireguard private key.

        - If the keyring does not contain such data or is expired, VPNSession will take care of refreshing it.
        - If the data is available through the keyring, it will be used as an off-line cache.
        - If there is the need to, data can still manually refresh with the :meth:`refresh()` method.

        Simple example use :

        .. code-block::

            from proton.vpn.session import VPNSession
            from proton.sso import ProtonSSO

            sso=ProtonSSO()
            vpnsession=sso.get_session(username, override_class=VPNSession)

            vpnsession.authenticate('USERNAME','PASSWORD')

            if vpnsession.authenticated:
                wireguard_private_key=vpnsession.vpn_account.vpn_credentials.pubkey_credentials.wg_private_key
                api_pem_certificate=vpn_account.vpn_credentials.pubkey_credentials.certificate_pem

    """

    def __init__(self, *args, **kwargs):
        self._vpninfo = None
        self._vpninfofetcher = VPNSettingsFetcher(session=self)
        self._vpncertcreds = None
        self._vpncertcredsfetcher = VPNCertCredentialsFetcher(session=self)
        self._vpn_pubkey_credentials = VPNPubkeyCredentials()
        super().__init__(*args, **kwargs)

    def __setstate__(self, data):
        try:
            self._vpninfo = VPNSettingsFetcher(_raw_data=data['vpn']['vpninfo']).fetch()
            private_key_bytes = base64.b64decode(data['vpn']['certcreds']['secrets']['ed25519_privatekey'])
            self._vpncertcreds = VPNCertCredentialsFetcher(_raw_data=data['vpn']['certcreds']['api_certificate'],_private_key=private_key_bytes).fetch()
            self._vpn_pubkey_credentials = VPNPubkeyCredentials()
            self._vpn_pubkey_credentials._refresh_and_check(self._vpncertcreds, strict=True)
            super().__setstate__(data)
        except KeyError:
            pass

    def __getstate__(self):
        d = super().__getstate__()
        if self._vpninfo and self._vpncertcreds and d != {}:
            d['vpn'] = {'vpninfo' : self._vpninfo.to_dict(), 'certcreds' : self._vpncertcreds.to_dict()}
        return d

    def login(self, username: str, password: str) -> LoginResult:
        if self.logged_in:
            return LoginResult(success=True, authenticated=True, twofa_required=False)

        if not self.authenticate(username, password):
            return LoginResult(success=False, authenticated=False, twofa_required=False)

        if self.needs_twofa:
            return LoginResult(success=False, authenticated=True, twofa_required=True)

        self.refresh()  # TODO: Laurent says we should not refresh the session manually
        return LoginResult(success=True, authenticated=True, twofa_required=False)

    def provide_2fa(self, code: str) -> LoginResult:
        valid_code = super().provide_2fa(code)
        if not valid_code:
            return LoginResult(success=False, authenticated=True, twofa_required=True)

        self.refresh()  # TODO: Laurent says we should not refresh the session manually
        return LoginResult(success=True, authenticated=True, twofa_required=False)

    def logout(self) -> bool:
        """ Logs out VPNSession, forgetting private key and certificate from memory (certificate will not be
            usable anymore anyway after logout)
        """
        self._vpninfo = None
        self._vpncertcredsfetcher = VPNCertCredentialsFetcher(session=self)
        self._vpn_pubkey_credentials = VPNPubkeyCredentials()
        return super().logout()

    @property
    def logged_in(self):
        return self.authenticated and not self.needs_twofa

    def refresh(self) -> None:
        """ Refresh VPNSession info from the API. This assumes that the session is authenticated.
            if not authenticated, this will raise :exc:`proton.session.exceptions.ProtonAPIAuthenticationNeeded` to the user.

            :raises VPNCertificateFingerprintError: certificate and key fingerprint do not match, try to refresh again.
        """
        self._vpninfofetcher.fetch_vpninfo()
        self._vpncertcredsfetcher.fetch_certcreds()
        self._vpn_pubkey_credentials._refresh_and_check(self._vpncertcreds, strict=True)

    def _try_go_get_certificate_holder(self) -> Optional[VPNPubkeyCredentials]:
        """ Return the object responsible to manage vpn client certificates and private keys.
        """
        try:
            _ = self._vpn_pubkey_credentials.certificate_pem
        except (VPNCertificateExpiredError, VPNCertificateNeedRefreshError, VPNCertificateNotAvailableError):
            self.refresh()

        return self._vpn_pubkey_credentials

    def _try_go_get_username_and_password(self) -> Optional[VPNUserPassCredentials]:
        """
        :return: :class:`VPNUserPassCredentials` usable credentials to login on ProtonVPN.
        """
        # VPN user and password are in vpn settings object as we simply
        # cache what's coming from the API.
        if self._vpninfo is None:
            self.refresh()

        return VPNUserPassCredentials(self._vpninfo.VPN.Name, self._vpninfo.VPN.Password)

    @property
    def vpn_account(self) -> VPNAccount:
        """
        :return: :class:`VPNAccount` that includes all information related to a vpn user account.
        """
        return VPNAccount(self)
