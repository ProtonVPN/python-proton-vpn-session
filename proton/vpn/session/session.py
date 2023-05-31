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
import asyncio
from typing import Optional

from proton.session import Session
from proton.session.api import sync_wrapper

from proton.vpn import logging
from proton.vpn.session.account import VPNAccount
from proton.vpn.session.api_fetchers import VPNAccountFetcher
from proton.vpn.session.credentials import VPNSecrets
from proton.vpn.session.dataclasses import LoginResult
from proton.vpn.session.exceptions import VPNCertificateError

logger = logging.getLogger(__name__)


class VPNSession(Session):
    """
    Augmented Session that provides helpers to a persistent offline keyring
    access to user account information available from the PROTON VPN REST API.

    Usage example:

    .. code-block::

        from proton.vpn.session import VPNSession
        from proton.sso import ProtonSSO

        sso = ProtonSSO()
        session=sso.get_session(username, override_class=VPNSession)

        session.authenticate('USERNAME','PASSWORD')

        if session.authenticated:
            pubkey_credentials = session.vpn_account.vpn_credentials.pubkey_credentials
            wireguard_private_key = pubkey_credentials.wg_private_key
            api_pem_certificate = pubkey_credentials.certificate_pem

    """

    def __init__(self, *args, **kwargs):
        self._fetcher = VPNAccountFetcher(session=self)
        self._vpn_account: VPNAccount = None
        super().__init__(*args, **kwargs)

    def __setstate__(self, data):
        try:
            if 'vpn' in data:
                self._vpn_account = VPNAccount.from_dict(data['vpn'])
        except VPNCertificateError:
            logger.exception("Error loading persisted VPN account")
        super().__setstate__(data)

    def __getstate__(self):
        state = super().__getstate__()

        if state and self._vpn_account:
            state['vpn'] = self._vpn_account.to_dict()

        return state

    async def async_login(self, username: str, password: str) -> LoginResult:
        """
        Logs the user in.
        :returns: the login result, indicating whether it was successful
        and whether 2FA is required or not.
        """
        if self.logged_in:
            return LoginResult(success=True, authenticated=True, twofa_required=False)

        if not await self.async_authenticate(username, password):
            return LoginResult(success=False, authenticated=False, twofa_required=False)

        if self.needs_twofa:
            return LoginResult(success=False, authenticated=True, twofa_required=True)

        await self.async_refresh_vpn_account()
        return LoginResult(success=True, authenticated=True, twofa_required=False)

    login = sync_wrapper(async_login)

    async def async_provide_2fa(self, code: str) -> LoginResult:  # pylint: disable=arguments-differ
        """
        Submits the 2FA code.
        :returns: whether the 2FA was successful or not.
        """
        valid_code = await super().async_provide_2fa(code)
        if not valid_code:
            return LoginResult(success=False, authenticated=True, twofa_required=True)

        await self.async_refresh_vpn_account()
        return LoginResult(success=True, authenticated=True, twofa_required=False)

    provide_2fa = sync_wrapper(async_provide_2fa)

    async def async_logout(self, no_condition_check=False, additional_headers=None) -> bool:
        """
        Logs out VPNSession, forgetting private key and certificate from memory
        (certificate will not be usable anymore anyway after logout).
        """
        self._vpn_account = None
        return await super().async_logout()

    logout = sync_wrapper(async_logout)

    @property
    def logged_in(self) -> bool:
        """
        :returns: whether the user already logged in or not.
        """
        return self.authenticated and not self.needs_twofa

    async def async_refresh_vpn_account(self) -> VPNAccount:
        """
        Updates the session with data from the /vpn REST APIs.
        """
        self._requests_lock()
        try:
            secrets = VPNSecrets(
                ed25519_privatekey=self._vpn_account.vpn_credentials.pubkey_credentials.ed_255519_private_key  # pylint: disable=line-too-long
            ) if self._vpn_account else VPNSecrets()

            vpninfo, certificate, location = await asyncio.gather(
                self._fetcher.fetch_vpn_info(),
                self._fetcher.fetch_certificate(client_public_key=secrets.ed25519_pk_pem),
                self._fetcher.fetch_location()
            )

            self._vpn_account = VPNAccount(
                vpninfo=vpninfo, certificate=certificate, secrets=secrets, location=location
            )
        finally:
            # IMPORTANT: apart from releasing the lock, _requests_unlock triggers the
            # serialization of the session to the keyring.
            self._requests_unlock()

        return self._vpn_account

    refresh_vpn_account = sync_wrapper(async_refresh_vpn_account)

    @property
    def vpn_account(self) -> Optional[VPNAccount]:
        """
        :returns: the information related to the VPN user account.
        If it was not loaded yet then None is returned instead.
        """
        return self._vpn_account
