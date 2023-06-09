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
from proton.vpn.session.fetcher import VPNSessionFetcher
from proton.vpn.session.client_config import ClientConfig
from proton.vpn.session.credentials import VPNSecrets
from proton.vpn.session.dataclasses import LoginResult
from proton.vpn.session.servers.logicals import ServerList

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

    def __init__(
            self, *args,
            fetcher: Optional[VPNSessionFetcher] = None,
            vpn_account: Optional[VPNAccount] = None,
            server_list: Optional[ServerList] = None,
            client_config: Optional[ClientConfig] = None,
            **kwargs
    ):
        self._fetcher = fetcher or VPNSessionFetcher(session=self)
        self._vpn_account = vpn_account
        self._server_list = server_list
        self._client_config = client_config
        super().__init__(*args, **kwargs)

    @property
    def loaded(self) -> bool:
        """:returns: whether the VPN session data was already loaded or not."""
        return self._vpn_account and self._server_list and self._client_config

    def __setstate__(self, data):
        """This method is called when deserializing the session from the keyring."""
        try:
            if 'vpn' in data:
                self._vpn_account = VPNAccount.from_dict(data['vpn'])

                # Some session data like the server list is not deserialized from the keyring data,
                # but from plain json file due to its size.
                self._server_list = self._fetcher.load_server_list_from_cache()
                self._client_config = self._fetcher.load_client_config_from_cache()
        except ValueError:
            logger.exception("Error deserializing VPN session.")
        super().__setstate__(data)

    def __getstate__(self):
        """This method is called to retrieve the session data to be serialized in the keyring."""
        state = super().__getstate__()

        if state and self._vpn_account:
            state['vpn'] = self._vpn_account.to_dict()

        # Note the server list is not persisted to the keyring

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

        await self.async_fetch_session_data()
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

        await self.async_fetch_session_data()
        return LoginResult(success=True, authenticated=True, twofa_required=False)

    provide_2fa = sync_wrapper(async_provide_2fa)

    async def async_logout(self, no_condition_check=False, additional_headers=None) -> bool:
        """
        Log out and reset session data.
        """
        result = await super().async_logout()
        self._vpn_account = None
        self._server_list = None
        self._client_config = None
        self._fetcher.clear_cache()
        return result

    logout = sync_wrapper(async_logout)

    @property
    def logged_in(self) -> bool:
        """
        :returns: whether the user already logged in or not.
        """
        return self.authenticated and not self.needs_twofa

    async def async_fetch_session_data(self):
        """
        Fetches the required session data from Proton's REST APIs.
        """
        self._requests_lock()
        try:
            secrets = VPNSecrets(
                # pylint: disable=line-too-long  # noqa: E501
                ed25519_privatekey=self._vpn_account.vpn_credentials.pubkey_credentials.ed_255519_private_key
            ) if self._vpn_account else VPNSecrets()

            vpninfo, certificate, location, client_config = await asyncio.gather(
                self._fetcher.fetch_vpn_info(),
                self._fetcher.fetch_certificate(client_public_key=secrets.ed25519_pk_pem),
                self._fetcher.fetch_location(),
                self._fetcher.fetch_client_config()
            )

            self._vpn_account = VPNAccount(
                vpninfo=vpninfo, certificate=certificate, secrets=secrets, location=location
            )
            self._client_config = client_config

            # The server list should be retrieved after the VPNAccount object
            # has been created, since it requires the location.
            self._server_list = await self._fetcher.fetch_server_list()
        finally:
            # IMPORTANT: apart from releasing the lock, _requests_unlock triggers the
            # serialization of the session to the keyring.
            self._requests_unlock()

    fetch_session_data = sync_wrapper(async_fetch_session_data)

    @property
    def vpn_account(self) -> VPNAccount:
        """
        Information related to the VPN user account.
        If it was not loaded yet then None is returned instead.
        """
        return self._vpn_account

    async def async_fetch_server_list(self) -> ServerList:
        """
        Fetches the server list from the REST API.
        """
        self._server_list = await self._fetcher.fetch_server_list()
        return self._server_list

    fetch_server_list = sync_wrapper(async_fetch_server_list)

    @property
    def server_list(self) -> ServerList:
        """The current server list."""
        return self._server_list

    async def async_update_server_loads(self) -> ServerList:
        """
        Fetches the server loads from the REST API and updates the current
        server list with them.
        """
        self._server_list = await self._fetcher.update_server_loads()
        return self._server_list

    update_server_loads = sync_wrapper(async_update_server_loads)

    async def async_fetch_client_config(self) -> ClientConfig:
        """Fetches the client configuration from the REST api."""
        self._client_config = await self._fetcher.fetch_client_config()
        return self._client_config

    fetch_client_config = sync_wrapper(async_fetch_client_config)

    @property
    def client_config(self) -> ClientConfig:
        """The current client configuration."""
        return self._client_config
