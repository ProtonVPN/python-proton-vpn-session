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

import base64

from proton.session.api import sync_wrapper
from proton.session import ProtonAPIError
from proton.vpn.session.dataclasses import (VPNCertCredentials, VPNCertificate,
                                            VPNSecrets, VPNSessions,
                                            VPNSettings)

from .key_mgr import KeyHandler


class VPNSettingsFetcher:
    """ Helper class to retrieve a :class:`VPNSettings` object from the API. If
        can be initialized directly with the raw data coming from the API, or
        provided with a Proton session object.
    """
    ROUTE = '/vpn'

    def __init__(self, _raw_data: dict = None, session: "VPNSession" = None):
        self._session = session
        self._raw_data = _raw_data

    def _fetch_raw_data(self) -> None:
        self._raw_data = self._session.api_request(VPNSettingsFetcher.ROUTE)

    async def _async_fetch_raw_data(self) -> None:
        self._raw_data = await self._session.async_api_request(VPNSettingsFetcher.ROUTE)

    async def async_fetch(self) -> 'VPNSettings':
        if self._raw_data is None:
            await self._async_fetch_raw_data()
        return VPNSettings.from_dict(self._raw_data)

    def fetch(self) -> 'VPNSettings':
        """ Return a :class:`VPNSettings` from a local cache or fetch it
            from the API if not available.
        """
        if self._raw_data is None:
            self._fetch_raw_data()
        return VPNSettings.from_dict(self._raw_data)

    async def async_fetch_vpninfo(self, no_condition_check=False) -> None:
        self._session._requests_lock(no_condition_check)

        try:
            vpninfo = await self._session.async_api_request(VPNSettingsFetcher.ROUTE, no_condition_check=True)
            self._session._vpninfo = VPNSettings.from_dict(vpninfo)
        except ProtonAPIError:
            raise
        finally:
            self._session._requests_unlock(no_condition_check)

    fetch_vpninfo = sync_wrapper(async_fetch_vpninfo)


class VPNCertCredentialsFetcher:
    """ Helper class to retrieve a :class:`VPNCertCredentials` object from the API. Same
        use as :class:`VPNSettingsFetcher`. This class also generates a private/public key pair
        locally at initialization time that will be available in the :class:`VPNCertCredentials`.
        cert_curation is in minutes.
    """
    ROUTE = '/vpn/v1/certificate'

    def __init__(
        self, _raw_data: dict = None, _private_key=None,
        cert_duration_in_minutes: int = 1440, features=None,
        session: "VPNSession" = None
    ):

        if _private_key is not None:
            self._keys = KeyHandler(private_key=_private_key)
        else:
            # This will generate a new set key with a different fingerprint.
            self._keys = KeyHandler()

        self._cert_duration = str(cert_duration_in_minutes) + " min"
        self._session = session
        self._features = features
        self._raw_api_cert_data = _raw_data

    def _fetch_raw_data(self) -> None:
        json_req = {"ClientPublicKey": self._keys.ed25519_pk_pem,
                    "Duration": self._cert_duration
                    }
        if self._features:
            json_req["Features"] = self._features
        self._raw_api_cert_data = self._session.api_request(VPNCertCredentialsFetcher.ROUTE, jsondata=json_req)

    def fetch(self) -> 'VPNCertCredentials':
        """ Return a :class:`VPNCertCredentials` from a local cache or fetch it
            from the API if not available.
        """
        if self._raw_api_cert_data is None:
            self._fetch_raw_data()

        return VPNCertCredentials(
            VPNCertificate.from_dict(self._raw_api_cert_data),
            VPNSecrets(
                wireguard_privatekey=self._keys.x25519_sk_str,
                openvpn_privatekey=self._keys.ed25519_sk_pem,
                ed25519_privatekey=base64.b64encode(self._keys.ed25519_sk_bytes).decode('ascii')
            )
        )

    async def async_fetch_certcreds(self, no_condition_check=False) -> None:
        self._session._requests_lock(no_condition_check)
        json_req = {"ClientPublicKey": self._keys.ed25519_pk_pem,
                    "Duration": self._cert_duration
                    }
        if self._features:
            json_req["Features"] = self._features

        try:
            raw_api_cert_data = await self._session.async_api_request(
                VPNCertCredentialsFetcher.ROUTE,
                jsondata=json_req,
                no_condition_check=True
            )

            self._session._vpncertcreds = VPNCertCredentials(
                VPNCertificate.from_dict(raw_api_cert_data),
                VPNSecrets(
                    wireguard_privatekey=self._keys.x25519_sk_str,
                    openvpn_privatekey=self._keys.ed25519_sk_pem,
                    ed25519_privatekey=base64.b64encode(self._keys.ed25519_sk_bytes).decode('ascii')
                )
            )
        except ProtonAPIError:
            raise
        finally:
            self._session._requests_unlock(no_condition_check)

    fetch_certcreds = sync_wrapper(async_fetch_certcreds)


class VPNSessionsFetcher:
    """ Helper class to retrieve a :class:`VPNSessions` object from the API. If
        can be initialized directly with the raw data coming from the API, or
        provided with a Proton session object.
    """

    ROUTE = '/vpn/sessions'

    def __init__(self, _raw_data: dict = None, session: "VPNSession" = None):
        self._session = session
        self._raw_data = _raw_data

    def _fetch_raw_data(self) -> None:
        self._raw_data = self._session.api_request(VPNSessionsFetcher.ROUTE)

    def fetch(self) -> 'VPNSessions':
        """ Return a :class:`VPNSessions` from a local cache or fetch it
            from the API if not available.
        """
        if self._raw_data is None:
            self._fetch_raw_data()
        return VPNSessions.from_dict(self._raw_data)
