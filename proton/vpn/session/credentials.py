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
from typing import Optional


class VPNCredentials:
    """ Interface to :class:`proton.vpn.connection.interfaces.VPNCredentials`
        See :attr:`proton.vpn.session.VPNSession.vpn_account.vpn_credentials` to get one.
    """
    def __init__(self, vpnsession: "VPNSession"):
        self._vpnsession = vpnsession

    @property
    def pubkey_credentials(self) -> Optional["VPNPubkeyCredentials"]:
        return self._vpnsession._try_go_get_certificate_holder()

    @property
    def userpass_credentials(self) -> Optional["VPNUserPassCredentials"]:
        return self._vpnsession._try_go_get_username_and_password()
