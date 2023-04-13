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
from typing import Optional, Sequence
from proton.vpn.session.credentials import VPNCredentials


class VPNAccount:
    """ This class is responsible to encapsulate all user vpn account information, including
        credentials (private keys, vpn user and password)
    """

    def __init__(self, vpnsession):
        self.__vpnsession = vpnsession

    @property
    def max_tier(self) -> Optional[int]:
        """
        :return: int `Maxtier` value of the acccount from :class:`api_data.VPNInfo`
        """
        if self.__vpnsession._vpninfo is not None:
            return self.__vpnsession._vpninfo.VPN.MaxTier
        else:
            return None

    @property
    def max_connections(self) -> Optional[int]:
        """
        :return: int the `MaxConnect` value of the acccount from :class:`api_data.VPNInfo`
        """
        if self.__vpnsession._vpninfo is not None:
            return self.__vpnsession._vpninfo.VPN.MaxConnect
        else:
            return None

    @property
    def delinquent(self) -> Optional[bool]:
        """
        :return: bool if the account is deliquent, based the value from :class:`api_data.VPNSettings`
        """
        if self.__vpnsession._vpninfo is not None:
            return True if self.__vpnsession._vpninfo.Delinquent > 2 else False
        else:
            return None

    @property
    def active_connections(self) -> Sequence["APIVPNSession"]:
        """
        :return: the list of active VPN session of the authenticated user on the infra
        """
        raise NotImplementedError

    @property
    def vpn_credentials(self) -> VPNCredentials:
        """ Return :class:`protonvpn.vpnconnection.interfaces.VPNCredentials` to
            provide an interface readily usable to instanciate a :class:`protonvpn.vpnconnection.VPNConnection`
        """
        return VPNCredentials(self.__vpnsession)
