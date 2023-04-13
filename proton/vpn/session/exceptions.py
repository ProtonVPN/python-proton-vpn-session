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


class VPNCertificateNotAvailableError(Exception):
    """ VPN Certificate data not available and should be reloaded by calling  :meth:`VPNSession.refresh`
    """


class VPNCertificateExpiredError(Exception):
    """ VPN Certificate is available but is expired, it should be refreshed with :meth:`VPNSession.refresh`
    """


class VPNCertificateNeedRefreshError(Exception):
    """ VPN Certificate is available but is expired, it should be refreshed with :meth:`VPNSession.refresh`
    """


class VPNCertificateFingerprintError(Exception):
    """ VPN Certificate and private key fingerprint are not matching, regenerate a key and get a new a certificate with
        the corresponding public key.
    """
