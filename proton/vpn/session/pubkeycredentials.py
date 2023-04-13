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
from typing import Optional
from proton.vpn.session.key_mgr import KeyHandler
from proton.vpn.session.certificates import Certificate
from proton.vpn.session.dataclasses import VPNSecrets
from proton.vpn.session.exceptions import (VPNCertificateExpiredError,
                                           VPNCertificateFingerprintError,
                                           VPNCertificateNeedRefreshError,
                                           VPNCertificateNotAvailableError)


class VPNPubkeyCredentials:
    """ Class responsible to hold vpn public key API RAW certificates and
        and its associated private key for authentication.
    """

    MINIMUM_VALIDITY_PERIOD_IN_SECS = 300

    def __init__(self):
        self._raw_vpn_cert_creds: Optional[VPNSecrets] = None
        self._certificate_obj = None

    def _refresh_and_check(self, raw_vpn_cert_creds: 'VPNCertCredentials', strict):
        """ Refresh certificate and secrets. They are tested for consistency and must share the
            same fingerprint and be valid, otherwhise an Exception will be raised.
        """
        # Get fingerprint from ED25519 private key
        keyhandler = KeyHandler(
            private_key=base64.b64decode(raw_vpn_cert_creds.secrets.ed25519_privatekey)
        )
        fingerprint_from_secrets = keyhandler.get_proton_fingerprint_from_x25519_pk(
            keyhandler.x25519_pk_bytes
        )

        # Get fingerprint from Certificate public key
        certificate = Certificate(cert_pem=raw_vpn_cert_creds.api_certificate.Certificate)
        fingerprint_from_certificate = certificate.proton_fingerprint

        # Refuse to store unmatching fingerprints when strict equal True
        if strict:
            if fingerprint_from_secrets != fingerprint_from_certificate:
                raise VPNCertificateFingerprintError

        self._raw_vpn_cert_creds = raw_vpn_cert_creds
        self._certificate_obj = Certificate(cert_pem=raw_vpn_cert_creds.api_certificate.Certificate)

    @property
    def certificate_pem(self) -> str:
        """ X509 client certificate in PEM format, can be used to connect for client based authentication to the local agent

            :raises VPNCertificateNotAvailableError: : certificate cannot be found :class:`VPNSession` must be populated with :meth:`VPNSession.refresh`
            :raises VPNCertificateNeedRefreshError: : certificate is expiring soon, refresh asap with :meth:`VPNSession.refresh`
            :raises VPNCertificateExpiredError: : certificate is expired
            :return: :class:`api_data.VPNCertificate.Certificate`
        """
        if self._certificate_obj is not None:
            if not self._certificate_obj.has_valid_date:
                raise VPNCertificateExpiredError
            if self._certificate_obj.validity_period > VPNPubkeyCredentials.MINIMUM_VALIDITY_PERIOD_IN_SECS:
                return self._certificate_obj.get_as_pem()
            else:
                raise VPNCertificateNeedRefreshError
        else:
            raise VPNCertificateNotAvailableError

    @property
    def wg_private_key(self) -> str:
        """ Get Wireguard private key in base64 format, directly usable in a wireguard configuration file. This key
            is tighed to the Proton :class:`VPNCertCredentials` by its corresponding API certificate.
            If the corresponding certificate is expired an :exc:`VPNCertificateNotAvailableError` will be trigged to the user, meaning
            that the user will have to reload a new certificate and secrets using :meth:`VPNSession.refresh`.

            :raises VPNCertificateNotAvailableError: : certificate cannot be found :class:`VPNSession` must be populated with :meth:`VPNSession.refresh`
            :raises VPNCertificateNeedRefreshError: : certificate linked to the key is expiring soon, refresh asap with :meth:`VPNSession.refresh`
            :raises VPNCertificateExpiredError: : certificate is expired
            :return: :class:`api_data.VPNSecrets.wireguard_privatekey`: Wireguard private key in base64 format.
        """
        if self._certificate_obj is not None:
            if not self._certificate_obj.has_valid_date:
                raise VPNCertificateExpiredError
            if self._certificate_obj.validity_period > VPNPubkeyCredentials.MINIMUM_VALIDITY_PERIOD_IN_SECS:
                return self._raw_vpn_cert_creds.secrets.wireguard_privatekey
            else:
                raise VPNCertificateNeedRefreshError
        else:
            raise VPNCertificateNotAvailableError

    @property
    def openvpn_private_key(self) -> str:
        """ Get OpenVPN private key in PEM format, directly usable in a openvpn configuration file. If the corresponding
            certificate is expired an :exc:`VPNCertificateNotAvailableError` will be trigged to the user.

            :raises VPNCertificateNotAvailableError: : certificate cannot be found :class:`VPNSession` must be populated with :meth:`VPNSession.refresh`
            :raises VPNCertificateNeedRefreshError: : certificate linked to the key is expiring soon, refresh asap with :meth:`VPNSession.refresh`
            :raises VPNCertificateExpiredError: : certificate is expired
            :return: :class:`api_data.VPNSecrets.openvpn_privatekey`: OpenVPN private key in PEM format.
        """
        if self._certificate_obj is not None:
            if not self._certificate_obj.has_valid_date:
                raise VPNCertificateExpiredError
            if self._certificate_obj.validity_period > 60:
                return self._raw_vpn_cert_creds.secrets.openvpn_privatekey
            else:
                raise VPNCertificateNeedRefreshError
        else:
            raise VPNCertificateNotAvailableError

    @property
    def ed_255519_private_key(self) -> bytes:
        if self._certificate_obj is not None:
            return base64.b64decode(self._raw_vpn_cert_creds.secrets.ed25519_privatekey)
        else:
            raise VPNCertificateNotAvailableError

    @property
    def certificate_validity_remaining(self) -> Optional[float]:
        """ remaining time the certificate is valid, in seconds.

            - < 0 : certificate is not valid anymore
            -  None we don't have a certificate.
        """
        if self._certificate_obj is None:
            return None
        else:
            return self._certificate_obj.validity_period

    @property
    def proton_extensions(self):
        if self._certificate_obj is None:
            return None
        else:
            return self._certificate_obj.proton_extensions

    @property
    def certificate_duration(self) -> Optional[float]:
        """ certificate range in seconds, even if not valid anymore.

            - return `None` if we don't have a certificate
        """
        if self._certificate_obj is None:
            return None
        else:
            return self._certificate_obj.duration.total_seconds()
