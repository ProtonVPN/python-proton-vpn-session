from .api_data import VPNSecrets, APIVPNSession, VPNCertCredentials
from .api_data import VPNSettingsFetcher, VPNCertCredentialsFetcher
from .certificates import Certificate
from .key_mgr import KeyHandler
import base64
from dataclasses import dataclass, fields
from proton.session import Session
from typing import Sequence, Optional, NamedTuple
from .exceptions import (VPNCertificateExpiredError,
                         VPNCertificateFingerprintError,
                         VPNCertificateNeedRefreshError,
                         VPNCertificateNotAvailableError)


class VPNUserPassCredentials(NamedTuple):
    """ Class responsible to hold vpn user/password credentials for authentication
    """
    username: str
    password: str


class VPNPubkeyCredentials:
    """ Class responsible to hold vpn public key API RAW certificates and
        and its associated private key for authentication.
    """

    MINIMUM_VALIDITY_PERIOD_IN_SECS=300

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
            if self._certificate_obj.validity_period > VPNPubkeyCredentials.MINIMUM_VALIDITY_PERIOD:
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
    def active_connections(self) -> Sequence['APIVPNSession']:
        """
        :return: the list of active VPN session of the authenticated user on the infra
        """
        raise NotImplementedError

    @property
    def vpn_credentials(self) -> 'VPNCredentials':
        """ Return :class:`protonvpn.vpnconnection.interfaces.VPNCredentials` to
            provide an interface readily usable to instanciate a :class:`protonvpn.vpnconnection.VPNConnection`
        """
        return VPNCredentials(self.__vpnsession)


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

    def authenticate(self, *args) -> bool:
        """Authenticate VPNSession. If the authentication is successfull, it will refresh as well :

            - VPN info
            - VPN Certificate and private key.

            :param username: Proton account username
            :type username: str
            :param password: Proton account password
            :type password: str
            :param no_condition_check: Internal flag to disable locking, defaults to False
            :type no_condition_check: bool, optional
            :return: True if authentication succeeded, False otherwise.
            :rtype: bool
        """
        auth = super().authenticate(*args)
        if auth:
            self.refresh()
        return auth

    def logout(self) -> bool:
        """ Logs out VPNSession, forgetting private key and certificate from memory (certificate will not be
            usable anymore anyway after logout)
        """
        self._vpninfo = None
        self._vpncertcredsfetcher = VPNCertCredentialsFetcher(session=self)
        self._vpn_pubkey_credentials = VPNPubkeyCredentials()
        return super().logout()

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
            pem_cert = self._vpn_pubkey_credentials.certificate_pem
        except (VPNCertificateExpiredError, VPNCertificateNeedRefreshError, VPNCertificateNotAvailableError):
            self.refresh()
        return self._vpn_pubkey_credentials

    def _try_go_get_username_and_password(self) -> Optional[VPNUserPassCredentials]:
        """
        :return: :class:`VPNUserPassCredentials` usable credentials to login on ProtonVPN.
        """
        # VPN user and password are in vpn settings object as we simply
        # cache what's coming from the API.
        if self._vpninfo is not None:
            return VPNUserPassCredentials(self._vpninfo.VPN.Name, self._vpninfo.VPN.Password)
        else:
            self.refresh()
            return VPNUserPassCredentials(self._vpninfo.VPN.Name, self._vpninfo.VPN.Password)

    @property
    def vpn_account(self) -> VPNAccount:
        """
        :return: :class:`VPNAccount` that includes all information related to a vpn user account.
        """
        return VPNAccount(self)





class VPNCredentials:
    """ Interface to :class:`proton.vpn.connection.interfaces.VPNCredentials`
        See :attr:`proton.vpn.session.VPNSession.vpn_account.vpn_credentials` to get one.
    """
    def __init__(self, vpnsession: VPNSession):
        self._vpnsession = vpnsession

    @property
    def pubkey_credentials(self) -> Optional[VPNPubkeyCredentials]:
        return self._vpnsession._try_go_get_certificate_holder()

    @property
    def userpass_credentials(self) -> Optional[VPNUserPassCredentials]:
        return self._vpnsession._try_go_get_username_and_password()
