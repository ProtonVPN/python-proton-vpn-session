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
