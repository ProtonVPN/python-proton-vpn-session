
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
