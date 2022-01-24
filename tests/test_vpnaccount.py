from curses import raw
import pytest
import json
import base64
from protonvpn.vpnaccount import VPNAccount, VPNUserPass, VPNAccountReloadVPNData, VPNCertificateNotAvailableError, VPNCertificateExpiredError, VPNCertificateFingerprintError
from protonvpn.vpnaccount.api_data import VPNSettings, VPNSettingsFetcher
from protonvpn.vpnaccount.api_data import VPNCertificate, VPNCertCredentials, VPNCertCredentialsFetcher
from protonvpn.vpnaccount.api_data import VPNSessions
from protonvpn.vpnaccount.api_data import VPNSecrets
from protonvpn.vpnaccount.key_mgr import KeyHandler
from protonvpn.vpnaccount.certificates import Certificate


class TestVpnAccountSerialize:
    @classmethod
    def setup_class(cls):
        with open('tests/data/api_cert_response.json','r') as f:
            cls.VPN_CLIENT_CERT_RAW_DATA=f.read()
            cls.api_certificate=json.loads(cls.VPN_CLIENT_CERT_RAW_DATA)
        with open('tests/data/api_vpnsettings_response.json','r') as f:
            cls.VPN_API_RAW_DATA=f.read()
        with open('tests/data/api_vpnsessions_response.json','r') as f:
            cls.VPN_SESSIONS_FROM_API_RAW_DATA=f.read()
        with open('tests/data/vpn_secrets.json','r') as f:
            cls.VPN_CLIENT_SECRET_RAW_DATA=f.read()
            cls.secrets=json.loads(cls.VPN_CLIENT_SECRET_RAW_DATA)
            #print(cls.secrets)

    def test_fingerprints(self):
        # Check if our fingerprints are matching for secrets, API and Certificate
        # Get fingerprint from the secrets. Wireguard private key from the API is in ED25519 FORMAT ?
        ovpn_priv_key = TestVpnAccountSerialize.secrets["openvpn_privatekey"]
        with open('/tmp/ovpn_privkey.pem','w') as f:
            f.write(ovpn_priv_key)
        keyhandler=KeyHandler.from_sk_file('/tmp/ovpn_privkey.pem')

        fingerprint_from_secrets=keyhandler.get_proton_fingerprint_from_x25519_pk(keyhandler.x25519_pk_bytes)
        # Get fingerprint from API
        fingerprint_from_api = TestVpnAccountSerialize.api_certificate["ClientKeyFingerprint"]
        # Get fingerprint from Certificate
        certificate = Certificate(cert_pem=TestVpnAccountSerialize.api_certificate["Certificate"])
        fingerprint_from_certificate=certificate.proton_fingerprint
        assert(fingerprint_from_api==fingerprint_from_certificate)
        #==fingerprint_from_secrets)

    def test_vpnaccount_data_unserialize(self):
        vpnaccount = VPNSettings.from_json(TestVpnAccountSerialize.VPN_API_RAW_DATA)
        assert(vpnaccount.VPN.Name=="test")
        assert(vpnaccount.VPN.Password=="passwordtest")
    
    def test_vpnaccount_data_serialize(self):
        vpnaccount = VPNSettings.from_json(TestVpnAccountSerialize.VPN_API_RAW_DATA)
        json.loads(vpnaccount.to_json())

    def test_vpnsettings_fetcher(self):
        vpnaccount=VPNSettingsFetcher(json.loads(TestVpnAccountSerialize.VPN_API_RAW_DATA)).fetch()
        assert(vpnaccount.VPN.Name=="test")
        assert(vpnaccount.VPN.Password=="passwordtest")


    def test_cert_unserialize(self):
        cert=VPNCertificate.from_json(TestVpnAccountSerialize.VPN_CLIENT_CERT_RAW_DATA)
        assert(cert.SerialNumber=="154197323")
        assert(cert.ClientKeyFingerprint=="a3CzIFFDKF5w4CtPDaz8mWZWzljRb+SqGTkvktCqznMhUemScDonoinYDz8ncOfQw7WI0Ek5aombSVSITnQDTw==")
        assert(cert.ClientKey=="-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAoqBxaQgj21lzBd9YG0iotoSoHLXQDYS2LdDtiE6Jtk=\n-----END PUBLIC KEY-----")
        assert(cert.Certificate=="-----BEGIN CERTIFICATE-----\nMIICJjCCAdigAwIBAgIECTDdSzAFBgMrZXAwMTEvMC0GA1UEAwwmUHJvdG9uVlBO\nIENsaWVudCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMjIwMTIwMjAyOTIxWhcN\nMjIwMTIxMjAyOTIyWjAUMRIwEAYDVQQDDAkxNTQxOTczMjMwKjAFBgMrZXADIQAC\nioHFpCCPbWXMF31gbSKi2hKgctdANhLYt0O2ITom2aOCAS0wggEpMB0GA1UdDgQW\nBBS/pHNS2Vf2irz16Cu8uw07PZHJ9zATBgwrBgEEAYO7aQEAAAAEAwIBADATBgwr\nBgEEAYO7aQEAAAEEAwIBATBQBgwrBgEEAYO7aQEAAAIEQDA+BAh2cG5iYXNpYwQY\ndnBuLWF1dGhvcml6ZWQtZm9yLWNoLTMyBBh2cG4tYXV0aG9yaXplZC1mb3ItY2gt\nMzMwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYB\nBQUHAwIwWQYDVR0jBFIwUIAUs+HMEJai+CKly9zPRAZGLOuSzgWhNaQzMDExLzAt\nBgNVBAMMJlByb3RvblZQTiBDbGllbnQgQ2VydGlmaWNhdGUgQXV0aG9yaXR5ggEB\nMAUGAytlcANBAKK+E6d7Rxn7X1u4s4AtJuD3kj6UjBEC3cFr3+A+tiV/THc19Qkr\n666A5Ass0n2LsjENVnAJ9VQ6x5lg7011sQk=\n-----END CERTIFICATE-----\n")
        assert(cert.ExpirationTime==1642796962)
        assert(cert.RefreshTime==1642775362)
        assert(cert.Mode=="session")
        assert(cert.DeviceName=="")
        assert(cert.ServerPublicKeyMode=="EC")
        assert(cert.ServerPublicKey=="-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEANm3aIvkeaMO9ctcIeEfM4K1ME3bU9feum5sWQ3Sdx+o=\n\
-----END PUBLIC KEY-----\n")

    def test_cert_serialize(self):
        cert=VPNCertificate.from_json(TestVpnAccountSerialize.VPN_CLIENT_CERT_RAW_DATA)
        json.loads(cert.to_json())

    def test_secrets_unserialize(self):
        secrets=VPNSecrets.from_json(TestVpnAccountSerialize.VPN_CLIENT_SECRET_RAW_DATA)
        assert(secrets.wireguard_privatekey=="GIbDx5QIf9aqrbIjI5jgNEQ6O7oqCse7mqkmM7Mrk3g=")
        assert(secrets.openvpn_privatekey=="-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIKzVt3S+QN3VK0F92Sm1QBS40hSXbw1OSc460a5yPnKL\n-----END PRIVATE KEY-----\n")
        assert(secrets.ed25519_privatekey=="rNW3dL5A3dUrQX3ZKbVAFLjSFJdvDU5JzjrRrnI+cos=")

    def test_secrets_serialize(self):
        secrets=VPNSecrets.from_json(TestVpnAccountSerialize.VPN_CLIENT_SECRET_RAW_DATA)
        json.loads(secrets.to_json())

    def test_cert_credentials_builder(self):
        cert=json.loads(TestVpnAccountSerialize.VPN_CLIENT_CERT_RAW_DATA)
        secrets=json.loads(TestVpnAccountSerialize.VPN_CLIENT_SECRET_RAW_DATA)
        cert_cred=VPNCertCredentials.from_dict(cert, secrets)

    def test_sessions_unserialize(self):
        sessions=VPNSessions.from_json(TestVpnAccountSerialize.VPN_SESSIONS_FROM_API_RAW_DATA)
        assert(len(sessions.Sessions)==2)
        assert(sessions.Sessions[0].ExitIP=='1.2.3.4')
        assert(sessions.Sessions[1].ExitIP=='5.6.7.8')


class TestVpnAccountFunction:

    def test_vpnsettings_must_reload(self):
        account=VPNAccount('test')
        account.clear()
        with pytest.raises(VPNAccountReloadVPNData):
            vpnaccount=account.vpn_get_username_and_password()
        account.clear()

    def test_vpnsettings_with_keyring(self):
        account=VPNAccount('test')
        account.vpn_reload_settings(VPNSettings.from_json(TestVpnAccountSerialize.VPN_API_RAW_DATA))
        vpnaccount=account.vpn_get_username_and_password()
        assert(account.max_tier==0)
        assert(account.vpn_max_connections==2)
        assert(account.delinquent is False)
        assert(vpnaccount.username=="test")
        assert(vpnaccount.password=="passwordtest")
        account.clear()
    
    def test_vpncertificate_must_reload(self):
        account=VPNAccount('test')
        account.clear()
        assert(account.vpn_get_certificate_holder() is not None)
        with pytest.raises(VPNCertificateNotAvailableError):
            pem_cert=account.vpn_get_certificate_holder().vpn_client_api_pem_certificate()
        with pytest.raises(VPNCertificateNotAvailableError):
            wg_key=account.vpn_get_certificate_holder().vpn_client_private_wg_key()
        with pytest.raises(VPNCertificateNotAvailableError):
            ovpn_priv_pem_key = account.vpn_get_certificate_holder().vpn_client_private_openvpn_key()
        account.clear()

    def test_vpncertificates_with_keyring(self):
        account=VPNAccount('test')
        account.clear()
        cert_dict = json.loads(TestVpnAccountSerialize.VPN_CLIENT_CERT_RAW_DATA)
        ed25519_privatekey=TestVpnAccountSerialize.secrets["ed25519_privatekey"]
        kh = KeyHandler(private_key=base64.b64decode(ed25519_privatekey))
        account.vpn_reload_cert_credentials(VPNCertCredentialsFetcher(_raw_data=cert_dict, _private_key=kh.ed25519_sk_bytes).fetch())

        # WARNING :
        # - Don't give X25519 private key to the fetcher, it's expecting ED25519 private key ONLY to generate X25519 private key.
        with pytest.raises(VPNCertificateFingerprintError):
            account.vpn_reload_cert_credentials(VPNCertCredentialsFetcher(_raw_data=cert_dict, _private_key=kh.x25519_sk_bytes).fetch())

        account.clear()

    def test_expired_certificate(self):
        pass