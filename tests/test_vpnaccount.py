import pytest
import json
from protonvpn.vpnaccount import VPNAccount, VPNUserPass, VPNAccountReloadVPNData
from protonvpn.vpnaccount.api_data import VPNSettings, VPNSettingsFetcher
from protonvpn.vpnaccount.api_data import VPNCertificate, VPNCertCredentials, VPNCertCredentialsFetcher
from protonvpn.vpnaccount.api_data import VPNSessions
from protonvpn.vpnaccount.api_data import VPNSecrets


class TestVpnAccount:
    VPN_API_DATA="""
{
"Code": 1000,

"VPN": {
    "ExpirationTime": 1,
    "Name": "test",
    "Password": "passwordtest",
    "GroupID": "testgroup",
    "Status": 1,
    "PlanName": "free",
    "PlanTitle": null,
    "MaxTier": 0,
    "MaxConnect": 2,
    "Groups": [
    "vpnfree"
    ],
    "NeedConnectionAllocation": false
},

"Services": 5,
"Subscribed": 0,
"Delinquent": 0,
"HasPaymentMethod": 1,
"Credit": 17091,
"Currency": "EUR",
"Warnings": []
}
"""
    VPN_CLIENT_CERT_DATA="""
{
  "Code": 1000,
  "SerialNumber": "143175174",
  "ClientKeyFingerprint": "Aj3O9pYE0ABRwIEG5LOcxVmMTqM2JxGOOnPZZkc8/OzM47zNoBBx0NIgiLLFwCHT5Qq7A9+MaZB5TGSuW1Focg==",
  "ClientKey": "-----BEGIN PUBLIC KEY-----\\n\
MCowBQYDK2VwAyEAqlMgclyVELA2fcTtGQe3gI4vnRVBtnMuDkzju5Sfr74=\\n\
-----END PUBLIC KEY-----",
  "Certificate": "-----BEGIN CERTIFICATE-----\\n\
MIIB7zCCAaGgAwIBAgIECIiuBjAFBgMrZXAwMTEvMC0GA1UEAwwmUHJvdG9uVlBO\\n\
IENsaWVudCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMjIwMTEyMDcxNzExWhcN\\n\
MjIwMTEzMDcxNzEyWjAUMRIwEAYDVQQDDAkxNDMxNzUxNzQwKjAFBgMrZXADIQCq\\n\
UyByXJUQsDZ9xO0ZB7eAji+dFUG2cy4OTOO7lJ+vvqOB9zCB9DAdBgNVHQ4EFgQU\\n\
xdRQtpXWDLqtyI4p9Pi7rlrTyuowEwYMKwYBBAGDu2kBAAAABAMCAQAwEwYMKwYB\\n\
BAGDu2kBAAABBAMCAQIwGwYMKwYBBAGDu2kBAAACBAswCQQHdnBucGx1czAOBgNV\\n\
HQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDAjBZ\\n\
BgNVHSMEUjBQgBSz4cwQlqL4IqXL3M9EBkYs65LOBaE1pDMwMTEvMC0GA1UEAwwm\\n\
UHJvdG9uVlBOIENsaWVudCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHmCAQEwBQYDK2Vw\\n\
A0EAkt/ZJlKcrc+FpkV4fZA7VmaGNkpFWhwRNttZBFcaLYw82LxOZKQbox2tewrt\\n\
Bvq8ArmKTRnE5P2+mBECko0LBg==\\n\
-----END CERTIFICATE-----\\n",
  "ExpirationTime": 1642058232,
  "RefreshTime": 1642036632,
  "Mode": "session",
  "DeviceName": "",
  "ServerPublicKeyMode": "EC",
  "ServerPublicKey": "-----BEGIN PUBLIC KEY-----\\n\
MCowBQYDK2VwAyEANm3aIvkeaMO9ctcIeEfM4K1ME3bU9feum5sWQ3Sdx+o=\\n\
-----END PUBLIC KEY-----\\n"
}
"""
    VPN_SESSIONS_FROM_API_DATA="""
{
    "Sessions": [
    {
    "SessionID": "9A35C20A09AC0833157B320C408CD679",
    "ExitIP": "1.2.3.4",
    "Protocol": "openvpn"
    },
    {
    "SessionID": "9A35C20A09AC0833157B320C408CD67A",
    "ExitIP": "5.6.7.8",
    "Protocol": "openvpn"
    }
    ]
}
"""
    VPN_CLIENT_SECRET_DATA="""{
"wireguard_privatekey": "0EU72yx+FbzuKW1gSOCaSM+zcaA+AcVjv6d31nxtDH4=",
"openvpn_privatekey": "-----BEGIN PRIVATE KEY-----\\n\
MC4CAQAwBQYDK2VwBCIEIMP3LkF1P16bARSzAaJEcTCfYbSUqDYSlBQcF16tHn5Q\\n\
-----END PRIVATE KEY-----\\n"
}
"""
    def test_vpnaccount_data_unserialize(self):
        vpnaccount = VPNSettings.from_json(TestVpnAccount.VPN_API_DATA)
        assert(vpnaccount.VPN.Name=="test")
        assert(vpnaccount.VPN.Password=="passwordtest")
    
    def test_vpnaccount_data_serialize(self):
        vpnaccount = VPNSettings.from_json(TestVpnAccount.VPN_API_DATA)
        json.loads(vpnaccount.to_json())

    def test_vpnsettings_fetcher(self):
        vpnaccount=VPNSettingsFetcher(json.loads(TestVpnAccount.VPN_API_DATA)).fetch()
        assert(vpnaccount.VPN.Name=="test")
        assert(vpnaccount.VPN.Password=="passwordtest")

    def test_vpnsettings_must_reload(self):
        account=VPNAccount('test')
        account.clear()
        with pytest.raises(VPNAccountReloadVPNData):
            vpnaccount=account.get_username_and_password()
    
    def test_vpnsettings_with_keyring(self):
        account=VPNAccount('test')
        account.reload_vpn_settings(VPNSettings.from_json(TestVpnAccount.VPN_API_DATA))
        vpnaccount=account.get_username_and_password()
        assert(vpnaccount.username=="test")
        assert(vpnaccount.password=="passwordtest")
        account.clear()

    def test_cert_unserialize(self):
        cert=VPNCertificate.from_json(TestVpnAccount.VPN_CLIENT_CERT_DATA)
        assert(cert.SerialNumber=="143175174")
        assert(cert.ClientKeyFingerprint=="Aj3O9pYE0ABRwIEG5LOcxVmMTqM2JxGOOnPZZkc8/OzM47zNoBBx0NIgiLLFwCHT5Qq7A9+MaZB5TGSuW1Focg==")
        assert(cert.ClientKey=="-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAqlMgclyVELA2fcTtGQe3gI4vnRVBtnMuDkzju5Sfr74=\n\
-----END PUBLIC KEY-----"
        )
        assert(cert.Certificate=="-----BEGIN CERTIFICATE-----\n\
MIIB7zCCAaGgAwIBAgIECIiuBjAFBgMrZXAwMTEvMC0GA1UEAwwmUHJvdG9uVlBO\n\
IENsaWVudCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMjIwMTEyMDcxNzExWhcN\n\
MjIwMTEzMDcxNzEyWjAUMRIwEAYDVQQDDAkxNDMxNzUxNzQwKjAFBgMrZXADIQCq\n\
UyByXJUQsDZ9xO0ZB7eAji+dFUG2cy4OTOO7lJ+vvqOB9zCB9DAdBgNVHQ4EFgQU\n\
xdRQtpXWDLqtyI4p9Pi7rlrTyuowEwYMKwYBBAGDu2kBAAAABAMCAQAwEwYMKwYB\n\
BAGDu2kBAAABBAMCAQIwGwYMKwYBBAGDu2kBAAACBAswCQQHdnBucGx1czAOBgNV\n\
HQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDAjBZ\n\
BgNVHSMEUjBQgBSz4cwQlqL4IqXL3M9EBkYs65LOBaE1pDMwMTEvMC0GA1UEAwwm\n\
UHJvdG9uVlBOIENsaWVudCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHmCAQEwBQYDK2Vw\n\
A0EAkt/ZJlKcrc+FpkV4fZA7VmaGNkpFWhwRNttZBFcaLYw82LxOZKQbox2tewrt\n\
Bvq8ArmKTRnE5P2+mBECko0LBg==\n\
-----END CERTIFICATE-----\n"
        )
        assert(cert.ExpirationTime==1642058232)
        assert(cert.RefreshTime==1642036632)
        assert(cert.Mode=="session")
        assert(cert.DeviceName=="")
        assert(cert.ServerPublicKeyMode=="EC")
        assert(cert.ServerPublicKey=="-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEANm3aIvkeaMO9ctcIeEfM4K1ME3bU9feum5sWQ3Sdx+o=\n\
-----END PUBLIC KEY-----\n")

    def test_cert_serialize(self):
        cert=VPNCertificate.from_json(TestVpnAccount.VPN_CLIENT_CERT_DATA)
        json.loads(cert.to_json())

    def test_secrets_unserialize(self):
        secrets=VPNSecrets.from_json(TestVpnAccount.VPN_CLIENT_SECRET_DATA)
        assert(secrets.wireguard_privatekey=="0EU72yx+FbzuKW1gSOCaSM+zcaA+AcVjv6d31nxtDH4=")
        assert(secrets.openvpn_privatekey=="-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIMP3LkF1P16bARSzAaJEcTCfYbSUqDYSlBQcF16tHn5Q\n\
-----END PRIVATE KEY-----\n")

    def test_secrets_serialize(self):
        secrets=VPNSecrets.from_json(TestVpnAccount.VPN_CLIENT_SECRET_DATA)
        json.loads(secrets.to_json())

    def test_cert_credentials_builder(self):
        cert=json.loads(TestVpnAccount.VPN_CLIENT_CERT_DATA)
        secrets=json.loads(TestVpnAccount.VPN_CLIENT_SECRET_DATA)
        cert_cred=VPNCertCredentials.from_dict(cert, secrets)

    def test_sessions_unserialize(self):
        sessions=VPNSessions.from_json(TestVpnAccount.VPN_SESSIONS_FROM_API_DATA)
        assert(len(sessions.Sessions)==2)
        assert(sessions.Sessions[0].ExitIP=='1.2.3.4')
        assert(sessions.Sessions[1].ExitIP=='5.6.7.8')