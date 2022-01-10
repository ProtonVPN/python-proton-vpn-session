import pytest
import json
from protonvpn.vpnaccount import VPNAccount, VPNUserPass, VPNAccountReloadVPNData
from protonvpn.vpnaccount.api_data import VPNSettings, VPNSettingsFetcher
from protonvpn.vpnaccount.api_data import VPNCertificate, VPNCertificateFetcher


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
  "SerialNumber": "139949609",
  "ClientKeyFingerprint": "L3BJUTjBiridwSXvu4vDSyxTK9t5pfFgSNX2L+4qlm6vYjffjt6WJuB/4g//wx5GtI9a/e4qQuv4YBiLn8Qzkw==",
  "ClientKey": "-----BEGIN PUBLIC KEY-----\\n\
MCowBQYDK2VwAyEAyvymacg4R/6yD9OGx+88SXKPEuZNVDJyrNTUWMvrNZM=\\n\
-----END PUBLIC KEY-----",
  "Certificate": "-----BEGIN CERTIFICATE-----\\n\
MIIB7zCCAaGgAwIBAgIECFd2KTAFBgMrZXAwMTEvMC0GA1UEAwwmUHJvdG9uVlBO\\n\
IENsaWVudCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMjIwMTA5MDkzMDUzWhcN\\n\
MjIwMTEwMDkzMDU0WjAUMRIwEAYDVQQDDAkxMzk5NDk2MDkwKjAFBgMrZXADIQDK\\n\
/KZpyDhH/rIP04bH7zxJco8S5k1UMnKs1NRYy+s1k6OB9zCB9DAdBgNVHQ4EFgQU\\n\
BjRe1mj0cfiLp46wH1GB6whc7PMwEwYMKwYBBAGDu2kBAAAABAMCAQAwEwYMKwYB\\n\
BAGDu2kBAAABBAMCAQIwGwYMKwYBBAGDu2kBAAACBAswCQQHdnBucGx1czAOBgNV\\n\
HQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDAjBZ\\n\
BgNVHSMEUjBQgBSz4cwQlqL4IqXL3M9EBkYs65LOBaE1pDMwMTEvMC0GA1UEAwwm\\n\
UHJvdG9uVlBOIENsaWVudCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHmCAQEwBQYDK2Vw\\n\
A0EAba35zlQCRgXz+JNpp31enLzIQfkfX0WEsnPL8Rz1l0A9OZXNT/QrN7GnojWY\\n\
LwbDS5HS/a3Ps3z5gsUVehq+DA==\\n\
-----END CERTIFICATE-----\\n",
  "ExpirationTime": 1641807054,
  "RefreshTime": 1641785454,
  "Mode": "session",
  "DeviceName": "",
  "ServerPublicKeyMode": "EC",
  "ServerPublicKey": "-----BEGIN PUBLIC KEY-----\\n\
MCowBQYDK2VwAyEANm3aIvkeaMO9ctcIeEfM4K1ME3bU9feum5sWQ3Sdx+o=\\n\
-----END PUBLIC KEY-----\\n",
  "wireguard_privatekey": "uOKx3prumFrghVKwhHzK1pbTix35a+jEQPdGEv3Z23A="
}
"""

    def test_vpnaccount_data_unserialize(self):
        vpnaccount = VPNSettings.from_json(TestVpnAccount.VPN_API_DATA)
        assert(vpnaccount.VPN.Name=="test")
        assert(vpnaccount.VPN.Password=="passwordtest")

    
    def test_vpnaccount_data_serialize(self):
        vpnaccount = VPNSettings.from_json(TestVpnAccount.VPN_API_DATA)
        json.loads(vpnaccount.to_json())

    def test_fetcher(self):
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
        assert(cert.SerialNumber=="139949609")
        assert(cert.ClientKeyFingerprint=="L3BJUTjBiridwSXvu4vDSyxTK9t5pfFgSNX2L+4qlm6vYjffjt6WJuB/4g//wx5GtI9a/e4qQuv4YBiLn8Qzkw==")
        assert(cert.ClientKey=="-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAyvymacg4R/6yD9OGx+88SXKPEuZNVDJyrNTUWMvrNZM=\n\
-----END PUBLIC KEY-----")
        assert(cert.Certificate=="-----BEGIN CERTIFICATE-----\n\
MIIB7zCCAaGgAwIBAgIECFd2KTAFBgMrZXAwMTEvMC0GA1UEAwwmUHJvdG9uVlBO\n\
IENsaWVudCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMjIwMTA5MDkzMDUzWhcN\n\
MjIwMTEwMDkzMDU0WjAUMRIwEAYDVQQDDAkxMzk5NDk2MDkwKjAFBgMrZXADIQDK\n\
/KZpyDhH/rIP04bH7zxJco8S5k1UMnKs1NRYy+s1k6OB9zCB9DAdBgNVHQ4EFgQU\n\
BjRe1mj0cfiLp46wH1GB6whc7PMwEwYMKwYBBAGDu2kBAAAABAMCAQAwEwYMKwYB\n\
BAGDu2kBAAABBAMCAQIwGwYMKwYBBAGDu2kBAAACBAswCQQHdnBucGx1czAOBgNV\n\
HQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDAjBZ\n\
BgNVHSMEUjBQgBSz4cwQlqL4IqXL3M9EBkYs65LOBaE1pDMwMTEvMC0GA1UEAwwm\n\
UHJvdG9uVlBOIENsaWVudCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHmCAQEwBQYDK2Vw\n\
A0EAba35zlQCRgXz+JNpp31enLzIQfkfX0WEsnPL8Rz1l0A9OZXNT/QrN7GnojWY\n\
LwbDS5HS/a3Ps3z5gsUVehq+DA==\n\
-----END CERTIFICATE-----\n")
        assert(cert.ExpirationTime== 1641807054)
        assert(cert.RefreshTime==1641785454)
        assert(cert.Mode=="session")
        assert(cert.DeviceName=="")
        assert(cert.ServerPublicKeyMode=="EC")
        assert(cert.ServerPublicKey=="-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEANm3aIvkeaMO9ctcIeEfM4K1ME3bU9feum5sWQ3Sdx+o=\n\
-----END PUBLIC KEY-----\n")

    def test_cert_serialize(self):
        cert=VPNCertificate.from_json(TestVpnAccount.VPN_CLIENT_CERT_DATA)
        json.loads(cert.to_json())