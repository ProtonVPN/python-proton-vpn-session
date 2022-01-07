import pytest
import json
from proton.vpnaccount.vpnaccount import VPNAccount, VPNUserPass, VPNAccountReloadVPNData


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

    def test_vpnsettings_must_reload(self):
        account=VPNAccount('test')
        account.clear()
        with pytest.raises(VPNAccountReloadVPNData):
            vpnaccount=account.get_username_and_password()
    
    def test_vpnsettings_with_keyring(self):
        account=VPNAccount('test')
        account.reload_vpn_data(json.loads(TestVpnAccount.VPN_API_DATA))
        vpnaccount=account.get_username_and_password()
        assert(vpnaccount.username=="test")
        assert(vpnaccount.password=="passwordtest")
        account.clear()