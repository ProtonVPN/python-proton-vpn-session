import pytest
import json
from proton.vpnaccount.vpnaccount import VPNAccount, VPNAccountReloadVPNData


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
            user=account.vpn_username
    
    def test_vpnsettings_with_keyring(self):
        account=VPNAccount('test')
        account._reload_vpn_data(json.loads(TestVpnAccount.VPN_API_DATA))
        assert(account.vpn_username=="test")
        assert(account.vpn_password=="passwordtest")
        account.clear()