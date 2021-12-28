from proton.sso import ProtonSSO
from proton.session.api import ProtonAPIAuthenticationNeeded
from proton.vpnaccount.vpnaccount import VPNAccount, VPNAccountReloadVPNData

def main():

    # Create VPN Account object
    account=VPNAccount('testas1')
    got_info=False

    # Business logic.
    try:
        vpnuser=account.vpn_username
        vpnpass=account.vpn_password
        tier=account.max_tier
        got_info=True
        print("we got user and password offline!")
    except VPNAccountReloadVPNData:
        sso = ProtonSSO()
        # This only works if you logged in before
        # proton-sso login testas1
        # -> Something to handle at the orchestrator level.
        try:
            account.reload_from_session(sso.get_session('testas1'))
            vpnuser=account.vpn_username
            vpnpass=account.vpn_password
            tier=account.max_tier
            got_info=True
            print('reloaded vpn account info to keyring')
        except ProtonAPIAuthenticationNeeded:
            print('please logon on proton API first')

    if got_info:
        print(f'User: {vpnuser}')
        print(f'Pass: {vpnpass}')
        print(f'Tier: {tier}')


if __name__=="__main__":
    main()