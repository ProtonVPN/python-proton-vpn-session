from proton.sso import ProtonSSO
from proton.vpnaccount.vpnaccount import VPNAccount, VPNAccountReloadVPNData

def main():
    # Create VPN Account object
    account=VPNAccount()
    # Business logic.
    try:
        vpnuser=account.vpn_username
        vpnpass=account.vpn_password
        tier=account.max_tier
        print("we got user and password offline!")
    except VPNAccountReloadVPNData:
        sso = ProtonSSO()
        # This only works if you logged in before
        # proton-sso login testas1
        # -> Something to handle at the orchestrator level.
        account.reload_from_session(sso.get_session('testas1'))
        vpnuser=account.vpn_username
        vpnpass=account.vpn_password
        tier=account.max_tier
        print('reloaded vpn account to keyring')
    finally:
        print(f'User: {vpnuser}')
        print(f'Pass: {vpnpass}')
        print(f'Tier: {tier}')

if __name__=="__main__":
    main()