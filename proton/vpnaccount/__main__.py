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
        # In that situation we have credentials to login on the VPN, but they might fail (because they were changed)
        # In that case, we must try to update them from the API.
        # The current business logic definition for that scenario is here :
        # - https://gitlab.protontech.ch/ProtonVPN/linux/protonvpn-nm-lib/-/blob/develop/protonvpn_nm_lib/core/accounting/default_accounting.py
        # here for the CLI:
        # - https://gitlab.protontech.ch/ProtonVPN/linux/linux-cli/-/blob/develop/protonvpn_cli/cli_wrapper.py#L409
        # here for the GUI:
        # - https://gitlab.protontech.ch/ProtonVPN/linux/linux-app/-/blob/develop/protonvpn_gui/view_model/dashboard.py#L460
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