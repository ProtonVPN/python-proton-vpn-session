from proton.sso import ProtonSSO
from proton.session.api import ProtonAPIAuthenticationNeeded
from protonvpn.vpnaccount import VPNAccount, VPNAccountReloadVPNData, VPNCertificateReload
from protonvpn.vpnaccount.api_data import VPNSettingsFetcher, VPNCertificateFetcher
import argparse

def show_vpn_creds(proton_username:str):

    # Create VPN Account object
    account=VPNAccount(proton_username)
    got_info=False
    sso = ProtonSSO()

    # Business logic -> Certificate
    try:
        cert=account.get_client_certificate()
        certificate=cert.Certificate
        wg_key = account.get_client_private_wg_key()
        print("we got the certificate and wg private keys offline!")
    except VPNCertificateReload:
        try:
            f = VPNCertificateFetcher(session=sso.get_session(proton_username))
            account.reload_certificate(f.fetch())
            cert=account.get_client_certificate()
            wg_key = account.get_client_private_wg_key
            print('reloaded vpn certificate info to keyring')
        except ProtonAPIAuthenticationNeeded:
            raise

    # Business logic -> User/Pass
    try:
        creds=account.get_username_and_password()
        vpnuser=creds.username
        vpnpass=creds.password
        tier=account.max_tier
        print("we got user and password offline!")
        # In that situation we have credentials to login on the VPN, but they might fail (because they were changed or reinitialized for ex.)
        # In that case, we must try to update them from the API.
        # The current business logic definition for that scenario is here :
        # - https://gitlab.protontech.ch/ProtonVPN/linux/protonvpn-nm-lib/-/blob/develop/protonvpn_nm_lib/core/accounting/default_accounting.py
        # here for the CLI:
        # - https://gitlab.protontech.ch/ProtonVPN/linux/linux-cli/-/blob/develop/protonvpn_cli/cli_wrapper.py#L409
        # here for the GUI:
        # - https://gitlab.protontech.ch/ProtonVPN/linux/linux-app/-/blob/develop/protonvpn_gui/view_model/dashboard.py#L460
        # See also https://confluence.protontech.ch/display/VPN/Reconnection+project
    except VPNAccountReloadVPNData:
        try:
            f = VPNSettingsFetcher(session=sso.get_session(proton_username))
            account.reload_vpn_settings(f.fetch())
            creds=account.get_username_and_password()
            print('reloaded vpn settings info to keyring')
        except ProtonAPIAuthenticationNeeded:
            raise
        # This only works if you logged in before
        # proton-sso login testas1
        # -> Something to handle at the coordinator/orchestrator/business logic implementation level.
    
    vpnuser=creds.username
    vpnpass=creds.password
    tier=account.max_tier
    certificate=cert.Certificate
    wg_key = account.get_client_private_wg_key()

    # If we reach that point, we should have everything we need
    print(f'User: {vpnuser}')
    print(f'Pass: {vpnpass}')
    print(f'Tier: {tier}')
    print(f'Local agent Cert: {certificate}')
    print(f'Wg client secret key: {wg_key}')


if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser('vpninfo', description="Tool to test VPN account and SSO")
    parser.add_argument('username',type=str, help='proton account username')
    args = parser.parse_args()
    try:
        show_vpn_creds(args.username)
    except ProtonAPIAuthenticationNeeded:
        print('please logon on proton API first')

