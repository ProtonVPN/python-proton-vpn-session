from proton.sso import ProtonSSO
from proton.session.api import ProtonAPIAuthenticationNeeded
from protonvpn.vpnaccount import VPNAccount, VPNAccountReloadVPNData, VPNCertificateReload
from protonvpn.vpnaccount.api_data import VPNSettingsFetcher, VPNCertCredentialsFetcher, VPNSessionsFetcher
import argparse

def get_cert_creds(account, session):
    try:

        certificate=account.get_client_api_pem_certificate()
        wg_key = account.get_client_private_wg_key()
        openvpn_key = account.get_client_private_openvpn_key()
        print(f'wireguard key: {wg_key}')
        print(f'openvpn private key: {openvpn_key}')
        print(f'API certificate: {certificate}')
        print("we got the certificate and wg private keys offline!")
    except VPNCertificateReload:
        try:
            f = VPNCertCredentialsFetcher(session=session)
            account.reload_vpn_cert_credentials(f.fetch())
            cert=account.get_client_api_pem_certificate()
            wg_key = account.get_client_private_wg_key()
            openvpn_key = account.get_client_private_openvpn_key()
            print('reloaded vpn certificate info to keyring')
        except ProtonAPIAuthenticationNeeded:
            raise
    return certificate, wg_key, openvpn_key

def get_vpn_settings(account, session):
    try:
        creds=account.get_username_and_password()
        vpnuser=creds.username
        vpnpass=creds.password
        tier=account.max_tier
        print("we got user and password offline!")
    except VPNAccountReloadVPNData:
        try:
            f = VPNSettingsFetcher(session=session)
            account.reload_vpn_settings(f.fetch())
            creds=account.get_username_and_password()
            vpnuser=creds.username
            vpnpass=creds.password
            tier=account.max_tier
            print('reloaded vpn settings info to keyring')
        except ProtonAPIAuthenticationNeeded:
            raise
    return vpnuser, vpnpass, tier

def show_vpn_creds(proton_username:str):

    # Create VPN Account object
    account=VPNAccount(proton_username)
    got_info=False
    sso = ProtonSSO()
    session = sso.get_session(proton_username)
    certificate, wg_key, openvpn_key = get_cert_creds(account, session)
    vpnuser, vpnpass, tier = get_vpn_settings(account,session)

    # If we reach that point, we should have everything we need
    print(f'User: {vpnuser}')
    print(f'Pass: {vpnpass}')
    print(f'Tier: {tier}')
    print(f'wireguard key: {wg_key}')
    print(f'openvpn private key: {openvpn_key}')
    print(f'API certificate: {certificate}')

def show_sessions(username):
    sso = ProtonSSO()
    f = VPNSessionsFetcher(session=sso.get_session(username))
    sessions = f.fetch()
    for s in sessions.Sessions:
        print(s)

def main():
    import argparse
    parser = argparse.ArgumentParser('vpninfo', description="Tool to test VPN account and SSO")
    parser.add_argument('username',type=str, help='proton account username')
    parser.add_argument('--sessions','-s',action='store_true', help='Show sessions info for the user')
    args = parser.parse_args()
    try:
        #quick_test(args.username)
        show_vpn_creds(args.username)
    except ProtonAPIAuthenticationNeeded:
        print('please logon on proton API first')

    if args.sessions:
        show_sessions(args.username)

def quick_test(proton_username:str):
    account=VPNAccount(proton_username)
    got_info=False
    sso = ProtonSSO()

    try:
        certificate=account.get_client_api_pem_certificate()
        wg_key = account.get_client_private_wg_key()
        #client_key = account._vpn_certificate.ClientKey
        openvpn_key = account.get_client_private_openvpn_key()
        print(f'wireguard key: {wg_key}')
        print(f'openvpn private key: {openvpn_key}')
        print(f'API certificate: {certificate}')
        print("we got the certificate and wg private keys offline!")
    except VPNCertificateReload:
        print('reload please')



    #f = VPNCertCredentialsFetcher(session=sso.get_session(proton_username))
    #account.reload_vpn_cert_credentials(f.fetch())
    #print(account.get_client_certificate())
    #print('quick test')

if __name__=="__main__":
    quick_test()
