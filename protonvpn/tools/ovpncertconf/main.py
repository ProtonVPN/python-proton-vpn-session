from .vpn_configuration import VPNConfiguration, ProtocolEnum
from protonvpn.vpnaccount import VPNAccount, VPNAccountReloadVPNData, VPNCertificateReload
from protonvpn.vpnaccount.api_data import VPNCertCredentialsFetcher
from proton.session.exceptions import ProtonAPIAuthenticationNeeded
from proton.sso import ProtonSSO
from protonvpn.servers.list import CachedServerList

class Server:
    def __init__(self, entry_ip, ports):
        self._entry_ip = entry_ip
        self._ports=ports

    @property
    def entry_ip(self):
        return self._entry_ip
    
    @property
    def ports(self):
        return self._ports


def make_sure_we_have_creds(account, session) -> None:
    try:
        certificate=account.get_client_api_pem_certificate()
        wg_key = account.get_client_private_wg_key()
        openvpn_key = account.get_client_private_openvpn_key()
    except VPNCertificateReload:
        try:
            f = VPNCertCredentialsFetcher(session=session)
            account.reload_vpn_cert_credentials(f.fetch())
            cert=account.get_client_api_pem_certificate()
            wg_key = account.get_client_private_wg_key()
            openvpn_key = account.get_client_private_openvpn_key()
        except ProtonAPIAuthenticationNeeded:
            raise

def main():
    import argparse
    parser = argparse.ArgumentParser('ovpnconf', description="Tool generate a VPN Configuration")
    parser.add_argument('logical',type=str, help='logical to generate wg config for (DE#13, FR#33)')
    parser.add_argument('--username','-u', type=str, help='proton account username (if not given use proton-sso default)')
    parser.add_argument('--outfile','-o', type=str, help='output file for the configuration')
    args = parser.parse_args()

    sso = ProtonSSO()
    if args.username is None:
        default_account_name=sso.sessions[0]
        account=VPNAccount(default_account_name)
        session = sso.get_default_session()
    else:
        account=VPNAccount(args.username)
        session = sso.get_session(args.username)

    try:
        make_sure_we_have_creds(account,session)
    except ProtonAPIAuthenticationNeeded:
        print('please logon on proton API first')
        return

    sl=CachedServerList()
    try:
        server=list(filter(lambda server: server.name == args.logical, sl))[0]
        ip = server.get_random_physical_server().entry_ip
    except:
        print('could not find server, maybe try another one or reload the server list ?')
        return

    vpnconfig = VPNConfiguration.factory(ProtocolEnum.UDP, Server(ip,[80,443,4569,1194,5060]), account)
    with vpnconfig as config_content:
        if args.outfile is None:
            print(f'{config_content}')
        else:
            with open(args.outfile,'w') as f:
                f.write(config_content)


if __name__ == "__main__":
    main()