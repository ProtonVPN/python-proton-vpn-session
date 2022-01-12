from proton.sso import ProtonSSO
from proton.session.exceptions import ProtonAPIAuthenticationNeeded
from protonvpn.vpnaccount import VPNAccount, VPNCertificateReload
from protonvpn.servers.list import CachedServerList
from protonvpn.vpnaccount.api_data import VPNCertCredentialsFetcher

def get_wg_key():
    sso = ProtonSSO()
    default_account_name=sso.sessions[0]
    account=VPNAccount(default_account_name)
    try:
        wg_key=account.get_client_private_wg_key()
    except VPNCertificateReload:
        try:
            f = VPNCertCredentialsFetcher(session=sso.get_default_session())
            account.reload_vpn_cert_credentials(f.fetch())
            wg_key=account.get_client_private_wg_key()
        except ProtonAPIAuthenticationNeeded:
                raise
    return wg_key


def main():
    import argparse
    parser = argparse.ArgumentParser('wgconf', description="Tool to generate a ProtonVPN wg conf")
    parser.add_argument("--wg-port", help="Wireguard port (default = 51820)", metavar="PORT", type=int, default=51820)
    parser.add_argument('logical',type=str, help='logical to generate wg config for (DE#13, FR#33)')
    args = parser.parse_args()
    
    try:
        wg_client_secret_key=get_wg_key()
    except ProtonAPIAuthenticationNeeded:
        print("please login first")
        return

    sl=CachedServerList()
    try:
        server=list(filter(lambda server: server.name == args.logical, sl))[0]
        wg_server_pk=server.physical_servers[0].x25519_pk
        wg_ip = server.get_random_physical_server().entry_ip
        wg_cfg = f"""\
[Interface]
PrivateKey = {wg_client_secret_key}
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = {wg_server_pk}
Endpoint = {wg_ip}:{args.wg_port}
AllowedIPs = 0.0.0.0/0
"""
        print(wg_cfg)
    except IndexError:
        print("Server not found")
    #nmcli connection import type wireguard file wg.conf

if __name__=="__main__":
    main()