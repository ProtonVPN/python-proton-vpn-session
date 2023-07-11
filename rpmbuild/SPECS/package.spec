%define unmangled_name proton-vpn-session
%define version 0.4.0
%define release 1

Prefix: %{_prefix}

Name: python3-%{unmangled_name}
Version: %{version}
Release: %{release}%{?dist}
Summary: %{unmangled_name} library

Group: ProtonVPN
License: GPLv3
Vendor: Proton Technologies AG <opensource@proton.me>
URL: https://github.com/ProtonVPN/%{unmangled_name}
Source0: %{unmangled_name}-%{version}.tar.gz
BuildArch: noarch
BuildRoot: %{_tmppath}/%{unmangled_name}-%{version}-%{release}-buildroot

BuildRequires: python3-pynacl
BuildRequires: python3-proton-core
BuildRequires: python3-proton-vpn-logger
BuildRequires: python3-setuptools
Requires: python3-proton-core
Requires: python3-proton-vpn-logger
Requires: python3-pynacl

Conflicts: python3-proton-vpn-api-core < 0.13.0

%{?python_disable_dependency_generator}

%description
Package %{unmangled_name} library.


%prep
%setup -n %{unmangled_name}-%{version} -n %{unmangled_name}-%{version}

%build
python3 setup.py build

%install
python3 setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES


%files -f INSTALLED_FILES
%{python3_sitelib}/proton/
%{python3_sitelib}/proton_vpn_session-%{version}*.egg-info/
%defattr(-,root,root)

%changelog
* Tue Jul 11 2023  Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.4.0
- Update endpoint to fetch clientconfig

* Wed Jun 14 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.3.0
- Move server list/loads and client config to VPN session [VPNLINUX-524]

* Tue Jun 06 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.2.0
- Retrieve location and store it in the keyring

* Wed Apr 19 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.1.0
- Fix rules

* Wed Jun 1 2022 Proton Technologies AG <opensource@proton.me> 0.0.2
- First RPM release
