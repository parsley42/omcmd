Summary: dhcp/omapi tool for operating on a running dhcp server
Name: omcmd
Version: 0.4.8
Release: 1
License: GPL
Group: System Environment/Daemons
Source: http://www.bridgewater.edu/~dparsley/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}root
BuildRequires: dhcp-devel

%description
omcmd is a CLI utility for querying and updating omapi objects in a running
ISC dhcp server.  It can be used to dynmically create/modify/remove/lookup
objects in the dhcp server, such as hosts and leases.

%prep
%setup -q

%build
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin
install -m 0755 omcmd $RPM_BUILD_ROOT/usr/bin
gzip --best omcmd.1
mkdir -p $RPM_BUILD_ROOT/%{_mandir}/man1
install -m 0755 omcmd.1.gz $RPM_BUILD_ROOT/%{_mandir}/man1

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-, root, root)
/usr/bin/omcmd
%doc README Changelog
%{_mandir}/man1/omcmd.1*

%changelog
* Wed Nov 12 2008 David L. Parsley <parsley@linuxjedi.org> 0.4.8-1
- Update to new version

* Fri Dec 09 2005 David L. Parsley <parsley@linuxjedi.org> 0.4.7-1
- Update to new version

* Mon Oct 10 2005 David L. Parsley <parsley@linuxjedi.org> 0.4.6-1
- Added manpage

* Thu Aug 05 2004 David L. Parsley <parsley@linuxjedi.org> 0.4.3-1
- Initial packaging
