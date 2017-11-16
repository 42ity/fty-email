#
#    fty-email - Email transport for 42ity (based on msmtp)
#
#    Copyright (C) 2014 - 2017 Eaton                                        
#                                                                           
#    This program is free software; you can redistribute it and/or modify   
#    it under the terms of the GNU General Public License as published by   
#    the Free Software Foundation; either version 2 of the License, or      
#    (at your option) any later version.                                    
#                                                                           
#    This program is distributed in the hope that it will be useful,        
#    but WITHOUT ANY WARRANTY; without even the implied warranty of         
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          
#    GNU General Public License for more details.                           
#                                                                           
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.            
#

# To build with draft APIs, use "--with drafts" in rpmbuild for local builds or add
#   Macros:
#   %_with_drafts 1
# at the BOTTOM of the OBS prjconf
%bcond_with drafts
%if %{with drafts}
%define DRAFTS yes
%else
%define DRAFTS no
%endif
%define SYSTEMD_UNIT_DIR %(pkg-config --variable=systemdsystemunitdir systemd)
Name:           fty-email
Version:        1.0.0
Release:        1
Summary:        email transport for 42ity (based on msmtp)
License:        GPL-2.0+
URL:            https://42ity.org
Source0:        %{name}-%{version}.tar.gz
Group:          System/Libraries
# Note: ghostscript is required by graphviz which is required by
#       asciidoc. On Fedora 24 the ghostscript dependencies cannot
#       be resolved automatically. Thus add working dependency here!
BuildRequires:  ghostscript
BuildRequires:  asciidoc
BuildRequires:  automake
BuildRequires:  autoconf
BuildRequires:  libtool
BuildRequires:  pkgconfig
BuildRequires:  systemd-devel
BuildRequires:  systemd
%{?systemd_requires}
BuildRequires:  xmlto
BuildRequires:  gcc-c++
BuildRequires:  zeromq-devel
BuildRequires:  czmq-devel
BuildRequires:  malamute-devel
BuildRequires:  fty-proto-devel
BuildRequires:  file-devel
BuildRequires:  cxxtools-devel
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
fty-email email transport for 42ity (based on msmtp).

%package -n libfty_email1
Group:          System/Libraries
Summary:        email transport for 42ity (based on msmtp) shared library

%description -n libfty_email1
This package contains shared library for fty-email: email transport for 42ity (based on msmtp)

%post -n libfty_email1 -p /sbin/ldconfig
%postun -n libfty_email1 -p /sbin/ldconfig

%files -n libfty_email1
%defattr(-,root,root)
%{_libdir}/libfty_email.so.*

%package devel
Summary:        email transport for 42ity (based on msmtp)
Group:          System/Libraries
Requires:       libfty_email1 = %{version}
Requires:       zeromq-devel
Requires:       czmq-devel
Requires:       malamute-devel
Requires:       fty-proto-devel
Requires:       file-devel
Requires:       cxxtools-devel

%description devel
email transport for 42ity (based on msmtp) development tools
This package contains development files for fty-email: email transport for 42ity (based on msmtp)

%files devel
%defattr(-,root,root)
%{_includedir}/*
%{_libdir}/libfty_email.so
%{_libdir}/pkgconfig/libfty_email.pc
%{_mandir}/man3/*
%{_mandir}/man7/*

%prep

%setup -q

%build
sh autogen.sh
%{configure} --enable-drafts=%{DRAFTS} --with-systemd-units
make %{_smp_mflags}

%install
make install DESTDIR=%{buildroot} %{?_smp_mflags}

# remove static libraries
find %{buildroot} -name '*.a' | xargs rm -f
find %{buildroot} -name '*.la' | xargs rm -f

%files
%defattr(-,root,root)
%doc README.md
%{_bindir}/fty-email
%{_mandir}/man1/fty-email*
%{_bindir}/fty-sendmail
%{_mandir}/man1/fty-sendmail*
%{_bindir}/fty-device-scan
%config(noreplace) %{_sysconfdir}/fty-email/fty-email.cfg
%{SYSTEMD_UNIT_DIR}/fty-email.service
%dir %{_sysconfdir}/fty-email
%if 0%{?suse_version} > 1315
%post
%systemd_post fty-email.service
%preun
%systemd_preun fty-email.service
%postun
%systemd_postun_with_restart fty-email.service
%endif

%changelog
