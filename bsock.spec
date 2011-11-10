%define name bsock
%define version 0.04

Name:    %{name}
Version: %{version}
Release: 1%{?dist}
Summary: bsock - bind() sockets to restricted ports for lower-privilege daemons

Group:		Systems Environment/Daemons
License:	BSD
Vendor:		Glue Logic LLC
URL:		https://github.com/gstrauss/bsock/
Source0:	bsock-%{version}.tar.gz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:	gcc
Requires:	glibc, %{name}-libs = %{version}

%package libs
Summary: bsock - shared libraries
Group:   System Environment/Libraries

%description
==
bsock - bind() sockets to restricted ports for lower-privilege daemons

bsock federates binding to (important) socket addresses/ports on a system and
removes the requirement that many daemons start with root privileges in order
to bind to assigned ports.

The bsock daemon listens for requests on a local unix domain socket.


proxyexec - proxy command execution without setuid

proxyexec is an executable that builds with libbsock.so and can be used
as a login shell or as the target of an sshd_config ForceCommand to
leverage operating system authentication to passing credentials to a
service program running under a single account.

proxyexec handles client/server communication by passing argv and stdin,
stdout, stderr fds over unix domain socket between processes owned by
different users.
==

%description libs
bsock - bind() sockets to restricted ports for lower-privilege daemons
This package contains bsock shared libraries.


%prep
%setup -q


%build
make %{?_smp_mflags} PREFIX=/usr PROXYEXEC_SOCKET_DIR=/var/run/proxyexec/


%install
rm -rf $RPM_BUILD_ROOT
make install PREFIX=$RPM_BUILD_ROOT/usr
make install-doc PREFIX=$RPM_BUILD_ROOT/usr
make install-headers PREFIX=$RPM_BUILD_ROOT/usr
mv $RPM_BUILD_ROOT/usr/share/doc/bsock \
   $RPM_BUILD_ROOT/usr/share/doc/bsock-%{version}
# permissions restored in files section below, after 'strip' is possibly run
chmod u+w $RPM_BUILD_ROOT/usr/%{_lib}/* $RPM_BUILD_ROOT/usr/sbin/*
mv $RPM_BUILD_ROOT/usr/etc $RPM_BUILD_ROOT/usr/var $RPM_BUILD_ROOT/


%clean
rm -rf $RPM_BUILD_ROOT


%post libs -p /sbin/ldconfig
%postun libs -p /sbin/ldconfig


%files
%defattr(-,root,root,-)
%config(noreplace)      /etc/*
                        /usr/include/bsock
%attr(0555,root,daemon) /usr/sbin/bsock
%attr(0555,root,root)   /usr/sbin/proxyexec
%ghost                  /var/run/bsock
%ghost                  /var/run/proxyexec
%doc                    /usr/share/doc/bsock-%{version}

%files libs
%defattr(-,root,root,-)
%attr(0555,root,root)   %{_libdir}/libbsock*

