%define name bsock
%define version 0.02

Name:    %{name}
Version: %{version}
Release: 1%{?dist}
Summary: bsock - bind() sockets to restricted ports for lower-privilege daemons

Group:		Systems Environment/Daemons
License:	BSD
Vendor:		Glue Logic LLC
URL:		https://github.com/gstrauss/bsock/
Source0:	bsock-0.02.tar.gz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:	gcc
Requires:	glibc

%description
==
bsock - bind() sockets to restricted ports for lower-privilege daemons

bsock federates binding to (important) socket addresses/ports on a system and
removes the requirement that many daemons start with root privileges in order
to bind to assigned ports.

The bsock daemon listens for requests on a local unix domain socket.


proxyexec - client/server passing argv and stdin, stdout, stderr fds over
            unix domain socket between processes owned by different users

proxyexec is an executable that builds with libbsock.so and can be used
as a login shell or as the target of an sshd_config ForceCommand to
leverage operating system authentication to passing credentials to a
service program running under a single account.
==

%prep
%setup -q


%build
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install PREFIX=$RPM_BUILD_ROOT
make install-doc PREFIX=$RPM_BUILD_ROOT
make install-headers PREFIX=$RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr
mv $RPM_BUILD_ROOT/share/doc/bsock $RPM_BUILD_ROOT/share/doc/bsock-%{version}
mv $RPM_BUILD_ROOT/share $RPM_BUILD_ROOT/usr/


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
                     /etc/*
                     /include/bsock
                     /lib/libbsock*
%attr(-,root,daemon) /sbin/bsock
                     /sbin/proxyexec
                     /var/run/bsock
%doc                 /usr/share/doc/bsock-0.02


%changelog

