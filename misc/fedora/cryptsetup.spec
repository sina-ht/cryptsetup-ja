# Simplified version of RPM spec for Fedora

Summary: Utility for setting up encrypted disks
Name: cryptsetup
Version: 2.4.0
Release: 1%{?dist}
License: GPLv2+ and LGPLv2+
URL: https://gitlab.com/cryptsetup/cryptsetup
BuildRequires: openssl-devel, popt-devel, device-mapper-devel
BuildRequires: libuuid-devel, gcc, json-c-devel, libargon2-devel
BuildRequires: libpwquality-devel, libblkid-devel
BuildRequires: make libssh-devel
Requires: cryptsetup-libs = %{version}-%{release}
Requires: libpwquality >= 1.2.0

%global upstream_version %{version}-git
Source0: https://www.kernel.org/pub/linux/utils/cryptsetup/v2.4/cryptsetup-%{upstream_version}.tar.xz
# Following patch has to applied last
#Patch9999: %{name}-add-system-library-paths.patch

%description
The cryptsetup package contains a utility for setting up
disk encryption using dm-crypt kernel module.

%package devel
Requires: %{name}-libs%{?_isa} = %{version}-%{release}
Requires: pkgconfig
Summary: Headers and libraries for using encrypted file systems

%description devel
The cryptsetup-devel package contains libraries and header files
used for writing code that makes use of disk encryption.

%package libs
Summary: Cryptsetup shared library

%description libs
This package contains the cryptsetup shared library, libcryptsetup.

%package ssh-token
Summary: Cryptsetup LUKS2 SSH token
Requires: cryptsetup-libs = %{version}-%{release}

%description ssh-token
This package contains the LUKS2 SSH token.

%package -n veritysetup
Summary: A utility for setting up dm-verity volumes
Requires: cryptsetup-libs = %{version}-%{release}

%description -n veritysetup
The veritysetup package contains a utility for setting up
disk verification using dm-verity kernel module.

%package -n integritysetup
Summary: A utility for setting up dm-integrity volumes
Requires: cryptsetup-libs = %{version}-%{release}

%description -n integritysetup
The integritysetup package contains a utility for setting up
disk integrity protection using dm-integrity kernel module.

%package reencrypt
Summary: A utility for offline reencryption of LUKS encrypted disks
Requires: cryptsetup-libs = %{version}-%{release}

%description reencrypt
This package contains cryptsetup-reencrypt utility which
can be used for offline reencryption of disk in situ.

%prep
%autosetup -n cryptsetup-%{upstream_version} -p 1

%build
%configure --enable-fips --enable-pwquality --enable-libargon2
%make_build

%install
%make_install
mkdir -p -m 0755 $RPM_BUILD_ROOT%{_libdir}/%{name}/
rm -rf %{buildroot}%{_libdir}/*.la
rm -rf %{buildroot}%{_libdir}/%{name}/*.la

%find_lang cryptsetup

%ldconfig_scriptlets -n cryptsetup-libs

%files
%license COPYING
%doc AUTHORS FAQ docs/*ReleaseNotes
%{_mandir}/man8/cryptsetup.8.gz
%{_sbindir}/cryptsetup

%files -n veritysetup
%license COPYING
%{_mandir}/man8/veritysetup.8.gz
%{_sbindir}/veritysetup

%files -n integritysetup
%license COPYING
%{_mandir}/man8/integritysetup.8.gz
%{_sbindir}/integritysetup

%files reencrypt
%license COPYING
%{_mandir}/man8/cryptsetup-reencrypt.8.gz
%{_sbindir}/cryptsetup-reencrypt

%files devel
%doc docs/examples/*
%{_includedir}/libcryptsetup.h
%{_libdir}/libcryptsetup.so
%{_libdir}/pkgconfig/libcryptsetup.pc

%files libs -f cryptsetup.lang
%license COPYING COPYING.LGPL
%{_libdir}/libcryptsetup.so.*
%dir %{_libdir}/%{name}/
%{_tmpfilesdir}/cryptsetup.conf
%ghost %attr(700, -, -) %dir /run/cryptsetup

%files ssh-token
%license COPYING COPYING.LGPL
%{_libdir}/%{name}/libcryptsetup-token-ssh.so
%{_mandir}/man8/cryptsetup-ssh.8.gz
%{_sbindir}/cryptsetup-ssh

%changelog
