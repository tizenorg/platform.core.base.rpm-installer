Name:             rpm-installer
Summary:          Native rpm installer
Version:          0.1.25
Release:          2
Group:            System/Libraries
License:          Apache-2.0
Source0:          %{name}-%{version}.tar.gz
Source1001:       rpm-installer.manifest
Requires(post):   /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:    cmake
BuildRequires:    edje-bin
BuildRequires:    rpm-devel
BuildRequires:    popt-devel
BuildRequires:    pkgconfig(glib-2.0)
BuildRequires:    pkgconfig(sqlite3)
BuildRequires:    pkgconfig(dlog)
BuildRequires:    pkgconfig(vconf)
BuildRequires:    pkgconfig(db-util)
BuildRequires:    pkgconfig(pkgmgr-types)
BuildRequires:    pkgconfig(pkgmgr-installer)
BuildRequires:    pkgconfig(pkgmgr-parser)
BuildRequires:    pkgconfig(pkgmgr)
BuildRequires:    pkgconfig(pkgmgr-info)
BuildRequires:    pkgconfig(app2sd)
BuildRequires:    pkgconfig(libxml-2.0)
BuildRequires:    pkgconfig(security-server)
BuildRequires:    pkgconfig(elementary)
BuildRequires:    pkgconfig(appcore-efl)
BuildRequires:    pkgconfig(evas)
BuildRequires:    pkgconfig(ecore)
BuildRequires:    pkgconfig(edje)
BuildRequires:    pkgconfig(libtzplatform-config)
BuildRequires:    gettext-tools
Requires:         cpio

%description
Native rpm installer

%prep
%setup -q
cp %{SOURCE1001} .

%build
CFLAGS+=" -fpic"
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

%post
mkdir -p /usr/etc/package-manager/backend
mkdir -p /usr/etc/package-manager/backendlib
ln -sf %{_bindir}/rpm-backend /usr/etc/package-manager/backend/rpm
ln -sf /usr/lib/libnativerpm.so /usr/etc/package-manager/backendlib/librpm.so

chmod 700 %{_bindir}/rpm-backend

vconftool set -t int db/private/rpm-installer/state "0"
vconftool set -t int db/private/rpm-installer/stateinfo "0"
vconftool set -t int db/private/rpm-installer/requestinfo/command "0"
vconftool set -t string db/private/rpm-installer/requestinfo/pkgname ""
vconftool set -t int db/private/rpm-installer/requestinfo/options "0"

%files
%manifest %{name}.manifest
%attr(0700,-,-) %{_bindir}/rpm-backend
%attr(0700,-,-) %{_bindir}/install_rpm_package.sh
%attr(0755,-,-) %{_bindir}/query_rpm_package.sh
%attr(0700,-,-) %{_bindir}/uninstall_rpm_package.sh
%attr(0700,-,-) %{_bindir}/upgrade_rpm_package.sh
%attr(0644,-,-) %lang(en_GB) /usr/share/locale/en_GB/LC_MESSAGES/rpm-installer.mo
%attr(0644,-,-) %lang(ja) /usr/share/locale/ja_JP/LC_MESSAGES/rpm-installer.mo
%attr(0644,-,-) %lang(zh) /usr/share/locale/zh_CN/LC_MESSAGES/rpm-installer.mo
%attr(0644,-,-) %lang(en_US) /usr/share/locale/en_US/LC_MESSAGES/rpm-installer.mo
%attr(0644,-,-) %lang(ko) /usr/share/locale/ko_KR/LC_MESSAGES/rpm-installer.mo
%attr(0644,-,-) /usr/lib/libnativerpm.so
