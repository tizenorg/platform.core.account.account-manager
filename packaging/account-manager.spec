
Name:       account-manager
Summary:    Account Manager
Version:    0.0.1
Release:    1
Group:      Social & Content/Other
License:    Apache-2.0
Source0:    account-manager-%{version}.tar.gz
Source1:    accounts-service.service

BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(db-util)
BuildRequires:  pkgconfig(capi-base-common)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(aul)
BuildRequires:	pkgconfig(glib-2.0) >= 2.26
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(gio-unix-2.0)
BuildRequires:  pkgconfig(cynara-client)
BuildRequires:  pkgconfig(cynara-session)
BuildRequires:  pkgconfig(cynara-creds-gdbus)
BuildRequires:  pkgconfig(accounts-svc)
BuildRequires:  python-xml
BuildRequires:  python-devel

Requires(post): /sbin/ldconfig
Requires(post): /usr/bin/sqlite3
Requires(postun): /sbin/ldconfig

%description
Account Daemon: no

%package devel
Summary:    Development files for %{name}
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}
%description devel
Development files for %{name}

%prep
%setup -q

%build
#export   CFLAGS+=" -Wextra -Wcast-align -Wcast-qual -Wshadow -Wwrite-strings -Wswitch-default"
#export CXXFLAGS+=" -Wextra -Wcast-align -Wcast-qual -Wshadow -Wwrite-strings -Wswitch-default -Wnon-virtual-dtor -Wno-c++0x-compat"
#export   CFLAGS+=" -Wno-unused-parameter -Wno-empty-body"
#export CXXFLAGS+=" -Wno-unused-parameter -Wno-empty-body"

#export   CFLAGS+=" -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-strict-aliasing -fno-unroll-loops -fsigned-char -fstrict-overflow -fno-common"
#export CXXFLAGS+=" -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-strict-aliasing -fno-unroll-loops -fsigned-char -fstrict-overflow"

export CFLAGS="${CFLAGS} -fPIC -fvisibility=hidden"
cmake . -DCMAKE_INSTALL_PREFIX=/usr

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
install -m 0644 %SOURCE1 %{buildroot}%{_libdir}/systemd/system/accounts-service.service
ln -s ../accounts-service.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/accounts-service.service

rm -rf %{buildroot}/usr/lib/account-manager

%post
/sbin/ldconfig
#if [ ! -d /opt/usr/dbspace ]
#then
#        mkdir -p /opt/usr/dbspace
#fi
if [ ! -f %{TZ_SYS_DB}/.account.db ]
then
        sqlite3 %{TZ_SYS_DB}/.account.db 'PRAGMA journal_mode = PERSIST;
        CREATE TABLE if not exists label (AppId TEXT, Label TEXT, Locale TEXT);
        CREATE TABLE if not exists account_type (_id INTEGER PRIMARY KEY AUTOINCREMENT, AppId TEXT,
        ServiceProviderId TEXT, IconPath TEXT, SmallIconPath TEXT, MultipleAccountSupport INT);
        CREATE TABLE if not exists account_custom (AccountId INTEGER, AppId TEXT, Key TEXT, Value TEXT);
        CREATE TABLE if not exists account (id INTEGER PRIMARY KEY AUTOINCREMENT, user_name TEXT, email_address TEXT, display_name TEXT, icon_path TEXT,
        source TEXT, package_name TEXT, access_token TEXT, domain_name TEXT, auth_type INTEGER, secret INTEGER, sync_support INTEGER,
        txt_custom0 TEXT, txt_custom1 TEXT, txt_custom2 TEXT, txt_custom3 TEXT, txt_custom4 TEXT,
        int_custom0 INTEGER, int_custom1 INTEGER, int_custom2 INTEGER, int_custom3 INTEGER, int_custom4 INTEGER);
        CREATE TABLE if not exists capability (_id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, value INTEGER,
	package_name TEXT, user_name TEXT,  account_id INTEGER, FOREIGN KEY (account_id) REFERENCES account(id));
	CREATE TABLE if not exists provider_feature (app_id TEXT, key TEXT);
'
fi

mkdir -p /opt/usr/share/account
chown root:root %{TZ_SYS_DB}/.account.db
chown root:root %{TZ_SYS_DB}/.account.db-journal

chmod 600 /opt/usr/dbspace/.account.db
chmod 600 /opt/usr/dbspace/.account.db-journal

#set message key value to NULL
#vconftool set -t string db/account/msg '' -g 6514
vconftool set -tf string db/account/msg '' -s libaccounts-svc -u 200 -g 5000

#smack labeling
if [ -f /usr/lib/rpm-plugins/msm.so ]
then
	chsmack -a 'libaccounts-svc::db' /opt/usr/dbspace/.account.db-journal
	chsmack -a 'libaccounts-svc::db' /opt/usr/dbspace/.account.db
fi


%postun -p /sbin/ldconfig



%files
%manifest libaccounts-svc.manifest
%defattr(-,root,root,-)
%attr(0755,root,root) %{_bindir}/account-svcd
%attr(-,root,root) %{_libdir}/systemd/system/accounts-service.service
%attr(-,root,root) %{_libdir}/systemd/system/multi-user.target.wants/accounts-service.service

%files devel
%defattr(-,root,root,-)
%attr(0755,root,root) %{_bindir}/account-svcd
%attr(-,root,root) %{_libdir}/systemd/system/accounts-service.service
%attr(-,root,root) %{_libdir}/systemd/system/multi-user.target.wants/accounts-service.service
