Summary: A simple fuzz test-case builder
Name: simple-fuzzer
Version: VERSION
Release: RELEASE
License: BSD
Group: Applications/System
URL: http://aconole.brad-x.com/programs/sfuzz.html
Source: http://aconole.brad-x.com/files/sfuzz-%{version}-dist/sfuzz-%{version}.%{release}.tar.bz2
BuildRoot: %{_tmppath}/sfuzz-%{version}.%{release}-root

%description
Simple-Fuzzer (sfuzz) is a simplistic fuzz test case generator. It is a generation-based fuzzer. 

%prep
%setup -q -n sfuzz-%{version}.%{release}

%build
%configure --force-symbols --enable-snoop
%{__make}

%install
%{__rm} -rf %{buildroot}
%{__make} DESTDIR=%{buildroot} install

%clean
%{__rm} -rf %{buildroot}

%files
%{_bindir}/*
%{_datadir}/sfuzz-db


%changelog
* Sat Mar  3 2012 Aaron Conole   - 0.7.0
- First RPM spec build
