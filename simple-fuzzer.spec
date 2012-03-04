Summary: A simple fuzz test-case builder
Name: simple-fuzzer
Version: VERSION
Release: RELEASE
Copyright: BSD
Group: Applications/System
URL: http://aconole.brad-x.com/programs/sfuzz.html
Source: http://aconole.brad-x.com/files/sfuzz-%{version}-dist/sfuzz-%{version}.%{release}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}.%{release}-root
BuildRequires: gcc-c++

%description
Simple-Fuzzer (sfuzz) is a simplistic fuzz test case generator. It is a generation-based fuzzer. 

%prep
%setup -q

%build
%configure --force-symbols --enable-snoop
%{__make}

%install
%{__rm} -rf %{buildroot}
%makeinstall

%clean
${__rm} -rf %{buildroot}

%files
%{_bindir}/*
%{_datadir}/sfuzz-db


%changelog
* Sat Mar  3 2012 Aaron Conole   - 0.7.0
- First RPM spec build
