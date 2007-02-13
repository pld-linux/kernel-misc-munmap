# Conditional build:
# _without_dist_kernel	- without distribution kernel
#

%define         _orig_name      munmap

Summary:	Kernel module for patching ptrace()
Summary(pl.UTF-8):	Moduł jądra łatający dziurę w munmap()
Name:		kernel-misc-%{_orig_name}
# Is there any version???
Version:	0.1
%define	_rel	1
Release:	%{_rel}@%{_kernel_ver_str}
License:	GPL v2
Group:		Base/Kernel
Source0:	http://toxygen.net/hotfixes/munmap.c
# Source0-md5:	4167f4235decb4b3495e356a06caf875
%{!?_without_dist_kernel:BuildRequires:	kernel-headers}
BuildRequires:	%{kgcc_package}
BuildRequires:	rpmbuild(macros) >= 1.118
%{!?_without_dist_kernel:%requires_releq_kernel_up}
Requires(post,postun):	/sbin/depmod
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)

%description
Kernel module for buggy munmap() system call in kernels <2.2.26,
<2.4.25.

%description -l pl.UTF-8
Moduł kernela łatający dziurawe wywołanie systemowe munmap() w
kernelach <2.2.26, <2.4.25.

%package -n kernel-smp-misc-%{_orig_name}
Summary:	SMP kernel module for disabling ptrace()
Summary(pl.UTF-8):	Moduł jądra SMP wyłączający ptrace()
Release:	%{_rel}@%{_kernel_ver_str}
Group:		Base/Kernel
%{!?_without_dist_kernel:%requires_releq_kernel_smp}
Requires(post,postun):	/sbin/depmod

%description -n kernel-smp-misc-%{_orig_name}
SMP kernel module for buggy munmap() system call in kernels <2.2.26,
<2.4.25.

%description -n kernel-smp-misc-%{_orig_name} -l pl.UTF-8
Moduł jądra SMP włatający dziurawe wywołanie systemowe munmap() w
kernelach <2.2.26, <2.4.25.

%prep
%setup -q -T -c
install %{SOURCE0} .

%build
%{kgcc} -D__KERNEL__ -DMODULE -D__SMP__ -DCONFIG_X86_LOCAL_APIC -I%{_kernelsrcdir}/include -Wall \
	-Wstrict-prototypes -fomit-frame-pointer -fno-strict-aliasing -pipe -fno-strength-reduce \
	%{rpmcflags} -c %{_orig_name}.c

mv -f %{_orig_name}.o %{_orig_name}smp.o

%{kgcc} -D__KERNEL__ -DMODULE -I%{_kernelsrcdir}/include -Wall -Wstrict-prototypes \
	-fomit-frame-pointer -fno-strict-aliasing -pipe -fno-strength-reduce \
	%{rpmcflags} -c %{_orig_name}.c

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT/lib/modules/%{_kernel_ver}{,smp}/misc

install %{_orig_name}.o $RPM_BUILD_ROOT/lib/modules/%{_kernel_ver}/misc
install %{_orig_name}smp.o $RPM_BUILD_ROOT/lib/modules/%{_kernel_ver}smp/misc/%{_orig_name}.o

%clean
rm -rf $RPM_BUILD_ROOT

%post
%depmod %{_kernel_ver}

%postun
%depmod %{_kernel_ver}

%post	-n kernel-smp-misc-%{_orig_name}
%depmod %{_kernel_ver}smp

%postun -n kernel-smp-misc-%{_orig_name}
%depmod %{_kernel_ver}smp

%files
%defattr(644,root,root,755)
/lib/modules/%{_kernel_ver}/misc/*

%files -n kernel-smp-misc-%{_orig_name}
%defattr(644,root,root,755)
/lib/modules/%{_kernel_ver}smp/misc/*
