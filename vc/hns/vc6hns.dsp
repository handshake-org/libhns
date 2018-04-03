# Microsoft Developer Studio Project File - Name="hns" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102
# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=hns - Win32 LIB Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "vc6hns.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "vc6hns.mak" CFG="hns - Win32 LIB Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "hns - Win32 DLL Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "hns - Win32 DLL Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "hns - Win32 LIB Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "hns - Win32 LIB Release" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""

!IF  "$(CFG)" == "hns - Win32 DLL Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "dll-debug"
# PROP BASE Intermediate_Dir "dll-debug/obj"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "dll-debug"
# PROP Intermediate_Dir "dll-debug/obj"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
CPP=cl.exe
# ADD BASE CPP /nologo /MDd /W3 /GX /Zi /Od /I "..\.." /D "_DEBUG" /D "WIN32" /D "DEBUGBUILD" /D "HNS_BUILDING_LIBRARY" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /GX /Zi /Od /I "..\.." /D "_DEBUG" /D "WIN32" /D "DEBUGBUILD" /D "HNS_BUILDING_LIBRARY" /FD /GZ /c
MTL=midl.exe
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
RSC=rc.exe
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 ws2_32.lib advapi32.lib kernel32.lib /nologo /dll /incremental:no /debug /machine:I386 /out:"dll-debug/hnsd.dll" /implib:"dll-debug/hnsd.lib" /pdbtype:con /fixed:no
# ADD LINK32 ws2_32.lib advapi32.lib kernel32.lib /nologo /dll /incremental:no /debug /machine:I386 /out:"dll-debug/hnsd.dll" /implib:"dll-debug/hnsd.lib" /pdbtype:con /fixed:no

!ELSEIF  "$(CFG)" == "hns - Win32 DLL Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "dll-release"
# PROP BASE Intermediate_Dir "dll-release/obj"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "dll-release"
# PROP Intermediate_Dir "dll-release/obj"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
CPP=cl.exe
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "..\.." /D "NDEBUG" /D "WIN32" /D "HNS_BUILDING_LIBRARY" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\.." /D "NDEBUG" /D "WIN32" /D "HNS_BUILDING_LIBRARY" /FD /c
MTL=midl.exe
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
RSC=rc.exe
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 ws2_32.lib advapi32.lib kernel32.lib /nologo /dll /pdb:none /machine:I386 /out:"dll-release/hns.dll" /implib:"dll-release/hns.lib" /fixed:no /release /incremental:no
# ADD LINK32 ws2_32.lib advapi32.lib kernel32.lib /nologo /dll /pdb:none /machine:I386 /out:"dll-release/hns.dll" /implib:"dll-release/hns.lib" /fixed:no /release /incremental:no

!ELSEIF  "$(CFG)" == "hns - Win32 LIB Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "lib-debug"
# PROP BASE Intermediate_Dir "lib-debug/obj"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "lib-debug"
# PROP Intermediate_Dir "lib-debug/obj"
# PROP Target_Dir ""
CPP=cl.exe
# ADD BASE CPP /nologo /MDd /W3 /GX /Zi /Od /I "..\.." /D "_DEBUG" /D "WIN32" /D "DEBUGBUILD" /D "HNS_BUILDING_LIBRARY" /D "HNS_STATICLIB" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /GX /Zi /Od /I "..\.." /D "_DEBUG" /D "WIN32" /D "DEBUGBUILD" /D "HNS_BUILDING_LIBRARY" /D "HNS_STATICLIB" /FD /GZ /c
RSC=rc.exe
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"lib-debug/libhnsd.lib" /machine:I386
# ADD LIB32 /nologo /out:"lib-debug/libhnsd.lib" /machine:I386

!ELSEIF  "$(CFG)" == "hns - Win32 LIB Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "lib-release"
# PROP BASE Intermediate_Dir "lib-release/obj"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "lib-release"
# PROP Intermediate_Dir "lib-release/obj"
# PROP Target_Dir ""
CPP=cl.exe
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "..\.." /D "NDEBUG" /D "WIN32" /D "HNS_BUILDING_LIBRARY" /D "HNS_STATICLIB" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\.." /D "NDEBUG" /D "WIN32" /D "HNS_BUILDING_LIBRARY" /D "HNS_STATICLIB" /FD /c
RSC=rc.exe
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"lib-release/libhns.lib" /machine:I386
# ADD LIB32 /nologo /out:"lib-release/libhns.lib" /machine:I386

!ENDIF 

# Begin Target

# Name "hns - Win32 DLL Debug"
# Name "hns - Win32 DLL Release"
# Name "hns - Win32 LIB Debug"
# Name "hns - Win32 LIB Release"
# Begin Group "Source Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\hns__close_sockets.c
# End Source File
# Begin Source File

SOURCE=..\..\hns__get_hostent.c
# End Source File
# Begin Source File

SOURCE=..\..\hns__read_line.c
# End Source File
# Begin Source File

SOURCE=..\..\hns__timeval.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_cancel.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_create_query.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_data.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_destroy.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_expand_name.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_expand_string.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_fds.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_free_hostent.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_free_string.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_getenv.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_gethostbyaddr.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_gethostbyname.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_getnameinfo.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_getsock.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_init.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_library_init.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_llist.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_mkquery.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_nowarn.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_options.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_parse_a_reply.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_parse_aaaa_reply.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_parse_mx_reply.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_parse_naptr_reply.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_parse_ns_reply.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_parse_ptr_reply.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_parse_soa_reply.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_parse_srv_reply.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_parse_txt_reply.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_platform.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_process.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_query.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_search.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_send.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_strcasecmp.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_strdup.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_strerror.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_timeout.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_version.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_writev.c
# End Source File
# Begin Source File

SOURCE=..\..\bitncmp.c
# End Source File
# Begin Source File

SOURCE=..\..\inet_net_pton.c
# End Source File
# Begin Source File

SOURCE=..\..\inet_ntop.c
# End Source File
# Begin Source File

SOURCE=..\..\windows_port.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\hns.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_build.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_data.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_dns.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_getenv.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_iphlpapi.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_ipv6.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_library_init.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_llist.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_nowarn.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_platform.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_private.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_rules.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_setup.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_strcasecmp.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_strdup.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_version.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_writev.h
# End Source File
# Begin Source File

SOURCE=..\..\bitncmp.h
# End Source File
# Begin Source File

SOURCE=..\..\config-win32.h
# End Source File
# Begin Source File

SOURCE=..\..\inet_net_pton.h
# End Source File
# Begin Source File

SOURCE=..\..\inet_ntop.h
# End Source File
# Begin Source File

SOURCE=..\..\nameser.h
# End Source File
# Begin Source File

SOURCE=..\..\setup_once.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\hns.rc
# End Source File
# End Group
# End Target
# End Project
