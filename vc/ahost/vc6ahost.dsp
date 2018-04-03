# Microsoft Developer Studio Project File - Name="hhost" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=hhost - Win32 using hns LIB Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "vc6hhost.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "vc6hhost.mak" CFG="hhost - Win32 using hns LIB Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "hhost - Win32 using hns DLL Debug" (based on "Win32 (x86) Console Application")
!MESSAGE "hhost - Win32 using hns DLL Release" (based on "Win32 (x86) Console Application")
!MESSAGE "hhost - Win32 using hns LIB Debug" (based on "Win32 (x86) Console Application")
!MESSAGE "hhost - Win32 using hns LIB Release" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "hhost - Win32 using hns DLL Debug"

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
# ADD BASE CPP /nologo /MDd /W3 /GX /Zi /Od /I "..\.." /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /GX /Zi /Od /I "..\.." /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 hnsd.lib ws2_32.lib advapi32.lib kernel32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /out:"dll-debug/hhost.exe" /pdbtype:con /libpath:"..\hns\dll-debug" /fixed:no
# ADD LINK32 hnsd.lib ws2_32.lib advapi32.lib kernel32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /out:"dll-debug/hhost.exe" /pdbtype:con /libpath:"..\hns\dll-debug" /fixed:no

!ELSEIF  "$(CFG)" == "hhost - Win32 using hns DLL Release"

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
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "..\.." /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\.." /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 hns.lib ws2_32.lib advapi32.lib kernel32.lib /nologo /subsystem:console /pdb:none /machine:I386 /out:"dll-release/hhost.exe" /libpath:"..\hns\dll-release" /fixed:no
# ADD LINK32 hns.lib ws2_32.lib advapi32.lib kernel32.lib /nologo /subsystem:console /pdb:none /machine:I386 /out:"dll-release/hhost.exe" /libpath:"..\hns\dll-release" /fixed:no

!ELSEIF  "$(CFG)" == "hhost - Win32 using hns LIB Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "lib-debug"
# PROP BASE Intermediate_Dir "lib-debug/obj"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "lib-debug"
# PROP Intermediate_Dir "lib-debug/obj"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /GX /Zi /Od /I "..\.." /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "HNS_STATICLIB" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /GX /Zi /Od /I "..\.." /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "HNS_STATICLIB" /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 libhnsd.lib ws2_32.lib advapi32.lib kernel32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /out:"lib-debug/hhost.exe" /pdbtype:con /libpath:"..\hns\lib-debug" /fixed:no
# ADD LINK32 libhnsd.lib ws2_32.lib advapi32.lib kernel32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /out:"lib-debug/hhost.exe" /pdbtype:con /libpath:"..\hns\lib-debug" /fixed:no

!ELSEIF  "$(CFG)" == "hhost - Win32 using hns LIB Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "lib-release"
# PROP BASE Intermediate_Dir "lib-release/obj"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "lib-release"
# PROP Intermediate_Dir "lib-release/obj"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "..\.." /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "HNS_STATICLIB" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\.." /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "HNS_STATICLIB" /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 libhns.lib ws2_32.lib advapi32.lib kernel32.lib /nologo /subsystem:console /pdb:none /machine:I386 /out:"lib-release/hhost.exe" /libpath:"..\hns\lib-release" /fixed:no
# ADD LINK32 libhns.lib ws2_32.lib advapi32.lib kernel32.lib /nologo /subsystem:console /pdb:none /machine:I386 /out:"lib-release/hhost.exe" /libpath:"..\hns\lib-release" /fixed:no

!ENDIF 

# Begin Target

# Name "hhost - Win32 using hns DLL Debug"
# Name "hhost - Win32 using hns DLL Release"
# Name "hhost - Win32 using hns LIB Debug"
# Name "hhost - Win32 using hns LIB Release"
# Begin Group "Source Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\hhost.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_getopt.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_nowarn.c
# End Source File
# Begin Source File

SOURCE=..\..\hns_strcasecmp.c
# End Source File
# Begin Source File

SOURCE=..\..\inet_net_pton.c
# End Source File
# Begin Source File

SOURCE=..\..\inet_ntop.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\hns_getopt.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_nowarn.h
# End Source File
# Begin Source File

SOURCE=..\..\hns_strcasecmp.h
# End Source File
# Begin Source File

SOURCE=..\..\inet_net_pton.h
# End Source File
# Begin Source File

SOURCE=..\..\inet_ntop.h
# End Source File
# End Group
# End Target
# End Project
