@echo off
REM
REM
REM This batch file must be used to set up a git tree to build on
REM systems where there is no autotools support (i.e. Microsoft).
REM
REM This file is not included nor needed for hns' release
REM archives, neither for hns' daily snapshot archives.

if exist GIT-INFO goto start_doing
ECHO ERROR: This file shall only be used with a hns git checkout.
goto end_all
:start_doing

if not exist hns_build.h.dist goto end_hns_build_h
copy /Y hns_build.h.dist hns_build.h
:end_hns_build_h

:end_all

