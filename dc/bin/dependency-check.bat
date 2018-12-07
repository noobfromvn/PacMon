@REM
@REM Copyright (c) 2012-2013 Jeremy Long.  All rights reserved.
@REM
@REM Licensed under the Apache License, Version 2.0 (the "License");
@REM you may not use this file except in compliance with the License.
@REM You may obtain a copy of the License at
@REM
@REM     http://www.apache.org/licenses/LICENSE-2.0
@REM
@REM Unless required by applicable law or agreed to in writing, software
@REM distributed under the License is distributed on an "AS IS" BASIS,
@REM WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
@REM See the License for the specific language governing permissions and
@REM limitations under the License.
@REM ----------------------------------------------------------------------------

@echo off

set ERROR_CODE=0

:init
@REM Decide how to startup depending on the version of windows

@REM -- Win98ME
if NOT "%OS%"=="Windows_NT" goto Win9xArg

@REM set local scope for the variables with windows NT shell
if "%OS%"=="Windows_NT" @setlocal

@REM -- 4NT shell
if "%eval[2+2]" == "4" goto 4NTArgs

@REM -- Regular WinNT shell
set CMD_LINE_ARGS=%*
goto WinNTGetScriptDir

@REM The 4NT Shell from jp software
:4NTArgs
set CMD_LINE_ARGS=%$
goto WinNTGetScriptDir

:Win9xArg
@REM Slurp the command line arguments.  This loop allows for an unlimited number
@REM of arguments (up to the command line limit, anyway).
set CMD_LINE_ARGS=
:Win9xApp
if %1a==a goto Win9xGetScriptDir
set CMD_LINE_ARGS=%CMD_LINE_ARGS% %1
shift
goto Win9xApp

:Win9xGetScriptDir
set SAVEDIR=%CD%
%0\
cd %0\..\.. 
set BASEDIR=%CD%
cd %SAVEDIR%
set SAVE_DIR=
goto repoSetup

:WinNTGetScriptDir
set BASEDIR=%~dp0\..

:repoSetup
set REPO=


if "%JAVACMD%"=="" set JAVACMD=java

if "%REPO%"=="" set REPO=%BASEDIR%\repo

set CLASSPATH="%BASEDIR%"\plugins\*;"%REPO%"\commons-cli\commons-cli\1.4\commons-cli-1.4.jar;"%REPO%"\org\owasp\dependency-check-core\4.0.0\dependency-check-core-4.0.0.jar;"%REPO%"\com\vdurmont\semver4j\2.2.0\semver4j-2.2.0.jar;"%REPO%"\joda-time\joda-time\1.6\joda-time-1.6.jar;"%REPO%"\org\apache\commons\commons-compress\1.18\commons-compress-1.18.jar;"%REPO%"\commons-io\commons-io\2.6\commons-io-2.6.jar;"%REPO%"\org\apache\commons\commons-lang3\3.4\commons-lang3-3.4.jar;"%REPO%"\org\apache\commons\commons-text\1.3\commons-text-1.3.jar;"%REPO%"\org\apache\lucene\lucene-core\7.5.0\lucene-core-7.5.0.jar;"%REPO%"\org\apache\lucene\lucene-analyzers-common\7.5.0\lucene-analyzers-common-7.5.0.jar;"%REPO%"\org\apache\lucene\lucene-queryparser\7.5.0\lucene-queryparser-7.5.0.jar;"%REPO%"\org\apache\lucene\lucene-queries\7.5.0\lucene-queries-7.5.0.jar;"%REPO%"\org\apache\lucene\lucene-sandbox\7.5.0\lucene-sandbox-7.5.0.jar;"%REPO%"\org\apache\velocity\velocity\1.7\velocity-1.7.jar;"%REPO%"\commons-collections\commons-collections\3.2.2\commons-collections-3.2.2.jar;"%REPO%"\commons-lang\commons-lang\2.4\commons-lang-2.4.jar;"%REPO%"\com\h2database\h2\1.4.196\h2-1.4.196.jar;"%REPO%"\org\glassfish\javax.json\1.0.4\javax.json-1.0.4.jar;"%REPO%"\org\jsoup\jsoup\1.11.3\jsoup-1.11.3.jar;"%REPO%"\com\sun\mail\mailapi\1.6.2\mailapi-1.6.2.jar;"%REPO%"\com\google\code\gson\gson\2.8.5\gson-2.8.5.jar;"%REPO%"\com\h3xstream\retirejs\retirejs-core\3.0.1\retirejs-core-3.0.1.jar;"%REPO%"\org\json\json\20140107\json-20140107.jar;"%REPO%"\com\esotericsoftware\minlog\1.3\minlog-1.3.jar;"%REPO%"\com\github\spullara\mustache\java\compiler\0.8.17\compiler-0.8.17.jar;"%REPO%"\com\google\guava\guava\27.0-jre\guava-27.0-jre.jar;"%REPO%"\com\google\guava\failureaccess\1.0\failureaccess-1.0.jar;"%REPO%"\com\google\guava\listenablefuture\9999.0-empty-to-avoid-conflict-with-guava\listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar;"%REPO%"\org\checkerframework\checker-qual\2.5.2\checker-qual-2.5.2.jar;"%REPO%"\com\google\errorprone\error_prone_annotations\2.2.0\error_prone_annotations-2.2.0.jar;"%REPO%"\com\google\j2objc\j2objc-annotations\1.1\j2objc-annotations-1.1.jar;"%REPO%"\org\codehaus\mojo\animal-sniffer-annotations\1.17\animal-sniffer-annotations-1.17.jar;"%REPO%"\org\owasp\dependency-check-utils\4.0.0\dependency-check-utils-4.0.0.jar;"%REPO%"\org\slf4j\slf4j-api\1.7.25\slf4j-api-1.7.25.jar;"%REPO%"\ch\qos\logback\logback-core\1.2.3\logback-core-1.2.3.jar;"%REPO%"\ch\qos\logback\logback-classic\1.2.3\logback-classic-1.2.3.jar;"%REPO%"\org\apache\ant\ant\1.9.9\ant-1.9.9.jar;"%REPO%"\com\google\code\findbugs\jsr305\3.0.1\jsr305-3.0.1.jar;"%REPO%"\org\owasp\dependency-check-cli\4.0.0\dependency-check-cli-4.0.0.jar

set ENDORSED_DIR=
if NOT "%ENDORSED_DIR%" == "" set CLASSPATH="%BASEDIR%"\%ENDORSED_DIR%\*;%CLASSPATH%

if NOT "%CLASSPATH_PREFIX%" == "" set CLASSPATH=%CLASSPATH_PREFIX%;%CLASSPATH%

@REM Reaching here means variables are defined and arguments have been captured
:endInit

%JAVACMD% %JAVA_OPTS%  -classpath %CLASSPATH% -Dapp.name="dependency-check" -Dapp.repo="%REPO%" -Dapp.home="%BASEDIR%" -Dbasedir="%BASEDIR%" org.owasp.dependencycheck.App %CMD_LINE_ARGS%
if %ERRORLEVEL% NEQ 0 goto error
goto end

:error
if "%OS%"=="Windows_NT" @endlocal
set ERROR_CODE=%ERRORLEVEL%

:end
@REM set local scope for the variables with windows NT shell
if "%OS%"=="Windows_NT" goto endNT

@REM For old DOS remove the set variables from ENV - we assume they were not set
@REM before we started - at least we don't leave any baggage around
set CMD_LINE_ARGS=
goto postExec

:endNT
@REM If error code is set to 1 then the endlocal was done already in :error.
if %ERROR_CODE% EQU 0 @endlocal


:postExec

if "%FORCE_EXIT_ON_ERROR%" == "on" (
  if %ERROR_CODE% NEQ 0 exit %ERROR_CODE%
)

exit /B %ERROR_CODE%
