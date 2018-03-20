
libtest1.so：     文件格式 elf64-x86-64


Disassembly of section .init:

0000000000000548 <_init>:
 548:	48 83 ec 08          	sub    $0x8,%rsp
 54c:	48 8b 05 8d 0a 20 00 	mov    0x200a8d(%rip),%rax        # 200fe0 <_DYNAMIC+0x1c8>
 553:	48 85 c0             	test   %rax,%rax
 556:	74 05                	je     55d <_init+0x15>
 558:	e8 33 00 00 00       	callq  590 <puts@plt+0x10>
 55d:	48 83 c4 08          	add    $0x8,%rsp
 561:	c3                   	retq   

Disassembly of section .plt:

0000000000000570 <puts@plt-0x10>:
 570:	ff 35 92 0a 20 00    	pushq  0x200a92(%rip)        # 201008 <_GLOBAL_OFFSET_TABLE_+0x8>
 576:	ff 25 94 0a 20 00    	jmpq   *0x200a94(%rip)        # 201010 <_GLOBAL_OFFSET_TABLE_+0x10>
 57c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000000580 <puts@plt>:
 580:	ff 25 92 0a 20 00    	jmpq   *0x200a92(%rip)        # 201018 <_GLOBAL_OFFSET_TABLE_+0x18>
 586:	68 00 00 00 00       	pushq  $0x0
 58b:	e9 e0 ff ff ff       	jmpq   570 <_init+0x28>

Disassembly of section .plt.got:

0000000000000590 <.plt.got>:
 590:	ff 25 4a 0a 20 00    	jmpq   *0x200a4a(%rip)        # 200fe0 <_DYNAMIC+0x1c8>
 596:	66 90                	xchg   %ax,%ax
 598:	ff 25 5a 0a 20 00    	jmpq   *0x200a5a(%rip)        # 200ff8 <_DYNAMIC+0x1e0>
 59e:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

00000000000005a0 <deregister_tm_clones>:
 5a0:	48 8d 3d 81 0a 20 00 	lea    0x200a81(%rip),%rdi        # 201028 <_edata>
 5a7:	48 8d 05 81 0a 20 00 	lea    0x200a81(%rip),%rax        # 20102f <_edata+0x7>
 5ae:	55                   	push   %rbp
 5af:	48 29 f8             	sub    %rdi,%rax
 5b2:	48 89 e5             	mov    %rsp,%rbp
 5b5:	48 83 f8 0e          	cmp    $0xe,%rax
 5b9:	76 15                	jbe    5d0 <deregister_tm_clones+0x30>
 5bb:	48 8b 05 16 0a 20 00 	mov    0x200a16(%rip),%rax        # 200fd8 <_DYNAMIC+0x1c0>
 5c2:	48 85 c0             	test   %rax,%rax
 5c5:	74 09                	je     5d0 <deregister_tm_clones+0x30>
 5c7:	5d                   	pop    %rbp
 5c8:	ff e0                	jmpq   *%rax
 5ca:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
 5d0:	5d                   	pop    %rbp
 5d1:	c3                   	retq   
 5d2:	0f 1f 40 00          	nopl   0x0(%rax)
 5d6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 5dd:	00 00 00 

00000000000005e0 <register_tm_clones>:
 5e0:	48 8d 3d 41 0a 20 00 	lea    0x200a41(%rip),%rdi        # 201028 <_edata>
 5e7:	48 8d 35 3a 0a 20 00 	lea    0x200a3a(%rip),%rsi        # 201028 <_edata>
 5ee:	55                   	push   %rbp
 5ef:	48 29 fe             	sub    %rdi,%rsi
 5f2:	48 89 e5             	mov    %rsp,%rbp
 5f5:	48 c1 fe 03          	sar    $0x3,%rsi
 5f9:	48 89 f0             	mov    %rsi,%rax
 5fc:	48 c1 e8 3f          	shr    $0x3f,%rax
 600:	48 01 c6             	add    %rax,%rsi
 603:	48 d1 fe             	sar    %rsi
 606:	74 18                	je     620 <register_tm_clones+0x40>
 608:	48 8b 05 e1 09 20 00 	mov    0x2009e1(%rip),%rax        # 200ff0 <_DYNAMIC+0x1d8>
 60f:	48 85 c0             	test   %rax,%rax
 612:	74 0c                	je     620 <register_tm_clones+0x40>
 614:	5d                   	pop    %rbp
 615:	ff e0                	jmpq   *%rax
 617:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
 61e:	00 00 
 620:	5d                   	pop    %rbp
 621:	c3                   	retq   
 622:	0f 1f 40 00          	nopl   0x0(%rax)
 626:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 62d:	00 00 00 

0000000000000630 <__do_global_dtors_aux>:
 630:	80 3d f1 09 20 00 00 	cmpb   $0x0,0x2009f1(%rip)        # 201028 <_edata>
 637:	75 27                	jne    660 <__do_global_dtors_aux+0x30>
 639:	48 83 3d b7 09 20 00 	cmpq   $0x0,0x2009b7(%rip)        # 200ff8 <_DYNAMIC+0x1e0>
 640:	00 
 641:	55                   	push   %rbp
 642:	48 89 e5             	mov    %rsp,%rbp
 645:	74 0c                	je     653 <__do_global_dtors_aux+0x23>
 647:	48 8b 3d d2 09 20 00 	mov    0x2009d2(%rip),%rdi        # 201020 <__dso_handle>
 64e:	e8 45 ff ff ff       	callq  598 <puts@plt+0x18>
 653:	e8 48 ff ff ff       	callq  5a0 <deregister_tm_clones>
 658:	5d                   	pop    %rbp
 659:	c6 05 c8 09 20 00 01 	movb   $0x1,0x2009c8(%rip)        # 201028 <_edata>
 660:	f3 c3                	repz retq 
 662:	0f 1f 40 00          	nopl   0x0(%rax)
 666:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 66d:	00 00 00 

0000000000000670 <frame_dummy>:
 670:	48 8d 3d 99 07 20 00 	lea    0x200799(%rip),%rdi        # 200e10 <__JCR_END__>
 677:	48 83 3f 00          	cmpq   $0x0,(%rdi)
 67b:	75 0b                	jne    688 <frame_dummy+0x18>
 67d:	e9 5e ff ff ff       	jmpq   5e0 <register_tm_clones>
 682:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
 688:	48 8b 05 59 09 20 00 	mov    0x200959(%rip),%rax        # 200fe8 <_DYNAMIC+0x1d0>
 68f:	48 85 c0             	test   %rax,%rax
 692:	74 e9                	je     67d <frame_dummy+0xd>
 694:	55                   	push   %rbp
 695:	48 89 e5             	mov    %rsp,%rbp
 698:	ff d0                	callq  *%rax
 69a:	5d                   	pop    %rbp
 69b:	e9 40 ff ff ff       	jmpq   5e0 <register_tm_clones>

00000000000006a0 <libtest1>:
int puts(char const *);

void libtest1()
{
 6a0:	55                   	push   %rbp
 6a1:	48 89 e5             	mov    %rsp,%rbp
    puts("libtest1: 1st call to the original puts()");
 6a4:	48 8d 3d 25 00 00 00 	lea    0x25(%rip),%rdi        # 6d0 <_fini+0x10>
 6ab:	e8 d0 fe ff ff       	callq  580 <puts@plt>
    puts("libtest1: 2nd call to the original puts()");
 6b0:	48 8d 3d 49 00 00 00 	lea    0x49(%rip),%rdi        # 700 <_fini+0x40>
 6b7:	e8 c4 fe ff ff       	callq  580 <puts@plt>
}
 6bc:	90                   	nop
 6bd:	5d                   	pop    %rbp
 6be:	c3                   	retq   

Disassembly of section .fini:

00000000000006c0 <_fini>:
 6c0:	48 83 ec 08          	sub    $0x8,%rsp
 6c4:	48 83 c4 08          	add    $0x8,%rsp
 6c8:	c3                   	retq   
