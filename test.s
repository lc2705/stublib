
test：     文件格式 elf64-x86-64


Disassembly of section .init:

00000000004005f8 <_init>:
  4005f8:	48 83 ec 08          	sub    $0x8,%rsp
  4005fc:	48 8b 05 f5 09 20 00 	mov    0x2009f5(%rip),%rax        # 600ff8 <_DYNAMIC+0x200>
  400603:	48 85 c0             	test   %rax,%rax
  400606:	74 05                	je     40060d <_init+0x15>
  400608:	e8 73 00 00 00       	callq  400680 <install_stub@plt+0x10>
  40060d:	48 83 c4 08          	add    $0x8,%rsp
  400611:	c3                   	retq   

Disassembly of section .plt:

0000000000400620 <libtest1@plt-0x10>:
  400620:	ff 35 e2 09 20 00    	pushq  0x2009e2(%rip)        # 601008 <_GLOBAL_OFFSET_TABLE_+0x8>
  400626:	ff 25 e4 09 20 00    	jmpq   *0x2009e4(%rip)        # 601010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40062c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000400630 <libtest1@plt>:
  400630:	ff 25 e2 09 20 00    	jmpq   *0x2009e2(%rip)        # 601018 <_GLOBAL_OFFSET_TABLE_+0x18>
  400636:	68 00 00 00 00       	pushq  $0x0
  40063b:	e9 e0 ff ff ff       	jmpq   400620 <_init+0x28>

0000000000400640 <__libc_start_main@plt>:
  400640:	ff 25 da 09 20 00    	jmpq   *0x2009da(%rip)        # 601020 <_GLOBAL_OFFSET_TABLE_+0x20>
  400646:	68 01 00 00 00       	pushq  $0x1
  40064b:	e9 d0 ff ff ff       	jmpq   400620 <_init+0x28>

0000000000400650 <uninstall_stub@plt>:
  400650:	ff 25 d2 09 20 00    	jmpq   *0x2009d2(%rip)        # 601028 <_GLOBAL_OFFSET_TABLE_+0x28>
  400656:	68 02 00 00 00       	pushq  $0x2
  40065b:	e9 c0 ff ff ff       	jmpq   400620 <_init+0x28>

0000000000400660 <libtest2@plt>:
  400660:	ff 25 ca 09 20 00    	jmpq   *0x2009ca(%rip)        # 601030 <_GLOBAL_OFFSET_TABLE_+0x30>
  400666:	68 03 00 00 00       	pushq  $0x3
  40066b:	e9 b0 ff ff ff       	jmpq   400620 <_init+0x28>

0000000000400670 <install_stub@plt>:
  400670:	ff 25 c2 09 20 00    	jmpq   *0x2009c2(%rip)        # 601038 <_GLOBAL_OFFSET_TABLE_+0x38>
  400676:	68 04 00 00 00       	pushq  $0x4
  40067b:	e9 a0 ff ff ff       	jmpq   400620 <_init+0x28>

Disassembly of section .plt.got:

0000000000400680 <.plt.got>:
  400680:	ff 25 72 09 20 00    	jmpq   *0x200972(%rip)        # 600ff8 <_DYNAMIC+0x200>
  400686:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

0000000000400690 <_start>:
  400690:	31 ed                	xor    %ebp,%ebp
  400692:	49 89 d1             	mov    %rdx,%r9
  400695:	5e                   	pop    %rsi
  400696:	48 89 e2             	mov    %rsp,%rdx
  400699:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  40069d:	50                   	push   %rax
  40069e:	54                   	push   %rsp
  40069f:	49 c7 c0 30 08 40 00 	mov    $0x400830,%r8
  4006a6:	48 c7 c1 c0 07 40 00 	mov    $0x4007c0,%rcx
  4006ad:	48 c7 c7 86 07 40 00 	mov    $0x400786,%rdi
  4006b4:	e8 87 ff ff ff       	callq  400640 <__libc_start_main@plt>
  4006b9:	f4                   	hlt    
  4006ba:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

00000000004006c0 <deregister_tm_clones>:
  4006c0:	b8 57 10 60 00       	mov    $0x601057,%eax
  4006c5:	55                   	push   %rbp
  4006c6:	48 2d 50 10 60 00    	sub    $0x601050,%rax
  4006cc:	48 83 f8 0e          	cmp    $0xe,%rax
  4006d0:	48 89 e5             	mov    %rsp,%rbp
  4006d3:	76 1b                	jbe    4006f0 <deregister_tm_clones+0x30>
  4006d5:	b8 00 00 00 00       	mov    $0x0,%eax
  4006da:	48 85 c0             	test   %rax,%rax
  4006dd:	74 11                	je     4006f0 <deregister_tm_clones+0x30>
  4006df:	5d                   	pop    %rbp
  4006e0:	bf 50 10 60 00       	mov    $0x601050,%edi
  4006e5:	ff e0                	jmpq   *%rax
  4006e7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  4006ee:	00 00 
  4006f0:	5d                   	pop    %rbp
  4006f1:	c3                   	retq   
  4006f2:	0f 1f 40 00          	nopl   0x0(%rax)
  4006f6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4006fd:	00 00 00 

0000000000400700 <register_tm_clones>:
  400700:	be 50 10 60 00       	mov    $0x601050,%esi
  400705:	55                   	push   %rbp
  400706:	48 81 ee 50 10 60 00 	sub    $0x601050,%rsi
  40070d:	48 c1 fe 03          	sar    $0x3,%rsi
  400711:	48 89 e5             	mov    %rsp,%rbp
  400714:	48 89 f0             	mov    %rsi,%rax
  400717:	48 c1 e8 3f          	shr    $0x3f,%rax
  40071b:	48 01 c6             	add    %rax,%rsi
  40071e:	48 d1 fe             	sar    %rsi
  400721:	74 15                	je     400738 <register_tm_clones+0x38>
  400723:	b8 00 00 00 00       	mov    $0x0,%eax
  400728:	48 85 c0             	test   %rax,%rax
  40072b:	74 0b                	je     400738 <register_tm_clones+0x38>
  40072d:	5d                   	pop    %rbp
  40072e:	bf 50 10 60 00       	mov    $0x601050,%edi
  400733:	ff e0                	jmpq   *%rax
  400735:	0f 1f 00             	nopl   (%rax)
  400738:	5d                   	pop    %rbp
  400739:	c3                   	retq   
  40073a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000400740 <__do_global_dtors_aux>:
  400740:	80 3d 09 09 20 00 00 	cmpb   $0x0,0x200909(%rip)        # 601050 <__TMC_END__>
  400747:	75 11                	jne    40075a <__do_global_dtors_aux+0x1a>
  400749:	55                   	push   %rbp
  40074a:	48 89 e5             	mov    %rsp,%rbp
  40074d:	e8 6e ff ff ff       	callq  4006c0 <deregister_tm_clones>
  400752:	5d                   	pop    %rbp
  400753:	c6 05 f6 08 20 00 01 	movb   $0x1,0x2008f6(%rip)        # 601050 <__TMC_END__>
  40075a:	f3 c3                	repz retq 
  40075c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000400760 <frame_dummy>:
  400760:	bf f0 0d 60 00       	mov    $0x600df0,%edi
  400765:	48 83 3f 00          	cmpq   $0x0,(%rdi)
  400769:	75 05                	jne    400770 <frame_dummy+0x10>
  40076b:	eb 93                	jmp    400700 <register_tm_clones>
  40076d:	0f 1f 00             	nopl   (%rax)
  400770:	b8 00 00 00 00       	mov    $0x0,%eax
  400775:	48 85 c0             	test   %rax,%rax
  400778:	74 f1                	je     40076b <frame_dummy+0xb>
  40077a:	55                   	push   %rbp
  40077b:	48 89 e5             	mov    %rsp,%rbp
  40077e:	ff d0                	callq  *%rax
  400780:	5d                   	pop    %rbp
  400781:	e9 7a ff ff ff       	jmpq   400700 <register_tm_clones>

0000000000400786 <main>:

void libtest1();
void libtest2();

int main() 
{
  400786:	55                   	push   %rbp
  400787:	48 89 e5             	mov    %rsp,%rbp
	libtest1();
  40078a:	b8 00 00 00 00       	mov    $0x0,%eax
  40078f:	e8 9c fe ff ff       	callq  400630 <libtest1@plt>

	//===============================

    install_stub(libtest1, libtest2);
  400794:	be 60 06 40 00       	mov    $0x400660,%esi
  400799:	bf 30 06 40 00       	mov    $0x400630,%edi
  40079e:	e8 cd fe ff ff       	callq  400670 <install_stub@plt>
	uninstall_stub(libtest1);
  4007a3:	bf 30 06 40 00       	mov    $0x400630,%edi
  4007a8:	e8 a3 fe ff ff       	callq  400650 <uninstall_stub@plt>

    //===============================
	libtest1();
  4007ad:	b8 00 00 00 00       	mov    $0x0,%eax
  4007b2:	e8 79 fe ff ff       	callq  400630 <libtest1@plt>
	return 0;	
  4007b7:	b8 00 00 00 00       	mov    $0x0,%eax
}
  4007bc:	5d                   	pop    %rbp
  4007bd:	c3                   	retq   
  4007be:	66 90                	xchg   %ax,%ax

00000000004007c0 <__libc_csu_init>:
  4007c0:	41 57                	push   %r15
  4007c2:	41 56                	push   %r14
  4007c4:	41 89 ff             	mov    %edi,%r15d
  4007c7:	41 55                	push   %r13
  4007c9:	41 54                	push   %r12
  4007cb:	4c 8d 25 0e 06 20 00 	lea    0x20060e(%rip),%r12        # 600de0 <__frame_dummy_init_array_entry>
  4007d2:	55                   	push   %rbp
  4007d3:	48 8d 2d 0e 06 20 00 	lea    0x20060e(%rip),%rbp        # 600de8 <__init_array_end>
  4007da:	53                   	push   %rbx
  4007db:	49 89 f6             	mov    %rsi,%r14
  4007de:	49 89 d5             	mov    %rdx,%r13
  4007e1:	4c 29 e5             	sub    %r12,%rbp
  4007e4:	48 83 ec 08          	sub    $0x8,%rsp
  4007e8:	48 c1 fd 03          	sar    $0x3,%rbp
  4007ec:	e8 07 fe ff ff       	callq  4005f8 <_init>
  4007f1:	48 85 ed             	test   %rbp,%rbp
  4007f4:	74 20                	je     400816 <__libc_csu_init+0x56>
  4007f6:	31 db                	xor    %ebx,%ebx
  4007f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  4007ff:	00 
  400800:	4c 89 ea             	mov    %r13,%rdx
  400803:	4c 89 f6             	mov    %r14,%rsi
  400806:	44 89 ff             	mov    %r15d,%edi
  400809:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  40080d:	48 83 c3 01          	add    $0x1,%rbx
  400811:	48 39 eb             	cmp    %rbp,%rbx
  400814:	75 ea                	jne    400800 <__libc_csu_init+0x40>
  400816:	48 83 c4 08          	add    $0x8,%rsp
  40081a:	5b                   	pop    %rbx
  40081b:	5d                   	pop    %rbp
  40081c:	41 5c                	pop    %r12
  40081e:	41 5d                	pop    %r13
  400820:	41 5e                	pop    %r14
  400822:	41 5f                	pop    %r15
  400824:	c3                   	retq   
  400825:	90                   	nop
  400826:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40082d:	00 00 00 

0000000000400830 <__libc_csu_fini>:
  400830:	f3 c3                	repz retq 

Disassembly of section .fini:

0000000000400834 <_fini>:
  400834:	48 83 ec 08          	sub    $0x8,%rsp
  400838:	48 83 c4 08          	add    $0x8,%rsp
  40083c:	c3                   	retq   
