#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/cdefs.h>
#include <sys/mman.h>
#include "utils/list.h"
#include "utils/InstructionSize.h"

#define DIRECT_JUMP 0xe9
#define UNDIRECT_JUMP 0x25ff
#define INSTRU_BUFF_SIZE 64
#define MAX_INSTRUCTION_LENGTH 0xf

#define unlikely(cond) __glibc_unlikely(cond)

//#define DEBUG

typedef struct _stub_info_t
{
	void *func_addr;
	void *new_addr;

	void *instru_buff;	
	void *orig_buff;
    int orig_buff_len;
}stub_info_t;


static list_t *stub_info_list = NULL;
static size_t pagesize = 0;


static int stub_info_match(void *func, stub_info_t *info)
{
	return info->func_addr == func;
}

static stub_info_t* stub_malloc()
{
	stub_info_t* stub = malloc(sizeof(stub_info_t));
    if(stub == NULL) {
	    fprintf(stderr, "stub malloc error.\n");
		return NULL;	
	}
	stub->func_addr = NULL;
	stub->new_addr = NULL;
	stub->instru_buff = NULL;
	stub->orig_buff = NULL;
	stub->orig_buff_len = 0;
	return stub;
}

static void stub_free(stub_info_t *stub)
{
	if(stub->instru_buff != NULL)
	    free(stub->instru_buff);
	if(stub->orig_buff != NULL)
	    free(stub->orig_buff);
	free(stub);
}

static int write_instru_jump(void *dst, void *src, int len)
{
    int ret = 0;
    if(unlikely(pagesize == 0)) {
	    pagesize = sysconf(_SC_PAGESIZE);	
		if(pagesize == -1) {
		    fprintf(stderr, "Get pagesize error.\n");
			return -1;	
		}
	}
	ret = mprotect((void*)((size_t)dst & (((size_t)-1) ^ (pagesize - 1))), pagesize, PROT_WRITE | PROT_EXEC | PROT_READ);
    if(ret != 0) {
	    perror("mprotect error");
		return -1;	
	}
	memcpy(dst, src, len);
	return 0;
}

static int write_instru_back(void *dst_func, void *src_func, int min_len, int buff_size)
{
	int ret = 0;
	long unsigned int real_len = 0, buff_len = 0, len = 0;
    unsigned char instru[INSTRU_BUFF_SIZE] = {0};
	unsigned char *instru_p = instru, *instru_end = instru + buff_size;
    long unsigned int tmp = 0; 

    if(unlikely(pagesize == 0)) {
	    pagesize = sysconf(_SC_PAGESIZE);	
		if(pagesize == -1) {
		    fprintf(stderr, "Get pagesize error.\n");
			return 0;	
		}
	}
    
	if(0 != mprotect((void*)((size_t)dst_func & (((size_t)-1) ^ (pagesize - 1))), pagesize, PROT_WRITE | PROT_EXEC | PROT_READ)) {
	    perror("mprotect error");
		return 0;	
	}

	while(0 < min_len) {
	    len = InstructionSize_x86_64(src_func + real_len, MAX_INSTRUCTION_LENGTH);

#ifdef DEBUG
		printf("len %d\n", len);
		for(int i = 0; i < len; i++)
			printf("%02x ", *(unsigned char*)(src_func + real_len + i));
		printf("\n");
#endif

        tmp = *(long unsigned int*)(src_func + real_len);
        switch(len) {
			case 5:
				if((tmp & 0xff) == 0xe8) {
				    //e8 d0 fe ff ff  callq -0x130(%rip)
#ifdef DEBUG
				    printf("callq rip\n");
#endif
					long unsigned int data = ((long unsigned int)tmp & 0xffffffff00) >> 8;
					if(data & ~0x7fffffff) {
					    data = (~data + 1) & 0xffffffff;
						data = (long unsigned int)src_func + real_len + len - data;
					} else {
					    data = (long unsigned int)src_func + real_len + len + data;
					}
			        long unsigned int diff = (long unsigned int) dst_func - data + len;
                    if(diff < 0xffffffff || diff > 0xffffffff00000000) {
					    tmp = (tmp & 0xff) | (diff << 8);
                        memcpy(instru_p, &tmp, len);
		                instru_p += len;
					} else {
						// new instruction ff 15 xx xx xx xx   callq *xxxxxxxx(%rip)
						// change instruction len to 6
					    instru_end -= sizeof(long unsigned int);
						memcpy(instru_end, &data, sizeof(long unsigned int));
						tmp = ((long unsigned int)instru_end - (long unsigned int)instru_p - 6) << 16;
						tmp |= 0x15ff; // callq *
                        memcpy(instru_p, &tmp, 6);
						instru_p += 6;
					}
				}
				break;
			case 6:
				if((tmp & 0xffff) == 0x25ff) {
					// ff 25 f2 38 3d 00    jmpq *0x3d38f2(%rip)
#ifdef DEBUG
				    printf("jmpq rip\n");	
#endif
				}
                memcpy(instru_p, &tmp, len);
		        instru_p += len;
				break;
		    case 7:
			    if((tmp & 0xffff) == 0x8d48 || (tmp & 0xffff) == 0x8b48) {
				    //48 8d 3d 25 00 00 00  lea 0x25(%rip), %rdi
#ifdef DEBUG
					printf("lea rip\n");
#endif
					long unsigned int data = ((long unsigned int)tmp & 0xffffffff000000) >> 24;
					if(data & ~0x7fffffff) {
					    data = (~data + 1) & 0xffffffff;
						data = (long unsigned int)src_func + real_len + len - data;
					} else {
					    data = (long unsigned int)src_func + real_len + len + data;
					}
					long unsigned int diff = (long unsigned int)dst_func - data + len;
					if(diff < 0xffffffff || diff > 0xffffffff00000000) {
					//direct
                        tmp = (tmp & 0xffffff) | (diff << 24);
					} else {
					//undirect
						instru_end -= sizeof(long unsigned int);
						memcpy(instru_end, &data, sizeof(long unsigned int));
						tmp &= 0xff0000;
						tmp |= ((long unsigned int)instru_end - (long unsigned int)instru_p - len) << 24;
						tmp |= 0x8b48;  // MOV
					}
				} else if ((tmp & 0xffff) == 0x8b48) {
					//48 8b 05 1d 37 3d 00  mov 0x3d371d(%rip), %rax 
#ifdef DEBUG
				    printf("mov rip\n");
#endif
					//long unsigned int data = *(long unsigned int*)(src + real_len + len + offset);
				}
                memcpy(instru_p, &tmp, len);
		        instru_p += len;
			    break;
			default:
                memcpy(instru_p, &tmp, len);
		        instru_p += len;
			    break;
		}
		real_len += len;
		min_len -= len;
	}
    
	tmp = UNDIRECT_JUMP;
	memcpy(instru_p, &tmp, 6);
    tmp = (long unsigned int)src_func + (long unsigned int)real_len;
	memcpy(instru_p + 6, &tmp, 8);
	memcpy(dst_func, instru, buff_size);	
	
	return real_len;
}

// -1 failed 
//  0 successfully
static int install_jump(stub_info_t *stub_info) 
{
	int ret = 0;
    void *orig_func = stub_info->func_addr;
	void *stub_func = stub_info->new_addr;
	long unsigned int diff = 0, op = 0, dst = 0;
    unsigned char instru_jump[INSTRU_BUFF_SIZE] = {0};
	unsigned char instru_back[INSTRU_BUFF_SIZE] = {0};
    unsigned int instru_jump_len = 0, instru_back_len = 0;


    diff = (long unsigned int)stub_func - (long unsigned int)orig_func;
#ifdef DEBUG 
    printf("%d : %llx, %llx\n", sizeof(long unsigned int), orig_func, stub_func);
    printf("diff %llx\n", diff);
#endif
//	if(diff < 0xffffffff || diff > 0xffffffff00000000) {
	if(diff > 0xffffffff && diff < 0xffffffff00000000) {
		op = DIRECT_JUMP;
		diff -= 5;
		memcpy(instru_jump, &op, 1);
		memcpy(instru_jump + 1, &diff, 4);
	    instru_jump_len += 5;
	} else {
        op = UNDIRECT_JUMP;
		dst = (long unsigned int)stub_func;
		memcpy(instru_jump, &op, 6);
		memcpy(instru_jump + 6, &dst, 8);
		instru_jump_len += 14;
	}

#ifdef DEBUG
	for(int i = 0; i < instru_jump_len; i++) 
		printf("%02x ", instru_jump[i]);
	printf("\n");	
#endif

    stub_info->instru_buff = malloc(INSTRU_BUFF_SIZE);
    stub_info->orig_buff = malloc(INSTRU_BUFF_SIZE);
	if(stub_info->instru_buff == NULL || stub_info->instru_buff == NULL) {
		ret = -1;
	    fprintf(stderr, "instructions buff malloc error.\n");
        stub_free(stub_info);
		goto install_jump_out;	
	}

    instru_back_len = write_instru_back(stub_info->instru_buff, orig_func, instru_jump_len, INSTRU_BUFF_SIZE);
	if(instru_back_len == 0) {
	    ret = -1;
		fprintf(stderr, "Write_instru_back failed.\n");
        stub_free(stub_info);
		goto install_jump_out;
	}

    memcpy(stub_info->orig_buff, orig_func, instru_back_len);
    stub_info->orig_buff_len = instru_back_len;

#ifdef DEBUG
    printf("instru_buff\n");
	for(int i = 0; i < INSTRU_BUFF_SIZE; i++) 
		printf("%02x ", *(unsigned char*)(stub_info->instru_buff+i));
	printf("\n");
    printf("orig_buff\n");
	for(int i = 0; i < INSTRU_BUFF_SIZE; i++) 
		printf("%02x ", *(unsigned char*)(stub_info->orig_buff+i));
	printf("\n");
#endif

    ret = write_instru_jump(orig_func, instru_jump, instru_jump_len);
	if(ret != 0) {
	    ret = -1;
		fprintf(stderr, "Write_instru_jump failed.\n");
        stub_free(stub_info);
		goto install_jump_out;
	}
install_jump_out:
	return ret;
}


/*
 *   API FUNCTION 
 */

void *install_stub(void* func, void* new)
{
	list_node_t *stub_info_node = NULL;
    stub_info_t *stub_info = NULL;
	if(unlikely(stub_info_list == NULL)) {
		stub_info_list = list_new();	
		typedef int(*func_type)();
	    stub_info_list->match = (func_type)stub_info_match;
	}
    
	stub_info_node = list_find(stub_info_list, func);
    if(stub_info_node != NULL) {
        fprintf(stdout, "This function has been stubbed already.\n");
		return (void*)(((stub_info_t*)(stub_info_node->val))->instru_buff);	
	}

    stub_info = stub_malloc();
	stub_info->func_addr = func;
	stub_info->new_addr = new;
    stub_info_node = list_node_new(stub_info);
    list_lpush(stub_info_list, stub_info_node); 

    if(-1 == install_jump(stub_info)) {
	    fprintf(stderr, "install_jump failed.\n");
		return NULL;
	} 

	return (void*)(stub_info->instru_buff);
}

/*
 *   API FUNCTION 
 */

int uninstall_stub(void* func)
{
    list_node_t *stub_info_node = NULL;
	stub_info_t *stub_info = NULL;

	stub_info_node = list_find(stub_info_list, func);
	if(stub_info_node == NULL) {
	    fprintf(stderr, "This function has not been stubbed yet. \n");
		return -1;	
	}
    stub_info = stub_info_node->val;
    if(stub_info == NULL) {
	    fprintf(stderr, "Unknow error.\n");
		return -1;
	}

    memcpy(stub_info->func_addr, stub_info->orig_buff, stub_info->orig_buff_len);
    stub_free(stub_info);
    list_remove(stub_info_list, stub_info_node);
	return 0;
}
