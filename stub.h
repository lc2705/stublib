#ifndef __STUB_H
#define __STUB_H

/*
 *  param:   func - address of original function to install stub
 *           new  - address of function to replace the original function
 *  
 *  retval:  NULL - install stub failed
 *           others - install stub successfully. 
 */
void *install_stub(void *func, void *new);


/*
 *  param:   address of func function that has been installed stub
 *  retval: -1 uninstall failed
 *           0 uninstall successfully
 */
int uninstall_stub(void *func);

/*
 *  param:  sym_name - symbol's name 
 *          elf_name - elf file's name which contains the symbol
 *
 *  retval: NULL     cannot find the symbol
 *          sym_addr symbol address in elf
 *
 */
void* get_symbol_by_name(char* sym_name, char* elf_name);


/*
 *  param:  elf_name - elf file's name
 */ 
void print_symbol_table(char* elf_name);

#endif
