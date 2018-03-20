#include <stdio.h>
#include <dlfcn.h>
#include "stub.h"

void libtest1();
void libtest2();
typedef void(*func_type)();

int main() 
{

	libtest1();
	//===============================

    void* handler1 = dlopen("./libtest1.so", RTLD_NOW);
	void* handler2 = dlopen("./libtest2.so", RTLD_NOW);
	void* func1 = dlsym(handler1, "libtest1");
	void* func2 = dlsym(handler2, "libtest2");
	
    func_type new_func = (func_type)install_stub(func1, func2);
    //===============================
	if(new_func == NULL) {
	    fprintf(stderr, "install stub failed.\n");
		return 0;
	}

	libtest1();
    new_func();

	if(0 != uninstall_stub(func1)) {
	    fprintf(stderr, "install stub failed.\n");
		return 0;
	}
	
	libtest1();
	
	return 0;	
}
