test:main.c libtest1.so libtest2.so libstub.so
	gcc -g -o $@ $^ -L. -ltest1 -ltest2 -lstub -ldl

libtest1.so:libtest1.c
	gcc -g -o $@ -shared -fPIC $^

libtest2.so:libtest2.c
	gcc -g -o $@ -shared -fPIC $^

libstub.so:stub.c utils/list.c utils/list_node.c utils/list_iterator.c utils/x86_64_InstructionSize.c
	gcc -g -o $@ -shared -fPIC $^ 

clean:
	rm -f *.so *.o test
