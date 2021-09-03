obj-m := lkm_example.o
default: main

main : cli main_app.c
	gcc -g -o bin/main main_app.c `xml2-config --cflags --libs` -ldmallocth

cli : cli_app.c
	gcc -g -o bin/cli cli_app.c -ldmallocth

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

docs: Doxyfile
	doxygen ./Doxyfile