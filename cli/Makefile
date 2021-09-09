default: cli install

cli: cli_app.c
	gcc -g -o cli cli_app.c -ldmallocth

install: cli
	mv cli ../bin
