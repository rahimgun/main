default: main install

main: main_app.c
	gcc -g -o main main_app.c `xml2-config --cflags --libs` -ldmallocth -pthread

install: main
	mv main ../bin
