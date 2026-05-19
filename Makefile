.PHONY: all semtex

all: semtex

SRC=main.c debug.c hooks.c registers.c disasm.c Zydis.c macho.c

OBJS=$(subst .c,.o,$(SRC))

# tested with macOS on Apple Silicon and Linux
# requires Unicorn Engine installation - https://github.com/unicorn-engine/unicorn/releases
semtex: $(OBJS) 
	$(CC) -o semtex $(OBJS) -lunicorn -L/usr/local/lib -I/usr/local/include

clean:
	rm -f semtex *.o
