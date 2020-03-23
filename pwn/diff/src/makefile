diff: a.o
	ld -o diff a.o  -m elf_i386
a.o: diff.s
	nasm -g -f elf32 diff.s -o a.o
clean:
	rm diff
	rm a.o
