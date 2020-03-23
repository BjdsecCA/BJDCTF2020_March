section .data
	f1 dd 0
	f2 dd 0
	err db "File open failed.",0
	lerr equ $-err
	ok db "一样",0
	lok equ $-ok
	SIZE equ 1024
section .bss
	buf1 resb SIZE
	buf2 resb SIZE
	output resb 32
section .text
	global _start
_start:
	push ebp
	mov ebp, esp
    sub esp, 0x80
	mov eax, [ebp+12] ; file1
	mov ebx, [ebp+16] ; file2
	mov ecx, f1
	mov [ecx], eax
	mov edx, f2
	mov [edx], ebx
	
	; open(arg1,O_RDONLY,0644)
	mov eax, 0x5
	mov ebx, dword [ebp+12]
	mov ecx, 00
	mov edx, 0644
	int 0x80
	test eax, eax
	js failed
	push eax ; fd of filea

	; open(arg2,O_RDONLY,0644)
	mov eax, 0x5
	mov ebx, dword [ebp+16]
    mov ecx, 00
    mov edx, 0644
	int 0x80
	test eax, eax
	js failed
	push eax ; fd of fileb

    call compare

	push eax
	call print
	call exit

failed:
	; write(1,err,18)
	mov eax, 4 
	mov ebx, 1
	mov ecx, err
	mov edx, lerr
	int 0x80
	call exit

exit:
	; exit(0)
	mov eax, 1
	mov ebx, 0
	int 0x80	

compare:
	push ebp
	mov ebp, esp
	sub esp, 0x80
	mov dword [ebp-0x80],  0 ; line

	; read(fd,buf1,128)
	mov eax, 0x3
	mov ebx, dword [ebp+0xc] ; fd1
	mov ecx, buf1
	mov edx, 128
	int 0x80
	test eax, eax
	js failed

	; read(fd,buf2,128)
	mov eax, 0x3
	mov ebx, dword [ebp+0x8] ; fd2
	lea ecx, [ebp-0x78]
	mov edx, 128
	int 0x80
	test eax, eax
	js failed

    nop
	mov esi, buf1
	lea edi, [ebp-0x78]

loopi:
	mov dword [ebp-0x7c], 0 ; i
	jmp cmpi
opi:
	nop
	mov eax, esi ; filea
	mov ebx, edi ; fileb
	add eax, ecx
	mov al, byte [eax]
	add ebx, ecx
	mov bl, byte [ebx]
	cmp al, bl
	jne different
cmpl:
	cmp al, 0xa ; \n
	je opl
	jmp donel
opl:
	add dword [ebp-0x80], 1 ; line++
donel:
	add dword [ebp-0x7c], 1 ; i++
cmpi:
	mov ecx, dword [ebp-0x7c]

	; check last byte
	mov eax, ecx
	add eax, esi
	xor edx, edx
	mov dl, byte [eax]
	mov eax, ecx
	add eax, edi
	add dl, byte [eax]
	test dl, dl
	je donei

	cmp ecx, SIZE
	jb opi
	jmp donei
different:
	mov eax, dword [ebp-0x80] ; eax <- line
	add eax, 1
	leave
	ret
donei:
	mov eax, 0
	leave
	ret

print:
	push ebp
	mov ebp, esp
	sub esp, 8
	test eax, eax
	je nodiff
	mov dword [ebp-0x80], eax 
	mov dword [ebp-0x7c], 0 ;cnt
	mov esi, output
	add esi, 28

tochr:
	mov eax, dword [ebp-0x80]
	mov ebx, 10
	xor edx, edx
	div ebx
	mov dword [ebp-0x80], eax
	add edx, 0x30 ; +'0'
	mov byte [esi], dl
	add dword [ebp-0x7c], 1 ; cnt++
	sub esi, 1
	test eax, eax
	jne tochr

	; write(1,output,cnt)
	mov eax, 4
	mov ebx, 1
	mov ecx, esi
	add ecx, 1
	mov edx, dword [ebp-0x7c]
	int 0x80

	leave
	ret

nodiff:
	mov eax, 4
	mov ebx, 1
	mov ecx, ok
	mov edx, lok
	int 0x80

	leave
	ret

