.data

extern SyscallCallback:proc

.code 

__image_base proc
	xor rax, rax
	mov rax, gs:[30h]
	mov rax, [rax + 60h]
	mov rax, [rax + 10h]
	ret
__image_base endp

__process_id proc
	xor rax, rax
	mov rax, gs:[30h]
	mov rax, [rax + 40h]
	ret
__process_id endp

__current_peb proc
	mov rax, gs:[60h]
	ret
__current_peb endp

__get_stack proc
	mov rax, rsp
	ret
__get_stack endp

__syscall_callback proc

	; rbp here might have caller module unicode_string ?
	; int 3h

	mov r8,  rsp					; save the stack for the callback

    push rax
	push rbx
	push rbp
	push rdi
	push rsi
	push rsp
	push r12
	push r13
	push r14
	push r15 

	push r8
	push r9
	push r10
	push r11

	push rcx
	push rdx
	; pushfq

	;sub     esp, 16
	;movdqu  dqword [esp], xmm0
	;sub     esp, 16
	;movdqu  dqword [esp], xmm1

	sub rsp, 0800h

	; use space at the end of teb 
	; 
	mov rcx, gs:[30h]				; get teb
									; use space at the end of teb for vars
	cmp qword ptr [rcx+19F0h], 0	; enables tracing for the current thread
	je return
	cmp qword ptr [rcx+19F8h], 1	; ignore recursive calls
	je return

	;mov [rcx+19E8h], r10			; todo:callback can decide what address to return to
			
	mov rcx, r10					; return address
	mov rdx, rax					; return value of syscall

	call SyscallCallback			; call our callback handler

return:
	
	add rsp, 0800h

	;movdqu  xmm1, dqword [esp]
	;add     esp, 16
	;movdqu  xmm0, dqword [esp]
	;add     esp, 16
	; _fxsave

	;pop xmm5
	;pop xmm4
	;pop xmm3
	;pop xmm2
	;pop xmm1
	;pop xmm0

	; popfq
	pop rdx
	pop rcx
	
	pop r11
	pop r10
	pop r9
	pop r8

	pop r15 
	pop r14
	pop r13
	pop r12
	pop rsp
	pop rsi
	pop rdi
	pop rbp
	pop rbx
	pop rax

	;mov rax, r11
    jmp r10

__syscall_callback endp

end
