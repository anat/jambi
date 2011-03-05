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
;;;;;;;;;;;;;;                     str_compare                   ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;               Return 1 if strings match           ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


str_compare PROC s1:DWORD, s2:DWORD

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
str_compare ENDP



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                    fatalError                     ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;     Display an error message and exit process     ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;fatalError PROC Line:DWORD
;	call	GetLastError
;	pushad
;	print		"Error !!!", 13, 10
;	popad
;	push	eax
;	call	ExitProcess
;fatalError ENDP



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                      mapFile                      ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;    Returns base address in eax and hMap in ebx    ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

mapFile PROC fileHandler
	push		ecx
	;; CreateFileMapping : Mapping en mémoire
	push		NULL
	push		0
	push		0
	push		PAGE_READWRITE
	push		NULL
	push		fileHandler
	call		CreateFileMapping
	cmp			eax, NULL
	je			mapFile_error
	
	push		eax
	
	;; MapViewOfFile : Mapping en mémoire
	push		0
	push		0
	push		0
	push		FILE_MAP_ALL_ACCESS
	push		eax
	call		MapViewOfFile
	
	cmp			eax, NULL			; Check 
	je			mapFile_error
	jmp			mapFile_end

	mapFile_error:
	pop			ecx			; pop dans le vide (retour de CreateFileMapping)
	pop			ecx
	xor			eax, eax
	ret

	mapFile_end:
	pop			ebx
	pop			ecx
	ret
mapFile ENDP



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                      fileOpen                     ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;               Returns a file handler              ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

fileOpen PROC BA:DWORD, curFile:DWORD
	push		0
	push		0
	push		OPEN_EXISTING
	push		NULL
	push		0
	mov			eax, GENERIC_READ
	or			eax, GENERIC_WRITE
	push		eax
	push		curFile
	call		CreateFile

	cmp			eax, INVALID_HANDLE_VALUE
	je			fileOpen_error
	ret
	fileOpen_error:
	xor			eax, eax
	ret
fileOpen ENDP



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;                   IncreaseFileSize                ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;      Return previous file size or 0 if no file    ;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

IncreaseFileSize PROC KBA:DWORD, fileName:DWORD, chunkSize:DWORD
	
	LOCAL fileSize:DWORD
	LOCAL hFile:DWORD

	;; Save register
	push		esi
	push		edi
	push		ecx
	push		edx
	
	;; CreateFile
	push		0
	push		0
	push		OPEN_EXISTING
	push		NULL
	push		0
	mov			eax, GENERIC_READ
	or			eax, GENERIC_WRITE
	push		eax
	push		fileName
	call		CreateFile

	cmp			eax, INVALID_HANDLE_VALUE
	je			failure2
			
	mov			hFile, eax				; Sauvegarde du handler du fichier original

	;; Get original file size
	push		0		
	push		hFile
	call		GetFileSize
	mov			fileSize, eax			; Sauvegarde de la taille du fichier original

	;; Increase file size
	push		FILE_BEGIN				
	push		NULL
	mov			eax, fileSize
	add			eax, chunkSize
	push		eax
	push		hFile
	call		SetFilePointer
	cmp			eax, INVALID_SET_FILE_POINTER
	je			failure


	push		hFile
	call		SetEndOfFile
	cmp			eax, 0
	je			failure


	push		hFile
	call		CloseHandle
	cmp			eax, 0
	je			failure

	
	mov			eax, fileSize
	pop			edx
	pop			ecx
	pop			edi
	pop			esi
	ret
	
failure:
	push		hFile
	call		CloseHandle
	;cmp			eax, 0
	;je			failure
failure2:
	xor			eax, eax
	pop			edx
	pop			ecx
	pop			edi
	pop			esi
	ret
IncreaseFileSize ENDP
