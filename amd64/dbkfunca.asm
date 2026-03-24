;RCX: 1st integer argument
;RDX: 2nd integer argument
;R8: 3rd integer argument
;R9: 4th integer argument

;I should probably start converting to inrinsics

_TEXT SEGMENT 'CODE'
PUBLIC getCS
getCS:
	mov ax,cs
	ret

PUBLIC getSS
getSS:
	mov ax,ss
	ret
	
PUBLIC getDS
getDS:
	mov ax,ds
	ret
	
PUBLIC getES
getES:
	mov ax,es
	ret	
	
PUBLIC getFS
getFS:
	mov ax,fs
	ret
	
PUBLIC getGS
getGS:
	mov ax,gs
	ret	
	
PUBLIC GetTR
GetTR:
	STR AX
	ret	
	
PUBLIC GetLDT
GetLDT:
	SLDT ax
	ret
	
PUBLIC GetGDT
GetGDT:
	SGDT [rcx]
	ret
	
PUBLIC _fxsave
_fxsave:
    fxsave [rcx]
    ret
	
PUBLIC getRSP
getRSP:
	mov rax,rsp
	add rax,8 ;undo the call push
	ret	
	
PUBLIC getRBP
getRBP:
    push rbp
    pop rax	
	ret	
	
PUBLIC getRAX
getRAX:	
	ret							
	
PUBLIC getRBX
getRBX:
	mov rax,rbx
	ret	
	
PUBLIC getRCX
getRCX:
	mov rax,rcx
	ret	
	
PUBLIC getRDX
getRDX:
	mov rax,rdx
	ret		
	
PUBLIC getRSI
getRSI:
	mov rax,rsi
	ret		
	
PUBLIC getRDI
getRDI:
	mov rax,rdi
	ret		
	
PUBLIC getR8
getR8:
	mov rax,r8
	ret		
	
PUBLIC getR9
getR9:
	mov rax,r9
	ret		
	
PUBLIC getR10
getR10:
	mov rax,r10
	ret		
	
PUBLIC getR11
getR11:
	mov rax,r11
	ret		
	
PUBLIC getR12
getR12:
	mov rax,r12
	ret		
	
PUBLIC getR13
getR13:
	mov rax,r13
	ret		
	
PUBLIC getR14
getR14:
	mov rax,r14
	ret		
	
PUBLIC getR15
getR15:
	mov rax,r15
	ret				
	
PUBLIC getAccessRights										
getAccessRights:
  xor rax,rax
  lar rax,rcx
  jnz getAccessRights_invalid
  shr rax,8
  and rax,0f0ffh
  ret
  getAccessRights_invalid:
  mov rax,010000h
  ret


PUBLIC getSegmentLimit										
getSegmentLimit:
  xor rax,rax
  lsl rax,rcx
  ret

; =========================================================================
; @brief Execute CPUID with RBX set to a specific value (context PA)
;
; [BUG FIX] __cpuidex does NOT set RBX before CPUID.
; The VMM reads vpData->Guest_gpr.Rbx to get the shared context PA.
; This function explicitly sets RBX = rbxValue before executing CPUID,
; so the VMM receives the correct context physical address.
;
; @param RCX = CPUID leaf (EAX)
; @param RDX = CPUID sub-leaf (ECX)  
; @param R8  = RBX value to set (context PA)
; @param R9  = pointer to int[4] for output {eax, ebx, ecx, edx}
; =========================================================================
PUBLIC HvCpuidWithRbx
HvCpuidWithRbx:
    push rbx              ; save caller's RBX (callee-saved register)
    
    mov eax, ecx          ; EAX = leaf
    mov ecx, edx          ; ECX = sub-leaf
    mov rbx, r8           ; RBX = context physical address
    
    cpuid                 ; VMEXIT here — VMM reads RBX as context PA
    
    ; Store results to output array
    mov [r9],    eax      ; regs[0] = EAX
    mov [r9+4],  ebx      ; regs[1] = EBX 
    mov [r9+8],  ecx      ; regs[2] = ECX
    mov [r9+12], edx      ; regs[3] = EDX
    
    pop rbx               ; restore caller's RBX
    ret

_TEXT   ENDS
        END

