; WINDOWS 11, 23H2 

.code

NtOpenProcess PROC
		mov r10, rcx
		mov eax, 26h
		syscall
		ret
NtOpenProcess ENDP

NtAllocateVirtualMemory PROC
		mov r10, rcx
		mov eax, 18h
		syscall
		ret
NtAllocateVirtualMemory ENDP

NtWriteVirtualMemory PROC
		mov r10, rcx
		mov eax, 3Ah
		syscall
		ret
NtWriteVirtualMemory ENDP

NtProtectVirtualMemory proc
		mov r10, rcx
		mov eax, 50h
		syscall
		ret                             
NtProtectVirtualMemory endp

NtCreateThreadEx PROC
		mov r10, rcx
		mov eax, 0C7h
		syscall
		ret
NtCreateThreadEx ENDP

NtFreeVirtualMemory PROC
		mov r10, rcx
		mov eax, 1Eh
		syscall
		ret
NtFreeVirtualMemory ENDP

NtWaitForSingleObject PROC
		mov r10, rcx
		mov eax, 4h
		syscall
		ret
NtWaitForSingleObject ENDP

NtClose PROC
		mov r10, rcx
		mov eax, 0Fh
		syscall
		ret
NtClose ENDP

end
