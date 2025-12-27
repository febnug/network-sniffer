BITS 64
GLOBAL _start

; ========================
; Syscalls
; ========================
%define SYS_READ        0
%define SYS_WRITE       1
%define SYS_OPEN        2
%define SYS_CLOSE       3
%define SYS_SOCKET     41
%define SYS_BIND       49
%define SYS_RECVFROM   45
%define SYS_EXIT       60
%define SYS_CLOCK_GETTIME 228

; ========================
; Constants
; ========================
%define AF_PACKET      17
%define SOCK_RAW       3
%define ETH_P_ALL      0x0300 ; Network Byte Order for 0x0003

%define STDOUT         1
%define O_CREAT        64
%define O_WRONLY       1
%define O_TRUNC        512

SECTION .data
    ifindex_path db "/sys/class/net/wlp6s0/ifindex",0
    pcap_file    db "dump.pcap",0
    verbose_msg  db "[+] captured packet len=",0
    nl           db 10

    ; ---- PCAP GLOBAL HEADER ----
    pcap_hdr:
    dd 0xa1b2c3d4
    dw 2
    dw 4
    dd 0
    dd 0
    dd 65535
    dd 1      ; LINKTYPE_ETHERNET

SECTION .bss
    sockfd      resq 1
    pcapfd      resq 1
    ifindex     resd 1
    buf         resb 65536
    ts          resq 2
    num_buf     resb 32

    sockaddr_ll:
        resw 1   ; sll_family
        resw 1   ; sll_protocol
        resd 1   ; sll_ifindex
        resw 1   ; sll_hatype
        resb 1   ; sll_pkttype
        resb 1   ; sll_halen
        resb 8   ; sll_addr

    pcap_rec_hdr:
        resd 1   ; ts_sec
        resd 1   ; ts_usec
        resd 1   ; incl_len
        resd 1   ; orig_len

SECTION .text

_start:
; ========================
; Read ifindex
; ========================
    mov rax, SYS_OPEN
    mov rdi, ifindex_path
    xor rsi, rsi
    syscall
    
    test rax, rax
    js exit_error

    mov rdi, rax
    mov rax, SYS_READ
    lea rsi, [num_buf]
    mov rdx, 16
    syscall

    ; parse ASCII -> int
    xor eax, eax
    xor rcx, rcx
.parse:
    movzx ebx, byte [num_buf + rcx]
    cmp bl, 10
    je .done
    cmp bl, '0'
    jl .done
    cmp bl, '9'
    jg .done
    sub bl, '0'
    imul eax, eax, 10
    add eax, ebx
    inc rcx
    jmp .parse
.done:
    mov [ifindex], eax

; ========================
; socket(AF_PACKET)
; ========================
    mov rax, SYS_SOCKET
    mov rdi, AF_PACKET
    mov rsi, SOCK_RAW
    mov rdx, ETH_P_ALL
    syscall
    mov [sockfd], rax

; ========================
; bind(sockfd)
; ========================
    mov word [sockaddr_ll], AF_PACKET
    mov word [sockaddr_ll+2], ETH_P_ALL
    mov eax, [ifindex]
    mov [sockaddr_ll+4], eax

    mov rax, SYS_BIND
    mov rdi, [sockfd]
    lea rsi, [sockaddr_ll]
    mov rdx, 20 ; Full size of sockaddr_ll
    syscall

; ========================
; open dump.pcap
; ========================
    mov rax, SYS_OPEN
    mov rdi, pcap_file
    mov rsi, O_CREAT|O_WRONLY|O_TRUNC
    mov rdx, 0644
    syscall
    mov [pcapfd], rax

    mov rax, SYS_WRITE
    mov rdi, [pcapfd]
    lea rsi, [pcap_hdr]
    mov rdx, 24
    syscall

; ========================
; Capture loop
; ========================
.loop:
    mov rax, SYS_RECVFROM
    mov rdi, [sockfd]
    lea rsi, [buf]
    mov rdx, 65535
    xor r10, r10
    xor r8, r8
    xor r9, r9
    syscall
    
    test rax, rax
    js .loop
    mov r12, rax     ; packet len

    ; timestamp
    mov rax, SYS_CLOCK_GETTIME
    mov rdi, 0 ; CLOCK_REALTIME
    lea rsi, [ts]
    syscall

    mov eax, [ts]     ; seconds
    mov [pcap_rec_hdr], eax
    mov rax, [ts+8]   ; nanoseconds
    xor rdx, rdx
    mov rbx, 1000
    div rbx           ; convert to microseconds
    mov [pcap_rec_hdr+4], eax
    
    mov eax, r12d
    mov [pcap_rec_hdr+8], eax
    mov [pcap_rec_hdr+12], eax

    ; write pcap record
    mov rax, SYS_WRITE
    mov rdi, [pcapfd]
    lea rsi, [pcap_rec_hdr]
    mov rdx, 16
    syscall

    mov rax, SYS_WRITE
    mov rdi, [pcapfd]
    lea rsi, [buf]
    mov rdx, r12
    syscall

    ; verbose output
    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [verbose_msg]
    mov rdx, 24
    syscall

    mov rdi, r12
    call print_num

    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [nl]
    mov rdx, 1
    syscall

    jmp .loop

exit_error:
    mov rax, SYS_EXIT
    mov rdi, 1
    syscall

; ========================
; print_num(rdi)
; ========================
print_num:
    mov rax, rdi
    mov rcx, 0
.conv:
    xor rdx, rdx
    mov rbx, 10
    div rbx
    add dl, '0'
    mov [num_buf+rcx], dl
    inc rcx
    test rax, rax
    jnz .conv

.rev:
    push rcx
    mov al, [num_buf+rcx-1]
    mov [num_buf+31], al

    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [num_buf+31]
    mov rdx, 1
    syscall
    pop rcx
    loop .rev
    ret
