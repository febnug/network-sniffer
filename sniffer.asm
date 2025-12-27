BITS 64
GLOBAL _start

%define SYS_WRITE 1
%define SYS_OPEN  2
%define STDOUT    1

SECTION .data
    ifindex_path  db "/sys/class/net/wlp6s0/ifindex",0
    pcap_filename db "dump.pcap",0
    
    ; PCAP Global Header (24 bytes)
    pcap_global_hdr dd 0xa1b2c3d4, 0x00040002, 0, 0, 0x0000ffff, 1

    msg_tcp      db "[+] TCP ",0
    msg_udp      db "[+] UDP ",0
    msg_arp      db "[+] ARP",0
    msg_arrow    db " -> ",0
    msg_len_lbl  db " len=",0
    nl           db 10

SECTION .bss
    sockfd       resq 1
    pcap_fd      resq 1
    ifindex      resd 1
    buf          resb 65536
    num_buf      resb 32
    sockaddr_ll  resb 20
    pkt_len      resq 1
    time_val     resq 2 ; tv_sec, tv_usec
    pcap_pkt_hdr resb 16

SECTION .text

_start:
    ; --- 1. Setup PCAP File ---
    mov rax, SYS_OPEN
    mov rdi, pcap_filename
    mov rsi, 0x41 ; O_CREAT | O_WRONLY | O_TRUNC
    mov rdx, 0644o
    syscall
    mov [pcap_fd], rax

    mov rax, SYS_WRITE
    mov rdi, [pcap_fd]
    mov rsi, pcap_global_hdr
    mov rdx, 24
    syscall

    ; --- 2. Setup Socket ---
    call get_ifindex
    mov rax, 41 ; SOCKET
    mov rdi, 17 ; AF_PACKET
    mov rsi, 3  ; SOCK_RAW
    mov rdx, 0x0300 
    syscall
    mov [sockfd], rax

    mov word [sockaddr_ll], 17
    mov word [sockaddr_ll+2], 0x0300
    mov eax, [ifindex]
    mov [sockaddr_ll+4], eax
    mov rax, 49 ; BIND
    mov rdi, [sockfd]
    lea rsi, [sockaddr_ll]
    mov rdx, 20
    syscall

.loop:
    ; --- 3. Receive Packet ---
    mov rax, 45 
    mov rdi, [sockfd]
    lea rsi, [buf]
    mov rdx, 65535
    xor r10, r10
    xor r8, r8
    xor r9, r9
    syscall
    test rax, rax
    jle .loop
    mov [pkt_len], rax

    ; --- 4. Write to PCAP ---
    push rax
    mov rax, 96 ; SYS_GETTIMEOFDAY
    lea rdi, [time_val]
    xor rsi, rsi
    syscall
    pop rax

    ; Build PCAP Packet Header
    mov rdx, [time_val]
    mov [pcap_pkt_hdr], edx
    mov rdx, [time_val+8]
    mov [pcap_pkt_hdr+4], edx
    mov rdx, [pkt_len]
    mov [pcap_pkt_hdr+8], edx
    mov [pcap_pkt_hdr+12], edx

    ; Write Metadata and Raw Buffer
    mov rax, SYS_WRITE
    mov rdi, [pcap_fd]
    lea rsi, [pcap_pkt_hdr]
    mov rdx, 16
    syscall

    mov rax, SYS_WRITE
    mov rdi, [pcap_fd]
    lea rsi, [buf]
    mov rdx, [pkt_len]
    syscall

    ; --- 5. Verbose Console Output ---
    movzx eax, word [buf + 12]
    cmp ax, 0x0608 ; ARP
    je .do_arp
    cmp ax, 0x0008 ; IPv4
    jne .loop

    movzx rbx, byte [buf + 23]
    cmp bl, 6
    je .do_tcp
    cmp bl, 17
    je .do_udp
    jmp .loop

.do_arp:
    mov rsi, msg_arp
    mov rdx, 7
    call print_str
    call print_len_suffix
    jmp .loop

.do_tcp:
    mov rsi, msg_tcp
    mov rdx, 8
    call print_str
    call print_flow
    jmp .loop

.do_udp:
    mov rsi, msg_udp
    mov rdx, 8
    call print_str
    call print_flow
    jmp .loop

; --- Logic Helpers ---

print_flow:
    lea r8, [buf + 26] ; Src IP
    call print_full_addr
    mov rsi, msg_arrow
    mov rdx, 4
    call print_str
    lea r8, [buf + 30] ; Dst IP
    call print_full_addr
    call print_len_suffix
    ret

print_len_suffix:
    mov rsi, msg_len_lbl
    mov rdx, 5
    call print_str
    mov rdi, [pkt_len]
    call print_num
    mov rsi, nl
    mov rdx, 1
    call print_str
    ret

print_full_addr:
    call print_ip_addr
    ; IHL offset
    movzx rdx, byte [buf+14]
    and rdx, 0x0F
    shl rdx, 2
    lea rax, [buf+26]
    cmp r8, rax
    je .src_p
    movzx rdi, word [buf + 14 + rdx + 2] 
    jmp .cont
.src_p:
    movzx rdi, word [buf + 14 + rdx]
.cont:
    rol di, 8
    call print_colon_port
    ret

get_ifindex:
    mov rax, 2
    mov rdi, ifindex_path
    xor rsi, rsi
    syscall
    mov rdi, rax
    mov rax, 0
    lea rsi, [num_buf]
    mov rdx, 8
    syscall
    xor eax, eax
    xor rcx, rcx
.p: movzx ebx, byte [num_buf+rcx]
    cmp bl, '0'
    jl .d
    imul eax, 10
    sub bl, '0'
    add eax, ebx
    inc rcx
    jmp .p
.d: mov [ifindex], eax
    ret

; --- Standard Printers ---

print_ip_addr:
    xor rcx, rcx
.li:
    movzx rdi, byte [r8+rcx]
    push rcx
    push r8
    call print_num
    pop r8
    pop rcx
    inc rcx
    cmp rcx, 4
    je .le
    push rcx
    push r8
    mov rsi, num_buf
    mov byte [rsi], '.'
    mov rdx, 1
    call print_str
    pop r8
    pop rcx
    jmp .li
.le: ret

print_colon_port:
    push rdi
    mov rsi, num_buf
    mov byte [rsi], ':'
    mov rdx, 1
    call print_str
    pop rdi
    call print_num
    ret

print_str:
    mov rax, SYS_WRITE
    mov rdi, STDOUT
    syscall
    ret

print_num:
    mov rax, rdi
    mov rcx, 0
    test rax, rax
    jnz .c
    mov byte [num_buf], '0'
    mov rcx, 1
    jmp .r
.c: xor rdx, rdx
    mov rbx, 10
    div rbx
    add dl, '0'
    mov [num_buf+rcx], dl
    inc rcx
    test rax, rax
    jnz .c
.r: push rcx
    mov al, byte [num_buf+rcx-1]
    mov [num_buf+31], al
    mov rax, SYS_WRITE
    mov rdi, STDOUT
    lea rsi, [num_buf+31]
    mov rdx, 1
    syscall
    pop rcx
    loop .r
    ret
