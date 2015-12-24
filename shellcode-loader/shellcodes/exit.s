.section __TEXT,__text
.globl _main
_main:
  xor %rbx, %rbx
  movl $0x2000001, %eax           # exit 0
  syscall
  