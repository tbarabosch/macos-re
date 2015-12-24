# hello_asm.s
# as hello_asm.s -o hello_asm.o
# ld hello_asm.o -e _main -o hello_asm

# the following program boils down to
# 4831db5348b8726c64215048b848656c6c50b804000002bf01000000488d342448c7c20e00000f05
# in hex

.section __TEXT,__text
.globl _main
_main:

  xor %rbx, %rbx                 # push the zero terminating C string to the stack
  pushq %rbx
  movq $0x0a21646c72, %rax
  pushq %rax
  movq $0x6f77206f6c6c6548, %rax
  pushq %rax

  movl $0x2000004, %eax           # 4 == write syscall
  movl $1, %edi                   # 1 == STDOUT file descriptor
  leaq (%rsp), %rsi               # string to print
  movq $14, %rdx                  # size of string
  syscall

  xor %rbx, %rbx
  movl $0x2000001, %eax           # exit 0
  syscall
