#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>

const char* MOV_RAX = "\x48\xb8";
const char* CALL_RAX = "\xff\xD0";
// make this variable global, i.e. they should be passed around
// especially not when the stack is involved, only God knows what happens
// to the stack during shell code execution
void *shellcode_buffer;

void printLine(){
    printf("---------------------------------------------------------------------\n");
}

long getFileSize(FILE* file){
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);
    return file_size;
}

void printShellcode(long file_size){
    printf("Hexdump of shellcode:\n");
    printLine();
    for(int i=0;i < file_size;i++)
        printf("%x", *(int*)(shellcode_buffer+i));
    printf("\n");
    printLine();
}

long readFileToBuffer(FILE *file) {
    long file_size = getFileSize(file);
    size_t page_size = getpagesize();
    
    if (file_size > page_size){
        printf("File is too big: %ld exceeds limit of %ld\n", file_size, page_size);
        exit(-1);
    }
    
    printf("Trying to read %ld bytes.\n", file_size);
    fread(shellcode_buffer, file_size, 1, file);
    fclose(file);
    
    printShellcode(file_size);
    
    return file_size;
}

void exitGracefully(){
    printLine();
    printf("Executed shellcode successfully\n");
    munmap(shellcode_buffer, getpagesize());
    printf("Freed shellcode buffer. Exiting.\n");
    exit(0);
}

void writeTrampoline(long file_size){
    void (*p)(void) = exitGracefully;
    printf("Writing trampoline to clean up function @%p after shellcode\n", p);
    memcpy((shellcode_buffer+file_size), MOV_RAX, 2);
    memcpy((shellcode_buffer+file_size+2), &p, sizeof(void*));
    memcpy((shellcode_buffer+file_size+2+sizeof(void*)), CALL_RAX, 2);
}

int main(int argc, const char * argv[]) {
    if (argc != 2){
        printf("Usage: shellcode_loader FILENAME\n");
        return 0;
    }
    else
    {
        char *filename = (char *)argv[1];
        size_t page_size = getpagesize();
        shellcode_buffer = mmap(NULL, page_size,
                         PROT_READ | PROT_WRITE,
                         MAP_ANON | MAP_PRIVATE,
                         -1, 0);
        
    
        printf("Opening %s\n", filename);
        FILE *file = fopen(filename, "r");
        if (file != NULL) {
            long file_size = readFileToBuffer(file);
            writeTrampoline(file_size);
            
        }
        else
        {
            printf("Could not open %s. Exiting...\n", filename);
            return -1;
        }
        
        printf("Changing protection to RX.\n");
        if (mprotect(shellcode_buffer, page_size, PROT_READ | PROT_EXEC) != 0){
            printf("Could not change to RX...\n");
            return -1;
        }
        
        printf("Loaded shell code to 0x%x. Calling in...\n", (unsigned int)shellcode_buffer);
        printLine();
        ((void (*)())shellcode_buffer)();
        
        // should never reach this point, either shellcode terminates program or the control flow
        //is directed to the cleaning function via the trampoline
    }
}