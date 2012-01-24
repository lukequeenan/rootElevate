#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <asm/unistd_64.h>

int main(int argc, char *argv[])
{
	int fd[2];
	pipe2(fd, O_NONBLOCK);
	int child = fork();
	if (child) {
		close(fd[1]);
		char buf;
		for (;;) {
			wait(NULL);
			if (read(fd[0], &buf, 1) > 0)
				break;
			ptrace(PTRACE_SYSCALL, child, NULL, NULL);
		}
		
		struct user_regs_struct regs;
		for (;;) {
			ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
			wait(NULL);
			ptrace(PTRACE_GETREGS, child, NULL, &regs);
			if (regs.rip < 0x700000000000) {
				printf("0x%lx\n", regs.rip);
				break;
			}
		}
	} else {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		close(fd[0]);
		dup2(fd[1], 2);
		execl("/bin/su", "su", "not-a-valid-user", NULL);
	}
	return 0;
}
