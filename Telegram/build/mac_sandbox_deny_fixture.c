#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *ErrorName(int error) {
	if (error == EPERM) {
		return "EPERM";
	} else if (error == EACCES) {
		return "EACCES";
	} else if (error == 0) {
		return "none";
	}
	return "other";
}

static int ExpectDenied(
		const char *role,
		const char *operation,
		const char *path,
		int flags,
		int reading) {
	errno = 0;
	const int descriptor = open(path, flags);
	int error = errno;
	int closeError = 0;
	ssize_t result = -1;
	const char *phase = "open";
	if (descriptor >= 0) {
		char byte = 0;
		errno = 0;
		phase = operation;
		result = reading ? read(descriptor, &byte, 1) : write(descriptor, "X", 1);
		error = errno;
		if (close(descriptor) != 0) {
			closeError = errno;
		}
	}
	const int denied = (descriptor < 0 || result < 0) && error == EPERM && closeError == 0;
	printf(
		"access role=%s pid=%ld ppid=%ld operation=%s phase=%s result=%s errno=%d name=%s close_errno=%d path=%s\n",
		role,
		(long)getpid(),
		(long)getppid(),
		operation,
		phase,
		denied ? "denied" : "unexpected",
		error,
		ErrorName(error),
		closeError,
		path);
	fflush(stdout);
	return denied ? 0 : 1;
}

static int CheckProcess(const char *role, const char *readPath, const char *writePath) {
	printf("process role=%s pid=%ld ppid=%ld\n", role, (long)getpid(), (long)getppid());
	fflush(stdout);
	int result = ExpectDenied(role, "read", readPath, O_RDONLY, 1);
	result |= ExpectDenied(role, "write", writePath, O_WRONLY | O_APPEND, 0);
	return result;
}

int main(int argc, char *argv[]) {
	if (argc != 3) {
		fprintf(stderr, "usage: fixture READ_PATH WRITE_PATH\n");
		return 2;
	}

	const int parentResult = CheckProcess("parent", argv[1], argv[2]);
	const pid_t child = fork();
	if (child < 0) {
		perror("fork");
		return 1;
	} else if (child == 0) {
		_exit(CheckProcess("child", argv[1], argv[2]));
	}

	printf("spawn role=parent pid=%ld child_pid=%ld\n", (long)getpid(), (long)child);
	fflush(stdout);
	int status = 0;
	pid_t waited = 0;
	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited != child) {
		perror("waitpid");
		return 1;
	}
	const int childFailed = !WIFEXITED(status) || WEXITSTATUS(status) != 0;
	printf("child-exit pid=%ld exit=%d\n", (long)child, childFailed ? 1 : 0);
	return parentResult || childFailed ? 1 : 0;
}
