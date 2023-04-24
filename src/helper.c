#include "helper.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "definitions.h"

NORETURN void exit_with_error_file_line(const char *file, const int line)
{
        int errcp = errno;
        (void)fprintf(stderr, "[%s:%d] %s\n", file, line, strerror(errcp));
        exit(EXIT_FAILURE);
}
