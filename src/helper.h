#ifndef HELPER_H
#define HELPER_H

#include "definitions.h"

NORETURN void exit_with_error_file_line(const char *file, int line);

#define exit_with_error() exit_with_error_file_line(__FILE__, __LINE__)

#endif
