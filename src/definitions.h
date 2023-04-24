#ifndef EXEC_DEFINITIONS_H
#define EXEC_DEFINITIONS_H

// unreachable() was defined in C23
#ifndef unreachable
        #ifdef __GNUC__
                #define unreachable() (__builtin_unreachable())
        #else
                #define unreachable()
        #endif
#endif

// [[noreturn]] was defined in C23, and _Noreturn was deprecated
#ifndef NORETURN
        #if (__STDC_VERSION__ < 202300L)
                #define NORETURN _Noreturn
        #else
                #define NORETURN [[noreturn]]
        #endif
#endif

#endif
