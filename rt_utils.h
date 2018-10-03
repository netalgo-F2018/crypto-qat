
#ifndef RT_UTILS_H
#define RT_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "cpa_sample_utils.h"
#include "cpa.h"

extern const char *__progname;
extern int errno;

#define RT_PRINT(fmt, args...) { printf("INFO: %s(): "fmt, __func__, ##args); }
#ifdef RT_DEBUG
#define RT_PRINT_DBG(fmt, args...) { printf("DBG: %s(): "fmt, __func__, ##args); }
#else
#define RT_PRINT_DBG(args...) { do {} while(0); }
#endif  // RT_DEBUG
#define RT_PRINT_ERR(fmt, args...) {    \
    fprintf(stderr, "ERR: %s(): "fmt, __func__, ##args); }

#define CHECK(expr) {                                                           \
    CpaStatus rc = (expr);                                                      \
    if (CPA_STATUS_SUCCESS != (rc)) {                                           \
        fprintf(stderr, "%s: %s:%d: %s(): ",                                    \
                __progname, __FILE__, __LINE__, __func__);                      \
        fprintf(stderr, "Assertion `(CPA_STATUS_SUCCESS == (%s))' failed:\n",   \
                #expr);                                                         \
        fprintf(stderr, "\t%s returns %d: %s cannot survive.\nAborted\n",       \
                #expr, rc, cpaErrStr(rc));                                      \
        exit(EXIT_FAILURE);                                                     \
    }                                                                           \
}

#define OS_CHECK(expr) {                                                        \
    int rc = (expr);                                                            \
    if (-1 == rc) {                                                             \
        fprintf(stderr, "%s: %s:%d: %s(): ",                                    \
                __progname, __FILE__, __LINE__, __func__);                      \
        fprintf(stderr, "Assertion `(-1 != (%s))' failed:\n",                   \
                #expr);                                                         \
        fprintf(stderr, "\t%s returns %d: %s: cannot survive.\nAborted\n",      \
                #expr, errno, strerror(errno));                                 \
        exit(EXIT_FAILURE);                                                     \
    }                                                                           \
}                                                                               \

static char *cpaErrStr(CpaStatus errStatus)
{
    char *errStr = calloc(1, CPA_STATUS_MAX_STR_LENGTH_IN_BYTES);
    assert(errStr != NULL);

    switch (errStatus) {
        // Fail status value.
        case CPA_STATUS_FAIL:
            sprintf(errStr, "%s", CPA_STATUS_STR_FAIL);
            break;
        // Retry status value;
        case CPA_STATUS_RETRY:
            sprintf(errStr, "%s", CPA_STATUS_STR_RETRY);
            break;
        // The resource that has been requested is unavailable. Refer to relevant
        // sections of the API for specifics on what the suggested course of
        // action is.
        case CPA_STATUS_RESOURCE:
            sprintf(errStr, "%s", CPA_STATUS_STR_RESOURCE);
            break;
        // Invalid parameter has beed passed in.
        case CPA_STATUS_INVALID_PARAM:
            sprintf(errStr, "%s", CPA_STATUS_STR_INVALID_PARAM);
            break;
        // A serious error has occurred. Recommended course of action is to
        // shutdown and restart the component.
        case CPA_STATUS_FATAL:
            sprintf(errStr, "%s", CPA_STATUS_STR_FATAL);
            break;
        // The function is not supported, at least not with the specific
        // parameters supplied. This may be because a particular capability is
        // not supported by the current implementation.
        case CPA_STATUS_UNSUPPORTED:
            sprintf(errStr, "%s", CPA_STATUS_STR_UNSUPPORTED);
            break;
        // The API implementation is restarting. This may be reported if, for
        // example, a hardware implementation is undergoing a reset. Recommended
        // course of action is to retry the request.
        //case CPA_STATUS_RESTARTING:
        //    sprintf(errStr, "%s", CPA_STATUS_STR_RESTARTING);
        //    break;
        default:
            sprintf(errStr, "Unknow error status:");
    }

    return errStr;
}

// TODO

#endif  // RT_UTILS_H
