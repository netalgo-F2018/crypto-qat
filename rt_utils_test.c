
#include "rt_utils.h"
#include "cpa_sample_utils.h"

#define ARRAY_SZ(a) (sizeof(a) / sizeof(*a))

typedef CpaStatus TestArgs;

TestArgs testCases[] = {
    CPA_STATUS_FAIL,
    CPA_STATUS_RETRY,
    CPA_STATUS_RESOURCE,
    CPA_STATUS_INVALID_PARAM,
    CPA_STATUS_FATAL,
    CPA_STATUS_UNSUPPORTED,
    CPA_STATUS_RESTARTING,};

CpaStatus emuCpaFuncFailure()
{
    return CPA_STATUS_FAIL;
}

int main()
{
    int nrCases = ARRAY_SZ(testCases);
    int i;

    // Test cpa_strerror
    for (i = 0; i < nrCases; i++) {
        fprintf(stderr, "%d: %s\n", testCases[i], cpaErrStr(testCases[i]));
    }

    // Test CPA specific assert
    CHECK(CPA_STATUS_SUCCESS);
    CHECK(CPA_STATUS_FAIL); 
    //CHECK(emuCpaFuncFailure());

    return 0;
}

