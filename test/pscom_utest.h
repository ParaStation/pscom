#ifndef _PSCOM_UTEST_H_
#define _PSCOM_UTEST_H_

typedef struct pscom_utest {
    struct {
        unsigned int memcpy;
    } mock_functions;
} pscom_utest_t;

extern pscom_utest_t pscom_utest;

#endif /* _PSCOM_UTEST_H_ */