#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

void null_test_success(void **state);

int main(void)
{
    const struct CMUnitTest pscom_tests[] = {
        cmocka_unit_test(null_test_success),
    };
    return cmocka_run_group_tests(pscom_tests, NULL, NULL);
}
