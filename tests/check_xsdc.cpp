#include <check.h>
#include <stdio.h>
#include <errno.h>
#include "../src/xsdc.h"

START_TEST (test_check_fillunpackstruct)
{
    UnpackData unpackData;
    char unformatted[] = "123^^0123456789qWeRtYuIoPaSdFgHjKlZxCcXzLkJhGfDsApOiUyTrEwQ0987654321666";
    fillUnpackStruct(&unpackData,unformatted);
    ck_assert_int_eq (unpackData.checksum, 123);
    ck_assert_int_eq (unpackData.xorVal, 666);
    void *fnkey = malloc(0x20);
    strncpy((char*)fnkey,(char*)unpackData.fileNameKey,0x20);
    ck_assert_str_eq ((char*)fnkey, "0123456789qWeRtYuIoPaSdFgHjKlZxC");
    void *hdrkey = malloc(0x20);
    strncpy((char*)hdrkey,(char*)unpackData.headerKey,0x20);
    ck_assert_str_eq ((char*)hdrkey, "cXzLkJhGfDsApOiUyTrEwQ0987654321");
}
END_TEST

START_TEST (test_check_decryptdata)
{
    char target[] = {
        0x42, 0x3F, 0x3B, 0x95, 0x72, 0x23, 0x86, 0xF1, 0x08, 0xB3, 0x09, 0xC5, 0x23, 0x59, 0x89, 0x04,
        0x87, 0x02, 0x17, 0x16, 0x50, 0x03, 0xA0, 0x50, 0x6C, 0xD3, 0x71, 0x09, 0x17, 0x80, 0xB3, 0x9F,
        0x32, 0xB1, 0x36, 0xAC, 0x71, 0xFC, 0xDF, 0xC4, 0x58, 0x92, 0xBF, 0xC6, 0x48, 0xD5, 0x2C, 0x35,
        0xFD, 0x66, 0xFB, 0xF7, 0xA5, 0x6F, 0x73, 0xB4, 0xE1, 0xA3, 0xF2, 0x47, 0x34, 0xB1, 0x44, 0x80,
        0x4F, 0x13, 0xCB, 0x6B, 0x6B, 0xB6, 0x01, 0x00
    };
    uint32_t targetSize = sizeof(target);
    char key[] = "IAMAKEYIAMAKEYIAMAKEYIAMAKEYIAMA";
    void *actual = decryptData(&target, &targetSize, key, 32);	//FIXME: fail with memory corruption @ 0x605810
    printf("%s\n",actual);
    char expected[] = "I am chunk of private data encrypted in a target. Can you decrypt me?";
    ck_assert_msg (strcmp((char*)actual, expected), "Fail! actual: 0x%04x (%s)",actual,actual);
//     free(actual);
    fail("OK!");
}
END_TEST

START_TEST (test_check_xorbuffer)
{
    unsigned char buf[] = {'\x0', '\x80', '\x7f', '\xff'};
    uint8_t factor = 0xcd;
    xorBuffer(factor, buf, 4);
    ck_assert_str_eq ((char*)buf, "\xcd\x4d\xb2\x32");
}
END_TEST

Suite *
xsdc_suite (void)
{
    Suite *s = suite_create ("xSDC");

    /* Core test case */
    TCase *tc_core = tcase_create ("Core");
    tcase_add_test (tc_core, test_check_fillunpackstruct);
//     tcase_add_test (tc_core, test_check_decryptdata);
    tcase_add_test (tc_core, test_check_xorbuffer);
    suite_add_tcase (s, tc_core);

    return s;
}

int
main (void)
{
    int number_failed;
    Suite *s = xsdc_suite ();
    SRunner *sr = srunner_create (s);
    srunner_set_fork_status(sr, CK_FORK);
    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
