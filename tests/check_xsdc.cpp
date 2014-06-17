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
    unsigned char target[] = {
        0x1F, 0xF1, 0x36, 0x40, 0xE1, 0x17, 0x3A, 0xDA, 0xFE, 0x52, 0x3E, 0x2E, 0xB7, 0x28, 0xCC, 0x4A, 0x0E, 0x6A, 
	0x5D, 0xA9, 0x48, 0x9A, 0x0F, 0x5D, 0xAB, 0xBB, 0xAD, 0x2B, 0xE7, 0x2B, 0xC1, 0x82, 0x9A, 0xC4, 0x92, 0x76, 
	0xB6, 0x60, 0x5D, 0x0A, 0x9E, 0xD5, 0xD0, 0x4A, 0xFC, 0x6F, 0x34, 0xF4, 0x47, 0x24, 0x35, 0x4A, 0x9F, 0xB3, 
	0x28, 0x19, 0x4A, 0x5D, 0xBE, 0xC0, 0x72, 0x73, 0x76, 0xE6, 0x20, 0xCB, 0x9F, 0xBF, 0xBB, 0x26, 0x07, 0x00
    };
    uint32_t targetSize = sizeof(target);
    char key[] = "IAMAKEYIAMAKEYIAMAKEYIAMAKEYIAMA";
    void *actual = malloc(getDataOutputSize(targetSize));
    decryptData(target, &targetSize, actual, key, 32);
    char expected[] = "I am chunk of private data encrypted in a target. Can you decrypt me?";
    ck_assert_msg (strncmp((char*)target,(char*)actual,targetSize),"%s\n",actual);
    ck_assert_msg (strcmp((char*)actual, expected), "Fail! actual: 0x%04x (%s)",actual,actual);
//     free(actual);
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
    tcase_add_test (tc_core, test_check_decryptdata);
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
