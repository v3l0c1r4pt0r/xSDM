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
        0x0b, 0xa2, 0xd1, 0xdb, 0xd8, 0xb9, 0xbd, 0x59, 0x34, 0xc4, 0x84, 0xf1, 0xc2, 0x04, 0x58, 0xc3,
        0x50, 0x71, 0x80, 0x04, 0x96, 0xd2, 0xa9, 0x00, 0x8b, 0x81, 0xa0, 0x50, 0xd9, 0x69, 0x1c, 0x4e,
        0xea, 0x7f, 0xb1, 0x9f, 0x51, 0x3c, 0x54, 0x22, 0x51, 0x54, 0xdc, 0xc4, 0xa1, 0x48, 0xa1, 0x8d,
        0x38, 0x03, 0x2f, 0x35, 0x53, 0xfb, 0xc7, 0x50, 0x5a, 0x7f, 0x78, 0xb4, 0x08, 0x62, 0x18, 0xe6,
        0xd3, 0x17, 0x4f, 0x80, 0x8d, 0x95, 0xbf, 0x30
    };
    uint32_t targetSize = sizeof(target);
    char key[] = "IAMAKEYIAMAKEYIAMAKEYIAMAKEYIAMA";
    void *actual = decryptData(target, &targetSize, key, 32);	//FIXME: fail with memory corruption
    char expected[] = "I am chunk of private data encrypted in a target. Can you decrypt me?";
    ck_assert_msg (strcmp((char*)actual, expected), "Fail! actual: 0x%04x (%s)",actual,actual);
//     free(actual);
}
END_TEST

START_TEST (test_check_openfile)
{
    FILE *f;
    char fName[] = "test_file";
    f = openFile(fName,"w");
    ck_assert_ptr_ne (f, NULL);
    fclose(f);
    f = openFile(fName,"r");
    ck_assert_ptr_ne (f, NULL);
    fclose(f);
    remove(fName);
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
    tcase_add_test (tc_core, test_check_openfile);
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
