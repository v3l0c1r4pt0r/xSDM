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
	0x42, 0x3f, 0x3b, 0x95, 0xdc, 0x05, 0xa3, 0x55, 0x08, 0xb3, 0x09, 0xc5, 0xb2, 0xc2, 0x11, 0x1a,
	0x87, 0x02, 0x17, 0x16, 0xfe, 0xcd, 0x6e, 0x11, 0x6c, 0xd3, 0x71, 0x09, 0x4d, 0xc7, 0xb0, 0x04,
	0x32, 0xb1, 0x36, 0xac, 0xdc, 0x7a, 0x30, 0x0e, 0x58, 0x92, 0xbf, 0xc6, 0x17, 0x58, 0x17, 0x8f,
	0xfd, 0x66, 0xfb, 0xf7, 0xe2, 0x60, 0xcd, 0x4a, 0xe1, 0xa3, 0xf2, 0x47, 0x6f, 0xd8, 0x1b, 0x02,
	0x4f, 0x13, 0xcb, 0x6b, 0x52, 0xab, 0x97, 0x2e
    };
    uint32_t targetSize = sizeof(target);
    char key[] = "IAMAKEYIAMAKEYIAMAKEYIAMAKEYIAMA";
    void *actual = malloc(getDataOutputSize(targetSize)+1);
    ((char*)actual)[getDataOutputSize(targetSize)] = '\0';
    decryptData(target, &targetSize, actual, key, 32);
    char expected[] = "I am chunk of private data encrypted in a target. Can you decrypt me?";
    printf("%s\n",actual);
    int i;
    for(i = 0; i < 72; i++)
      printf("0x%02X, ", ((unsigned char*)actual)[i]);
    printf("\n");
    ck_assert_msg (strncmp((char*)expected,(char*)actual,targetSize) == 0,"%s\n",actual);
    free(actual);
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

