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
        0x42, 0x3F, 0x3B, 0x95, 0x07, 0xA6, 0xF4, 0x2A, 0x08, 0xB3, 0x09, 0xC5, 0xC0, 0x52, 0xB7, 0x1D,
	0x87, 0x02, 0x17, 0x16, 0xB0, 0xEC, 0xFE, 0xD1, 0x6C, 0xD3, 0x71, 0x09, 0xFD, 0x48, 0x57, 0xF9,
	0x32, 0xB1, 0x36, 0xAC, 0xC1, 0xD9, 0x9F, 0x29, 0x58, 0x92, 0xBF, 0xC6, 0x0B, 0xA7, 0xBD, 0x79,
	0xFD, 0x66, 0xFB, 0xF7, 0x41, 0xAD, 0x4B, 0x16, 0xE1, 0xA3, 0xF2, 0x47, 0x24, 0x2A, 0xD2, 0x85,
	0x4F, 0x13, 0xCB, 0x6B, 0x1F, 0x0F, 0x0D, 0x00
    };
    uint32_t targetSize = sizeof(target);
    char key[] = "IAMAKEYIAMAKEYIAMAKEYIAMAKEYIAMA";
    void *actual = malloc(getDataOutputSize(targetSize)+1);
    ((char*)actual)[getDataOutputSize(targetSize)] = '\0';
    decryptData(target, &targetSize, actual, key, 32);
    char expected[] = "I am chunk of private data encrypted in a target. Can you decrypt me?";
//     CBlowFish cbf;
//     cbf.Initialize((unsigned char*)key,32);
//     cbf.Encode((unsigned char*)expected,(unsigned char*)actual,strlen(expected)+1);
    printf("%s\n",actual);
    int i;
    for(i = 0; i < 72; i++)
      printf("0x%02X, ", ((unsigned char*)actual)[i]);
    printf("\n");
//     ck_assert_msg (strncmp((char*)expected,(char*)actual,targetSize) == 0,"%s\n",actual);
//     free(actual);
    fail("%s\n",expected);
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

