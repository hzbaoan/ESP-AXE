#include "unity.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>

TEST_CASE("Test double sha", "[utils]")
{
    const char *input = "68656c6c6f";
    char *output = double_sha256(input);
    TEST_ASSERT_EQUAL_STRING("9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50", output);
}

TEST_CASE("Test hex2bin", "[utils]")
{
    char *hex_string = "48454c4c4f";
    size_t bin_len = strlen(hex_string) / 2;
    uint8_t *bin = malloc(bin_len);
    hex2bin(hex_string, bin, bin_len);
    TEST_ASSERT_EQUAL(72, bin[0]);
    TEST_ASSERT_EQUAL(69, bin[1]);
    TEST_ASSERT_EQUAL(76, bin[2]);
    TEST_ASSERT_EQUAL(76, bin[3]);
    TEST_ASSERT_EQUAL(79, bin[4]);
}

TEST_CASE("Test bin2hex", "[utils]")
{
    uint8_t bin[5] = {72, 69, 76, 76, 79};
    char hex_string[11];
    bin2hex(bin, 5, hex_string, 11);
    TEST_ASSERT_EQUAL_STRING("48454c4c4f", hex_string);
}

TEST_CASE("bin2hex rejects undersized output buffers", "[utils]")
{
    uint8_t bin[5] = {72, 69, 76, 76, 79};
    char hex_string[10];

    TEST_ASSERT_EQUAL_UINT(0, bin2hex(bin, 5, hex_string, sizeof(hex_string)));
}

TEST_CASE("hex2bin_exact validates length and characters", "[utils]")
{
    uint8_t bin[2] = {0};

    TEST_ASSERT_TRUE(hex2bin_exact("0a1B", bin, sizeof(bin)));
    TEST_ASSERT_EQUAL_HEX8(0x0a, bin[0]);
    TEST_ASSERT_EQUAL_HEX8(0x1b, bin[1]);
    TEST_ASSERT_FALSE(hex2bin_exact("0a1", bin, sizeof(bin)));
    TEST_ASSERT_FALSE(hex2bin_exact("0x1b", bin, sizeof(bin)));
}

TEST_CASE("Test hex2char", "[utils]")
{
    char output;
    int result = hex2char(1, &output);
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL('1', output);

    result = hex2char(15, &output);
    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL('f', output);

    result = hex2char(16, &output);
    TEST_ASSERT_EQUAL(-1, result);
}
