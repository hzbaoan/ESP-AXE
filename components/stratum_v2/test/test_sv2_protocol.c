#include "unity.h"
#include "sv2_protocol.h"

#include <string.h>

static void put_u8(uint8_t *buffer, size_t *pos, uint8_t value)
{
    buffer[(*pos)++] = value;
}

static void put_u16_le(uint8_t *buffer, size_t *pos, uint16_t value)
{
    buffer[(*pos)++] = (uint8_t)(value & 0xffU);
    buffer[(*pos)++] = (uint8_t)((value >> 8) & 0xffU);
}

static void put_u32_le(uint8_t *buffer, size_t *pos, uint32_t value)
{
    buffer[(*pos)++] = (uint8_t)(value & 0xffU);
    buffer[(*pos)++] = (uint8_t)((value >> 8) & 0xffU);
    buffer[(*pos)++] = (uint8_t)((value >> 16) & 0xffU);
    buffer[(*pos)++] = (uint8_t)((value >> 24) & 0xffU);
}

static void put_bytes(uint8_t *buffer, size_t *pos, const uint8_t *bytes, size_t len)
{
    memcpy(buffer + *pos, bytes, len);
    *pos += len;
}

TEST_CASE("production SV2 common message IDs match spec", "[stratum_v2_protocol]")
{
    TEST_ASSERT_EQUAL_UINT8(0x03, SV2_MSG_CHANNEL_ENDPOINT_CHANGED);
    TEST_ASSERT_EQUAL_UINT8(0x04, SV2_MSG_RECONNECT);
    TEST_ASSERT_EQUAL_UINT8(0x16, SV2_MSG_UPDATE_CHANNEL);
    TEST_ASSERT_EQUAL_UINT8(0x17, SV2_MSG_UPDATE_CHANNEL_ERROR);
    TEST_ASSERT_EQUAL_UINT8(0x18, SV2_MSG_CLOSE_CHANNEL);
    TEST_ASSERT_EQUAL_UINT8(0x19, SV2_MSG_SET_EXTRANONCE_PREFIX);
}

TEST_CASE("production SV2 parses SetExtranoncePrefix", "[stratum_v2_protocol]")
{
    uint8_t payload[16] = {0};
    uint8_t prefix[32] = {0};
    const uint8_t expected_prefix[] = {0xaa, 0xbb, 0xcc, 0xdd};
    uint32_t channel_id = 0;
    uint8_t prefix_len = 0;
    size_t pos = 0;

    put_u32_le(payload, &pos, 42);
    put_u8(payload, &pos, sizeof(expected_prefix));
    put_bytes(payload, &pos, expected_prefix, sizeof(expected_prefix));

    TEST_ASSERT_EQUAL_INT(0, sv2_parse_set_extranonce_prefix(payload,
                                                            pos,
                                                            &channel_id,
                                                            prefix,
                                                            &prefix_len));
    TEST_ASSERT_EQUAL_UINT32(42, channel_id);
    TEST_ASSERT_EQUAL_UINT8(sizeof(expected_prefix), prefix_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected_prefix, prefix, sizeof(expected_prefix));
}

TEST_CASE("production SV2 rejects invalid Option flag", "[stratum_v2_protocol]")
{
    uint8_t payload[64] = {0};
    uint8_t merkle_root[32] = {0};
    uint32_t channel_id = 0;
    uint32_t job_id = 0;
    uint32_t min_ntime = 0;
    uint32_t version = 0;
    bool has_min_ntime = false;
    size_t pos = 0;

    put_u32_le(payload, &pos, 42);
    put_u32_le(payload, &pos, 1001);
    put_u8(payload, &pos, 2);
    put_u32_le(payload, &pos, 0x20000004);
    memset(payload + pos, 0x11, sizeof(merkle_root));
    pos += sizeof(merkle_root);

    TEST_ASSERT_EQUAL_INT(-1, sv2_parse_new_mining_job(payload,
                                                       pos,
                                                       &channel_id,
                                                       &job_id,
                                                       &has_min_ntime,
                                                       &min_ntime,
                                                       &version,
                                                       merkle_root));
    TEST_ASSERT_EQUAL_PTR(NULL, sv2_parse_new_extended_mining_job(payload, pos, &channel_id));
}

TEST_CASE("production SV2 parses Reconnect host and port", "[stratum_v2_protocol]")
{
    uint8_t payload[64] = {0};
    char host[32] = {0};
    uint16_t port = 0;
    const char expected_host[] = "pool.example";
    size_t pos = 0;

    put_u8(payload, &pos, strlen(expected_host));
    put_bytes(payload, &pos, (const uint8_t *)expected_host, strlen(expected_host));
    put_u16_le(payload, &pos, 3333);

    TEST_ASSERT_EQUAL_INT(0, sv2_parse_reconnect(payload, pos, host, sizeof(host), &port));
    TEST_ASSERT_EQUAL_STRING(expected_host, host);
    TEST_ASSERT_EQUAL_UINT16(3333, port);
}

TEST_CASE("production SV2 target conversion tolerates unaligned buffers", "[stratum_v2_protocol]")
{
    uint8_t raw[33] = {0};
    uint8_t *target = raw + 1;

    memset(target, 0xff, 32);
    TEST_ASSERT_EQUAL_UINT32(1, sv2_target_to_pdiff(target));
}
