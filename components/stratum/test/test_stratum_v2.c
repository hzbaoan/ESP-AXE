#include "unity.h"
#include "stratum_v2.h"

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

static void fill_sequence(uint8_t *buffer, size_t len, uint8_t start)
{
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t)(start + i);
    }
}

TEST_CASE("SV2 frame header uses little endian extension and u24 length", "[stratum_v2]")
{
    uint8_t header[STRATUM_V2_FRAME_HEADER_SIZE];
    stratum_v2_frame_header_t parsed;

    TEST_ASSERT_TRUE(STRATUM_V2_build_frame_header(
        STRATUM_V2_EXT_CORE,
        STRATUM_V2_MSG_NEW_EXTENDED_MINING_JOB,
        0x1234,
        header));

    TEST_ASSERT_EQUAL_UINT8(0x00, header[0]);
    TEST_ASSERT_EQUAL_UINT8(0x00, header[1]);
    TEST_ASSERT_EQUAL_UINT8(STRATUM_V2_MSG_NEW_EXTENDED_MINING_JOB, header[2]);
    TEST_ASSERT_EQUAL_UINT8(0x34, header[3]);
    TEST_ASSERT_EQUAL_UINT8(0x12, header[4]);
    TEST_ASSERT_EQUAL_UINT8(0x00, header[5]);

    TEST_ASSERT_TRUE(STRATUM_V2_parse_frame_header(header, &parsed));
    TEST_ASSERT_EQUAL_UINT16(STRATUM_V2_EXT_CORE, parsed.extension_type);
    TEST_ASSERT_EQUAL_UINT8(STRATUM_V2_MSG_NEW_EXTENDED_MINING_JOB, parsed.msg_type);
    TEST_ASSERT_EQUAL_UINT32(0x1234, parsed.payload_len);
}

TEST_CASE("SV2 OpenExtendedMiningChannel.Success maps channel extranonce state", "[stratum_v2]")
{
    uint8_t payload[128] = {0};
    uint8_t target[32];
    uint8_t prefix[4] = {0xaa, 0xbb, 0xcc, 0xdd};
    size_t pos = 0;
    stratum_v2_channel_t channel;

    fill_sequence(target, sizeof(target), 0x10);
    put_u32_le(payload, &pos, 2);
    put_u32_le(payload, &pos, 42);
    put_bytes(payload, &pos, target, sizeof(target));
    put_u16_le(payload, &pos, 8);
    put_u8(payload, &pos, sizeof(prefix));
    put_bytes(payload, &pos, prefix, sizeof(prefix));
    put_u32_le(payload, &pos, 99);

    TEST_ASSERT_TRUE(STRATUM_V2_parse_open_extended_success(&channel, payload, pos, 2));
    TEST_ASSERT_TRUE(channel.valid);
    TEST_ASSERT_TRUE(channel.target_valid);
    TEST_ASSERT_EQUAL_UINT32(42, channel.channel_id);
    TEST_ASSERT_EQUAL_UINT32(99, channel.group_channel_id);
    TEST_ASSERT_EQUAL_UINT16(8, channel.extranonce_size);
    TEST_ASSERT_EQUAL_UINT8(sizeof(prefix), channel.extranonce_prefix_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(prefix, channel.extranonce_prefix, sizeof(prefix));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(target, channel.target, sizeof(target));
}

TEST_CASE("SV2 extended job plus prevhash converts to mining_notify", "[stratum_v2]")
{
    stratum_v2_channel_t channel = {
        .valid = true,
        .channel_id = 42,
    };
    stratum_v2_job_cache_t cache;
    uint8_t job_payload[256] = {0};
    uint8_t prev_payload[64] = {0};
    uint8_t merkle[32];
    uint8_t prev_hash[32];
    uint8_t coinbase_prefix[3] = {0x01, 0x02, 0x03};
    uint8_t coinbase_suffix[2] = {0xfe, 0xff};
    size_t pos = 0;
    mining_notify *notify = NULL;
    bool clean_jobs = false;

    STRATUM_V2_job_cache_init(&cache);
    fill_sequence(merkle, sizeof(merkle), 0x20);
    fill_sequence(prev_hash, sizeof(prev_hash), 0x40);

    put_u32_le(job_payload, &pos, 42);
    put_u32_le(job_payload, &pos, 1001);
    put_u8(job_payload, &pos, 0);
    put_u32_le(job_payload, &pos, 0x20000004);
    put_u8(job_payload, &pos, 1);
    put_u8(job_payload, &pos, 1);
    put_bytes(job_payload, &pos, merkle, sizeof(merkle));
    put_u16_le(job_payload, &pos, sizeof(coinbase_prefix));
    put_bytes(job_payload, &pos, coinbase_prefix, sizeof(coinbase_prefix));
    put_u16_le(job_payload, &pos, sizeof(coinbase_suffix));
    put_bytes(job_payload, &pos, coinbase_suffix, sizeof(coinbase_suffix));

    TEST_ASSERT_TRUE(STRATUM_V2_parse_new_extended_mining_job(&cache, &channel, job_payload, pos));

    pos = 0;
    put_u32_le(prev_payload, &pos, 42);
    put_u32_le(prev_payload, &pos, 1001);
    put_bytes(prev_payload, &pos, prev_hash, sizeof(prev_hash));
    put_u32_le(prev_payload, &pos, 0x66554433);
    put_u32_le(prev_payload, &pos, 0x1705c739);

    TEST_ASSERT_TRUE(STRATUM_V2_parse_set_new_prev_hash(&cache, prev_payload, pos, &notify, &clean_jobs));
    TEST_ASSERT_NOT_NULL(notify);
    TEST_ASSERT_TRUE(clean_jobs);
    TEST_ASSERT_EQUAL_STRING("1001", notify->job_id);
    TEST_ASSERT_EQUAL_UINT32(0x20000004, notify->version);
    TEST_ASSERT_EQUAL_UINT32(0x66554433, notify->ntime);
    TEST_ASSERT_EQUAL_UINT32(0x1705c739, notify->target);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(prev_hash, notify->prev_block_hash_bin, sizeof(prev_hash));
    TEST_ASSERT_EQUAL_UINT(1, notify->n_merkle_branches);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(merkle, notify->merkle_branches, sizeof(merkle));
    TEST_ASSERT_EQUAL_UINT(sizeof(coinbase_prefix), notify->coinbase_1_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(coinbase_prefix, notify->coinbase_1_bin, sizeof(coinbase_prefix));
    TEST_ASSERT_EQUAL_UINT(sizeof(coinbase_suffix), notify->coinbase_2_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(coinbase_suffix, notify->coinbase_2_bin, sizeof(coinbase_suffix));

    STRATUM_V1_free_mining_notify(notify);
    STRATUM_V2_job_cache_clear(&cache);
}

TEST_CASE("SV2 SubmitSharesExtended payload is encoded from internal share fields", "[stratum_v2]")
{
    uint8_t payload[64] = {0};
    uint8_t extranonce[4] = {0xde, 0xad, 0xbe, 0xef};
    size_t len;

    len = STRATUM_V2_build_submit_shares_extended(
        payload,
        sizeof(payload),
        42,
        7,
        1001,
        0x11223344,
        0x66554433,
        0x20000004,
        extranonce,
        sizeof(extranonce));

    TEST_ASSERT_EQUAL_UINT(29, len);
    TEST_ASSERT_EQUAL_UINT32(42, STRATUM_V2_read_u32_le(payload));
    TEST_ASSERT_EQUAL_UINT32(7, STRATUM_V2_read_u32_le(payload + 4));
    TEST_ASSERT_EQUAL_UINT32(1001, STRATUM_V2_read_u32_le(payload + 8));
    TEST_ASSERT_EQUAL_UINT32(0x11223344, STRATUM_V2_read_u32_le(payload + 12));
    TEST_ASSERT_EQUAL_UINT32(0x66554433, STRATUM_V2_read_u32_le(payload + 16));
    TEST_ASSERT_EQUAL_UINT32(0x20000004, STRATUM_V2_read_u32_le(payload + 20));
    TEST_ASSERT_EQUAL_UINT8(sizeof(extranonce), payload[24]);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(extranonce, payload + 25, sizeof(extranonce));
}
