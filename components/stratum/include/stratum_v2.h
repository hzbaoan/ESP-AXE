#ifndef STRATUM_V2_H
#define STRATUM_V2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "stratum_api.h"

#define STRATUM_V2_FRAME_HEADER_SIZE 6
#define STRATUM_V2_MAX_PAYLOAD_SIZE 4096
#define STRATUM_V2_MAX_COINBASE_PART_SIZE 1536
#define STRATUM_V2_JOB_CACHE_SIZE 4

#define STRATUM_V2_EXT_CORE 0x0000

#define STRATUM_V2_MSG_SETUP_CONNECTION 0x00
#define STRATUM_V2_MSG_SETUP_CONNECTION_SUCCESS 0x01
#define STRATUM_V2_MSG_SETUP_CONNECTION_ERROR 0x02
#define STRATUM_V2_MSG_CHANNEL_ENDPOINT_CHANGED 0x03
#define STRATUM_V2_MSG_RECONNECT 0x04
#define STRATUM_V2_MSG_OPEN_EXTENDED_MINING_CHANNEL 0x13
#define STRATUM_V2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS 0x14
#define STRATUM_V2_MSG_NEW_EXTENDED_MINING_JOB 0x1f
#define STRATUM_V2_MSG_SET_NEW_PREV_HASH 0x20
#define STRATUM_V2_MSG_SET_TARGET 0x21
#define STRATUM_V2_MSG_SUBMIT_SHARES_EXTENDED 0x1b
#define STRATUM_V2_MSG_SUBMIT_SHARES_SUCCESS 0x1c
#define STRATUM_V2_MSG_SUBMIT_SHARES_ERROR 0x1d

typedef struct
{
    uint16_t extension_type;
    uint8_t msg_type;
    uint32_t payload_len;
} stratum_v2_frame_header_t;

typedef struct
{
    bool valid;
    bool target_valid;
    uint32_t channel_id;
    uint32_t group_channel_id;
    uint8_t target[32];
    uint8_t extranonce_prefix[32];
    uint8_t extranonce_prefix_len;
    uint16_t extranonce_size;
} stratum_v2_channel_t;

typedef struct
{
    bool valid;
    bool active;
    uint32_t job_id;
    mining_notify *notify;
} stratum_v2_cached_job_t;

typedef struct
{
    stratum_v2_cached_job_t jobs[STRATUM_V2_JOB_CACHE_SIZE];
} stratum_v2_job_cache_t;

uint16_t STRATUM_V2_read_u16_le(const uint8_t *bytes);
uint32_t STRATUM_V2_read_u24_le(const uint8_t *bytes);
uint32_t STRATUM_V2_read_u32_le(const uint8_t *bytes);

bool STRATUM_V2_parse_frame_header(const uint8_t header[STRATUM_V2_FRAME_HEADER_SIZE],
                                   stratum_v2_frame_header_t *out);
bool STRATUM_V2_build_frame_header(uint16_t extension_type, uint8_t msg_type,
                                   uint32_t payload_len,
                                   uint8_t out[STRATUM_V2_FRAME_HEADER_SIZE]);

void STRATUM_V2_channel_reset(stratum_v2_channel_t *channel);
void STRATUM_V2_job_cache_init(stratum_v2_job_cache_t *cache);
void STRATUM_V2_job_cache_clear(stratum_v2_job_cache_t *cache);

bool STRATUM_V2_parse_open_extended_success(stratum_v2_channel_t *channel,
                                            const uint8_t *payload,
                                            size_t payload_len,
                                            uint32_t expected_request_id);
bool STRATUM_V2_parse_set_target(stratum_v2_channel_t *channel,
                                 const uint8_t *payload,
                                 size_t payload_len);
bool STRATUM_V2_parse_new_extended_mining_job(stratum_v2_job_cache_t *cache,
                                              const stratum_v2_channel_t *channel,
                                              const uint8_t *payload,
                                              size_t payload_len);
bool STRATUM_V2_parse_set_new_prev_hash(stratum_v2_job_cache_t *cache,
                                        const uint8_t *payload,
                                        size_t payload_len,
                                        mining_notify **out_notify,
                                        bool *clean_jobs);
size_t STRATUM_V2_build_submit_shares_extended(uint8_t *out,
                                               size_t out_len,
                                               uint32_t channel_id,
                                               uint32_t sequence_number,
                                               uint32_t job_id,
                                               uint32_t nonce,
                                               uint32_t ntime,
                                               uint32_t version,
                                               const uint8_t *extranonce,
                                               uint8_t extranonce_len);

#endif // STRATUM_V2_H
