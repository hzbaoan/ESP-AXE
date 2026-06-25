#include "stratum_v2.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"

typedef struct
{
    const uint8_t *payload;
    size_t len;
    size_t pos;
} sv2_reader_t;

static bool sv2_reader_get_u8(sv2_reader_t *reader, uint8_t *out)
{
    if (reader == NULL || out == NULL || reader->pos + 1U > reader->len) {
        return false;
    }

    *out = reader->payload[reader->pos++];
    return true;
}

static bool sv2_reader_get_bool(sv2_reader_t *reader, bool *out)
{
    uint8_t value;

    if (!sv2_reader_get_u8(reader, &value) || out == NULL) {
        return false;
    }

    *out = (value & 1U) != 0U;
    return true;
}

static bool sv2_reader_get_u16(sv2_reader_t *reader, uint16_t *out)
{
    if (reader == NULL || out == NULL || reader->pos + 2U > reader->len) {
        return false;
    }

    *out = STRATUM_V2_read_u16_le(reader->payload + reader->pos);
    reader->pos += 2U;
    return true;
}

static bool sv2_reader_get_u32(sv2_reader_t *reader, uint32_t *out)
{
    if (reader == NULL || out == NULL || reader->pos + 4U > reader->len) {
        return false;
    }

    *out = STRATUM_V2_read_u32_le(reader->payload + reader->pos);
    reader->pos += 4U;
    return true;
}

static bool sv2_reader_get_u256(sv2_reader_t *reader, uint8_t out[32])
{
    if (reader == NULL || out == NULL || reader->pos + 32U > reader->len) {
        return false;
    }

    memcpy(out, reader->payload + reader->pos, 32U);
    reader->pos += 32U;
    return true;
}

static bool sv2_reader_get_option_u32(sv2_reader_t *reader, bool *present, uint32_t *out)
{
    uint8_t count;

    if (present == NULL || out == NULL || !sv2_reader_get_u8(reader, &count)) {
        return false;
    }

    *present = false;
    *out = 0;
    if (count == 0U) {
        return true;
    }
    if (count != 1U) {
        return false;
    }

    *present = true;
    return sv2_reader_get_u32(reader, out);
}

static bool sv2_reader_get_b032(sv2_reader_t *reader, const uint8_t **out, uint8_t *out_len)
{
    uint8_t len;

    if (out == NULL || out_len == NULL || !sv2_reader_get_u8(reader, &len)) {
        return false;
    }
    if (len > 32U || reader->pos + len > reader->len) {
        return false;
    }

    *out = reader->payload + reader->pos;
    *out_len = len;
    reader->pos += len;
    return true;
}

static bool sv2_reader_get_b064k_alloc(sv2_reader_t *reader, uint8_t **out, size_t *out_len)
{
    uint16_t len;

    if (out == NULL || out_len == NULL || !sv2_reader_get_u16(reader, &len)) {
        return false;
    }
    if (len > STRATUM_V2_MAX_COINBASE_PART_SIZE || reader->pos + len > reader->len) {
        return false;
    }

    *out = NULL;
    *out_len = len;
    if (len == 0U) {
        return true;
    }

    *out = malloc(len);
    if (*out == NULL) {
        *out_len = 0;
        return false;
    }

    memcpy(*out, reader->payload + reader->pos, len);
    reader->pos += len;
    return true;
}

static bool sv2_writer_put_u32(uint8_t *out, size_t out_len, size_t *pos, uint32_t value)
{
    if (out == NULL || pos == NULL || *pos + 4U > out_len) {
        return false;
    }

    out[(*pos)++] = (uint8_t)(value & 0xffU);
    out[(*pos)++] = (uint8_t)((value >> 8) & 0xffU);
    out[(*pos)++] = (uint8_t)((value >> 16) & 0xffU);
    out[(*pos)++] = (uint8_t)((value >> 24) & 0xffU);
    return true;
}

static bool sv2_writer_put_b032(uint8_t *out, size_t out_len, size_t *pos,
                                const uint8_t *bytes, uint8_t bytes_len)
{
    if (out == NULL || pos == NULL || bytes_len > 32U || *pos + 1U + bytes_len > out_len) {
        return false;
    }
    if (bytes_len > 0U && bytes == NULL) {
        return false;
    }

    out[(*pos)++] = bytes_len;
    if (bytes_len > 0U) {
        memcpy(out + *pos, bytes, bytes_len);
        *pos += bytes_len;
    }
    return true;
}

static mining_notify *sv2_alloc_notify(uint32_t job_id)
{
    mining_notify *notify = calloc(1, sizeof(*notify));
    char job_id_text[11];

    if (notify == NULL) {
        return NULL;
    }

    snprintf(job_id_text, sizeof(job_id_text), "%lu", (unsigned long)job_id);

    notify->job_id = malloc(strlen(job_id_text) + 1U);
    if (notify->job_id == NULL) {
        STRATUM_V1_free_mining_notify(notify);
        return NULL;
    }

    strcpy(notify->job_id, job_id_text);
    return notify;
}

static void sv2_set_prev_hash(mining_notify *notify, const uint8_t prev_hash[32])
{
    memcpy(notify->prev_block_hash_bin, prev_hash, sizeof(notify->prev_block_hash_bin));
    flip32bytes(notify->prev_block_hash, notify->prev_block_hash_bin);
    memcpy(notify->prev_block_hash_be, notify->prev_block_hash_bin, sizeof(notify->prev_block_hash_be));
    reverse_bytes(notify->prev_block_hash_be, sizeof(notify->prev_block_hash_be));
}

static stratum_v2_cached_job_t *sv2_find_job(stratum_v2_job_cache_t *cache, uint32_t job_id)
{
    if (cache == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < STRATUM_V2_JOB_CACHE_SIZE; i++) {
        if (cache->jobs[i].valid && cache->jobs[i].job_id == job_id) {
            return &cache->jobs[i];
        }
    }

    return NULL;
}

static stratum_v2_cached_job_t *sv2_alloc_job_slot(stratum_v2_job_cache_t *cache, uint32_t job_id)
{
    stratum_v2_cached_job_t *existing = sv2_find_job(cache, job_id);

    if (existing != NULL) {
        STRATUM_V1_free_mining_notify(existing->notify);
        memset(existing, 0, sizeof(*existing));
        return existing;
    }

    for (size_t i = 0; i < STRATUM_V2_JOB_CACHE_SIZE; i++) {
        if (!cache->jobs[i].valid) {
            return &cache->jobs[i];
        }
    }

    STRATUM_V1_free_mining_notify(cache->jobs[0].notify);
    memset(&cache->jobs[0], 0, sizeof(cache->jobs[0]));
    return &cache->jobs[0];
}

uint16_t STRATUM_V2_read_u16_le(const uint8_t *bytes)
{
    return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
}

uint32_t STRATUM_V2_read_u24_le(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16);
}

uint32_t STRATUM_V2_read_u32_le(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

bool STRATUM_V2_parse_frame_header(const uint8_t header[STRATUM_V2_FRAME_HEADER_SIZE],
                                   stratum_v2_frame_header_t *out)
{
    if (header == NULL || out == NULL) {
        return false;
    }

    out->extension_type = STRATUM_V2_read_u16_le(header);
    out->msg_type = header[2];
    out->payload_len = STRATUM_V2_read_u24_le(header + 3);
    return out->payload_len <= STRATUM_V2_MAX_PAYLOAD_SIZE;
}

bool STRATUM_V2_build_frame_header(uint16_t extension_type, uint8_t msg_type,
                                   uint32_t payload_len,
                                   uint8_t out[STRATUM_V2_FRAME_HEADER_SIZE])
{
    if (out == NULL || payload_len > 0x00ffffffUL || payload_len > STRATUM_V2_MAX_PAYLOAD_SIZE) {
        return false;
    }

    out[0] = (uint8_t)(extension_type & 0xffU);
    out[1] = (uint8_t)((extension_type >> 8) & 0xffU);
    out[2] = msg_type;
    out[3] = (uint8_t)(payload_len & 0xffU);
    out[4] = (uint8_t)((payload_len >> 8) & 0xffU);
    out[5] = (uint8_t)((payload_len >> 16) & 0xffU);
    return true;
}

size_t STRATUM_V2_build_submit_shares_extended(uint8_t *out,
                                               size_t out_len,
                                               uint32_t channel_id,
                                               uint32_t sequence_number,
                                               uint32_t job_id,
                                               uint32_t nonce,
                                               uint32_t ntime,
                                               uint32_t version,
                                               const uint8_t *extranonce,
                                               uint8_t extranonce_len)
{
    size_t pos = 0;

    if (!sv2_writer_put_u32(out, out_len, &pos, channel_id) ||
            !sv2_writer_put_u32(out, out_len, &pos, sequence_number) ||
            !sv2_writer_put_u32(out, out_len, &pos, job_id) ||
            !sv2_writer_put_u32(out, out_len, &pos, nonce) ||
            !sv2_writer_put_u32(out, out_len, &pos, ntime) ||
            !sv2_writer_put_u32(out, out_len, &pos, version) ||
            !sv2_writer_put_b032(out, out_len, &pos, extranonce, extranonce_len)) {
        return 0;
    }

    return pos;
}

void STRATUM_V2_channel_reset(stratum_v2_channel_t *channel)
{
    if (channel != NULL) {
        memset(channel, 0, sizeof(*channel));
    }
}

void STRATUM_V2_job_cache_init(stratum_v2_job_cache_t *cache)
{
    if (cache != NULL) {
        memset(cache, 0, sizeof(*cache));
    }
}

void STRATUM_V2_job_cache_clear(stratum_v2_job_cache_t *cache)
{
    if (cache == NULL) {
        return;
    }

    for (size_t i = 0; i < STRATUM_V2_JOB_CACHE_SIZE; i++) {
        STRATUM_V1_free_mining_notify(cache->jobs[i].notify);
    }
    memset(cache, 0, sizeof(*cache));
}

bool STRATUM_V2_parse_open_extended_success(stratum_v2_channel_t *channel,
                                            const uint8_t *payload,
                                            size_t payload_len,
                                            uint32_t expected_request_id)
{
    sv2_reader_t reader = {.payload = payload, .len = payload_len};
    uint32_t request_id;
    const uint8_t *extranonce_prefix;
    uint8_t extranonce_prefix_len;

    if (channel == NULL || payload == NULL) {
        return false;
    }

    STRATUM_V2_channel_reset(channel);
    if (!sv2_reader_get_u32(&reader, &request_id) ||
            request_id != expected_request_id ||
            !sv2_reader_get_u32(&reader, &channel->channel_id) ||
            !sv2_reader_get_u256(&reader, channel->target) ||
            !sv2_reader_get_u16(&reader, &channel->extranonce_size) ||
            !sv2_reader_get_b032(&reader, &extranonce_prefix, &extranonce_prefix_len) ||
            !sv2_reader_get_u32(&reader, &channel->group_channel_id)) {
        STRATUM_V2_channel_reset(channel);
        return false;
    }

    channel->extranonce_prefix_len = extranonce_prefix_len;
    if (extranonce_prefix_len > 0U) {
        memcpy(channel->extranonce_prefix, extranonce_prefix, extranonce_prefix_len);
    }
    channel->target_valid = true;
    channel->valid = true;
    return true;
}

bool STRATUM_V2_parse_set_target(stratum_v2_channel_t *channel,
                                 const uint8_t *payload,
                                 size_t payload_len)
{
    sv2_reader_t reader = {.payload = payload, .len = payload_len};
    uint32_t channel_id;

    if (channel == NULL || payload == NULL ||
            !sv2_reader_get_u32(&reader, &channel_id) ||
            !sv2_reader_get_u256(&reader, channel->target)) {
        return false;
    }

    if (channel->valid && channel->channel_id != 0U && channel_id != channel->channel_id) {
        return false;
    }

    channel->channel_id = channel_id;
    channel->target_valid = true;
    return true;
}

bool STRATUM_V2_parse_new_extended_mining_job(stratum_v2_job_cache_t *cache,
                                              const stratum_v2_channel_t *channel,
                                              const uint8_t *payload,
                                              size_t payload_len)
{
    sv2_reader_t reader = {.payload = payload, .len = payload_len};
    uint32_t channel_id;
    uint32_t job_id;
    uint32_t min_ntime;
    bool has_min_ntime;
    bool version_rolling_allowed;
    uint8_t merkle_count;
    stratum_v2_cached_job_t *slot;
    mining_notify *notify;

    if (cache == NULL || payload == NULL ||
            !sv2_reader_get_u32(&reader, &channel_id) ||
            !sv2_reader_get_u32(&reader, &job_id) ||
            !sv2_reader_get_option_u32(&reader, &has_min_ntime, &min_ntime)) {
        return false;
    }

    if (channel != NULL && channel->valid && channel->channel_id != 0U && channel_id != channel->channel_id) {
        return false;
    }

    notify = sv2_alloc_notify(job_id);
    if (notify == NULL) {
        return false;
    }

    if (!sv2_reader_get_u32(&reader, &notify->version) ||
            !sv2_reader_get_bool(&reader, &version_rolling_allowed) ||
            !sv2_reader_get_u8(&reader, &merkle_count)) {
        STRATUM_V1_free_mining_notify(notify);
        return false;
    }
    (void)version_rolling_allowed;

    if (merkle_count > MAX_MERKLE_BRANCHES) {
        STRATUM_V1_free_mining_notify(notify);
        return false;
    }

    notify->n_merkle_branches = merkle_count;
    if (merkle_count > 0U) {
        notify->merkle_branches = malloc((size_t)merkle_count * HASH_SIZE);
        if (notify->merkle_branches == NULL) {
            STRATUM_V1_free_mining_notify(notify);
            return false;
        }
    }

    for (uint8_t i = 0; i < merkle_count; i++) {
        if (!sv2_reader_get_u256(&reader, notify->merkle_branches + ((size_t)i * HASH_SIZE))) {
            STRATUM_V1_free_mining_notify(notify);
            return false;
        }
    }

    if (!sv2_reader_get_b064k_alloc(&reader, &notify->coinbase_1_bin, &notify->coinbase_1_len) ||
            !sv2_reader_get_b064k_alloc(&reader, &notify->coinbase_2_bin, &notify->coinbase_2_len)) {
        STRATUM_V1_free_mining_notify(notify);
        return false;
    }

    if (has_min_ntime) {
        notify->ntime = min_ntime;
    }

    slot = sv2_alloc_job_slot(cache, job_id);
    slot->valid = true;
    slot->active = false;
    slot->job_id = job_id;
    slot->notify = notify;
    return true;
}

bool STRATUM_V2_parse_set_new_prev_hash(stratum_v2_job_cache_t *cache,
                                        const uint8_t *payload,
                                        size_t payload_len,
                                        mining_notify **out_notify,
                                        bool *clean_jobs)
{
    sv2_reader_t reader = {.payload = payload, .len = payload_len};
    uint32_t channel_id;
    uint32_t job_id;
    uint8_t prev_hash[32];
    uint32_t min_ntime;
    uint32_t nbits;
    stratum_v2_cached_job_t *slot;

    if (out_notify != NULL) {
        *out_notify = NULL;
    }
    if (clean_jobs != NULL) {
        *clean_jobs = false;
    }

    if (cache == NULL || payload == NULL || out_notify == NULL ||
            !sv2_reader_get_u32(&reader, &channel_id) ||
            !sv2_reader_get_u32(&reader, &job_id) ||
            !sv2_reader_get_u256(&reader, prev_hash) ||
            !sv2_reader_get_u32(&reader, &min_ntime) ||
            !sv2_reader_get_u32(&reader, &nbits)) {
        return false;
    }

    slot = sv2_find_job(cache, job_id);
    if (slot == NULL || slot->notify == NULL) {
        return false;
    }

    for (size_t i = 0; i < STRATUM_V2_JOB_CACHE_SIZE; i++) {
        cache->jobs[i].active = false;
    }

    sv2_set_prev_hash(slot->notify, prev_hash);
    slot->notify->ntime = min_ntime;
    slot->notify->target = nbits;
    slot->active = true;
    *out_notify = slot->notify;
    slot->notify = NULL;
    slot->valid = false;
    slot->active = false;
    if (clean_jobs != NULL) {
        *clean_jobs = true;
    }

    return true;
}
