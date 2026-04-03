#include "mining.h"

#include <stdlib.h>
#include <string.h>

#include "mbedtls/sha256.h"
#include "utils.h"

static const double truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0;
static const uint8_t diff1_target_be[32] = {
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static inline void fast_word_reverse_32(const uint8_t *src, uint8_t *dest)
{
    const uint32_t *s = (const uint32_t *)src;
    uint32_t *d = (uint32_t *)dest;

    d[0] = s[7];
    d[1] = s[6];
    d[2] = s[5];
    d[3] = s[4];
    d[4] = s[3];
    d[5] = s[2];
    d[6] = s[1];
    d[7] = s[0];
}

static int compare_u72(const uint8_t lhs[9], const uint8_t rhs[9])
{
    for (int i = 0; i < 9; i++) {
        if (lhs[i] < rhs[i]) {
            return -1;
        }
        if (lhs[i] > rhs[i]) {
            return 1;
        }
    }
    return 0;
}

static void subtract_u72(uint8_t lhs[9], const uint8_t rhs[9])
{
    int borrow = 0;

    for (int i = 8; i >= 0; i--) {
        int value = (int)lhs[i] - (int)rhs[i] - borrow;
        if (value < 0) {
            value += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        lhs[i] = (uint8_t)value;
    }
}

static void shift_u72_and_append(uint8_t value[9], uint8_t byte)
{
    memmove(value, value + 1, 8);
    value[8] = byte;
}

static void u64_to_u72_be(uint64_t value, uint8_t out[9])
{
    out[0] = 0;
    for (int i = 0; i < 8; i++) {
        out[8 - i] = (uint8_t)(value & 0xff);
        value >>= 8;
    }
}

static void reverse_copy_32(const uint8_t *src, uint8_t *dest)
{
    for (int i = 0; i < 32; i++) {
        dest[i] = src[31 - i];
    }
}

static void divide_u256_be_by_u64(const uint8_t numerator[32], uint64_t divisor, uint8_t quotient[32])
{
    uint8_t remainder[9] = {0};
    uint8_t divisor_be[9] = {0};

    memset(quotient, 0, 32);

    if (divisor == 0) {
        memset(quotient, 0xff, 32);
        return;
    }

    u64_to_u72_be(divisor, divisor_be);

    for (int i = 0; i < 32; i++) {
        uint8_t q = 0;

        shift_u72_and_append(remainder, numerator[i]);
        while (compare_u72(remainder, divisor_be) >= 0) {
            subtract_u72(remainder, divisor_be);
            q++;
        }
        quotient[i] = q;
    }
}

void calculate_merkle_root_hash_from_coinbase_hash_bin(const uint8_t *coinbase_hash_bin, const uint8_t merkle_branches[][32], int num_merkle_branches, uint8_t *merkle_root_bin)
{
    uint8_t both_merkles[64];

    memcpy(both_merkles, coinbase_hash_bin, 32);
    for (int i = 0; i < num_merkle_branches; i++) {
        memcpy(both_merkles + 32, merkle_branches[i], 32);
        double_sha256_bin(both_merkles, 64, both_merkles);
    }

    memcpy(merkle_root_bin, both_merkles, 32);
}

void calculate_merkle_root_hash_bin(const uint8_t *coinbase_bin, size_t coinbase_len, const uint8_t merkle_branches[][32], int num_merkle_branches, uint8_t *merkle_root_bin)
{
    uint8_t coinbase_hash[32];

    double_sha256_bin(coinbase_bin, coinbase_len, coinbase_hash);
    calculate_merkle_root_hash_from_coinbase_hash_bin(coinbase_hash, merkle_branches, num_merkle_branches, merkle_root_bin);
}

void compact_to_target_le(uint32_t compact, uint8_t target[32])
{
    uint8_t target_be[32] = {0};
    uint32_t mantissa = compact & 0x007fffff;
    uint8_t exponent = (uint8_t)(compact >> 24);

    memset(target, 0, 32);
    if (mantissa == 0) {
        return;
    }

    if (exponent <= 3) {
        mantissa >>= 8 * (3 - exponent);
        exponent = 3;
    }

    int offset = 32 - exponent;
    if (offset < 0 || (offset + 2) >= 32) {
        memset(target, 0xff, 32);
        return;
    }

    target_be[offset] = (uint8_t)((mantissa >> 16) & 0xff);
    target_be[offset + 1] = (uint8_t)((mantissa >> 8) & 0xff);
    target_be[offset + 2] = (uint8_t)(mantissa & 0xff);

    reverse_copy_32(target_be, target);
}

void difficulty_to_target_le(uint64_t difficulty, uint8_t target[32])
{
    uint8_t quotient_be[32];

    if (difficulty == 0) {
        memset(target, 0xff, 32);
        return;
    }

    divide_u256_be_by_u64(diff1_target_be, difficulty, quotient_be);
    reverse_copy_32(quotient_be, target);
}

uint8_t version_rolling_mask_slots(uint32_t version, uint32_t version_mask, uint8_t max_slots)
{
    if (version_mask == 0 || max_slots == 0) {
        return 1;
    }

    uint8_t slots = 1;
    uint32_t rolled_version = version;

    while (slots < max_slots) {
        rolled_version = increment_bitmask(rolled_version, version_mask);
        if (rolled_version == version) {
            break;
        }
        slots++;
    }

    return slots;
}

uint32_t rolled_version_from_bits(uint32_t base_version, uint32_t version_mask, uint32_t version_bits)
{
    return (base_version & ~version_mask) | (version_bits & version_mask);
}

uint32_t submit_version_bits(uint32_t rolled_version, uint32_t version_mask)
{
    return rolled_version & version_mask;
}

bool should_clean_jobs(bool should_abandon_work)
{
    // clean_jobs invalidates active ASIC work even if both software queues are empty.
    return should_abandon_work;
}

static void copy_string_bounded(char *dest, size_t dest_size, const char *src)
{
    if (dest_size == 0) {
        return;
    }

    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

static bool recent_share_entry_matches(const recent_share_entry *entry, const char *jobid, const char *extranonce2,
                                       uint32_t ntime, uint32_t nonce, uint32_t version_bits)
{
    return entry->valid &&
           entry->ntime == ntime &&
           entry->nonce == nonce &&
           entry->version_bits == version_bits &&
           strncmp(entry->jobid, jobid, sizeof(entry->jobid)) == 0 &&
           strncmp(entry->extranonce2, extranonce2, sizeof(entry->extranonce2)) == 0;
}

void recent_share_cache_clear(recent_share_cache *cache)
{
    if (cache == NULL) {
        return;
    }

    memset(cache, 0, sizeof(*cache));
}

bool recent_share_cache_add(recent_share_cache *cache, const char *jobid, const char *extranonce2,
                            uint32_t ntime, uint32_t nonce, uint32_t version_bits)
{
    if (cache == NULL || jobid == NULL || extranonce2 == NULL) {
        return true;
    }

    for (size_t i = 0; i < RECENT_SHARE_CACHE_SIZE; i++) {
        if (recent_share_entry_matches(&cache->entries[i], jobid, extranonce2, ntime, nonce, version_bits)) {
            return false;
        }
    }

    recent_share_entry *entry = &cache->entries[cache->next_index];

    entry->valid = true;
    entry->ntime = ntime;
    entry->nonce = nonce;
    entry->version_bits = version_bits;
    copy_string_bounded(entry->jobid, sizeof(entry->jobid), jobid);
    copy_string_bounded(entry->extranonce2, sizeof(entry->extranonce2), extranonce2);

    cache->next_index = (cache->next_index + 1) % RECENT_SHARE_CACHE_SIZE;
    return true;
}

void construct_bm_job_bin_into(bm_job *job, const mining_notify *params, const uint8_t *merkle_root_bin, uint32_t version_mask, uint8_t max_midstates, uint32_t difficulty)
{
    uint8_t midstate_data[64];
    uint32_t rolled_version;
    uint8_t midstate_slots;

    memset(job, 0, sizeof(*job));

    job->version = params->version;
    job->version_mask = version_mask;
    job->target = params->target;
    job->ntime = params->ntime;
    job->starting_nonce = 0;
    job->pool_diff = difficulty;

    memcpy(job->merkle_root, merkle_root_bin, 32);
    fast_word_reverse_32(job->merkle_root, job->merkle_root_be);

    memcpy(job->prev_block_hash, params->prev_block_hash, 32);
    memcpy(job->prev_block_hash_be, params->prev_block_hash_be, 32);

    difficulty_to_target_le(difficulty, job->pool_target);
    compact_to_target_le(params->target, job->network_target);

    memcpy(midstate_data, &job->version, 4);
    memcpy(midstate_data + 4, job->prev_block_hash, 32);
    memcpy(midstate_data + 36, job->merkle_root, 28);

    midstate_sha256_bin(midstate_data, 64, job->midstate);
    reverse_bytes(job->midstate, 32);

    midstate_slots = version_rolling_mask_slots(job->version, version_mask, max_midstates);
    job->num_midstates = midstate_slots;

    if (midstate_slots > 1) {
        rolled_version = increment_bitmask(job->version, version_mask);
        memcpy(midstate_data, &rolled_version, 4);
        midstate_sha256_bin(midstate_data, 64, job->midstate1);
        reverse_bytes(job->midstate1, 32);
    }

    if (midstate_slots > 2) {
        rolled_version = increment_bitmask(job->version, version_mask);
        rolled_version = increment_bitmask(rolled_version, version_mask);
        memcpy(midstate_data, &rolled_version, 4);
        midstate_sha256_bin(midstate_data, 64, job->midstate2);
        reverse_bytes(job->midstate2, 32);
    }

    if (midstate_slots > 3) {
        rolled_version = increment_bitmask(job->version, version_mask);
        rolled_version = increment_bitmask(rolled_version, version_mask);
        rolled_version = increment_bitmask(rolled_version, version_mask);
        memcpy(midstate_data, &rolled_version, 4);
        midstate_sha256_bin(midstate_data, 64, job->midstate3);
        reverse_bytes(job->midstate3, 32);
    }
}

bm_job construct_bm_job_bin(mining_notify *params, const uint8_t *merkle_root_bin, uint32_t version_mask, uint8_t max_midstates, uint32_t difficulty)
{
    bm_job new_job;

    construct_bm_job_bin_into(&new_job, params, merkle_root_bin, version_mask, max_midstates, difficulty);
    return new_job;
}

void calculate_nonce_hash(const bm_job *job, uint32_t nonce, uint32_t rolled_version, uint8_t hash_result[32])
{
    unsigned char header[80];
    unsigned char hash_buffer[32];

    memcpy(header, &rolled_version, 4);
    memcpy(header + 4, job->prev_block_hash, 32);
    memcpy(header + 36, job->merkle_root, 32);
    memcpy(header + 68, &job->ntime, 4);
    memcpy(header + 72, &job->target, 4);
    memcpy(header + 76, &nonce, 4);

    mbedtls_sha256(header, 80, hash_buffer, 0);
    mbedtls_sha256(hash_buffer, 32, hash_result, 0);
}

bool hash_meets_target(const uint8_t hash[32], const uint8_t target[32])
{
    for (int i = 31; i >= 0; i--) {
        if (hash[i] < target[i]) {
            return true;
        }
        if (hash[i] > target[i]) {
            return false;
        }
    }

    return true;
}

double hash_to_diff(const uint8_t hash[32])
{
    double hash_value = le256todouble(hash);

    if (hash_value == 0.0) {
        return truediffone;
    }

    return truediffone / hash_value;
}

double test_nonce_value(const bm_job *job, uint32_t nonce, uint32_t rolled_version)
{
    uint8_t hash_result[32];

    calculate_nonce_hash(job, nonce, rolled_version, hash_result);
    return hash_to_diff(hash_result);
}

uint32_t increment_bitmask(uint32_t value, uint32_t mask)
{
    if (mask == 0) {
        return value;
    }

    uint32_t carry = (value & mask) + (mask & -mask);
    uint32_t overflow = carry & ~mask;
    uint32_t new_value = (value & ~mask) | (carry & mask);

    if (overflow > 0) {
        uint32_t carry_mask = (overflow << 1);
        new_value = increment_bitmask(new_value, carry_mask);
    }

    return new_value;
}
