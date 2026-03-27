#ifndef MINING_H_
#define MINING_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "stratum_api.h"

#define BM_JOB_ID_MAX_LEN 128
#define BM_EXTRANONCE2_HEX_MAX_LEN 64

typedef struct
{
    uint32_t version;
    uint32_t version_mask;
    uint8_t prev_block_hash[32];
    uint8_t prev_block_hash_be[32];
    uint8_t merkle_root[32];
    uint8_t merkle_root_be[32];
    uint32_t ntime;
    uint32_t target;
    uint32_t starting_nonce;

    uint8_t num_midstates;
    uint8_t midstate[32];
    uint8_t midstate1[32];
    uint8_t midstate2[32];
    uint8_t midstate3[32];
    uint32_t pool_diff;
    uint8_t pool_target[32];
    uint8_t network_target[32];
    char jobid[BM_JOB_ID_MAX_LEN];
    char extranonce2[BM_EXTRANONCE2_HEX_MAX_LEN + 1];
} bm_job;

void calculate_merkle_root_hash_from_coinbase_hash_bin(const uint8_t *coinbase_hash_bin, const uint8_t merkle_branches[][32], int num_merkle_branches, uint8_t *merkle_root_bin);
void calculate_merkle_root_hash_bin(const uint8_t *coinbase_bin, size_t coinbase_len, const uint8_t merkle_branches[][32], int num_merkle_branches, uint8_t *merkle_root_bin);

void construct_bm_job_bin_into(bm_job *job, const mining_notify *params, const uint8_t *merkle_root_bin, uint32_t version_mask, uint32_t difficulty);
bm_job construct_bm_job_bin(mining_notify *params, const uint8_t *merkle_root_bin, uint32_t version_mask, uint32_t difficulty);

void calculate_nonce_hash(const bm_job *job, uint32_t nonce, uint32_t rolled_version, uint8_t hash_result[32]);
bool hash_meets_target(const uint8_t hash[32], const uint8_t target[32]);
double hash_to_diff(const uint8_t hash[32]);
double test_nonce_value(const bm_job *job, uint32_t nonce, uint32_t rolled_version);
void compact_to_target_le(uint32_t compact, uint8_t target[32]);
void difficulty_to_target_le(uint64_t difficulty, uint8_t target[32]);

uint32_t increment_bitmask(uint32_t value, uint32_t mask);

#endif /* MINING_H_ */
