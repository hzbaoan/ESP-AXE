#include <inttypes.h>
#include <string.h>

#include <lwip/tcpip.h>

#include "asic.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "stratum_task.h"
#include "system.h"

#define ASIC_RAW_RESULT_CACHE_SIZE 32
#define ASIC_VALID_RESULT_CACHE_SIZE 32

typedef struct
{
    uint8_t job_id;
    uint32_t nonce;
    uint32_t version_bits;
    uint32_t history_revision;
    bool valid;
} asic_raw_result_cache_entry;

typedef struct
{
    asic_raw_result_cache_entry entries[ASIC_RAW_RESULT_CACHE_SIZE];
    size_t next_index;
} asic_raw_result_cache;

typedef struct
{
    uint8_t hash[32];
    uint32_t work_epoch;
    bool valid;
} asic_valid_result_cache_entry;

typedef struct
{
    asic_valid_result_cache_entry entries[ASIC_VALID_RESULT_CACHE_SIZE];
    size_t next_index;
} asic_valid_result_cache;

static const char *TAG = "asic_result";
static recent_share_cache recent_shares;
static asic_raw_result_cache recent_raw_results;
static asic_valid_result_cache recent_valid_results;
static pthread_mutex_t recent_shares_lock = PTHREAD_MUTEX_INITIALIZER;

static bool raw_result_cache_add(asic_raw_result_cache *cache, uint8_t job_id,
                                 uint32_t nonce, uint32_t version_bits,
                                 uint32_t history_revision)
{
    for (size_t i = 0; i < ASIC_RAW_RESULT_CACHE_SIZE; i++) {
        const asic_raw_result_cache_entry *entry = &cache->entries[i];

        if (entry->valid && entry->job_id == job_id && entry->nonce == nonce &&
                entry->version_bits == version_bits &&
                entry->history_revision == history_revision) {
            return false;
        }
    }

    cache->entries[cache->next_index] = (asic_raw_result_cache_entry) {
        .job_id = job_id,
        .nonce = nonce,
        .version_bits = version_bits,
        .history_revision = history_revision,
        .valid = true,
    };
    cache->next_index = (cache->next_index + 1U) % ASIC_RAW_RESULT_CACHE_SIZE;
    return true;
}

static bool valid_result_cache_add(asic_valid_result_cache *cache, uint32_t work_epoch,
                                   const uint8_t hash[32])
{
    for (size_t i = 0; i < ASIC_VALID_RESULT_CACHE_SIZE; i++) {
        const asic_valid_result_cache_entry *entry = &cache->entries[i];

        if (entry->valid && entry->work_epoch == work_epoch &&
                memcmp(entry->hash, hash, sizeof(entry->hash)) == 0) {
            return false;
        }
    }

    asic_valid_result_cache_entry *entry = &cache->entries[cache->next_index];
    memcpy(entry->hash, hash, sizeof(entry->hash));
    entry->work_epoch = work_epoch;
    entry->valid = true;
    cache->next_index = (cache->next_index + 1U) % ASIC_VALID_RESULT_CACHE_SIZE;
    return true;
}

static bool work_epoch_is_current(GlobalState *GLOBAL_STATE, uint32_t work_epoch)
{
    bool current;

    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    current = GLOBAL_STATE->abandon_work == 0 &&
              GLOBAL_STATE->work_epoch == work_epoch;
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
    return current;
}

static void queue_pool_share(GlobalState *GLOBAL_STATE, const bm_job *job,
                             uint32_t nonce, uint32_t rolled_version)
{
    uint32_t version_bits = submit_version_bits(rolled_version, job->version_mask);
    uint32_t submit_version = GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback ?
        (GLOBAL_STATE->SYSTEM_MODULE.fallback_pool_protocol == STRATUM_PROTOCOL_V2 ?
         rolled_version : version_bits) :
        (GLOBAL_STATE->SYSTEM_MODULE.pool_protocol == STRATUM_PROTOCOL_V2 ?
         rolled_version : version_bits);
    bool should_submit;
    stratum_share_submission share = {0};
    char *user = GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback ?
        GLOBAL_STATE->SYSTEM_MODULE.fallback_pool_user : GLOBAL_STATE->SYSTEM_MODULE.pool_user;

    pthread_mutex_lock(&recent_shares_lock);
    should_submit = recent_share_cache_add(&recent_shares,
                                           job->jobid,
                                           job->extranonce2,
                                           job->ntime,
                                           nonce,
                                           submit_version,
                                           job->work_epoch);
    pthread_mutex_unlock(&recent_shares_lock);

    if (!should_submit) {
        ESP_LOGW(TAG, "Dropping duplicate share: id=%s nonce=%08" PRIX32 " ver=%08" PRIX32,
                 job->jobid, nonce, submit_version);
        return;
    }

    strncpy(share.username, user != NULL ? user : "", sizeof(share.username) - 1);
    strncpy(share.jobid, job->jobid, sizeof(share.jobid) - 1);
    strncpy(share.extranonce_2, job->extranonce2, sizeof(share.extranonce_2) - 1);
    share.ntime = job->ntime;
    share.nonce = nonce;
    share.version = submit_version;
    share.work_epoch = job->work_epoch;

    if (!stratum_queue_share(GLOBAL_STATE, &share)) {
        ESP_LOGW(TAG,
                 "Share queue full or stale, dropping share: id=%s nonce=%08" PRIX32 " ver=%08" PRIX32,
                 job->jobid,
                 nonce,
                 submit_version);
    }
}

void ASIC_result_reset_recent_shares(void)
{
    pthread_mutex_lock(&recent_shares_lock);
    recent_share_cache_clear(&recent_shares);
    memset(&recent_raw_results, 0, sizeof(recent_raw_results));
    memset(&recent_valid_results, 0, sizeof(recent_valid_results));
    pthread_mutex_unlock(&recent_shares_lock);
}

void ASIC_result_task(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;
    const size_t candidate_buffer_size = ASIC_JOB_CANDIDATE_COUNT * sizeof(bm_job);
    bm_job *candidates = heap_caps_malloc(
        candidate_buffer_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);

    if (candidates == NULL) {
        ESP_LOGE(TAG, "Failed to allocate ASIC result candidate buffer in PSRAM (%u bytes)",
                 (unsigned int)candidate_buffer_size);
        vTaskDelete(NULL);
        return;
    }

    while (1)
    {
        task_result *asic_result = ASIC_process_work(GLOBAL_STATE);
        if (asic_result == NULL) {
            continue;
        }

        uint32_t history_revision = 0;
        size_t candidate_count = ASIC_copy_job_candidates(
            GLOBAL_STATE,
            asic_result->job_id,
            candidates,
            ASIC_JOB_CANDIDATE_COUNT,
            &history_revision);
        bool matched_result = false;
        bool matched_retired_job = false;
        bool duplicate_result = false;
        bool found_block = false;
        double best_diff = -1.0;
        uint32_t accounting_difficulty = UINT32_MAX;
        uint32_t matched_work_epoch = 0;

        if (candidate_count == 0) {
            GLOBAL_STATE->ASIC_TASK_MODULE.job_lookup_miss_count++;
            continue;
        }

        pthread_mutex_lock(&recent_shares_lock);
        bool unique_raw_result = raw_result_cache_add(
            &recent_raw_results,
            asic_result->job_id,
            asic_result->nonce,
            asic_result->version_bits,
            history_revision);
        pthread_mutex_unlock(&recent_shares_lock);
        if (!unique_raw_result) {
            GLOBAL_STATE->ASIC_TASK_MODULE.duplicate_result_count++;
            continue;
        }

        for (size_t candidate_index = 0; candidate_index < candidate_count; candidate_index++) {
            bm_job *candidate = &candidates[candidate_index];
            uint8_t hash_result[32];
            uint8_t report_target[32];
            uint32_t report_difficulty = candidate->asic_report_difficulty;
            uint32_t rolled_version;
            bool is_share;
            bool candidate_found_block;
            bool needs_diff;
            bool unique_valid_result;
            double nonce_diff = -1.0;

            if (!work_epoch_is_current(GLOBAL_STATE, candidate->work_epoch)) {
                continue;
            }
            if (report_difficulty == 0) {
                report_difficulty = ASIC_get_report_difficulty(candidate->pool_diff);
            }

            rolled_version = rolled_version_from_bits(
                candidate->version,
                candidate->version_mask,
                asic_result->version_bits);
            calculate_nonce_hash(candidate, asic_result->nonce, rolled_version, hash_result);
            difficulty_to_target_le(report_difficulty, report_target);
            if (!hash_meets_target(hash_result, report_target)) {
                continue;
            }

            pthread_mutex_lock(&recent_shares_lock);
            unique_valid_result = valid_result_cache_add(
                &recent_valid_results, candidate->work_epoch, hash_result);
            pthread_mutex_unlock(&recent_shares_lock);
            if (!unique_valid_result) {
                duplicate_result = true;
                continue;
            }

            matched_result = true;
            matched_retired_job = matched_retired_job || candidate_index > 0;
            matched_work_epoch = candidate->work_epoch;
            if (report_difficulty < accounting_difficulty) {
                accounting_difficulty = report_difficulty;
            }

            is_share = hash_meets_target(hash_result, candidate->pool_target);
            candidate_found_block = hash_meets_target(hash_result, candidate->network_target);
            found_block = found_block || candidate_found_block;
            needs_diff = is_share || SYSTEM_is_potential_best_nonce(GLOBAL_STATE, hash_result);
            if (needs_diff) {
                nonce_diff = hash_to_diff(hash_result);
                if (nonce_diff > best_diff) {
                    best_diff = nonce_diff;
                }
                ESP_LOGI(TAG,
                         "ID: %s, ver: %08" PRIX32 " Nonce %08" PRIX32 " diff %.1f of %.1f%s.",
                         candidate->jobid,
                         rolled_version,
                         asic_result->nonce,
                         nonce_diff,
                         (double)candidate->pool_diff,
                         candidate_index > 0 ? " (retired job)" : "");
            }

            if (is_share) {
                queue_pool_share(GLOBAL_STATE, candidate, asic_result->nonce, rolled_version);
            }
        }

        if (!matched_result) {
            if (duplicate_result) {
                GLOBAL_STATE->ASIC_TASK_MODULE.duplicate_result_count++;
                continue;
            }
            uint64_t invalid_count = ++GLOBAL_STATE->ASIC_TASK_MODULE.invalid_result_count;
            if ((invalid_count & 0xffU) == 1U) {
                ESP_LOGW(TAG,
                         "ASIC result did not match any retained job at report difficulty (invalid=%llu, misses=%llu)",
                         (unsigned long long)invalid_count,
                         (unsigned long long)GLOBAL_STATE->ASIC_TASK_MODULE.job_lookup_miss_count);
            }
            continue;
        }

        GLOBAL_STATE->ASIC_TASK_MODULE.valid_result_count++;
        if (matched_retired_job) {
            GLOBAL_STATE->ASIC_TASK_MODULE.retired_job_match_count++;
        }
        SYSTEM_notify_found_nonce(GLOBAL_STATE,
                                  found_block,
                                  best_diff,
                                  accounting_difficulty,
                                  matched_work_epoch);
    }
}
