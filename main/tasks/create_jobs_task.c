#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <sys/time.h>

#include "mbedtls/sha256.h"

#include "asic.h"
#include "esp_log.h"
#include "esp_system.h"
#include "global_state.h"
#include "mining.h"
#include "system.h"
#include "stratum_task.h"
#include "utils.h"
#include "work_queue.h"

static const char *TAG = "create_jobs_task";
static const uint16_t DEFAULT_QUEUE_LOW_WATER_MARK = QUEUE_LOW_WATER_MARK_MAX;

#ifdef CONFIG_STRICT_HEADER_COVERAGE
#define STRICT_HEADER_COVERAGE_ENABLED 1
#else
#define STRICT_HEADER_COVERAGE_ENABLED 0
#endif

static bool should_generate_more_work(GlobalState *GLOBAL_STATE)
{
    uint16_t queue_low_water_mark = GLOBAL_STATE->ASIC_TASK_MODULE.queue_low_water_mark;

    if (queue_low_water_mark == 0) {
        queue_low_water_mark = DEFAULT_QUEUE_LOW_WATER_MARK;
    }

    return queue_count(&GLOBAL_STATE->ASIC_jobs_queue) < queue_low_water_mark;
}

static void encode_extranonce2_counter(uint8_t *dest, size_t dest_size,
                                       const asic_extranonce2_counter_t *counter)
{
    size_t copy_size;

    if (dest == NULL || dest_size == 0) {
        return;
    }

    memset(dest, 0, dest_size);
    if (counter == NULL) {
        return;
    }

    copy_size = dest_size;
    if (copy_size > sizeof(counter->bytes)) {
        copy_size = sizeof(counter->bytes);
    }

    memcpy(dest, counter->bytes, copy_size);
}

static void calculate_coinbase_hash(const mbedtls_sha256_context *prefix_ctx, const uint8_t *extranonce2_bin, size_t extranonce2_len, const uint8_t *coinbase_2_bin, size_t coinbase_2_len, uint8_t coinbase_hash[32])
{
    mbedtls_sha256_context coinbase_ctx = *prefix_ctx;
    uint8_t first_hash[32];

    mbedtls_sha256_update(&coinbase_ctx, extranonce2_bin, extranonce2_len);
    mbedtls_sha256_update(&coinbase_ctx, coinbase_2_bin, coinbase_2_len);
    mbedtls_sha256_finish(&coinbase_ctx, first_hash);
    mbedtls_sha256(first_hash, 32, coinbase_hash, 0);
}

void create_jobs_task(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;
    uint32_t difficulty = GLOBAL_STATE->stratum_difficulty;
    asic_header_cursor_t cursor = {0};

    while (1)
    {
        mining_notify *mining_notification = (mining_notify *)queue_dequeue(&GLOBAL_STATE->stratum_queue);
        if (mining_notification == NULL) {
            ESP_LOGE(TAG, "Failed to dequeue mining notification");
            vTaskDelay(100 / portTICK_PERIOD_MS);
            continue;
        }

        ESP_LOGI(TAG, "New Work Dequeued %s", mining_notification->job_id);

        if (stratum_is_abandoning_work(GLOBAL_STATE)) {
            stratum_set_abandon_work(GLOBAL_STATE, 0);
            if (GLOBAL_STATE->ASIC_TASK_MODULE.semaphore != NULL) {
                xSemaphoreGive(GLOBAL_STATE->ASIC_TASK_MODULE.semaphore);
            }
            SYSTEM_update_hashrate_estimate(GLOBAL_STATE);
        }

        if (GLOBAL_STATE->new_set_mining_difficulty_msg) {
            difficulty = GLOBAL_STATE->stratum_difficulty;
            GLOBAL_STATE->new_set_mining_difficulty_msg = false;
        }

        uint32_t job_version_mask = GLOBAL_STATE->version_mask;
        bool apply_pending_version_mask = false;
        uint32_t pending_version_mask = 0;

        pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
        if (GLOBAL_STATE->new_stratum_version_rolling_msg) {
            pending_version_mask = GLOBAL_STATE->pending_version_mask;
            GLOBAL_STATE->new_stratum_version_rolling_msg = false;
            apply_pending_version_mask = true;
        }
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);

        if (apply_pending_version_mask) {
            ASIC_set_version_mask(GLOBAL_STATE, pending_version_mask);
        }

        job_version_mask = GLOBAL_STATE->version_mask;

        if (GLOBAL_STATE->extranonce_2_len <= 0) {
            ESP_LOGE(TAG, "Invalid extranonce2 length: %d", GLOBAL_STATE->extranonce_2_len);
            STRATUM_V1_free_mining_notify(mining_notification);
            continue;
        }

        size_t extranonce2_len = (size_t)GLOBAL_STATE->extranonce_2_len;
        if (extranonce2_len > (sizeof(((bm_job *)0)->extranonce2) - 1) / 2) {
            ESP_LOGE(TAG, "Unsupported extranonce2 length: %u", (unsigned int)extranonce2_len);
            STRATUM_V1_free_mining_notify(mining_notification);
            continue;
        }
        if (extranonce2_len > ASIC_EXTRANONCE2_COUNTER_MAX_BYTES) {
            ESP_LOGE(TAG,
                     "Extranonce2 length %u exceeds generator capacity %u",
                     (unsigned int)extranonce2_len,
                     (unsigned int)ASIC_EXTRANONCE2_COUNTER_MAX_BYTES);
            STRATUM_V1_free_mining_notify(mining_notification);
            continue;
        }

        asic_header_schedule_policy_t header_policy = ASIC_get_header_schedule_policy(GLOBAL_STATE);
        uint32_t version_window_count =
            ASIC_get_header_schedule_version_window_count(&header_policy, job_version_mask);
        uint8_t extranonce2_bin[ASIC_EXTRANONCE2_COUNTER_MAX_BYTES] = {0};
        char initial_extranonce2_hex[BM_EXTRANONCE2_HEX_MAX_LEN + 1] = {0};
        mbedtls_sha256_context coinbase_prefix_ctx;
        asic_header_schedule_snapshot_t initial_snapshot;
        uint32_t jobs_generated_for_notify = 0;

        assert(header_policy.job_midstate_capacity > 0);
        assert(header_policy.nonce_partition_count > 0);

        ASIC_normalize_header_cursor(&cursor, &header_policy, version_window_count);
        initial_snapshot = ASIC_snapshot_header_cursor(&cursor, &header_policy, version_window_count);
        encode_extranonce2_counter(extranonce2_bin, extranonce2_len, &initial_snapshot.extranonce2_counter);
        if (bin2hex(extranonce2_bin, extranonce2_len, initial_extranonce2_hex, sizeof(initial_extranonce2_hex)) == 0) {
            strncpy(initial_extranonce2_hex, "<encode_error>", sizeof(initial_extranonce2_hex) - 1);
        }

        ESP_LOGI(TAG,
                 "Job %s: ex2_start=%s nonce_partitions=%u version_windows=%lu strict=%d starting_nonce=%08" PRIx32 " version_window_index=%lu version_mode=%d host_nonce=%d host_version=%d host_ex2=%d",
                 mining_notification->job_id,
                 initial_extranonce2_hex,
                 (unsigned int)header_policy.nonce_partition_count,
                 (unsigned long)version_window_count,
                 STRICT_HEADER_COVERAGE_ENABLED,
                 initial_snapshot.starting_nonce,
                 (unsigned long)initial_snapshot.version_window_index,
                 header_policy.version_mode,
                 header_policy.host_expands_nonce,
                 header_policy.host_expands_version,
                 header_policy.host_expands_extranonce2);

        mbedtls_sha256_init(&coinbase_prefix_ctx);
        mbedtls_sha256_starts(&coinbase_prefix_ctx, 0);
        mbedtls_sha256_update(&coinbase_prefix_ctx, mining_notification->coinbase_1_bin, mining_notification->coinbase_1_len);
        mbedtls_sha256_update(&coinbase_prefix_ctx, GLOBAL_STATE->extranonce_bin, GLOBAL_STATE->extranonce_bin_len);

        while (queue_count(&GLOBAL_STATE->stratum_queue) < 1 && !stratum_is_abandoning_work(GLOBAL_STATE))
        {
            if (!should_generate_more_work(GLOBAL_STATE)) {
                vTaskDelay(10 / portTICK_PERIOD_MS);
                continue;
            }

            bm_job *queued_next_job = ASIC_job_pool_acquire(GLOBAL_STATE);
            if (queued_next_job == NULL) {
                ESP_LOGW(TAG, "Job pool exhausted, waiting for free slot");
                vTaskDelay(1 / portTICK_PERIOD_MS);
                continue;
            }

            asic_header_schedule_snapshot_t header_snapshot =
                ASIC_snapshot_header_cursor(&cursor, &header_policy, version_window_count);
            uint8_t coinbase_hash[32];
            uint8_t merkle_root_bin[32];

            encode_extranonce2_counter(extranonce2_bin, extranonce2_len, &header_snapshot.extranonce2_counter);

            calculate_coinbase_hash(&coinbase_prefix_ctx, extranonce2_bin, extranonce2_len, mining_notification->coinbase_2_bin, mining_notification->coinbase_2_len, coinbase_hash);
            calculate_merkle_root_hash_from_coinbase_hash_bin(coinbase_hash,
                                                              (const uint8_t(*)[32])mining_notification->merkle_branches,
                                                              (int)mining_notification->n_merkle_branches,
                                                              merkle_root_bin);

            construct_bm_job_bin_windowed_into(
                queued_next_job,
                mining_notification,
                merkle_root_bin,
                job_version_mask,
                header_policy.job_midstate_capacity,
                header_snapshot.version_window_index,
                difficulty);
            queued_next_job->starting_nonce = header_snapshot.starting_nonce;

            strncpy(queued_next_job->jobid, mining_notification->job_id, sizeof(queued_next_job->jobid) - 1);
            if (bin2hex(extranonce2_bin, extranonce2_len, queued_next_job->extranonce2, sizeof(queued_next_job->extranonce2)) == 0) {
                ESP_LOGE(TAG, "Failed to encode extranonce2");
                ASIC_job_pool_release(GLOBAL_STATE, queued_next_job);
                continue;
            }

            if (jobs_generated_for_notify < 4) {
                ESP_LOGI(TAG,
                         "Job %s[%lu]: ex2=%s nonce_partition=%u starting_nonce=%08" PRIx32 " version_window_index=%lu version_mode=%d",
                         mining_notification->job_id,
                         (unsigned long)jobs_generated_for_notify,
                         queued_next_job->extranonce2,
                         (unsigned int)header_snapshot.nonce_partition_index,
                         header_snapshot.starting_nonce,
                         (unsigned long)header_snapshot.version_window_index,
                         header_policy.version_mode);
            }

            queue_enqueue(&GLOBAL_STATE->ASIC_jobs_queue, queued_next_job);
            jobs_generated_for_notify++;
            ASIC_advance_header_cursor(&cursor,
                                       &header_policy,
                                       version_window_count,
                                       STRICT_HEADER_COVERAGE_ENABLED);
        }

        mbedtls_sha256_free(&coinbase_prefix_ctx);
        STRATUM_V1_free_mining_notify(mining_notification);
    }
}
