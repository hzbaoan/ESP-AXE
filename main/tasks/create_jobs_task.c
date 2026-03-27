#include <limits.h>
#include <string.h>
#include <sys/time.h>

#include "mbedtls/sha256.h"

#include "asic.h"
#include "esp_log.h"
#include "esp_system.h"
#include "global_state.h"
#include "mining.h"
#include "utils.h"
#include "work_queue.h"

static const char *TAG = "create_jobs_task";

#define QUEUE_LOW_WATER_MARK 12

static bool should_generate_more_work(GlobalState *GLOBAL_STATE)
{
    return GLOBAL_STATE->ASIC_jobs_queue.count < QUEUE_LOW_WATER_MARK;
}

static inline uint64_t rotate_left_dynamic(uint64_t value, uint32_t shift, size_t bytes)
{
    uint32_t bits = (uint32_t)(bytes * 8);

    if (bits == 0 || bits > 64) {
        return value;
    }

    shift %= bits;
    if (shift == 0) {
        return value;
    }

    uint64_t mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1);

    value &= mask;
    return ((value << shift) | (value >> (bits - shift))) & mask;
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

    uint64_t global_counter = 0;
    uint32_t global_shift_offset = 0;

    while (1)
    {
        mining_notify *mining_notification = (mining_notify *)queue_dequeue(&GLOBAL_STATE->stratum_queue);
        if (mining_notification == NULL) {
            ESP_LOGE(TAG, "Failed to dequeue mining notification");
            vTaskDelay(100 / portTICK_PERIOD_MS);
            continue;
        }

        ESP_LOGI(TAG, "New Work Dequeued %s", mining_notification->job_id);

        if (GLOBAL_STATE->abandon_work == 1) {
            GLOBAL_STATE->abandon_work = 0;
            if (GLOBAL_STATE->ASIC_TASK_MODULE.semaphore != NULL) {
                xSemaphoreGive(GLOBAL_STATE->ASIC_TASK_MODULE.semaphore);
            }
        }

        if (GLOBAL_STATE->new_set_mining_difficulty_msg) {
            difficulty = GLOBAL_STATE->stratum_difficulty;
            GLOBAL_STATE->new_set_mining_difficulty_msg = false;
        }

        if (GLOBAL_STATE->new_stratum_version_rolling_msg) {
            ASIC_set_version_mask(GLOBAL_STATE, GLOBAL_STATE->version_mask);
            GLOBAL_STATE->new_stratum_version_rolling_msg = false;
        }

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
        if (extranonce2_len > sizeof(uint64_t)) {
            ESP_LOGE(TAG, "Extranonce2 length %u exceeds 64-bit generator capacity", (unsigned int)extranonce2_len);
            STRATUM_V1_free_mining_notify(mining_notification);
            continue;
        }

        uint32_t current_bits = (uint32_t)(extranonce2_len * 8);
        uint32_t current_job_shift = global_shift_offset % current_bits;
        uint8_t extranonce2_bin[BM_EXTRANONCE2_HEX_MAX_LEN / 2] = {0};
        mbedtls_sha256_context coinbase_prefix_ctx;

        global_shift_offset = (global_shift_offset + 8) % current_bits;

        ESP_LOGI(TAG, "Job %s: Ex2 Shift = %lu bits (Window: %lu bits), Base Counter = %llu",
                 mining_notification->job_id, (unsigned long)current_job_shift,
                 (unsigned long)current_bits, global_counter);

        mbedtls_sha256_init(&coinbase_prefix_ctx);
        mbedtls_sha256_starts(&coinbase_prefix_ctx, 0);
        mbedtls_sha256_update(&coinbase_prefix_ctx, mining_notification->coinbase_1_bin, mining_notification->coinbase_1_len);
        mbedtls_sha256_update(&coinbase_prefix_ctx, GLOBAL_STATE->extranonce_bin, GLOBAL_STATE->extranonce_bin_len);

        while (GLOBAL_STATE->stratum_queue.count < 1 && GLOBAL_STATE->abandon_work == 0)
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

            uint64_t rotated_value = rotate_left_dynamic(global_counter, current_job_shift, extranonce2_len);
            uint8_t coinbase_hash[32];
            uint8_t merkle_root_bin[32];

            memset(extranonce2_bin, 0, sizeof(extranonce2_bin));
            memcpy(extranonce2_bin, &rotated_value, extranonce2_len);

            calculate_coinbase_hash(&coinbase_prefix_ctx, extranonce2_bin, extranonce2_len, mining_notification->coinbase_2_bin, mining_notification->coinbase_2_len, coinbase_hash);
            calculate_merkle_root_hash_from_coinbase_hash_bin(coinbase_hash,
                                                              (const uint8_t(*)[32])mining_notification->merkle_branches,
                                                              (int)mining_notification->n_merkle_branches,
                                                              merkle_root_bin);

            construct_bm_job_bin_into(queued_next_job, mining_notification, merkle_root_bin, GLOBAL_STATE->version_mask, difficulty);

            strncpy(queued_next_job->jobid, mining_notification->job_id, sizeof(queued_next_job->jobid) - 1);
            if (bin2hex(extranonce2_bin, extranonce2_len, queued_next_job->extranonce2, sizeof(queued_next_job->extranonce2)) == 0) {
                ESP_LOGE(TAG, "Failed to encode extranonce2");
                ASIC_job_pool_release(GLOBAL_STATE, queued_next_job);
                continue;
            }

            queue_enqueue(&GLOBAL_STATE->ASIC_jobs_queue, queued_next_job);
            global_counter++;
        }

        mbedtls_sha256_free(&coinbase_prefix_ctx);
        STRATUM_V1_free_mining_notify(mining_notification);
    }
}
