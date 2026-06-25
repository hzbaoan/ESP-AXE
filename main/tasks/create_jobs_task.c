#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/sha256.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

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
static const uint16_t DEFAULT_QUEUE_HIGH_WATER_MARK = QUEUE_LOW_WATER_MARK_MAX + 1;
static const uint32_t MAX_QUEUE_REFILL_WAIT_MS = 10;

static uint16_t get_queue_low_water_mark(GlobalState *GLOBAL_STATE)
{
    uint16_t queue_low_water_mark = GLOBAL_STATE->ASIC_TASK_MODULE.queue_low_water_mark;

    if (queue_low_water_mark == 0) {
        queue_low_water_mark = DEFAULT_QUEUE_LOW_WATER_MARK;
    }
    if (queue_low_water_mark > QUEUE_LOW_WATER_MARK_MAX) {
        queue_low_water_mark = QUEUE_LOW_WATER_MARK_MAX;
    }

    return queue_low_water_mark;
}

static uint16_t get_queue_high_water_mark(GlobalState *GLOBAL_STATE, uint16_t queue_low_water_mark)
{
    uint16_t queue_high_water_mark = GLOBAL_STATE->ASIC_TASK_MODULE.queue_high_water_mark;
    uint16_t max_queue_fill = QUEUE_SIZE - 2;

    if (queue_high_water_mark == 0) {
        queue_high_water_mark = DEFAULT_QUEUE_HIGH_WATER_MARK;
    }
    if (queue_high_water_mark <= queue_low_water_mark) {
        queue_high_water_mark = queue_low_water_mark + 1;
    }
    if (queue_high_water_mark > max_queue_fill) {
        queue_high_water_mark = max_queue_fill;
    }

    assert(queue_high_water_mark > 0);
    return queue_high_water_mark;
}

static uint32_t normalize_pool_difficulty(uint32_t difficulty)
{
    return difficulty == 0 ? 1U : difficulty;
}

typedef struct
{
    uint8_t *extranonce_bin;
    size_t extranonce_bin_len;
    int extranonce_2_len;
    uint32_t extranonce_generation;
} stratum_job_state_snapshot_t;

static void free_stratum_job_state_snapshot(stratum_job_state_snapshot_t *snapshot)
{
    if (snapshot == NULL) {
        return;
    }

    free(snapshot->extranonce_bin);
    memset(snapshot, 0, sizeof(*snapshot));
}

static bool snapshot_stratum_job_state(GlobalState *GLOBAL_STATE, stratum_job_state_snapshot_t *snapshot)
{
    if (GLOBAL_STATE == NULL || snapshot == NULL) {
        return false;
    }

    memset(snapshot, 0, sizeof(*snapshot));

    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    snapshot->extranonce_2_len = GLOBAL_STATE->extranonce_2_len;
    snapshot->extranonce_generation = GLOBAL_STATE->extranonce_generation;
    snapshot->extranonce_bin_len = GLOBAL_STATE->extranonce_bin_len;

    if (snapshot->extranonce_bin_len > 0) {
        if (GLOBAL_STATE->extranonce_bin == NULL) {
            pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
            return false;
        }

        snapshot->extranonce_bin = malloc(snapshot->extranonce_bin_len);
        if (snapshot->extranonce_bin == NULL) {
            pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
            return false;
        }

        memcpy(snapshot->extranonce_bin, GLOBAL_STATE->extranonce_bin, snapshot->extranonce_bin_len);
    }

    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
    return true;
}

static TickType_t calculate_queue_refill_wait_ticks(GlobalState *GLOBAL_STATE,
                                                    int queue_depth,
                                                    uint16_t queue_refill_mark)
{
    uint32_t dispatch_interval_us = GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_current_us;
    uint32_t jobs_to_consume;
    uint64_t wait_ms;
    TickType_t wait_ticks;

    if (queue_depth < queue_refill_mark) {
        return 0;
    }

    if (dispatch_interval_us == 0) {
        dispatch_interval_us = GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_target_us;
    }
    if (dispatch_interval_us == 0) {
        dispatch_interval_us = 1000;
    }

    jobs_to_consume = (uint32_t)(queue_depth - queue_refill_mark + 1);
    wait_ms = (((uint64_t)dispatch_interval_us * jobs_to_consume) + 999ULL) / 1000ULL;
    if (wait_ms == 0) {
        wait_ms = 1;
    }
    if (wait_ms > MAX_QUEUE_REFILL_WAIT_MS) {
        wait_ms = MAX_QUEUE_REFILL_WAIT_MS;
    }

    wait_ticks = pdMS_TO_TICKS((uint32_t)wait_ms);
    if (wait_ticks == 0) {
        wait_ticks = 1;
    }

    return wait_ticks;
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

static bool extranonce2_counter_matches(const asic_extranonce2_counter_t *a,
                                        const asic_extranonce2_counter_t *b)
{
    if (a == NULL || b == NULL) {
        return false;
    }

    return memcmp(a->bytes, b->bytes, sizeof(a->bytes)) == 0;
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
    uint32_t difficulty = normalize_pool_difficulty(GLOBAL_STATE->stratum_difficulty);
    asic_header_cursor_t chip_cursors[ASIC_MAX_CHIP_COUNT] = {0};
    uint32_t cursor_extranonce_generation = 0;
    uint32_t cursor_version_window_count = 0;
    uint32_t cursor_job_version_mask = 0;
    uint32_t requested_version_mask = GLOBAL_STATE->version_mask;
    uint8_t cursor_chip_count = 0;
    bool chip_cursors_initialized = false;

    GLOBAL_STATE->ASIC_TASK_MODULE.job_generator_task_handle = xTaskGetCurrentTaskHandle();

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
            difficulty = normalize_pool_difficulty(GLOBAL_STATE->stratum_difficulty);
            ASIC_set_job_difficulty_mask(GLOBAL_STATE, difficulty);
            ESP_LOGI(TAG,
                     "Applied pool difficulty %lu with ASIC report difficulty %lu",
                     (unsigned long)difficulty,
                     (unsigned long)GLOBAL_STATE->ASIC_difficulty);
            GLOBAL_STATE->new_set_mining_difficulty_msg = false;
        }

        uint32_t job_version_mask = requested_version_mask;
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
            requested_version_mask = pending_version_mask & ASIC_get_supported_version_mask(GLOBAL_STATE);
        }

        job_version_mask = requested_version_mask;
        if (mining_notification->version_rolling_allowed_set &&
                !mining_notification->version_rolling_allowed) {
            job_version_mask = 0;
        }
        // Keep the ASIC hardware mask aligned with per-job SV2 rolling permissions.
        if (apply_pending_version_mask || GLOBAL_STATE->version_mask != job_version_mask) {
            ASIC_set_version_mask(GLOBAL_STATE, job_version_mask);
        }

        stratum_job_state_snapshot_t stratum_snapshot;
        if (!snapshot_stratum_job_state(GLOBAL_STATE, &stratum_snapshot)) {
            ESP_LOGE(TAG, "Failed to snapshot stratum extranonce state");
            STRATUM_V1_free_mining_notify(mining_notification);
            continue;
        }

        if (stratum_snapshot.extranonce_2_len <= 0) {
            ESP_LOGE(TAG, "Invalid extranonce2 length: %d", stratum_snapshot.extranonce_2_len);
            free_stratum_job_state_snapshot(&stratum_snapshot);
            STRATUM_V1_free_mining_notify(mining_notification);
            continue;
        }

        size_t extranonce2_len = (size_t)stratum_snapshot.extranonce_2_len;
        if (extranonce2_len > (sizeof(((bm_job *)0)->extranonce2) - 1) / 2) {
            ESP_LOGE(TAG, "Unsupported extranonce2 length: %u", (unsigned int)extranonce2_len);
            free_stratum_job_state_snapshot(&stratum_snapshot);
            STRATUM_V1_free_mining_notify(mining_notification);
            continue;
        }
        if (extranonce2_len > ASIC_EXTRANONCE2_COUNTER_MAX_BYTES) {
            ESP_LOGE(TAG,
                     "Extranonce2 length %u exceeds generator capacity %u",
                     (unsigned int)extranonce2_len,
                     (unsigned int)ASIC_EXTRANONCE2_COUNTER_MAX_BYTES);
            free_stratum_job_state_snapshot(&stratum_snapshot);
            STRATUM_V1_free_mining_notify(mining_notification);
            continue;
        }

        uint32_t current_extranonce_generation = stratum_snapshot.extranonce_generation;
        if (cursor_extranonce_generation != current_extranonce_generation) {
            memset(chip_cursors, 0, sizeof(chip_cursors));
            cursor_extranonce_generation = current_extranonce_generation;
            chip_cursors_initialized = false;
            ESP_LOGI(TAG,
                     "Reset extranonce2 cursor for extranonce generation %lu",
                     (unsigned long)current_extranonce_generation);
        }

        asic_header_schedule_policy_t header_policy = ASIC_get_header_schedule_policy(GLOBAL_STATE);
        uint32_t version_window_count =
            ASIC_get_header_schedule_version_window_count(&header_policy, job_version_mask);
        uint32_t host_version_mask =
            ASIC_get_header_schedule_host_version_mask(&header_policy, job_version_mask);
        uint32_t asic_version_mask =
            ASIC_get_header_schedule_asic_version_mask(&header_policy, job_version_mask);
        uint8_t active_chip_count = ASIC_get_asic_count(GLOBAL_STATE);
        uint8_t extranonce2_bin[ASIC_EXTRANONCE2_COUNTER_MAX_BYTES] = {0};
        char initial_extranonce2_hex[BM_EXTRANONCE2_HEX_MAX_LEN + 1] = {0};
        bm_job job_template;
        mbedtls_sha256_context coinbase_prefix_ctx;
        asic_header_schedule_snapshot_t initial_snapshot;
        uint32_t jobs_generated_for_notify = 0;
        // Merkle root caching: Safe because the same extranonce2 is reused across
        // multiple host version windows. Merkle root depends only on extranonce2,
        // not on version bits. Cache invalidates when extranonce2 changes.
        asic_extranonce2_counter_t cached_extranonce2_counter = {0};
        uint8_t cached_extranonce2_bin[ASIC_EXTRANONCE2_COUNTER_MAX_BYTES] = {0};
        char cached_extranonce2_hex[BM_EXTRANONCE2_HEX_MAX_LEN + 1] = {0};
        uint8_t cached_merkle_root_bin[32] = {0};
        bool cached_extranonce2_valid = false;
        uint8_t initial_job_log_count;

        if (active_chip_count == 0) {
            active_chip_count = 1;
        }
        if (active_chip_count > ASIC_MAX_CHIP_COUNT) {
            active_chip_count = ASIC_MAX_CHIP_COUNT;
        }
        initial_job_log_count = active_chip_count;

        if (!chip_cursors_initialized ||
                cursor_chip_count != active_chip_count ||
                cursor_version_window_count != version_window_count ||
                cursor_job_version_mask != job_version_mask) {
            ASIC_init_partitioned_header_cursors(chip_cursors,
                                                 active_chip_count,
                                                 &header_policy,
                                                 version_window_count);
            cursor_chip_count = active_chip_count;
            cursor_version_window_count = version_window_count;
            cursor_job_version_mask = job_version_mask;
            chip_cursors_initialized = true;
        }

        bool partition_exhausted = false;
        for (uint8_t chip_index = 0; chip_index < active_chip_count; chip_index++) {
            ASIC_normalize_header_cursor(&chip_cursors[chip_index], &header_policy, version_window_count);
            if (ASIC_extranonce2_counter_has_overflowed_len(&chip_cursors[chip_index].extranonce2_counter,
                                                            extranonce2_len)) {
                ESP_LOGE(TAG,
                         "Extranonce2 length %u exhausted before job %s on chip partition %u; reconnecting for a fresh extranonce1",
                         (unsigned int)extranonce2_len,
                         mining_notification->job_id,
                         chip_index);
                stratum_close_connection(GLOBAL_STATE);
                partition_exhausted = true;
                break;
            }
        }
        if (partition_exhausted) {
            free_stratum_job_state_snapshot(&stratum_snapshot);
            STRATUM_V1_free_mining_notify(mining_notification);
            continue;
        }

        initial_snapshot = ASIC_snapshot_header_cursor(&chip_cursors[0], &header_policy, version_window_count);
        encode_extranonce2_counter(extranonce2_bin, extranonce2_len, &initial_snapshot.extranonce2_counter);
        if (bin2hex(extranonce2_bin, extranonce2_len, initial_extranonce2_hex, sizeof(initial_extranonce2_hex)) == 0) {
            strncpy(initial_extranonce2_hex, "<encode_error>", sizeof(initial_extranonce2_hex) - 1);
        }

        ESP_LOGI(TAG,
                 "Job %s: chips=%u ex2_start=%s version_windows=%lu version_window_index=%lu version_mode=%d host_version=%d host_ex2=%d host_mask=%08" PRIx32 " asic_mask=%08" PRIx32,
                 mining_notification->job_id,
                 active_chip_count,
                 initial_extranonce2_hex,
                 (unsigned long)version_window_count,
                 (unsigned long)initial_snapshot.version_window_index,
                 header_policy.version_mode,
                 header_policy.host_expands_version,
                 header_policy.host_expands_extranonce2,
                 host_version_mask,
                 asic_version_mask);

        prepare_bm_job_template_with_version_masks_into(&job_template,
                                                        mining_notification,
                                                        job_version_mask,
                                                        asic_version_mask,
                                                        difficulty);

        mbedtls_sha256_init(&coinbase_prefix_ctx);
        mbedtls_sha256_starts(&coinbase_prefix_ctx, 0);
        mbedtls_sha256_update(&coinbase_prefix_ctx, mining_notification->coinbase_1_bin, mining_notification->coinbase_1_len);
        mbedtls_sha256_update(&coinbase_prefix_ctx, stratum_snapshot.extranonce_bin, stratum_snapshot.extranonce_bin_len);

        while (queue_count(&GLOBAL_STATE->stratum_queue) < 1 && !stratum_is_abandoning_work(GLOBAL_STATE))
        {
            int queue_depth = queue_count(&GLOBAL_STATE->ASIC_jobs_queue);
            uint16_t queue_low_water_mark = get_queue_low_water_mark(GLOBAL_STATE);
            uint16_t queue_high_water_mark = get_queue_high_water_mark(GLOBAL_STATE, queue_low_water_mark);

            if (queue_depth >= queue_high_water_mark) {
                ulTaskNotifyTake(pdTRUE,
                                 calculate_queue_refill_wait_ticks(
                                     GLOBAL_STATE,
                                     queue_depth,
                                     queue_high_water_mark));
                continue;
            }

            bm_job *queued_next_job = ASIC_job_pool_acquire(GLOBAL_STATE);
            if (queued_next_job == NULL) {
                ESP_LOGW(TAG, "Job pool exhausted, waiting for free slot");
                vTaskDelay(1 / portTICK_PERIOD_MS);
                continue;
            }

            uint8_t chip_index = (uint8_t)(jobs_generated_for_notify % active_chip_count);
            asic_header_cursor_t *chip_cursor = &chip_cursors[chip_index];
            asic_header_schedule_snapshot_t header_snapshot =
                ASIC_snapshot_header_cursor(chip_cursor, &header_policy, version_window_count);
            uint32_t host_version_bits =
                ASIC_get_header_schedule_host_version_bits(
                    &header_policy,
                    job_version_mask,
                    header_snapshot.version_window_index);

            assert((host_version_bits & ~host_version_mask) == 0);
            assert((asic_version_mask & host_version_mask) == 0);

            if (!cached_extranonce2_valid ||
                    !extranonce2_counter_matches(&cached_extranonce2_counter, &header_snapshot.extranonce2_counter)) {
                uint8_t coinbase_hash[32];

                encode_extranonce2_counter(cached_extranonce2_bin,
                                           extranonce2_len,
                                           &header_snapshot.extranonce2_counter);
                calculate_coinbase_hash(&coinbase_prefix_ctx,
                                        cached_extranonce2_bin,
                                        extranonce2_len,
                                        mining_notification->coinbase_2_bin,
                                        mining_notification->coinbase_2_len,
                                        coinbase_hash);
                calculate_merkle_root_hash_from_coinbase_hash_bin(
                    coinbase_hash,
                    (const uint8_t(*)[32])mining_notification->merkle_branches,
                    (int)mining_notification->n_merkle_branches,
                    cached_merkle_root_bin);

                if (bin2hex(cached_extranonce2_bin,
                            extranonce2_len,
                            cached_extranonce2_hex,
                            sizeof(cached_extranonce2_hex)) == 0) {
                    ESP_LOGE(TAG, "Failed to encode extranonce2");
                    ASIC_job_pool_release(GLOBAL_STATE, queued_next_job);
                    continue;
                }

                cached_extranonce2_counter = header_snapshot.extranonce2_counter;
                cached_extranonce2_valid = true;
            }

            populate_bm_job_from_template_into(
                queued_next_job,
                &job_template,
                cached_merkle_root_bin,
                host_version_bits,
                chip_index);

            strncpy(queued_next_job->jobid, mining_notification->job_id, sizeof(queued_next_job->jobid) - 1);
            strncpy(queued_next_job->extranonce2, cached_extranonce2_hex, sizeof(queued_next_job->extranonce2) - 1);
            queued_next_job->extranonce2[sizeof(queued_next_job->extranonce2) - 1] = '\0';

            if (queue_count(&GLOBAL_STATE->stratum_queue) > 0 || stratum_is_abandoning_work(GLOBAL_STATE)) {
                ASIC_job_pool_release(GLOBAL_STATE, queued_next_job);
                break;
            }

            if (jobs_generated_for_notify < initial_job_log_count) {
                ESP_LOGI(TAG,
                         "Job %s[%lu]: chip=%u ex2=%s version_window_index=%lu host_bits=%08" PRIx32 " asic_mask=%08" PRIx32 " version_mode=%d",
                         mining_notification->job_id,
                         (unsigned long)jobs_generated_for_notify,
                         chip_index,
                         queued_next_job->extranonce2,
                         (unsigned long)header_snapshot.version_window_index,
                         host_version_bits,
                         queued_next_job->version_mask,
                         header_policy.version_mode);
            }

            queue_enqueue(&GLOBAL_STATE->ASIC_jobs_queue, queued_next_job);
            if (stratum_is_abandoning_work(GLOBAL_STATE)) {
                ASIC_jobs_queue_clear(&GLOBAL_STATE->ASIC_jobs_queue, GLOBAL_STATE);
                break;
            }
            jobs_generated_for_notify++;
            ASIC_advance_header_cursor_by(chip_cursor,
                                          &header_policy,
                                          version_window_count,
                                          active_chip_count);
            if (ASIC_extranonce2_counter_has_overflowed_len(&chip_cursor->extranonce2_counter, extranonce2_len)) {
                ESP_LOGE(TAG,
                         "Extranonce2 length %u exhausted after %lu generated jobs for %s; reconnecting for a fresh extranonce1",
                         (unsigned int)extranonce2_len,
                         (unsigned long)jobs_generated_for_notify,
                         mining_notification->job_id);
                stratum_close_connection(GLOBAL_STATE);
                break;
            }
        }

        mbedtls_sha256_free(&coinbase_prefix_ctx);
        free_stratum_job_state_snapshot(&stratum_snapshot);
        STRATUM_V1_free_mining_notify(mining_notification);
    }
}
