#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/sha256.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "asic.h"
#include "extranonce.h"
#include "esp_log.h"
#include "esp_random.h"
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

static uint16_t get_queue_low_water_mark(const ASICDispatchConfig *dispatch_config)
{
    uint16_t queue_low_water_mark = dispatch_config->queue_low_water_mark;

    if (queue_low_water_mark == 0) {
        queue_low_water_mark = DEFAULT_QUEUE_LOW_WATER_MARK;
    }
    if (queue_low_water_mark > QUEUE_LOW_WATER_MARK_MAX) {
        queue_low_water_mark = QUEUE_LOW_WATER_MARK_MAX;
    }

    return queue_low_water_mark;
}

static uint16_t get_queue_high_water_mark(const ASICDispatchConfig *dispatch_config,
                                          uint16_t queue_low_water_mark)
{
    uint16_t queue_high_water_mark = dispatch_config->queue_high_water_mark;
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
    uint32_t work_epoch;
    uint32_t asic_report_difficulty;
    uint32_t asic_config_epoch;
} stratum_job_state_snapshot_t;

static void free_stratum_job_state_snapshot(stratum_job_state_snapshot_t *snapshot)
{
    if (snapshot == NULL) {
        return;
    }

    free(snapshot->extranonce_bin);
    memset(snapshot, 0, sizeof(*snapshot));
}

typedef enum
{
    NOTIFICATION_STATE_STALE = -1,
    NOTIFICATION_STATE_UNCHANGED = 0,
    NOTIFICATION_STATE_CHANGED = 1,
} notification_state_result_t;

static notification_state_result_t refresh_dynamic_notification_state(
    GlobalState *GLOBAL_STATE,
    mining_notify *notification)
{
    bool changed = false;

    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    if (GLOBAL_STATE->abandon_work != 0 ||
            notification->work_generation != GLOBAL_STATE->work_generation) {
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
        return NOTIFICATION_STATE_STALE;
    }

    if (notification->work_epoch != GLOBAL_STATE->work_epoch) {
        notification->work_epoch = GLOBAL_STATE->work_epoch;
        notification->invalidate_active_work = true;
        changed = true;
    }

    if (notification->version_mask_tracks_connection) {
        uint32_t current_mask = GLOBAL_STATE->pending_version_mask &
                                ASIC_get_supported_version_mask(GLOBAL_STATE);

        if (notification->version_mask != current_mask) {
            notification->version_mask = current_mask;
            changed = true;
        }
    }

    if (notification->pool_target_tracks_channel &&
            GLOBAL_STATE->sv2_pool_target_valid &&
            (!notification->pool_target_set ||
             memcmp(notification->pool_target,
                    GLOBAL_STATE->sv2_pool_target,
                    sizeof(notification->pool_target)) != 0)) {
        memcpy(notification->pool_target,
               GLOBAL_STATE->sv2_pool_target,
               sizeof(notification->pool_target));
        notification->pool_target_set = true;
        notification->pool_difficulty = GLOBAL_STATE->stratum_difficulty;
        changed = true;
    }

    if (GLOBAL_STATE->asic_work_refresh_required) {
        notification->invalidate_active_work = true;
        GLOBAL_STATE->asic_work_refresh_required = false;
        changed = true;
    }
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);

    return changed ? NOTIFICATION_STATE_CHANGED : NOTIFICATION_STATE_UNCHANGED;
}

static bool notification_is_current(GlobalState *GLOBAL_STATE,
                                    const mining_notify *notification)
{
    bool current;

    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    current = GLOBAL_STATE->abandon_work == 0 &&
              notification->work_generation == GLOBAL_STATE->work_generation &&
              notification->work_epoch == GLOBAL_STATE->work_epoch;
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
    return current;
}

static bool snapshot_stratum_job_state(GlobalState *GLOBAL_STATE,
                                       uint32_t expected_work_epoch,
                                       uint32_t expected_work_generation,
                                       stratum_job_state_snapshot_t *snapshot)
{
    if (GLOBAL_STATE == NULL || snapshot == NULL) {
        return false;
    }

    memset(snapshot, 0, sizeof(*snapshot));

    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    if (GLOBAL_STATE->abandon_work != 0 ||
            GLOBAL_STATE->work_epoch != expected_work_epoch ||
            GLOBAL_STATE->work_generation != expected_work_generation) {
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
        return false;
    }
    snapshot->extranonce_2_len = GLOBAL_STATE->extranonce_2_len;
    snapshot->work_epoch = GLOBAL_STATE->work_epoch;
    snapshot->asic_report_difficulty = GLOBAL_STATE->ASIC_difficulty;
    snapshot->asic_config_epoch = GLOBAL_STATE->asic_config_epoch;
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

static TickType_t calculate_queue_refill_wait_ticks(const ASICDispatchConfig *dispatch_config,
                                                    int queue_depth,
                                                    uint16_t queue_refill_mark)
{
    uint32_t dispatch_interval_us = dispatch_config->current_interval_us;
    uint32_t jobs_to_consume;
    uint64_t wait_ms;
    TickType_t wait_ticks;

    if (queue_depth < queue_refill_mark) {
        return 0;
    }

    if (dispatch_interval_us == 0) {
        dispatch_interval_us = dispatch_config->target_interval_us;
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
    uint32_t difficulty = 0;
    uint32_t requested_version_mask;

    GLOBAL_STATE->ASIC_TASK_MODULE.job_generator_task_handle = xTaskGetCurrentTaskHandle();

    while (1)
    {
        mining_notify *mining_notification = (mining_notify *)queue_dequeue(&GLOBAL_STATE->stratum_queue);
        if (mining_notification == NULL) {
            ESP_LOGE(TAG, "Failed to dequeue mining notification");
            vTaskDelay(100 / portTICK_PERIOD_MS);
            continue;
        }

refresh_current_notification:
        ;
        ESP_LOGI(TAG, "New Work Dequeued %s", mining_notification->job_id);

        notification_state_result_t initial_state =
            refresh_dynamic_notification_state(GLOBAL_STATE, mining_notification);

        if (initial_state == NOTIFICATION_STATE_STALE ||
                !notification_is_current(GLOBAL_STATE, mining_notification)) {
            ESP_LOGW(TAG,
                     "Dropping stale work %s from epoch %lu",
                     mining_notification->job_id,
                     (unsigned long)mining_notification->work_epoch);
            STRATUM_V1_free_mining_notify(mining_notification);
            continue;
        }

        uint32_t notification_difficulty =
            normalize_pool_difficulty(mining_notification->pool_difficulty);

        if (notification_difficulty != difficulty || mining_notification->invalidate_active_work) {
            uint32_t applied_report_difficulty;

            ASIC_jobs_queue_clear(&GLOBAL_STATE->ASIC_jobs_queue, GLOBAL_STATE);
            if (!ASIC_set_job_difficulty_mask(GLOBAL_STATE, notification_difficulty)) {
                ESP_LOGE(TAG, "ASIC difficulty update failed; reconnecting before generating work");
                stratum_close_connection(GLOBAL_STATE);
                STRATUM_V1_free_mining_notify(mining_notification);
                continue;
            }
            difficulty = notification_difficulty;
            pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
            applied_report_difficulty = GLOBAL_STATE->ASIC_difficulty;
            pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
            ESP_LOGI(TAG,
                     "Applied pool difficulty %lu with ASIC report difficulty %lu",
                     (unsigned long)difficulty,
                     (unsigned long)applied_report_difficulty);
        }

        requested_version_mask = mining_notification->version_mask &
                                 ASIC_get_supported_version_mask(GLOBAL_STATE);
        uint32_t job_version_mask = requested_version_mask;
        uint32_t current_version_mask;

        pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
        current_version_mask = GLOBAL_STATE->version_mask;
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
        if (mining_notification->version_rolling_allowed_set &&
                !mining_notification->version_rolling_allowed) {
            job_version_mask = 0;
        }
        // Keep the ASIC hardware mask aligned with per-job SV2 rolling permissions.
        if (current_version_mask != job_version_mask) {
            ASIC_jobs_queue_clear(&GLOBAL_STATE->ASIC_jobs_queue, GLOBAL_STATE);
            if (!ASIC_set_version_mask(GLOBAL_STATE, job_version_mask)) {
                ESP_LOGE(TAG, "ASIC version-mask update failed; reconnecting before generating work");
                stratum_close_connection(GLOBAL_STATE);
                STRATUM_V1_free_mining_notify(mining_notification);
                continue;
            }
        }

        if (mining_notification->invalidate_active_work) {
            pthread_mutex_lock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);
            ASIC_clear_job_history(GLOBAL_STATE);
            pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);
            mining_notification->invalidate_active_work = false;
        }

        stratum_job_state_snapshot_t stratum_snapshot;
        if (!snapshot_stratum_job_state(GLOBAL_STATE,
                                        mining_notification->work_epoch,
                                        mining_notification->work_generation,
                                        &stratum_snapshot)) {
            ESP_LOGW(TAG, "Work epoch changed while snapshotting job %s",
                     mining_notification->job_id);
            STRATUM_V1_free_mining_notify(mining_notification);
            continue;
        }

        if (stratum_snapshot.extranonce_2_len < (int)EXTRANONCE2_MIN_BYTES ||
                stratum_snapshot.extranonce_2_len > (int)EXTRANONCE2_MAX_BYTES) {
            ESP_LOGE(TAG,
                     "Extranonce2 length %d outside supported range [%u,%u]",
                     stratum_snapshot.extranonce_2_len,
                     (unsigned int)EXTRANONCE2_MIN_BYTES,
                     (unsigned int)EXTRANONCE2_MAX_BYTES);
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
        bm_job job_template;
        mbedtls_sha256_context coinbase_prefix_ctx;
        uint32_t jobs_generated_for_notify = 0;
        bool dynamic_state_changed = false;
        const uint8_t initial_job_log_count = 1;

        ESP_LOGI(TAG,
                 "Job %s: chips=%u ex2_mode=random ASIC version mask=%08" PRIx32,
                 mining_notification->job_id,
                 ASIC_get_asic_count(GLOBAL_STATE),
                 job_version_mask);

        prepare_bm_job_template_into(&job_template,
                                     mining_notification,
                                     job_version_mask,
                                     difficulty);
        job_template.asic_report_difficulty = stratum_snapshot.asic_report_difficulty;
        job_template.asic_config_epoch = stratum_snapshot.asic_config_epoch;
        job_template.work_epoch = stratum_snapshot.work_epoch;

        mbedtls_sha256_init(&coinbase_prefix_ctx);
        mbedtls_sha256_starts(&coinbase_prefix_ctx, 0);
        mbedtls_sha256_update(&coinbase_prefix_ctx, mining_notification->coinbase_1_bin, mining_notification->coinbase_1_len);
        if (mining_notification->extranonce_prefix_set) {
            mbedtls_sha256_update(&coinbase_prefix_ctx,
                                  mining_notification->extranonce_prefix,
                                  mining_notification->extranonce_prefix_len);
        } else {
            mbedtls_sha256_update(&coinbase_prefix_ctx,
                                  stratum_snapshot.extranonce_bin,
                                  stratum_snapshot.extranonce_bin_len);
        }

        while (queue_count(&GLOBAL_STATE->stratum_queue) < 1 && !stratum_is_abandoning_work(GLOBAL_STATE))
        {
            notification_state_result_t notification_state =
                refresh_dynamic_notification_state(GLOBAL_STATE, mining_notification);
            if (notification_state == NOTIFICATION_STATE_CHANGED) {
                dynamic_state_changed = true;
                break;
            }
            if (notification_state == NOTIFICATION_STATE_STALE ||
                    !notification_is_current(GLOBAL_STATE, mining_notification)) {
                break;
            }

            int queue_depth = queue_count(&GLOBAL_STATE->ASIC_jobs_queue);
            ASICDispatchConfig dispatch_config;
            ASIC_get_dispatch_config(GLOBAL_STATE, &dispatch_config);
            uint16_t queue_low_water_mark = get_queue_low_water_mark(&dispatch_config);
            uint16_t queue_high_water_mark = get_queue_high_water_mark(&dispatch_config,
                                                                        queue_low_water_mark);

            if (queue_depth >= queue_high_water_mark) {
                ulTaskNotifyTake(pdTRUE,
                                 calculate_queue_refill_wait_ticks(
                                     &dispatch_config,
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

            uint8_t coinbase_hash[32];
            uint8_t merkle_root_bin[32];
            uint8_t current_extranonce2_bin[EXTRANONCE2_MAX_BYTES] = {0};
            char current_extranonce2_hex[BM_EXTRANONCE2_HEX_MAX_LEN + 1] = {0};
            size_t filled_hex_positions =
                ASIC_generate_extranonce2(current_extranonce2_bin,
                                          extranonce2_len,
                                          esp_random());

            if (filled_hex_positions == 0) {
                ESP_LOGE(TAG, "Failed to generate extranonce2");
                ASIC_job_pool_release(GLOBAL_STATE, queued_next_job);
                continue;
            }
            calculate_coinbase_hash(&coinbase_prefix_ctx,
                                    current_extranonce2_bin,
                                    extranonce2_len,
                                    mining_notification->coinbase_2_bin,
                                    mining_notification->coinbase_2_len,
                                    coinbase_hash);
            calculate_merkle_root_hash_from_coinbase_hash_bin(
                coinbase_hash,
                (const uint8_t(*)[32])mining_notification->merkle_branches,
                (int)mining_notification->n_merkle_branches,
                merkle_root_bin);

            if (bin2hex(current_extranonce2_bin,
                        extranonce2_len,
                        current_extranonce2_hex,
                        sizeof(current_extranonce2_hex)) == 0) {
                ESP_LOGE(TAG, "Failed to encode extranonce2");
                ASIC_job_pool_release(GLOBAL_STATE, queued_next_job);
                continue;
            }

            populate_bm_job_from_template_into(
                queued_next_job,
                &job_template,
                merkle_root_bin);

            strncpy(queued_next_job->jobid, mining_notification->job_id, sizeof(queued_next_job->jobid) - 1);
            strncpy(queued_next_job->extranonce2, current_extranonce2_hex, sizeof(queued_next_job->extranonce2) - 1);
            queued_next_job->extranonce2[sizeof(queued_next_job->extranonce2) - 1] = '\0';

            notification_state =
                refresh_dynamic_notification_state(GLOBAL_STATE, mining_notification);
            if (queue_count(&GLOBAL_STATE->stratum_queue) > 0 ||
                    notification_state != NOTIFICATION_STATE_UNCHANGED ||
                    !notification_is_current(GLOBAL_STATE, mining_notification)) {
                if (notification_state == NOTIFICATION_STATE_CHANGED) {
                    dynamic_state_changed = true;
                }
                ASIC_job_pool_release(GLOBAL_STATE, queued_next_job);
                break;
            }

            if (jobs_generated_for_notify < initial_job_log_count) {
                ESP_LOGI(TAG,
                         "Job %s[%lu]: ex2=%s filled=%u ASIC version mask=%08" PRIx32,
                         mining_notification->job_id,
                         (unsigned long)jobs_generated_for_notify,
                         queued_next_job->extranonce2,
                         (unsigned int)filled_hex_positions,
                         queued_next_job->version_mask);
            }

            queue_enqueue(&GLOBAL_STATE->ASIC_jobs_queue, queued_next_job);
            jobs_generated_for_notify++;
            notification_state =
                refresh_dynamic_notification_state(GLOBAL_STATE, mining_notification);
            if (notification_state != NOTIFICATION_STATE_UNCHANGED ||
                    !notification_is_current(GLOBAL_STATE, mining_notification)) {
                if (notification_state == NOTIFICATION_STATE_CHANGED) {
                    dynamic_state_changed = true;
                }
                ASIC_jobs_queue_clear(&GLOBAL_STATE->ASIC_jobs_queue, GLOBAL_STATE);
                break;
            }
        }

        mbedtls_sha256_free(&coinbase_prefix_ctx);
        free_stratum_job_state_snapshot(&stratum_snapshot);

        if (dynamic_state_changed &&
                queue_count(&GLOBAL_STATE->stratum_queue) == 0 &&
                !stratum_is_abandoning_work(GLOBAL_STATE)) {
            ESP_LOGI(TAG, "Refreshing active job %s after dynamic pool-state update",
                     mining_notification->job_id);
            goto refresh_current_notification;
        }

        STRATUM_V1_free_mining_notify(mining_notification);
    }
}
