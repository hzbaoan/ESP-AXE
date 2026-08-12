#include <math.h>
#include <stdint.h>
#include <string.h>

#include <esp_log.h>

#include "freertos/FreeRTOS.h"

#include "bm1366.h"
#include "bm1368.h"
#include "bm1370.h"

#include "asic.h"
#include "nvs_config.h"
#include "system.h"
#include "utils.h"

static const uint32_t ASIC_QUEUE_TARGET_BUFFER_US = 200000;
static const uint16_t ASIC_QUEUE_MIN_LOW_WATER_MARK = 1;
static const uint16_t ASIC_QUEUE_MAX_LOW_WATER_MARK = QUEUE_LOW_WATER_MARK_MAX;
static const uint32_t ASIC_DISPATCH_MIN_US = 1;
static const uint32_t ASIC_JOB_UART_MIN_US = 880;
static const double ASIC_DISPATCH_SPACE_FRACTION = 1.00;
static const double ASIC_HCN_SINGLE_BATCH_HEADROOM = ASIC_HCN_MAX_SEARCH_SCALE;
static const uint32_t BM1366_DEFAULT_JOB_TIMEOUT_MS = 2000;
static const uint32_t BM1368_DEFAULT_JOB_TIMEOUT_MS = 500;
static const uint32_t BM1370_DEFAULT_JOB_TIMEOUT_MS = 500;
static const size_t ASIC_EXTRANONCE2_MIN_RANDOM_HEX_POSITIONS = 2U;

static const char *TAG = "asic";

static bool ASIC_set_nonce_space_unlocked(GlobalState *GLOBAL_STATE, double nonce_scale);
static portMUX_TYPE ASIC_dispatch_config_lock = portMUX_INITIALIZER_UNLOCKED;

static float ASIC_get_actual_frequency_mhz(const GlobalState *GLOBAL_STATE)
{
    if (GLOBAL_STATE == NULL) {
        return 0.0f;
    }
    if (GLOBAL_STATE->POWER_MANAGEMENT_MODULE.actual_frequency > 0.0f) {
        return GLOBAL_STATE->POWER_MANAGEMENT_MODULE.actual_frequency;
    }
    return GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value;
}

static uint16_t ASIC_get_core_count_for_model(DeviceModel device_model)
{
    switch (device_model) {
        case DEVICE_ULTRA:
        case DEVICE_HEX:
            return (uint16_t)BM1366_CORE_COUNT;
        case DEVICE_SUPRA:
        case DEVICE_SUPRAHEX:
            return (uint16_t)BM1368_CORE_COUNT;
        case DEVICE_GAMMA:
        case DEVICE_GAMMATURBO:
            return (uint16_t)BM1370_CORE_COUNT;
        default:
            return 0;
    }
}

static uint32_t ASIC_get_default_job_timeout_ms(DeviceModel device_model)
{
    switch (device_model) {
        case DEVICE_ULTRA:
        case DEVICE_HEX:
            return BM1366_DEFAULT_JOB_TIMEOUT_MS;
        case DEVICE_SUPRA:
        case DEVICE_SUPRAHEX:
            return BM1368_DEFAULT_JOB_TIMEOUT_MS;
        case DEVICE_GAMMA:
        case DEVICE_GAMMATURBO:
            return BM1370_DEFAULT_JOB_TIMEOUT_MS;
        default:
            return BM1368_DEFAULT_JOB_TIMEOUT_MS;
    }
}

static double ASIC_get_model_job_timeout_ms(GlobalState *GLOBAL_STATE)
{
    return (double)ASIC_get_default_job_timeout_ms(GLOBAL_STATE->device_model);
}

static uint8_t ASIC_ceil_log2_u32(uint32_t value)
{
    uint8_t bits = 0;
    uint32_t capacity = 1U;

    while (capacity < value && bits < 31U) {
        capacity <<= 1U;
        bits++;
    }

    return bits;
}

static uint32_t ASIC_get_parallel_version_capacity(GlobalState *GLOBAL_STATE)
{
    uint32_t rounded_cores;
    uint32_t rounded_small_cores;

    if (GLOBAL_STATE == NULL) {
        return 0;
    }

    rounded_cores = _next_power_of_two_u32(
        ASIC_get_core_count_for_model(GLOBAL_STATE->device_model));
    rounded_small_cores = _next_power_of_two_u32(
        ASIC_get_small_core_count(GLOBAL_STATE));
    if (rounded_cores == 0 || rounded_small_cores < rounded_cores) {
        return 0;
    }

    return rounded_small_cores / rounded_cores;
}

uint8_t ASIC_get_minimum_pool_version_bits(GlobalState *GLOBAL_STATE)
{
    double one_batch_ms;
    uint32_t parallel_version_capacity;
    uint32_t required_batches;
    uint32_t required_versions;
    uint8_t required_bits;

    if (GLOBAL_STATE == NULL) {
        return 1;
    }

    parallel_version_capacity = ASIC_get_parallel_version_capacity(GLOBAL_STATE);
    one_batch_ms = calculate_bm_full_space_ms(
        (double)NVS_CONFIG_ASIC_FREQUENCY_MAX_MHZ,
        ASIC_get_asic_count(GLOBAL_STATE),
        ASIC_get_small_core_count(GLOBAL_STATE),
        ASIC_get_core_count_for_model(GLOBAL_STATE->device_model),
        1U);
    if (parallel_version_capacity == 0 || one_batch_ms <= 0.0) {
        return 1;
    }

    // Fill every hardware version slot first. If a complete nonce batch is
    // ever shorter than one UART Job frame, request additional full batches
    // so unique work lasts until the next frame can arrive.
    required_batches = (uint32_t)ceil(
        (double)ASIC_JOB_UART_MIN_US / (one_batch_ms * 1000.0));
    if (required_batches == 0) {
        required_batches = 1;
    }
    required_versions = parallel_version_capacity * required_batches;
    required_bits = ASIC_ceil_log2_u32(required_versions);

    return required_bits == 0 ? 1 : required_bits;
}

static uint8_t ASIC_count_mask_bits(uint32_t mask)
{
    return (uint8_t)__builtin_popcount(mask);
}

double ASIC_get_hcn_search_multiplier(GlobalState *GLOBAL_STATE, uint32_t version_mask)
{
    uint32_t parallel_version_capacity;
    uint8_t version_bits;
    uint32_t version_count;

    if (GLOBAL_STATE == NULL) {
        return 1.0;
    }

    parallel_version_capacity = ASIC_get_parallel_version_capacity(GLOBAL_STATE);
    if (parallel_version_capacity == 0) {
        return 1.0;
    }

    version_bits = ASIC_count_mask_bits(
        version_mask & ASIC_get_supported_version_mask(GLOBAL_STATE));
    version_count = UINT32_C(1) << version_bits;

    // When all negotiated versions fit in one hardware batch, the next Job
    // replaces the work after one nominal 32-bit nonce traversal. Keep the HCN
    // stop point 20% beyond that boundary so PLL quantization, BM1370's counter
    // correction and dispatch jitter cannot leave the ASIC idle. The scheduler
    // still uses the real ASIC count, so this headroom is never budgeted as
    // unique search space. Multi-batch rolling keeps exact HCN partitions to
    // avoid repeating the tail of every version batch.
    if (version_count <= parallel_version_capacity) {
        return ASIC_HCN_SINGLE_BATCH_HEADROOM;
    }

    return 1.0;
}

uint32_t ASIC_get_report_difficulty(uint32_t pool_difficulty)
{
    return _largest_power_of_two_u32(pool_difficulty);
}

static uint32_t ASIC_extranonce2_random_next(uint32_t *state)
{
    uint32_t value = *state;

    value ^= value << 13U;
    value ^= value >> 17U;
    value ^= value << 5U;
    *state = value;
    return value;
}

size_t ASIC_generate_extranonce2(uint8_t *dest, size_t extranonce2_len, uint32_t random_seed)
{
    uint8_t positions[EXTRANONCE2_HEX_MAX_LEN];
    size_t hex_len;
    size_t fill_count;
    uint32_t random_state;

    if (dest == NULL ||
            extranonce2_len < EXTRANONCE2_MIN_BYTES ||
            extranonce2_len > EXTRANONCE2_MAX_BYTES) {
        return 0;
    }

    memset(dest, 0, extranonce2_len);
    hex_len = extranonce2_len * 2U;
    random_state = random_seed != 0U ? random_seed : 0x9e3779b9U;
    fill_count = ASIC_EXTRANONCE2_MIN_RANDOM_HEX_POSITIONS;
    if (hex_len > fill_count) {
        fill_count += ASIC_extranonce2_random_next(&random_state) %
                      (hex_len - fill_count + 1U);
    }

    for (size_t i = 0; i < hex_len; i++) {
        positions[i] = (uint8_t)i;
    }

    for (size_t i = 0; i < fill_count; i++) {
        size_t remaining = hex_len - i;
        size_t selected = i;
        uint8_t position;
        uint8_t nibble;
        size_t byte_index;

        if (remaining > 1U) {
            selected += ASIC_extranonce2_random_next(&random_state) % remaining;
        }
        position = positions[selected];
        positions[selected] = positions[i];
        positions[i] = position;

        nibble = (uint8_t)(ASIC_extranonce2_random_next(&random_state) & 0x0fU);
        byte_index = position / 2U;
        if ((position & 1U) == 0U) {
            dest[byte_index] = (uint8_t)((dest[byte_index] & 0x0fU) | (nibble << 4U));
        } else {
            dest[byte_index] = (uint8_t)((dest[byte_index] & 0xf0U) | nibble);
        }
    }

    return fill_count;
}

// .init_fn = BM1366_init,
uint8_t ASIC_init(GlobalState * GLOBAL_STATE) {
    uint8_t chip_count = 0;
    float actual_frequency = 56.25f;
    float requested_frequency = GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value;

    switch (GLOBAL_STATE->device_model) {
        case DEVICE_ULTRA:
            chip_count = BM1366_init(requested_frequency, BITAXE_ULTRA_ASIC_COUNT, &actual_frequency);
            break;
        case DEVICE_SUPRA:
            chip_count = BM1368_init(requested_frequency, BITAXE_SUPRA_ASIC_COUNT, &actual_frequency);
            break;
        case DEVICE_GAMMA:
            chip_count = BM1370_init(requested_frequency, BITAXE_GAMMA_ASIC_COUNT, &actual_frequency);
            break;
        case DEVICE_GAMMATURBO:
            chip_count = BM1370_init(requested_frequency, BITAXE_GAMMATURBO_ASIC_COUNT, &actual_frequency);
            break;
        case DEVICE_HEX:
            chip_count = BM1366_init(requested_frequency, BITAXE_HEX_ASIC_COUNT, &actual_frequency);
            break;
        case DEVICE_SUPRAHEX:
            chip_count = BM1368_init(requested_frequency, BITAXE_SUPRAHEX_ASIC_COUNT, &actual_frequency);
            break;
        default:
            break;
    }

    GLOBAL_STATE->detected_asic_count = chip_count;

    if (chip_count != 0) {
        uint32_t default_version_mask = ASIC_get_supported_version_mask(GLOBAL_STATE);

        GLOBAL_STATE->POWER_MANAGEMENT_MODULE.actual_frequency = actual_frequency;
        GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value = actual_frequency;
        pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
        GLOBAL_STATE->pending_version_mask = default_version_mask;
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
        if (!ASIC_set_version_mask(GLOBAL_STATE, default_version_mask)) {
            ESP_LOGE(TAG, "Failed to initialize ASIC version mask");
            GLOBAL_STATE->detected_asic_count = 0;
            return 0;
        }
    }

    return chip_count;
}

uint8_t ASIC_get_expected_asic_count(GlobalState *GLOBAL_STATE) {
    uint8_t configured_count = 0;

    switch (GLOBAL_STATE->device_model) {
        case DEVICE_ULTRA:
            configured_count = BITAXE_ULTRA_ASIC_COUNT;
            break;
        case DEVICE_SUPRA:
            configured_count = BITAXE_SUPRA_ASIC_COUNT;
            break;
        case DEVICE_GAMMA:
            configured_count = BITAXE_GAMMA_ASIC_COUNT;
            break;
        case DEVICE_GAMMATURBO:
            configured_count = BITAXE_GAMMATURBO_ASIC_COUNT;
            break;
        case DEVICE_HEX:
            configured_count = BITAXE_HEX_ASIC_COUNT;
            break;
        case DEVICE_SUPRAHEX:
            configured_count = BITAXE_SUPRAHEX_ASIC_COUNT;
            break;
        default:
            break;
    }

    return configured_count;
}

uint8_t ASIC_get_asic_count(GlobalState * GLOBAL_STATE) {
    uint8_t configured_count = ASIC_get_expected_asic_count(GLOBAL_STATE);

    if (GLOBAL_STATE->detected_asic_count > 0) {
        return GLOBAL_STATE->detected_asic_count;
    }

    return configured_count;
}

void ASIC_get_dispatch_config(const GlobalState *GLOBAL_STATE, ASICDispatchConfig *config)
{
    if (config == NULL) {
        return;
    }

    memset(config, 0, sizeof(*config));
    if (GLOBAL_STATE == NULL) {
        return;
    }

    portENTER_CRITICAL(&ASIC_dispatch_config_lock);
    config->target_interval_us = GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_target_us;
    config->current_interval_us = GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_current_us;
    config->queue_low_water_mark = GLOBAL_STATE->ASIC_TASK_MODULE.queue_low_water_mark;
    config->queue_high_water_mark = GLOBAL_STATE->ASIC_TASK_MODULE.queue_high_water_mark;
    portEXIT_CRITICAL(&ASIC_dispatch_config_lock);
}

static void ASIC_calculate_queue_watermarks(uint32_t current_interval_us,
                                            uint16_t *queue_low_water_mark_out,
                                            uint16_t *queue_high_water_mark_out)
{
    uint32_t interval_for_queue_us;
    uint32_t queue_low_water_mark;
    uint32_t queue_high_water_mark;

    if (current_interval_us == 0) {
        current_interval_us = ASIC_DISPATCH_MIN_US;
    }

    interval_for_queue_us = current_interval_us;
    queue_low_water_mark = (uint32_t)((ASIC_QUEUE_TARGET_BUFFER_US + interval_for_queue_us - 1) / interval_for_queue_us);
    if (queue_low_water_mark < ASIC_QUEUE_MIN_LOW_WATER_MARK) {
        queue_low_water_mark = ASIC_QUEUE_MIN_LOW_WATER_MARK;
    }
    if (queue_low_water_mark > ASIC_QUEUE_MAX_LOW_WATER_MARK) {
        queue_low_water_mark = ASIC_QUEUE_MAX_LOW_WATER_MARK;
    }

    queue_high_water_mark = queue_low_water_mark + 1;
    if (queue_high_water_mark > (QUEUE_SIZE - 2)) {
        queue_high_water_mark = QUEUE_SIZE - 2;
    }

    *queue_low_water_mark_out = (uint16_t)queue_low_water_mark;
    *queue_high_water_mark_out = (uint16_t)queue_high_water_mark;
}

static void ASIC_publish_dispatch_config(GlobalState *GLOBAL_STATE,
                                         uint32_t target_interval_us,
                                         uint16_t queue_low_water_mark,
                                         uint16_t queue_high_water_mark)
{
    portENTER_CRITICAL(&ASIC_dispatch_config_lock);
    GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_target_us = target_interval_us;
    GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_current_us = target_interval_us;
    GLOBAL_STATE->ASIC_TASK_MODULE.queue_low_water_mark = queue_low_water_mark;
    GLOBAL_STATE->ASIC_TASK_MODULE.queue_high_water_mark = queue_high_water_mark;
    portEXIT_CRITICAL(&ASIC_dispatch_config_lock);
}

uint16_t ASIC_get_small_core_count(GlobalState * GLOBAL_STATE) {
    switch (GLOBAL_STATE->device_model) {
        case DEVICE_ULTRA:
        case DEVICE_HEX:
            return BM1366_SMALL_CORE_COUNT;
        case DEVICE_SUPRA:
        case DEVICE_SUPRAHEX:
            return BM1368_SMALL_CORE_COUNT;
        case DEVICE_GAMMA:
            return BM1370_SMALL_CORE_COUNT;
        case DEVICE_GAMMATURBO:
            return BM1370_SMALL_CORE_COUNT;
        default:
    }
    return 0;
}

uint32_t ASIC_get_supported_version_mask(GlobalState * GLOBAL_STATE)
{
    (void)GLOBAL_STATE;
    return STRATUM_DEFAULT_VERSION_MASK;
}

size_t ASIC_copy_job_candidates(GlobalState *GLOBAL_STATE, uint8_t job_id,
                                bm_job *job_snapshots, size_t snapshot_capacity,
                                uint32_t *history_revision)
{
    size_t copied = 0;

    if (GLOBAL_STATE == NULL || job_snapshots == NULL || snapshot_capacity == 0 ||
            history_revision == NULL || job_id >= ASIC_ACTIVE_JOB_SLOTS) {
        return 0;
    }

    pthread_mutex_lock(&GLOBAL_STATE->job_history_lock);
    *history_revision = GLOBAL_STATE->ASIC_TASK_MODULE.job_history_revision[job_id];
    if (GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id] != NULL) {
        job_snapshots[copied++] = *GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id];
    }

    for (size_t history_offset = 0;
            history_offset < ASIC_JOB_HISTORY_DEPTH && copied < snapshot_capacity;
            history_offset++) {
        size_t history_index =
            (GLOBAL_STATE->ASIC_TASK_MODULE.retired_job_next[job_id] +
             ASIC_JOB_HISTORY_DEPTH - 1U - history_offset) % ASIC_JOB_HISTORY_DEPTH;
        bm_job *historical_job =
            GLOBAL_STATE->ASIC_TASK_MODULE.retired_jobs[job_id][history_index];

        if (historical_job != NULL) {
            job_snapshots[copied++] = *historical_job;
        }
    }
    pthread_mutex_unlock(&GLOBAL_STATE->job_history_lock);

    return copied;
}

void ASIC_clear_job_history(GlobalState *GLOBAL_STATE)
{
    if (GLOBAL_STATE == NULL) {
        return;
    }

    pthread_mutex_lock(&GLOBAL_STATE->job_history_lock);
    for (size_t job_id = 0; job_id < ASIC_ACTIVE_JOB_SLOTS; job_id++) {
        ASIC_job_pool_release(GLOBAL_STATE, GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id]);
        GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id] = NULL;

        for (size_t history_index = 0; history_index < ASIC_JOB_HISTORY_DEPTH; history_index++) {
            ASIC_job_pool_release(
                GLOBAL_STATE,
                GLOBAL_STATE->ASIC_TASK_MODULE.retired_jobs[job_id][history_index]);
            GLOBAL_STATE->ASIC_TASK_MODULE.retired_jobs[job_id][history_index] = NULL;
        }
        GLOBAL_STATE->ASIC_TASK_MODULE.retired_job_next[job_id] = 0;
        GLOBAL_STATE->ASIC_TASK_MODULE.job_history_revision[job_id]++;
    }
    pthread_mutex_unlock(&GLOBAL_STATE->job_history_lock);
}

static void ASIC_lower_job_history_report_difficulty_locked(GlobalState *GLOBAL_STATE,
                                                            uint32_t difficulty)
{
    for (size_t job_id = 0; job_id < ASIC_ACTIVE_JOB_SLOTS; job_id++) {
        bm_job *active_job = GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id];
        bool changed = false;

        if (active_job != NULL &&
                (active_job->asic_report_difficulty == 0 ||
                 active_job->asic_report_difficulty > difficulty)) {
            active_job->asic_report_difficulty = difficulty;
            changed = true;
        }

        for (size_t history_index = 0;
                history_index < ASIC_JOB_HISTORY_DEPTH;
                history_index++) {
            bm_job *retired_job =
                GLOBAL_STATE->ASIC_TASK_MODULE.retired_jobs[job_id][history_index];

            if (retired_job != NULL &&
                    (retired_job->asic_report_difficulty == 0 ||
                     retired_job->asic_report_difficulty > difficulty)) {
                retired_job->asic_report_difficulty = difficulty;
                changed = true;
            }
        }

        if (changed) {
            GLOBAL_STATE->ASIC_TASK_MODULE.job_history_revision[job_id]++;
        }
    }
}

void ASIC_update_job_pool_target(GlobalState *GLOBAL_STATE, const uint8_t pool_target[32],
                                 uint32_t pool_difficulty)
{
    uint32_t report_difficulty;

    if (GLOBAL_STATE == NULL || pool_target == NULL) {
        return;
    }

    if (pool_difficulty == 0) {
        pool_difficulty = 1;
    }
    report_difficulty = ASIC_get_report_difficulty(pool_difficulty);

    pthread_mutex_lock(&GLOBAL_STATE->job_history_lock);
    for (size_t job_id = 0; job_id < ASIC_ACTIVE_JOB_SLOTS; job_id++) {
        bool changed = false;
        bm_job *jobs[ASIC_JOB_HISTORY_DEPTH + 1];

        jobs[0] = GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id];
        for (size_t history_index = 0; history_index < ASIC_JOB_HISTORY_DEPTH; history_index++) {
            jobs[history_index + 1U] =
                GLOBAL_STATE->ASIC_TASK_MODULE.retired_jobs[job_id][history_index];
        }

        for (size_t job_index = 0; job_index < ASIC_JOB_HISTORY_DEPTH + 1U; job_index++) {
            bm_job *job = jobs[job_index];

            if (job == NULL || !job->pool_target_tracks_channel) {
                continue;
            }

            if (memcmp(job->pool_target, pool_target, sizeof(job->pool_target)) != 0) {
                memcpy(job->pool_target, pool_target, sizeof(job->pool_target));
                changed = true;
            }
            if (job->pool_diff != pool_difficulty) {
                job->pool_diff = pool_difficulty;
                changed = true;
            }
            if (job->asic_report_difficulty == 0 ||
                    job->asic_report_difficulty > report_difficulty) {
                job->asic_report_difficulty = report_difficulty;
                changed = true;
            }
        }

        if (changed) {
            GLOBAL_STATE->ASIC_TASK_MODULE.job_history_revision[job_id]++;
        }
    }
    pthread_mutex_unlock(&GLOBAL_STATE->job_history_lock);
}

bool ASIC_begin_active_job_send(GlobalState *GLOBAL_STATE, uint8_t job_id, bm_job *next_job, bm_job **replaced_job)
{
    if (GLOBAL_STATE == NULL || next_job == NULL || replaced_job == NULL ||
            job_id >= ASIC_ACTIVE_JOB_SLOTS) {
        return false;
    }

    pthread_mutex_lock(&GLOBAL_STATE->job_history_lock);
    *replaced_job = GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id];
    GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id] = next_job;

    return true;
}

void ASIC_finish_active_job_send(GlobalState *GLOBAL_STATE, uint8_t job_id, bm_job *sent_job, bm_job *replaced_job, bool send_ok)
{
    bm_job *release_sent_job = NULL;
    bm_job *release_replaced_job = replaced_job;
    bm_job *release_expired_job = NULL;

    if (GLOBAL_STATE == NULL) {
        return;
    }
    if (sent_job == NULL || job_id >= ASIC_ACTIVE_JOB_SLOTS) {
        pthread_mutex_unlock(&GLOBAL_STATE->job_history_lock);
        ASIC_job_pool_release(GLOBAL_STATE, sent_job);
        ASIC_job_pool_release(GLOBAL_STATE, replaced_job);
        return;
    }

    if (GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id] == sent_job) {
        if (!send_ok) {
            GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id] = replaced_job;
            release_sent_job = sent_job;
            release_replaced_job = NULL;
        } else {
            if (replaced_job != NULL) {
                uint8_t history_index = GLOBAL_STATE->ASIC_TASK_MODULE.retired_job_next[job_id];

                release_expired_job =
                    GLOBAL_STATE->ASIC_TASK_MODULE.retired_jobs[job_id][history_index];
                GLOBAL_STATE->ASIC_TASK_MODULE.retired_jobs[job_id][history_index] = replaced_job;
                GLOBAL_STATE->ASIC_TASK_MODULE.retired_job_next[job_id] =
                    (uint8_t)((history_index + 1U) % ASIC_JOB_HISTORY_DEPTH);
                release_replaced_job = NULL;
            }
            GLOBAL_STATE->ASIC_TASK_MODULE.job_history_revision[job_id]++;
        }
    }
    pthread_mutex_unlock(&GLOBAL_STATE->job_history_lock);

    ASIC_job_pool_release(GLOBAL_STATE, release_expired_job);
    ASIC_job_pool_release(GLOBAL_STATE, release_replaced_job);
    ASIC_job_pool_release(GLOBAL_STATE, release_sent_job);
}

// .receive_result_fn = BM1366_process_work,
task_result * ASIC_process_work(GlobalState * GLOBAL_STATE) {
    switch (GLOBAL_STATE->device_model) {
        case DEVICE_ULTRA:
        case DEVICE_HEX:
            return BM1366_process_work(GLOBAL_STATE);
        case DEVICE_SUPRA:
        case DEVICE_SUPRAHEX:
            return BM1368_process_work(GLOBAL_STATE);
        case DEVICE_GAMMA:
        case DEVICE_GAMMATURBO:
            return BM1370_process_work(GLOBAL_STATE);
        default:
    }
    return NULL;
}

// .set_max_baud_fn = BM1366_set_max_baud,
int ASIC_set_max_baud(GlobalState * GLOBAL_STATE) {
    switch (GLOBAL_STATE->device_model) {
        case DEVICE_ULTRA:
        case DEVICE_HEX:
            return BM1366_set_max_baud();
        case DEVICE_SUPRA:
        case DEVICE_SUPRAHEX:
            return BM1368_set_max_baud();
        case DEVICE_GAMMA:
        case DEVICE_GAMMATURBO:
            return BM1370_set_max_baud();
        default:
    return 0;
    }
}

// .set_difficulty_mask_fn = BM1366_set_job_difficulty_mask,
bool ASIC_set_job_difficulty_mask(GlobalState *GLOBAL_STATE, uint32_t difficulty) {
    bool applied = false;
    bool history_locked = false;
    uint32_t previous_difficulty;

    difficulty = ASIC_get_report_difficulty(difficulty);
    pthread_mutex_lock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);
    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    previous_difficulty = GLOBAL_STATE->ASIC_difficulty;
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);

    if (difficulty == previous_difficulty) {
        pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
        GLOBAL_STATE->asic_config_epoch++;
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
        pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);
        return true;
    }

    if (difficulty < previous_difficulty) {
        // Block result snapshots until the lower hardware threshold and the
        // retained-job metadata describe the same reporting regime.
        pthread_mutex_lock(&GLOBAL_STATE->job_history_lock);
        history_locked = true;
    }

    switch (GLOBAL_STATE->device_model) {
        case DEVICE_ULTRA:
        case DEVICE_HEX:
            applied = BM1366_set_job_difficulty_mask(difficulty);
            break;
        case DEVICE_SUPRA:
        case DEVICE_SUPRAHEX:
            applied = BM1368_set_job_difficulty_mask(difficulty);
            break;
        case DEVICE_GAMMA:
        case DEVICE_GAMMATURBO:
            applied = BM1370_set_job_difficulty_mask(difficulty);
            break;
        default:
            break;
    }

    if (applied && history_locked) {
        ASIC_lower_job_history_report_difficulty_locked(GLOBAL_STATE, difficulty);
    }
    if (history_locked) {
        pthread_mutex_unlock(&GLOBAL_STATE->job_history_lock);
    }

    if (applied) {
        pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
        GLOBAL_STATE->ASIC_difficulty = difficulty;
        GLOBAL_STATE->asic_config_epoch++;
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
    }
    pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);

    if (!applied) {
        ESP_LOGE(TAG, "Failed to apply ASIC report difficulty %" PRIu32, difficulty);
    }
    return applied;
}

// .send_work_fn = BM1366_send_work,
void ASIC_send_work(GlobalState * GLOBAL_STATE, void * next_job) {
    bool abandon_work;
    bool stale_work;
    bm_job *job = (bm_job *)next_job;

    if (next_job == NULL) {
        return;
    }

    pthread_mutex_lock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);
    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    abandon_work = GLOBAL_STATE->abandon_work != 0;
    stale_work = job->work_epoch != GLOBAL_STATE->work_epoch ||
                 job->asic_config_epoch != GLOBAL_STATE->asic_config_epoch;
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);

    if (abandon_work || stale_work) {
        ASIC_job_pool_release(GLOBAL_STATE, job);
        pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);
        return;
    }

    switch (GLOBAL_STATE->device_model) {
        case DEVICE_ULTRA:
        case DEVICE_HEX:
            BM1366_send_work(GLOBAL_STATE, next_job);
            break;
        case DEVICE_SUPRA:
        case DEVICE_SUPRAHEX:
            BM1368_send_work(GLOBAL_STATE, next_job);
            break;
        case DEVICE_GAMMA:
        case DEVICE_GAMMATURBO:
            BM1370_send_work(GLOBAL_STATE, next_job);
            break;
        default:
            ASIC_job_pool_release(GLOBAL_STATE, job);
            pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);
            return;
    }
    pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);
}

// .set_version_mask = BM1366_set_version_mask
bool ASIC_set_version_mask(GlobalState *GLOBAL_STATE, uint32_t mask) {
    bool applied = false;
    bool mask_changed;
    uint32_t full_mask = mask & ASIC_get_supported_version_mask(GLOBAL_STATE);
    uint32_t previous_mask;
    double hcn_search_multiplier =
        ASIC_get_hcn_search_multiplier(GLOBAL_STATE, full_mask);

    pthread_mutex_lock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);

    switch (GLOBAL_STATE->device_model) {
        case DEVICE_ULTRA:
        case DEVICE_HEX:
            applied = BM1366_set_version_mask(full_mask);
            break;
        case DEVICE_SUPRA:
        case DEVICE_SUPRAHEX:
            applied = BM1368_set_version_mask(full_mask);
            break;
        case DEVICE_GAMMA:
        case DEVICE_GAMMATURBO:
            applied = BM1370_set_version_mask(full_mask);
            break;
        default:
            break;
    }

    if (!applied) {
        pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);
        ESP_LOGE(TAG,
                 "Failed to apply ASIC version mask %08" PRIx32,
                 full_mask);
        return false;
    }

    if (!ASIC_set_nonce_space_unlocked(GLOBAL_STATE, hcn_search_multiplier)) {
        pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);
        ESP_LOGE(TAG,
                 "Failed to apply %.3fx HCN scale for version mask %08" PRIx32,
                 hcn_search_multiplier,
                 full_mask);
        return false;
    }

    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    previous_mask = GLOBAL_STATE->version_mask;
    GLOBAL_STATE->version_mask = full_mask;
    mask_changed = full_mask != previous_mask;
    if (mask_changed) {
        GLOBAL_STATE->asic_config_epoch++;
    }
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
    if (mask_changed) {
        ASIC_clear_job_history(GLOBAL_STATE);
    }
    ASIC_refresh_job_interval(GLOBAL_STATE);
    pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);

    if (mask_changed && GLOBAL_STATE->ASIC_TASK_MODULE.semaphore != NULL) {
        xSemaphoreGive(GLOBAL_STATE->ASIC_TASK_MODULE.semaphore);
    }

    ESP_LOGI(TAG,
             "ASIC version mask applied: %08" PRIx32 ", HCN scale %.3fx",
             full_mask,
             hcn_search_multiplier);
    return true;
}

static bool ASIC_set_nonce_space_unlocked(GlobalState *GLOBAL_STATE, double nonce_scale)
{
    float frequency = ASIC_get_actual_frequency_mhz(GLOBAL_STATE);
    uint16_t asic_count = ASIC_get_asic_count(GLOBAL_STATE);

    switch (GLOBAL_STATE->asic_model) {
        case ASIC_BM1366:
            return BM1366_set_nonce_space(frequency, asic_count, nonce_scale);
        case ASIC_BM1368:
            return BM1368_set_nonce_space(frequency, asic_count, nonce_scale);
        case ASIC_BM1370:
            return BM1370_set_nonce_space(frequency, asic_count, nonce_scale);
        default:
            ESP_LOGE(TAG, "Unknown ASIC model, cannot set nonce space");
            return false;
    }
}

static float ASIC_send_hash_frequency_unlocked(GlobalState *GLOBAL_STATE,
                                                float target_frequency)
{
    switch (GLOBAL_STATE->asic_model) {
        case ASIC_BM1366:
            return BM1366_send_hash_frequency(target_frequency);
        case ASIC_BM1368:
            return BM1368_send_hash_frequency(target_frequency);
        case ASIC_BM1370:
            return BM1370_send_hash_frequency(target_frequency);
        default:
            ESP_LOGE(TAG, "Unknown ASIC model, cannot set frequency");
            return 0.0f;
    }
}

bool ASIC_set_frequency(GlobalState * GLOBAL_STATE, float target_frequency) {
    const float transition_step_mhz = 6.25f;
    const float frequency_epsilon = 0.001f;
    bool success = true;
    bool nonce_space_synchronized = false;
    bool interval_refreshed_at_end = false;
    float actual_frequency = ASIC_get_actual_frequency_mhz(GLOBAL_STATE);
    float command_frequency = actual_frequency;

    if (target_frequency < (float)NVS_CONFIG_ASIC_FREQUENCY_MIN_MHZ ||
            target_frequency > (float)NVS_CONFIG_ASIC_FREQUENCY_MAX_MHZ ||
            actual_frequency <= 0.0f) {
        ESP_LOGE(TAG,
                 "Invalid ASIC frequency transition %.2f -> %.2f MHz",
                 actual_frequency,
                 target_frequency);
        return false;
    }

    ESP_LOGI(TAG, "Setting ASIC frequency to %.2f MHz", target_frequency);

    while (fabsf(command_frequency - target_frequency) > frequency_epsilon) {
        float delta = target_frequency - command_frequency;
        float next_command = command_frequency +
                             (delta > 0.0f ? transition_step_mhz : -transition_step_mhz);

        if ((delta > 0.0f && next_command > target_frequency) ||
                (delta < 0.0f && next_command < target_frequency)) {
            next_command = target_frequency;
        }

        pthread_mutex_lock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);
        float applied_frequency =
            ASIC_send_hash_frequency_unlocked(GLOBAL_STATE, next_command);
        if (applied_frequency <= 0.0f) {
            pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);
            success = false;
            break;
        }

        actual_frequency = applied_frequency;
        command_frequency = next_command;
        GLOBAL_STATE->POWER_MANAGEMENT_MODULE.actual_frequency = actual_frequency;
        GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value = actual_frequency;
        nonce_space_synchronized = false;
        double nonce_scale = ASIC_get_hcn_search_multiplier(
            GLOBAL_STATE, GLOBAL_STATE->version_mask);
        if (!ASIC_set_nonce_space_unlocked(GLOBAL_STATE, nonce_scale)) {
            pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);
            break;
        }
        ASIC_refresh_job_interval(GLOBAL_STATE);
        nonce_space_synchronized = true;
        pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);

        if (GLOBAL_STATE->ASIC_TASK_MODULE.semaphore != NULL) {
            xSemaphoreGive(GLOBAL_STATE->ASIC_TASK_MODULE.semaphore);
        }
        if (fabsf(command_frequency - target_frequency) > frequency_epsilon) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }

    pthread_mutex_lock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);
    if (!nonce_space_synchronized) {
        double nonce_scale = ASIC_get_hcn_search_multiplier(
            GLOBAL_STATE, GLOBAL_STATE->version_mask);
        if (!ASIC_set_nonce_space_unlocked(GLOBAL_STATE, nonce_scale)) {
            success = false;
        }
    }
    SYSTEM_reset_hashrate_estimate(GLOBAL_STATE);
    if (!nonce_space_synchronized) {
        ASIC_refresh_job_interval(GLOBAL_STATE);
        interval_refreshed_at_end = true;
    } else {
        SYSTEM_update_hashrate_estimate(GLOBAL_STATE);
    }
    pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock);

    if (interval_refreshed_at_end && GLOBAL_STATE->ASIC_TASK_MODULE.semaphore != NULL) {
        xSemaphoreGive(GLOBAL_STATE->ASIC_TASK_MODULE.semaphore);
    }

    if (success && fabsf(command_frequency - target_frequency) <= frequency_epsilon) {
        ESP_LOGI(TAG,
                 "ASIC frequency transition complete: requested %.2f MHz, applied %.2f MHz",
                 target_frequency,
                 actual_frequency);
        return true;
    }

    ESP_LOGE(TAG,
             "ASIC frequency transition incomplete: requested %.2f MHz, last applied %.2f MHz",
             target_frequency,
             actual_frequency);
    return false;
}

void ASIC_refresh_job_interval(GlobalState * GLOBAL_STATE)
{
    uint8_t asic_count = ASIC_get_asic_count(GLOBAL_STATE);
    uint32_t asic_mask = GLOBAL_STATE->version_mask & ASIC_get_supported_version_mask(GLOBAL_STATE);
    uint8_t asic_version_bits = ASIC_count_mask_bits(asic_mask);
    uint32_t version_count = UINT32_C(1) << asic_version_bits;
    double model_timeout_ms = ASIC_get_model_job_timeout_ms(GLOBAL_STATE);
    double one_batch_ms = calculate_bm_full_space_ms(
        ASIC_get_actual_frequency_mhz(GLOBAL_STATE),
        asic_count,
        ASIC_get_small_core_count(GLOBAL_STATE),
        ASIC_get_core_count_for_model(GLOBAL_STATE->device_model),
        1U);
    double full_space_ms = calculate_bm_full_space_ms(
        ASIC_get_actual_frequency_mhz(GLOBAL_STATE),
        asic_count,
        ASIC_get_small_core_count(GLOBAL_STATE),
        ASIC_get_core_count_for_model(GLOBAL_STATE->device_model),
        version_count);
    // A model timeout may limit how many rolled-version batches stay active,
    // but it must never truncate the first complete 32-bit nonce pass.
    double interval_ceiling_ms = fmax(model_timeout_ms, one_batch_ms);
    double interval_ms = interval_ceiling_ms;
    uint32_t target_interval_us;
    uint16_t queue_low_water_mark;
    uint16_t queue_high_water_mark;

    if (full_space_ms > 0.0 && interval_ms > full_space_ms * ASIC_DISPATCH_SPACE_FRACTION) {
        interval_ms = full_space_ms * ASIC_DISPATCH_SPACE_FRACTION;
    }
    target_interval_us = (uint32_t)llround(interval_ms * 1000.0);

    if (target_interval_us < ASIC_DISPATCH_MIN_US) {
        target_interval_us = ASIC_DISPATCH_MIN_US;
    }

    interval_ms = (double)target_interval_us / 1000.0;
    GLOBAL_STATE->asic_job_frequency_ms = interval_ms;
    ASIC_calculate_queue_watermarks(target_interval_us,
                                    &queue_low_water_mark,
                                    &queue_high_water_mark);
    ASIC_publish_dispatch_config(GLOBAL_STATE,
                                 target_interval_us,
                                 queue_low_water_mark,
                                 queue_high_water_mark);
    SYSTEM_update_hashrate_estimate(GLOBAL_STATE);

    ESP_LOGI(TAG,
             "ASIC job interval %.2f ms (model limit %.2f ms, full pass %.2f ms, search space %.2f ms, freq %.2f MHz, chips %u, ASIC version bits %u, queue %u/%u)",
             interval_ms,
             model_timeout_ms,
             one_batch_ms,
             full_space_ms,
             ASIC_get_actual_frequency_mhz(GLOBAL_STATE),
             asic_count,
             asic_version_bits,
             (unsigned int)queue_low_water_mark,
             (unsigned int)queue_high_water_mark);
    if (target_interval_us < ASIC_JOB_UART_MIN_US) {
        double unique_work_utilization =
            full_space_ms * 1000.0 * 100.0 / (double)ASIC_JOB_UART_MIN_US;
        if (unique_work_utilization > 100.0) {
            unique_work_utilization = 100.0;
        }
        ESP_LOGW(TAG,
                 "ASIC search budget %lu us is below the ~%lu us UART job-frame time; dispatch will run continuously, unique-work utilization is capped near %.1f%% (ASIC version bits %u)",
                 (unsigned long)target_interval_us,
                 (unsigned long)ASIC_JOB_UART_MIN_US,
                 unique_work_utilization,
                 asic_version_bits);
    }
}

esp_err_t ASIC_set_device_model(GlobalState * GLOBAL_STATE) {

    if (GLOBAL_STATE->device_model_str == NULL) {
        ESP_LOGE(TAG, "No device model string found");
        return ESP_FAIL;
    }

    if (strcmp(GLOBAL_STATE->device_model_str, "ultra") == 0) {
        GLOBAL_STATE->asic_model = ASIC_BM1366;
        GLOBAL_STATE->ASIC_difficulty = BM1366_ASIC_DIFFICULTY;
        GLOBAL_STATE->device_model = DEVICE_ULTRA;
        ASIC_refresh_job_interval(GLOBAL_STATE);
        ESP_LOGI(TAG, "DEVICE: bitaxeUltra");
        ESP_LOGI(TAG, "ASIC: %dx BM1366 (%" PRIu64 " cores)", BITAXE_ULTRA_ASIC_COUNT, BM1366_CORE_COUNT);

    }else if (strcmp(GLOBAL_STATE->device_model_str, "hex") == 0) {
        GLOBAL_STATE->asic_model = ASIC_BM1366;
        GLOBAL_STATE->ASIC_difficulty = BM1366_ASIC_DIFFICULTY;
        GLOBAL_STATE->device_model = DEVICE_HEX;
        ASIC_refresh_job_interval(GLOBAL_STATE);
        ESP_LOGI(TAG, "DEVICE: bitaxeUltraHex");
        ESP_LOGI(TAG, "ASIC: %dx BM1366 (%" PRIu64 " cores)", BITAXE_HEX_ASIC_COUNT, BM1366_CORE_COUNT);

    } else if (strcmp(GLOBAL_STATE->device_model_str, "supra") == 0) {
        GLOBAL_STATE->asic_model = ASIC_BM1368;
        GLOBAL_STATE->ASIC_difficulty = BM1368_ASIC_DIFFICULTY;
        GLOBAL_STATE->device_model = DEVICE_SUPRA;
        ASIC_refresh_job_interval(GLOBAL_STATE);
        ESP_LOGI(TAG, "DEVICE: bitaxeSupra");
        ESP_LOGI(TAG, "ASIC: %dx BM1368 (%" PRIu64 " cores)", BITAXE_SUPRA_ASIC_COUNT, BM1368_CORE_COUNT);

    }else if (strcmp(GLOBAL_STATE->device_model_str, "suprahex") == 0) {
        GLOBAL_STATE->asic_model = ASIC_BM1368;
        GLOBAL_STATE->ASIC_difficulty = BM1368_ASIC_DIFFICULTY;
        GLOBAL_STATE->device_model = DEVICE_SUPRAHEX;
        ASIC_refresh_job_interval(GLOBAL_STATE);
        ESP_LOGI(TAG, "DEVICE: bitaxeSupra");
        ESP_LOGI(TAG, "ASIC: %dx BM1368 (%" PRIu64 " cores)", BITAXE_SUPRAHEX_ASIC_COUNT, BM1368_CORE_COUNT);

    } else if (strcmp(GLOBAL_STATE->device_model_str, "gamma") == 0) {
        GLOBAL_STATE->asic_model = ASIC_BM1370;
        GLOBAL_STATE->ASIC_difficulty = BM1370_ASIC_DIFFICULTY;
        GLOBAL_STATE->device_model = DEVICE_GAMMA;
        ASIC_refresh_job_interval(GLOBAL_STATE);
        ESP_LOGI(TAG, "DEVICE: bitaxeGamma");
        ESP_LOGI(TAG, "ASIC: %dx BM1370 (%" PRIu64 " cores)", BITAXE_GAMMA_ASIC_COUNT, BM1370_CORE_COUNT);

    } else if (strcmp(GLOBAL_STATE->device_model_str, "gammaturbo") == 0) {
        GLOBAL_STATE->asic_model = ASIC_BM1370;
        GLOBAL_STATE->ASIC_difficulty = BM1370_ASIC_DIFFICULTY;
        GLOBAL_STATE->device_model = DEVICE_GAMMATURBO;
        ASIC_refresh_job_interval(GLOBAL_STATE);
        ESP_LOGI(TAG, "DEVICE: bitaxeGammaTurbo");
        ESP_LOGI(TAG, "ASIC: %dx BM1370 (%" PRIu64 " cores)", BITAXE_GAMMATURBO_ASIC_COUNT, BM1370_CORE_COUNT);

    } else {
        ESP_LOGE(TAG, "Invalid DEVICE model");
        GLOBAL_STATE->device_model = DEVICE_UNKNOWN;
        return ESP_FAIL;
    }
    return ESP_OK;
}
