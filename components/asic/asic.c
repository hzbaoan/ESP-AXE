#include <math.h>
#include <stdint.h>
#include <string.h>

#include <esp_log.h>

#include "bm1366.h"
#include "bm1368.h"
#include "bm1370.h"

#include "asic.h"
#include "system.h"
#include "utils.h"

#ifndef CONFIG_ASIC_DISPATCH_SAFETY_MARGIN_PERCENT
#define CONFIG_ASIC_DISPATCH_SAFETY_MARGIN_PERCENT 1
#endif

#ifndef CONFIG_ASIC_DISPATCH_OBSERVED_HASHRATE_MIN_SAMPLES
#define CONFIG_ASIC_DISPATCH_OBSERVED_HASHRATE_MIN_SAMPLES 4
#endif

#ifndef CONFIG_ASIC_DISPATCH_OBSERVED_HASHRATE_MIN_DELTA_PERCENT
#define CONFIG_ASIC_DISPATCH_OBSERVED_HASHRATE_MIN_DELTA_PERCENT 5
#endif

#ifndef CONFIG_ASIC_HOST_VERSION_BITS
#define CONFIG_ASIC_HOST_VERSION_BITS 10
#endif

static const double NONCE_SPACE = 4294967296.0; //  2^32
static const double HASHES_PER_GIGAHASH = 1000000000.0;
static const double HASHES_PER_MEGAHASH = 1000000.0;
static const uint32_t ASIC_QUEUE_TARGET_BUFFER_US = 200000;
static const uint16_t ASIC_QUEUE_MIN_LOW_WATER_MARK = 1;
static const uint16_t ASIC_QUEUE_MAX_LOW_WATER_MARK = QUEUE_LOW_WATER_MARK_MAX;
static const uint32_t ASIC_DISPATCH_MIN_US = 1000;

static const char *TAG = "asic";

static double ASIC_calculate_nominal_hashrate_hps(double frequency_mhz,
                                                  uint64_t parallel_work_units,
                                                  uint8_t asic_count)
{
    if (frequency_mhz <= 0.0 || parallel_work_units == 0 || asic_count == 0) {
        return 0.0;
    }

    return frequency_mhz * HASHES_PER_MEGAHASH * (double)parallel_work_units * (double)asic_count;
}

static double ASIC_calculate_job_interval_ms(double hash_rate_hps,
                                             uint8_t dispatch_span,
                                             uint8_t active_job_slots)
{
    double interval_ms;

    if (hash_rate_hps <= 0.0 || dispatch_span == 0 || active_job_slots == 0) {
        return 1.0;
    }

    interval_ms = (NONCE_SPACE * 1000.0) / hash_rate_hps;
    interval_ms *= (double)dispatch_span;
    interval_ms /= (double)active_job_slots;
    return interval_ms < 1.0 ? 1.0 : interval_ms;
}

static double ASIC_get_observed_hashrate_hps(const GlobalState *GLOBAL_STATE)
{
    if (GLOBAL_STATE == NULL) {
        return 0.0;
    }
    if (GLOBAL_STATE->SYSTEM_MODULE.historical_hashrate_init <
            CONFIG_ASIC_DISPATCH_OBSERVED_HASHRATE_MIN_SAMPLES) {
        return 0.0;
    }
    if (GLOBAL_STATE->SYSTEM_MODULE.current_hashrate <= 0.0) {
        return 0.0;
    }

    return GLOBAL_STATE->SYSTEM_MODULE.current_hashrate * HASHES_PER_GIGAHASH;
}

static double ASIC_select_dispatch_hashrate_hps(const GlobalState *GLOBAL_STATE,
                                                double nominal_hashrate_hps,
                                                bool *using_observed_hashrate,
                                                double *observed_hashrate_hps_out)
{
    double observed_hashrate_hps = ASIC_get_observed_hashrate_hps(GLOBAL_STATE);

    if (using_observed_hashrate != NULL) {
        *using_observed_hashrate = false;
    }
    if (observed_hashrate_hps_out != NULL) {
        *observed_hashrate_hps_out = observed_hashrate_hps;
    }

    return nominal_hashrate_hps;
}

static double ASIC_apply_dispatch_safety_margin(double interval_ms)
{
    double margin_factor =
        1.0 + ((double)CONFIG_ASIC_DISPATCH_SAFETY_MARGIN_PERCENT / 100.0);

    return interval_ms * margin_factor;
}

static uint64_t ASIC_get_parallel_work_units(DeviceModel device_model)
{
    switch (device_model) {
        case DEVICE_ULTRA:
        case DEVICE_HEX:
            return BM1366_SMALL_CORE_COUNT;
        case DEVICE_SUPRA:
        case DEVICE_SUPRAHEX:
            return BM1368_SMALL_CORE_COUNT;
        case DEVICE_GAMMA:
        case DEVICE_GAMMATURBO:
            return BM1370_SMALL_CORE_COUNT;
        default:
            return 0;
    }
}

static uint8_t ASIC_count_mask_bits(uint32_t mask)
{
    return (uint8_t)__builtin_popcount(mask);
}

static uint8_t ASIC_get_host_version_slot_bit_count(const asic_header_schedule_policy_t *policy,
                                                    uint32_t version_mask)
{
    uint8_t mask_bits;
    uint8_t configured_slot_bits = CONFIG_ASIC_HOST_VERSION_BITS;

    if (policy == NULL || !policy->host_expands_version || policy->active_job_slots <= 1 ||
            configured_slot_bits == 0) {
        return 0;
    }

    mask_bits = ASIC_count_mask_bits(version_mask);
    if (mask_bits > configured_slot_bits) {
        return configured_slot_bits;
    }

    return mask_bits;
}

static uint32_t ASIC_take_lowest_mask_bits(uint32_t mask, uint8_t bit_count)
{
    uint32_t result = 0;

    for (uint8_t i = 0; i < bit_count && mask != 0; i++) {
        uint32_t lowest_bit = mask & -mask;
        result |= lowest_bit;
        mask &= mask - 1;
    }

    return result;
}

uint32_t ASIC_get_report_difficulty(uint32_t pool_difficulty)
{
    return _largest_power_of_two_u32(pool_difficulty);
}

void ASIC_sync_version_mask_state(GlobalState * GLOBAL_STATE, uint32_t mask)
{
    if (GLOBAL_STATE == NULL) {
        return;
    }

    mask &= ASIC_get_supported_version_mask(GLOBAL_STATE);
    GLOBAL_STATE->version_mask = mask;
    ASIC_refresh_job_interval(GLOBAL_STATE);
}

static asic_header_schedule_policy_t ASIC_get_header_schedule_policy_for_model(DeviceModel device_model)
{
    asic_header_schedule_policy_t policy = {
        .version_mode = ASIC_VERSION_MODE_NONE,
        .active_job_slots = 1,
        .host_expands_version = false,
        .host_expands_extranonce2 = true,
    };

    switch (device_model) {
        case DEVICE_ULTRA:
        case DEVICE_HEX:
        case DEVICE_SUPRA:
        case DEVICE_SUPRAHEX:
        case DEVICE_GAMMA:
        case DEVICE_GAMMATURBO:
            policy.version_mode = ASIC_VERSION_MODE_INTERNAL_BITS;
            policy.active_job_slots = 6;
            policy.host_expands_version = true;
            break;
        default:
            break;
    }

    return policy;
}

static uint32_t ASIC_get_effective_version_window_count(const asic_header_schedule_policy_t *policy,
                                                        uint32_t version_window_count)
{
    if (policy == NULL || !policy->host_expands_version || version_window_count == 0) {
        return 1;
    }

    return version_window_count;
}

static void ASIC_increment_extranonce2_counter(asic_extranonce2_counter_t *counter)
{
    size_t i;

    if (counter == NULL) {
        return;
    }

    for (i = 0; i < sizeof(counter->bytes); ++i) {
        counter->bytes[i]++;
        if (counter->bytes[i] != 0) {
            return;
        }
    }
}

asic_header_schedule_policy_t ASIC_get_header_schedule_policy(GlobalState * GLOBAL_STATE)
{
    if (GLOBAL_STATE == NULL) {
        return ASIC_get_header_schedule_policy_for_model(DEVICE_UNKNOWN);
    }

    return ASIC_get_header_schedule_policy_for_model(GLOBAL_STATE->device_model);
}

uint32_t ASIC_get_header_schedule_version_window_count(const asic_header_schedule_policy_t *policy,
                                                       uint32_t version_mask)
{
    uint8_t host_slot_bits;

    if (policy == NULL || !policy->host_expands_version) {
        return 1;
    }

    host_slot_bits = ASIC_get_host_version_slot_bit_count(policy, version_mask);
    if (host_slot_bits == 0) {
        return 1;
    }

    return UINT32_C(1) << host_slot_bits;
}

uint32_t ASIC_get_header_schedule_host_version_mask(const asic_header_schedule_policy_t *policy,
                                                    uint32_t version_mask)
{
    return ASIC_take_lowest_mask_bits(
        version_mask,
        ASIC_get_host_version_slot_bit_count(policy, version_mask));
}

uint32_t ASIC_get_header_schedule_asic_version_mask(const asic_header_schedule_policy_t *policy,
                                                    uint32_t version_mask)
{
    uint32_t host_version_mask = ASIC_get_header_schedule_host_version_mask(policy, version_mask);

    return version_mask & ~host_version_mask;
}

uint32_t ASIC_get_header_schedule_host_version_bits(const asic_header_schedule_policy_t *policy,
                                                    uint32_t version_mask,
                                                    uint32_t version_window_index)
{
    uint32_t host_version_mask = ASIC_get_header_schedule_host_version_mask(policy, version_mask);

    return rolled_version_from_index(0, host_version_mask, version_window_index) & host_version_mask;
}

bool ASIC_extranonce2_counter_has_overflowed_len(const asic_extranonce2_counter_t *counter,
                                                 size_t extranonce2_len)
{
    if (counter == NULL || extranonce2_len >= sizeof(counter->bytes)) {
        return false;
    }

    for (size_t i = extranonce2_len; i < sizeof(counter->bytes); i++) {
        if (counter->bytes[i] != 0) {
            return true;
        }
    }

    return false;
}

void ASIC_normalize_header_cursor(asic_header_cursor_t *cursor,
                                  const asic_header_schedule_policy_t *policy,
                                  uint32_t version_window_count)
{
    uint32_t effective_version_window_count;

    if (cursor == NULL) {
        return;
    }

    effective_version_window_count = ASIC_get_effective_version_window_count(policy, version_window_count);

    cursor->version_window_index %= effective_version_window_count;
}

asic_header_schedule_snapshot_t ASIC_snapshot_header_cursor(const asic_header_cursor_t *cursor,
                                                           const asic_header_schedule_policy_t *policy,
                                                           uint32_t version_window_count)
{
    asic_header_schedule_snapshot_t snapshot = {0};
    asic_header_cursor_t normalized_cursor = {0};

    if (cursor != NULL) {
        normalized_cursor = *cursor;
    }

    ASIC_normalize_header_cursor(&normalized_cursor, policy, version_window_count);

    snapshot.extranonce2_counter = (policy != NULL && policy->host_expands_extranonce2)
                                       ? normalized_cursor.extranonce2_counter
                                       : (asic_extranonce2_counter_t){0};
    snapshot.version_window_index = (policy != NULL && policy->host_expands_version)
                                        ? normalized_cursor.version_window_index
                                        : 0;

    return snapshot;
}

void ASIC_advance_header_cursor(asic_header_cursor_t *cursor,
                                const asic_header_schedule_policy_t *policy,
                                uint32_t version_window_count)
{
    uint32_t effective_version_window_count;

    if (cursor == NULL) {
        return;
    }

    ASIC_normalize_header_cursor(cursor, policy, version_window_count);

    effective_version_window_count = ASIC_get_effective_version_window_count(policy, version_window_count);

    cursor->version_window_index++;
    if (cursor->version_window_index >= effective_version_window_count) {
        cursor->version_window_index = 0;
        if (policy == NULL || policy->host_expands_extranonce2) {
            ASIC_increment_extranonce2_counter(&cursor->extranonce2_counter);
        }
    }
}

void ASIC_advance_header_cursor_by(asic_header_cursor_t *cursor,
                                   const asic_header_schedule_policy_t *policy,
                                   uint32_t version_window_count,
                                   uint8_t steps)
{
    for (uint8_t i = 0; i < steps; i++) {
        ASIC_advance_header_cursor(cursor, policy, version_window_count);
    }
}

void ASIC_init_partitioned_header_cursors(asic_header_cursor_t *cursors,
                                          uint8_t cursor_count,
                                          const asic_header_schedule_policy_t *policy,
                                          uint32_t version_window_count)
{
    if (cursors == NULL) {
        return;
    }

    for (uint8_t chip_index = 0; chip_index < cursor_count; chip_index++) {
        memset(&cursors[chip_index], 0, sizeof(cursors[chip_index]));
        ASIC_advance_header_cursor_by(&cursors[chip_index],
                                      policy,
                                      version_window_count,
                                      chip_index);
    }
}

asic_version_mode_t ASIC_get_version_mode(GlobalState * GLOBAL_STATE)
{
    return ASIC_get_header_schedule_policy(GLOBAL_STATE).version_mode;
}

// .init_fn = BM1366_init,
uint8_t ASIC_init(GlobalState * GLOBAL_STATE) {
    uint8_t chip_count = 0;

    switch (GLOBAL_STATE->device_model) {
        case DEVICE_ULTRA:
            chip_count = BM1366_init(GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value, BITAXE_ULTRA_ASIC_COUNT);
            break;
        case DEVICE_SUPRA:
            chip_count = BM1368_init(GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value, BITAXE_SUPRA_ASIC_COUNT);
            break;
        case DEVICE_GAMMA:
            chip_count = BM1370_init(GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value, BITAXE_GAMMA_ASIC_COUNT);
            break;
        case DEVICE_GAMMATURBO:
            chip_count = BM1370_init(GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value, BITAXE_GAMMATURBO_ASIC_COUNT);
            break;
        case DEVICE_HEX:
            chip_count = BM1366_init(GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value, BITAXE_HEX_ASIC_COUNT);
            break;
        case DEVICE_SUPRAHEX:
            chip_count = BM1368_init(GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value, BITAXE_SUPRAHEX_ASIC_COUNT);
            break;
        default:
            break;
    }

    GLOBAL_STATE->detected_asic_count = chip_count;

    if (chip_count != 0) {
        uint32_t default_version_mask = ASIC_get_supported_version_mask(GLOBAL_STATE);

        GLOBAL_STATE->pending_version_mask = default_version_mask;
        GLOBAL_STATE->new_stratum_version_rolling_msg = false;
        ASIC_set_version_mask(GLOBAL_STATE, default_version_mask);
    }

    return chip_count;
}

uint8_t ASIC_get_asic_count(GlobalState * GLOBAL_STATE) {
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

    if (GLOBAL_STATE->detected_asic_count > 0 &&
            GLOBAL_STATE->detected_asic_count < configured_count) {
        return GLOBAL_STATE->detected_asic_count;
    }

    return configured_count;
}

static void ASIC_refresh_queue_watermarks(GlobalState * GLOBAL_STATE)
{
    uint32_t current_interval_us = GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_current_us;
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

    GLOBAL_STATE->ASIC_TASK_MODULE.queue_low_water_mark = (uint16_t)queue_low_water_mark;
    GLOBAL_STATE->ASIC_TASK_MODULE.queue_high_water_mark = (uint16_t)queue_high_water_mark;
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

uint8_t ASIC_get_active_job_slot_count(GlobalState * GLOBAL_STATE)
{
    return ASIC_get_header_schedule_policy(GLOBAL_STATE).active_job_slots;
}

static uint8_t ASIC_get_dispatch_span(GlobalState * GLOBAL_STATE)
{
    (void)GLOBAL_STATE;
    return 1;
}

uint32_t ASIC_get_supported_version_mask(GlobalState * GLOBAL_STATE)
{
    (void)GLOBAL_STATE;
    return STRATUM_DEFAULT_VERSION_MASK;
}

bool ASIC_copy_active_job(GlobalState * GLOBAL_STATE, uint8_t job_id, bm_job *job_snapshot)
{
    bool copied = false;

    pthread_mutex_lock(&GLOBAL_STATE->valid_jobs_lock);
    if (GLOBAL_STATE->valid_jobs[job_id] != 0 &&
            GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id] != NULL) {
        *job_snapshot = *GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id];
        copied = true;
    }
    pthread_mutex_unlock(&GLOBAL_STATE->valid_jobs_lock);

    return copied;
}

bool ASIC_begin_active_job_send(GlobalState *GLOBAL_STATE, uint8_t job_id, bm_job *next_job, bm_job **replaced_job)
{
    if (GLOBAL_STATE == NULL || next_job == NULL || job_id >= ASIC_ACTIVE_JOB_SLOTS) {
        return false;
    }

    pthread_mutex_lock(&GLOBAL_STATE->valid_jobs_lock);
    if (replaced_job != NULL) {
        *replaced_job = GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id];
    }
    GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id] = next_job;
    GLOBAL_STATE->valid_jobs[job_id] = 1;
    pthread_mutex_unlock(&GLOBAL_STATE->valid_jobs_lock);

    return true;
}

void ASIC_finish_active_job_send(GlobalState *GLOBAL_STATE, uint8_t job_id, bm_job *sent_job, bm_job *replaced_job, bool send_ok)
{
    bm_job *release_sent_job = NULL;
    bm_job *release_replaced_job = replaced_job;

    if (GLOBAL_STATE == NULL) {
        return;
    }
    if (sent_job == NULL || job_id >= ASIC_ACTIVE_JOB_SLOTS) {
        ASIC_job_pool_release(GLOBAL_STATE, sent_job);
        ASIC_job_pool_release(GLOBAL_STATE, replaced_job);
        return;
    }

    pthread_mutex_lock(&GLOBAL_STATE->valid_jobs_lock);
    if (!send_ok && GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id] == sent_job) {
        GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id] = replaced_job;
        GLOBAL_STATE->valid_jobs[job_id] = replaced_job != NULL ? 1 : 0;
        release_sent_job = sent_job;
        release_replaced_job = NULL;
    }
    pthread_mutex_unlock(&GLOBAL_STATE->valid_jobs_lock);

    ASIC_job_pool_release(GLOBAL_STATE, release_replaced_job);
    ASIC_job_pool_release(GLOBAL_STATE, release_sent_job);
}

void ASIC_set_dispatch_interval(GlobalState * GLOBAL_STATE, uint32_t interval_us)
{
    if (interval_us < GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_min_us) {
        interval_us = GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_min_us;
    }
    if (interval_us > GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_max_us) {
        interval_us = GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_max_us;
    }
    if (interval_us < ASIC_DISPATCH_MIN_US) {
        interval_us = ASIC_DISPATCH_MIN_US;
    }

    GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_current_us = interval_us;
    ASIC_refresh_queue_watermarks(GLOBAL_STATE);
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
void ASIC_set_job_difficulty_mask(GlobalState * GLOBAL_STATE, uint32_t difficulty) {
    difficulty = ASIC_get_report_difficulty(difficulty);

    switch (GLOBAL_STATE->device_model) {
        case DEVICE_ULTRA:
        case DEVICE_HEX:
            BM1366_set_job_difficulty_mask(difficulty);
            break;
        case DEVICE_SUPRA:
        case DEVICE_SUPRAHEX:
            BM1368_set_job_difficulty_mask(difficulty);
            break;
        case DEVICE_GAMMA:
        case DEVICE_GAMMATURBO:
            BM1370_set_job_difficulty_mask(difficulty);
            break;
        default:
            return;
    }

    GLOBAL_STATE->ASIC_difficulty = difficulty;
}

// .send_work_fn = BM1366_send_work,
void ASIC_send_work(GlobalState * GLOBAL_STATE, void * next_job) {
    bool abandon_work;

    if (next_job == NULL) {
        return;
    }

    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    abandon_work = GLOBAL_STATE->abandon_work != 0;
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);

    if (abandon_work) {
        ASIC_job_pool_release(GLOBAL_STATE, (bm_job *)next_job);
        return;
    }

    if (ASIC_get_asic_count(GLOBAL_STATE) > 1) {
        bm_job *job = (bm_job *)next_job;
        ESP_LOGD(TAG, "Dispatching chip partition %u", job->intended_chip_id);
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
            ASIC_job_pool_release(GLOBAL_STATE, (bm_job *)next_job);
            return;
    }
}

// .set_version_mask = BM1366_set_version_mask
void ASIC_set_version_mask(GlobalState * GLOBAL_STATE, uint32_t mask) {
    asic_header_schedule_policy_t policy = ASIC_get_header_schedule_policy(GLOBAL_STATE);
    uint32_t full_mask = mask & ASIC_get_supported_version_mask(GLOBAL_STATE);
    uint32_t asic_mask = ASIC_get_header_schedule_asic_version_mask(&policy, full_mask);

    switch (GLOBAL_STATE->device_model) {
        case DEVICE_ULTRA:
        case DEVICE_HEX:
            BM1366_set_version_mask(asic_mask);
            break;
        case DEVICE_SUPRA:
        case DEVICE_SUPRAHEX:
            BM1368_set_version_mask(asic_mask);
            break;
        case DEVICE_GAMMA:
        case DEVICE_GAMMATURBO:
            BM1370_set_version_mask(asic_mask);
            break;
        default:
    return;
    }

    ASIC_sync_version_mask_state(GLOBAL_STATE, full_mask);
}

bool ASIC_set_frequency(GlobalState * GLOBAL_STATE, float target_frequency) {
    ESP_LOGI(TAG, "Setting ASIC frequency to %.2f MHz", target_frequency);
    bool success = false;
    
    switch (GLOBAL_STATE->asic_model) {
        case ASIC_BM1366:
            success = BM1366_set_frequency(target_frequency);
            break;
        case ASIC_BM1368:
            success = BM1368_set_frequency(target_frequency);
            break;
        case ASIC_BM1370:
            success = BM1370_set_frequency(target_frequency);
            break;
        default:
            ESP_LOGE(TAG, "Unknown ASIC model, cannot set frequency");
            success = false;
            break;
    }
    
    if (success) {
        GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value = target_frequency;
        SYSTEM_reset_hashrate_estimate(GLOBAL_STATE);
        ASIC_refresh_job_interval(GLOBAL_STATE);
        ESP_LOGI(TAG, "Successfully transitioned to new ASIC frequency: %.2f MHz", target_frequency);
    } else {
        ESP_LOGE(TAG, "Failed to transition to new ASIC frequency: %.2f MHz", target_frequency);
    }
    
    return success;
}

void ASIC_refresh_job_interval(GlobalState * GLOBAL_STATE)
{
    uint64_t parallel_work_units = ASIC_get_parallel_work_units(GLOBAL_STATE->device_model);
    uint8_t asic_count = ASIC_get_asic_count(GLOBAL_STATE);
    uint8_t active_job_slots = ASIC_get_active_job_slot_count(GLOBAL_STATE);
    uint8_t dispatch_span = ASIC_get_dispatch_span(GLOBAL_STATE);
    double nominal_hashrate_hps = ASIC_calculate_nominal_hashrate_hps(
        GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value,
        parallel_work_units,
        asic_count);
    double observed_hashrate_hps = 0.0;
    bool using_observed_hashrate = false;
    double effective_hashrate_hps = ASIC_select_dispatch_hashrate_hps(
        GLOBAL_STATE,
        nominal_hashrate_hps,
        &using_observed_hashrate,
        &observed_hashrate_hps);
    double interval_ms = ASIC_calculate_job_interval_ms(
        effective_hashrate_hps,
        dispatch_span,
        active_job_slots);
    uint32_t target_interval_us = (uint32_t)llround(interval_ms * 1000.0);
    uint32_t current_interval_us;

    interval_ms = ASIC_apply_dispatch_safety_margin(interval_ms);
    target_interval_us = (uint32_t)llround(interval_ms * 1000.0);

    if (target_interval_us < ASIC_DISPATCH_MIN_US) {
        target_interval_us = ASIC_DISPATCH_MIN_US;
    }

    interval_ms = (double)target_interval_us / 1000.0;
    GLOBAL_STATE->asic_job_frequency_ms = interval_ms;
    GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_target_us = target_interval_us;
    GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_min_us = target_interval_us;
    GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_max_us = target_interval_us * 4;
    if (GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_max_us < target_interval_us) {
        GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_max_us = target_interval_us;
    }

    current_interval_us = GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_current_us;
    if (current_interval_us == 0) {
        current_interval_us = target_interval_us;
    }
    ASIC_set_dispatch_interval(GLOBAL_STATE, current_interval_us);
    SYSTEM_update_hashrate_estimate(GLOBAL_STATE);

    ESP_LOGI(TAG,
             "ASIC job interval updated to %.2f ms (freq %.2f MHz, work units %" PRIu64 ", chips %u, dispatch span %u, active slots %u, nominal %.2f GH/s, observed %.2f GH/s, effective %.2f GH/s, source %s, guard %u%%, queue %u/%u)",
             interval_ms,
             GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value,
             parallel_work_units,
             asic_count,
             dispatch_span,
             active_job_slots,
             nominal_hashrate_hps / HASHES_PER_GIGAHASH,
             observed_hashrate_hps / HASHES_PER_GIGAHASH,
             effective_hashrate_hps / HASHES_PER_GIGAHASH,
             using_observed_hashrate ? "observed" : "nominal",
             (unsigned int)CONFIG_ASIC_DISPATCH_SAFETY_MARGIN_PERCENT,
             (unsigned int)GLOBAL_STATE->ASIC_TASK_MODULE.queue_low_water_mark,
             (unsigned int)GLOBAL_STATE->ASIC_TASK_MODULE.queue_high_water_mark);
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
