#include <math.h>
#include <string.h>

#include <esp_log.h>

#include "bm1397.h"
#include "bm1366.h"
#include "bm1368.h"
#include "bm1370.h"

#include "asic.h"
#include "system.h"
#include "utils.h"

static const double NONCE_SPACE = 4294967296.0; //  2^32
static const uint32_t ASIC_QUEUE_TARGET_BUFFER_US = 50000;
static const uint16_t ASIC_QUEUE_MIN_LOW_WATER_MARK = 4;
static const uint16_t ASIC_QUEUE_MAX_LOW_WATER_MARK = QUEUE_SIZE - 8;
static const uint32_t ASIC_DISPATCH_MIN_US = 1000;

static const char *TAG = "asic";

static double ASIC_calculate_job_interval_ms(double frequency_mhz, uint64_t parallel_work_units, uint8_t asic_count, uint8_t dispatch_span)
{
    if (frequency_mhz <= 0.0 || parallel_work_units == 0 || asic_count == 0) {
        return 1.0;
    }

    double interval_ms = NONCE_SPACE / (frequency_mhz * (double)parallel_work_units * 1000.0 * (double)asic_count);
    interval_ms *= (double)dispatch_span;
    return interval_ms < 1.0 ? 1.0 : interval_ms;
}

static uint64_t ASIC_get_parallel_work_units(DeviceModel device_model)
{
    switch (device_model) {
        case DEVICE_MAX:
            return BM1397_SMALL_CORE_COUNT;
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

static uint8_t ASIC_get_active_job_slot_count(DeviceModel device_model)
{
    switch (device_model) {
        case DEVICE_MAX:
            return 32;
        case DEVICE_ULTRA:
        case DEVICE_HEX:
            return 16;
        case DEVICE_SUPRA:
        case DEVICE_SUPRAHEX:
        case DEVICE_GAMMA:
        case DEVICE_GAMMATURBO:
            return 8;
        default:
            return 1;
    }
}

// .init_fn = BM1366_init,
uint8_t ASIC_init(GlobalState * GLOBAL_STATE) {
    switch (GLOBAL_STATE->device_model) {
        case DEVICE_MAX:
            return BM1397_init(GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value, BITAXE_MAX_ASIC_COUNT);
        case DEVICE_ULTRA:
            return BM1366_init(GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value, BITAXE_ULTRA_ASIC_COUNT);
        case DEVICE_SUPRA:
            return BM1368_init(GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value, BITAXE_SUPRA_ASIC_COUNT);
        case DEVICE_GAMMA:
            return BM1370_init(GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value, BITAXE_GAMMA_ASIC_COUNT);
        case DEVICE_GAMMATURBO:
            return BM1370_init(GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value, BITAXE_GAMMATURBO_ASIC_COUNT);
        case DEVICE_HEX:
            return BM1366_init(GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value, BITAXE_HEX_ASIC_COUNT); 
        case DEVICE_SUPRAHEX:
            return BM1368_init(GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value, BITAXE_SUPRAHEX_ASIC_COUNT); 
        default:
    }
    return ESP_OK;
}

uint8_t ASIC_get_asic_count(GlobalState * GLOBAL_STATE) {
    switch (GLOBAL_STATE->device_model) {
        case DEVICE_MAX:
            return BITAXE_MAX_ASIC_COUNT;
        case DEVICE_ULTRA:
            return BITAXE_ULTRA_ASIC_COUNT;
        case DEVICE_SUPRA:
            return BITAXE_SUPRA_ASIC_COUNT;
        case DEVICE_GAMMA:
            return BITAXE_GAMMA_ASIC_COUNT;
        case DEVICE_GAMMATURBO:
            return BITAXE_GAMMATURBO_ASIC_COUNT;
        case DEVICE_HEX:
            return BITAXE_HEX_ASIC_COUNT;
        case DEVICE_SUPRAHEX:
            return BITAXE_SUPRAHEX_ASIC_COUNT;
        default:
    }
    return 0;
}

static void ASIC_refresh_queue_watermarks(GlobalState * GLOBAL_STATE)
{
    uint32_t current_interval_us = GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_current_us;
    uint32_t interval_for_queue_us;
    uint32_t queue_cap;
    uint32_t queue_low_water_mark;
    uint32_t queue_high_water_mark;
    uint32_t queue_high_cap;

    if (current_interval_us == 0) {
        current_interval_us = ASIC_DISPATCH_MIN_US;
    }

    interval_for_queue_us = current_interval_us;
    queue_low_water_mark = (uint32_t)((ASIC_QUEUE_TARGET_BUFFER_US + interval_for_queue_us - 1) / interval_for_queue_us);
    if (queue_low_water_mark < ASIC_QUEUE_MIN_LOW_WATER_MARK) {
        queue_low_water_mark = ASIC_QUEUE_MIN_LOW_WATER_MARK;
    }
    queue_cap = ASIC_get_active_job_slot_count(GLOBAL_STATE->device_model) + 4;
    if (queue_low_water_mark > queue_cap) {
        queue_low_water_mark = queue_cap;
    }
    if (queue_low_water_mark > ASIC_QUEUE_MAX_LOW_WATER_MARK) {
        queue_low_water_mark = ASIC_QUEUE_MAX_LOW_WATER_MARK;
    }

    queue_high_water_mark = queue_low_water_mark + 4;
    queue_high_cap = queue_cap + 4;
    if (queue_high_water_mark > queue_high_cap) {
        queue_high_water_mark = queue_high_cap;
    }
    if (queue_high_water_mark > (QUEUE_SIZE - 2)) {
        queue_high_water_mark = QUEUE_SIZE - 2;
    }

    GLOBAL_STATE->ASIC_TASK_MODULE.queue_low_water_mark = (uint16_t)queue_low_water_mark;
    GLOBAL_STATE->ASIC_TASK_MODULE.queue_high_water_mark = (uint16_t)queue_high_water_mark;
}

uint16_t ASIC_get_small_core_count(GlobalState * GLOBAL_STATE) {
    switch (GLOBAL_STATE->device_model) {
        case DEVICE_MAX:
            return BM1397_SMALL_CORE_COUNT;
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

uint8_t ASIC_get_job_midstate_capacity(GlobalState * GLOBAL_STATE)
{
    switch (GLOBAL_STATE->device_model) {
        case DEVICE_MAX:
            return 4;
        default:
            return 1;
    }
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
        case DEVICE_MAX:
            return BM1397_process_work(GLOBAL_STATE);
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
        case DEVICE_MAX:
            return BM1397_set_max_baud();
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
void ASIC_set_job_difficulty_mask(GlobalState * GLOBAL_STATE, uint8_t mask) {
    switch (GLOBAL_STATE->device_model) {
        case DEVICE_MAX:
            BM1397_set_job_difficulty_mask(mask);
            break;
        case DEVICE_ULTRA:
        case DEVICE_HEX:
            BM1366_set_job_difficulty_mask(mask);
            break;
        case DEVICE_SUPRA:
        case DEVICE_SUPRAHEX:
            BM1368_set_job_difficulty_mask(mask);
            break;
        case DEVICE_GAMMA:
        case DEVICE_GAMMATURBO:
            BM1370_set_job_difficulty_mask(mask);
            break;
        default:
    }
}

// .send_work_fn = BM1366_send_work,
void ASIC_send_work(GlobalState * GLOBAL_STATE, void * next_job) {
    switch (GLOBAL_STATE->device_model) {
        case DEVICE_MAX:
            BM1397_send_work(GLOBAL_STATE, next_job);
            break;
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
    return;
    }
}

// .set_version_mask = BM1366_set_version_mask
void ASIC_set_version_mask(GlobalState * GLOBAL_STATE, uint32_t mask) {
    mask &= ASIC_get_supported_version_mask(GLOBAL_STATE);

    switch (GLOBAL_STATE->device_model) {
        case DEVICE_MAX:
            BM1397_set_version_mask(mask);
            break;
        case DEVICE_ULTRA:
        case DEVICE_HEX:
            BM1366_set_version_mask(mask);
            break;
        case DEVICE_SUPRA:
        case DEVICE_SUPRAHEX:
            BM1368_set_version_mask(mask);
            break;
        case DEVICE_GAMMA:
        case DEVICE_GAMMATURBO:
            BM1370_set_version_mask(mask);
            break;
        default:
    return;
    }

    GLOBAL_STATE->version_mask = mask;
    ASIC_refresh_job_interval(GLOBAL_STATE);
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
        case ASIC_BM1397:
            // BM1397 doesn't have a set_frequency function yet
            ESP_LOGE(TAG, "Frequency transition not implemented for BM1397");
            success = false;
            break;
        default:
            ESP_LOGE(TAG, "Unknown ASIC model, cannot set frequency");
            success = false;
            break;
    }
    
    if (success) {
        GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value = target_frequency;
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
    uint8_t active_job_slots = ASIC_get_active_job_slot_count(GLOBAL_STATE->device_model);
    // Dispatch lifetime only scales with software-expanded header variants.
    // ASIC-side version rolling stays inside one resident job and must not extend dispatch interval math.
    uint8_t dispatch_span = version_rolling_mask_slots(0, GLOBAL_STATE->version_mask, ASIC_get_job_midstate_capacity(GLOBAL_STATE));
    double interval_ms = ASIC_calculate_job_interval_ms(
        GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value,
        parallel_work_units,
        asic_count,
        dispatch_span);
    interval_ms /= (double)active_job_slots;
    if (interval_ms < ((double)ASIC_DISPATCH_MIN_US / 1000.0)) {
        interval_ms = (double)ASIC_DISPATCH_MIN_US / 1000.0;
    }
    uint32_t target_interval_us = (uint32_t)llround(interval_ms * 1000.0);
    uint32_t current_interval_us;

    if (target_interval_us < ASIC_DISPATCH_MIN_US) {
        target_interval_us = ASIC_DISPATCH_MIN_US;
    }

    GLOBAL_STATE->asic_job_frequency_ms = interval_ms;
    GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_target_us = target_interval_us;
    GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_min_us = target_interval_us / 2;
    if (GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_min_us < ASIC_DISPATCH_MIN_US) {
        GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_min_us = ASIC_DISPATCH_MIN_US;
    }
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
             "ASIC job interval updated to %.2f ms (freq %.2f MHz, work units %" PRIu64 ", chips %u, dispatch span %u, active slots %u, queue %u/%u)",
             interval_ms,
             GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value,
             parallel_work_units,
             asic_count,
             dispatch_span,
             active_job_slots,
             (unsigned int)GLOBAL_STATE->ASIC_TASK_MODULE.queue_low_water_mark,
             (unsigned int)GLOBAL_STATE->ASIC_TASK_MODULE.queue_high_water_mark);
}

esp_err_t ASIC_set_device_model(GlobalState * GLOBAL_STATE) {

    if (GLOBAL_STATE->device_model_str == NULL) {
        ESP_LOGE(TAG, "No device model string found");
        return ESP_FAIL;
    }

    if (strcmp(GLOBAL_STATE->device_model_str, "max") == 0) {
        GLOBAL_STATE->asic_model = ASIC_BM1397;
        GLOBAL_STATE->ASIC_difficulty = BM1397_ASIC_DIFFICULTY;
        GLOBAL_STATE->device_model = DEVICE_MAX;
        ASIC_refresh_job_interval(GLOBAL_STATE);
        ESP_LOGI(TAG, "DEVICE: bitaxeMax");
        ESP_LOGI(TAG, "ASIC: %dx BM1397 (%" PRIu64 " cores)", BITAXE_MAX_ASIC_COUNT, BM1397_CORE_COUNT);

    } else if (strcmp(GLOBAL_STATE->device_model_str, "ultra") == 0) {
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
