#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "driver/gpio.h"
#include "esp_app_desc.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "lwip/inet.h"

#include "INA260.h"
#include "adc.h"
#include "asic.h"
#include "connect.h"
#include "display.h"
#include "i2c_bitaxe.h"
#include "input.h"
#include "nvs_config.h"
#include "screen.h"
#include "stratum_task.h"
#include "system.h"
#include "thermal.h"
#include "vcore.h"

static const char *TAG = "SystemModule";

static esp_netif_t *netif;

static esp_err_t ensure_overheat_mode_config(void);
static void _check_for_best_diff(GlobalState *GLOBAL_STATE, double diff);
static void _suffix_string(uint64_t val, char *buf, size_t bufsiz, int sigdigits);
static void reset_hashrate_history(SystemModule *module);
static bool hashrate_observation_is_active(GlobalState *GLOBAL_STATE);
static void append_hashrate_sample(GlobalState *GLOBAL_STATE);
static double calculate_observed_hashrate_ghs(const SystemModule *module, int64_t now_us);

void SYSTEM_init_system(GlobalState *GLOBAL_STATE)
{
    SystemModule *module = &GLOBAL_STATE->SYSTEM_MODULE;

    reset_hashrate_history(module);
    module->current_hashrate = 0;
    module->screen_page = 0;
    module->shares_accepted = 0;
    module->shares_rejected = 0;
    module->best_nonce_diff = nvs_config_get_u64(NVS_CONFIG_BEST_DIFF, 0);
    module->best_target_valid = false;
    module->best_session_nonce_diff = 0;
    module->best_session_target_valid = false;
    module->start_time = esp_timer_get_time();
    module->lastClockSync = 0;
    module->FOUND_BLOCK = false;

    module->pool_url = nvs_config_get_string(NVS_CONFIG_STRATUM_URL, CONFIG_STRATUM_URL);
    module->fallback_pool_url = nvs_config_get_string(NVS_CONFIG_FALLBACK_STRATUM_URL, CONFIG_FALLBACK_STRATUM_URL);
    module->pool_port = nvs_config_get_u16(NVS_CONFIG_STRATUM_PORT, CONFIG_STRATUM_PORT);
    module->fallback_pool_port = nvs_config_get_u16(NVS_CONFIG_FALLBACK_STRATUM_PORT, CONFIG_FALLBACK_STRATUM_PORT);
    module->pool_user = nvs_config_get_string(NVS_CONFIG_STRATUM_USER, CONFIG_STRATUM_USER);
    module->fallback_pool_user = nvs_config_get_string(NVS_CONFIG_FALLBACK_STRATUM_USER, CONFIG_FALLBACK_STRATUM_USER);
    module->pool_pass = nvs_config_get_string(NVS_CONFIG_STRATUM_PASS, CONFIG_STRATUM_PW);
    module->fallback_pool_pass = nvs_config_get_string(NVS_CONFIG_FALLBACK_STRATUM_PASS, CONFIG_FALLBACK_STRATUM_PW);
    module->is_using_fallback = false;

    module->overheat_mode = 0;
    ESP_LOGI(TAG, "Runtime overheat mode reset to: %d", module->overheat_mode);
    module->power_fault = 0;

    _suffix_string(module->best_nonce_diff, module->best_diff_string, DIFF_STRING_SIZE, 0);
    _suffix_string(module->best_session_nonce_diff, module->best_session_diff_string, DIFF_STRING_SIZE, 0);

    memset(module->best_target, 0xff, sizeof(module->best_target));
    memset(module->best_session_target, 0xff, sizeof(module->best_session_target));
    if (module->best_nonce_diff > 0) {
        difficulty_to_target_le(module->best_nonce_diff, module->best_target);
        module->best_target_valid = true;
    }

    memset(module->ssid, 0, sizeof(module->ssid));
    memset(module->wifi_status, 0, sizeof(module->wifi_status));
}

esp_err_t SYSTEM_init_peripherals(GlobalState *GLOBAL_STATE)
{
    uint16_t requested_core_voltage = nvs_config_get_u16(NVS_CONFIG_ASIC_VOLTAGE, CONFIG_ASIC_VOLTAGE);
    uint16_t startup_core_voltage = POWER_MANAGEMENT_get_startup_voltage_mv(
        ASIC_get_asic_count(GLOBAL_STATE),
        requested_core_voltage);

    ESP_RETURN_ON_ERROR(gpio_install_isr_service(0), TAG, "Error installing ISR service");
    ESP_RETURN_ON_ERROR(VCORE_init(GLOBAL_STATE), TAG, "VCORE init failed!");
    if (startup_core_voltage != requested_core_voltage) {
        ESP_LOGI(TAG,
                 "Applying startup warm-up voltage for multi-ASIC bring-up: requested %umV, using %umV",
                 requested_core_voltage,
                 startup_core_voltage);
    }
    ESP_RETURN_ON_ERROR(VCORE_set_voltage((float)startup_core_voltage / 1000.0f, GLOBAL_STATE), TAG, "VCORE set voltage failed!");
    ESP_RETURN_ON_ERROR(Thermal_init(GLOBAL_STATE->device_model, nvs_config_get_u16(NVS_CONFIG_INVERT_FAN_POLARITY, 1)), TAG, "Thermal init failed!");

    vTaskDelay(500 / portTICK_PERIOD_MS);
    ESP_RETURN_ON_ERROR(ensure_overheat_mode_config(), TAG, "Failed to ensure overheat_mode config");

    switch (GLOBAL_STATE->device_model) {
        case DEVICE_ULTRA:
        case DEVICE_SUPRA:
        case DEVICE_GAMMA:
        case DEVICE_GAMMATURBO:
        case DEVICE_HEX:
        case DEVICE_SUPRAHEX:
            if (display_init(GLOBAL_STATE) != ESP_OK || !GLOBAL_STATE->SYSTEM_MODULE.is_screen_active) {
                ESP_LOGW(TAG, "OLED init failed!");
            } else {
                ESP_LOGI(TAG, "OLED init success!");
            }
            break;
        default:
            break;
    }

    ESP_RETURN_ON_ERROR(input_init(screen_next, toggle_wifi_softap), TAG, "Input init failed!");
    ESP_RETURN_ON_ERROR(screen_start(GLOBAL_STATE), TAG, "Screen start failed!");

    netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    return ESP_OK;
}

void SYSTEM_notify_accepted_share(GlobalState *GLOBAL_STATE)
{
    GLOBAL_STATE->SYSTEM_MODULE.shares_accepted++;
}

static int compare_rejected_reason_stats(const void *a, const void *b)
{
    const RejectedReasonStat *ea = a;
    const RejectedReasonStat *eb = b;
    return (eb->count > ea->count) - (ea->count > eb->count);
}

void SYSTEM_notify_rejected_share(GlobalState *GLOBAL_STATE, char *error_msg)
{
    SystemModule *module = &GLOBAL_STATE->SYSTEM_MODULE;

    module->shares_rejected++;

    for (int i = 0; i < module->rejected_reason_stats_count; i++) {
        if (strncmp(module->rejected_reason_stats[i].message, error_msg, sizeof(module->rejected_reason_stats[i].message) - 1) == 0) {
            module->rejected_reason_stats[i].count++;
            return;
        }
    }

    size_t max_stats_count = sizeof(module->rejected_reason_stats) / sizeof(module->rejected_reason_stats[0]);
    if (module->rejected_reason_stats_count < (int)max_stats_count) {
        strncpy(module->rejected_reason_stats[module->rejected_reason_stats_count].message,
                error_msg,
                sizeof(module->rejected_reason_stats[module->rejected_reason_stats_count].message) - 1);
        module->rejected_reason_stats[module->rejected_reason_stats_count].message[sizeof(module->rejected_reason_stats[module->rejected_reason_stats_count].message) - 1] = '\0';
        module->rejected_reason_stats[module->rejected_reason_stats_count].count = 1;
        module->rejected_reason_stats_count++;
    }

    if (module->rejected_reason_stats_count > 1) {
        qsort(module->rejected_reason_stats, module->rejected_reason_stats_count,
              sizeof(module->rejected_reason_stats[0]), compare_rejected_reason_stats);
    }
}

void SYSTEM_notify_mining_started(GlobalState *GLOBAL_STATE)
{
    reset_hashrate_history(&GLOBAL_STATE->SYSTEM_MODULE);
    SYSTEM_update_hashrate_estimate(GLOBAL_STATE);
}

void SYSTEM_notify_new_ntime(GlobalState *GLOBAL_STATE, uint32_t ntime)
{
    SystemModule *module = &GLOBAL_STATE->SYSTEM_MODULE;

    if (module->lastClockSync + (60 * 60) > ntime) {
        return;
    }

    ESP_LOGI(TAG, "Syncing clock");
    module->lastClockSync = ntime;

    struct timeval tv;
    tv.tv_sec = ntime;
    tv.tv_usec = 0;
    settimeofday(&tv, NULL);
}

bool SYSTEM_is_potential_best_nonce(GlobalState *GLOBAL_STATE, const uint8_t hash[32])
{
    SystemModule *module = &GLOBAL_STATE->SYSTEM_MODULE;

    if (!module->best_session_target_valid || hash_meets_target(hash, module->best_session_target)) {
        return true;
    }

    if (!module->best_target_valid || hash_meets_target(hash, module->best_target)) {
        return true;
    }

    return false;
}

void SYSTEM_notify_found_nonce(GlobalState *GLOBAL_STATE, bool found_block, double found_diff)
{
    SystemModule *module = &GLOBAL_STATE->SYSTEM_MODULE;

    if (hashrate_observation_is_active(GLOBAL_STATE)) {
        append_hashrate_sample(GLOBAL_STATE);
        module->current_hashrate = calculate_observed_hashrate_ghs(module, esp_timer_get_time());
    }

    if (found_block) {
        module->FOUND_BLOCK = true;
    }

    if (found_diff >= 0.0) {
        _check_for_best_diff(GLOBAL_STATE, found_diff);
    }
}

void SYSTEM_reset_hashrate_estimate(GlobalState *GLOBAL_STATE)
{
    SystemModule *module = &GLOBAL_STATE->SYSTEM_MODULE;

    reset_hashrate_history(module);
    module->current_hashrate = 0.0;
}

void SYSTEM_update_hashrate_estimate(GlobalState *GLOBAL_STATE)
{
    SystemModule *module = &GLOBAL_STATE->SYSTEM_MODULE;

    if (!hashrate_observation_is_active(GLOBAL_STATE)) {
        SYSTEM_reset_hashrate_estimate(GLOBAL_STATE);
        return;
    }

    module->current_hashrate = calculate_observed_hashrate_ghs(module, esp_timer_get_time());
}

static void _check_for_best_diff(GlobalState *GLOBAL_STATE, double diff)
{
    SystemModule *module = &GLOBAL_STATE->SYSTEM_MODULE;
    uint64_t diff_u64 = (uint64_t)diff;

    if (diff_u64 == 0) {
        return;
    }

    if (diff_u64 > module->best_session_nonce_diff) {
        module->best_session_nonce_diff = diff_u64;
        difficulty_to_target_le(diff_u64, module->best_session_target);
        module->best_session_target_valid = true;
        _suffix_string(diff_u64, module->best_session_diff_string, DIFF_STRING_SIZE, 0);
    }

    if (diff_u64 <= module->best_nonce_diff) {
        return;
    }

    module->best_nonce_diff = diff_u64;
    difficulty_to_target_le(diff_u64, module->best_target);
    module->best_target_valid = true;
    nvs_config_set_u64(NVS_CONFIG_BEST_DIFF, module->best_nonce_diff);
    _suffix_string(diff_u64, module->best_diff_string, DIFF_STRING_SIZE, 0);
}

static void reset_hashrate_history(SystemModule *module)
{
    module->duration_start = 0.0;
    module->historical_hashrate_rolling_index = 0;
    module->historical_hashrate_init = 0;
    memset(module->historical_hashrate_time_stamps, 0, sizeof(module->historical_hashrate_time_stamps));
    memset(module->historical_hashrate, 0, sizeof(module->historical_hashrate));
}

static bool hashrate_observation_is_active(GlobalState *GLOBAL_STATE)
{
    uint8_t asic_count;
    uint16_t small_core_count;
    double frequency_mhz;

    if (!GLOBAL_STATE->ASIC_initalized || !GLOBAL_STATE->job_queue_initalized) {
        return false;
    }
    if (GLOBAL_STATE->sock < 0 || stratum_is_abandoning_work(GLOBAL_STATE)) {
        return false;
    }

    asic_count = ASIC_get_asic_count(GLOBAL_STATE);
    small_core_count = ASIC_get_small_core_count(GLOBAL_STATE);
    frequency_mhz = GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value;

    return asic_count > 0 && small_core_count > 0 && frequency_mhz > 0.0;
}

static void append_hashrate_sample(GlobalState *GLOBAL_STATE)
{
    SystemModule *module = &GLOBAL_STATE->SYSTEM_MODULE;
    int index = module->historical_hashrate_rolling_index;

    module->historical_hashrate[index] = (double)GLOBAL_STATE->ASIC_difficulty;
    module->historical_hashrate_time_stamps[index] = (double)esp_timer_get_time();
    module->historical_hashrate_rolling_index = (index + 1) % HISTORY_LENGTH;

    if (module->historical_hashrate_init < HISTORY_LENGTH) {
        module->historical_hashrate_init++;
    }
}

static double calculate_observed_hashrate_ghs(const SystemModule *module, int64_t now_us)
{
    int sample_count;
    int oldest_index;
    double sum = 0.0;
    double oldest_ts;
    double duration_s;

    if (module->historical_hashrate_init <= 0) {
        return 0.0;
    }

    sample_count = module->historical_hashrate_init;
    oldest_index = (sample_count < HISTORY_LENGTH) ? 0 : module->historical_hashrate_rolling_index;
    oldest_ts = module->historical_hashrate_time_stamps[oldest_index];
    if (oldest_ts <= 0.0) {
        return 0.0;
    }

    if (sample_count < HISTORY_LENGTH) {
        for (int i = 0; i < sample_count; i++) {
            sum += module->historical_hashrate[i];
        }
    } else {
        for (int i = 0; i < HISTORY_LENGTH; i++) {
            int idx = (module->historical_hashrate_rolling_index + i) % HISTORY_LENGTH;
            sum += module->historical_hashrate[idx];
        }
    }

    duration_s = ((double)now_us - oldest_ts) / 1000000.0;
    if (duration_s <= 0.0) {
        return 0.0;
    }

    return (sum * 4294967296.0) / (duration_s * 1000000000.0);
}

static void _suffix_string(uint64_t val, char *buf, size_t bufsiz, int sigdigits)
{
    const double dkilo = 1000.0;
    const uint64_t kilo = 1000ull;
    const uint64_t mega = 1000000ull;
    const uint64_t giga = 1000000000ull;
    const uint64_t tera = 1000000000000ull;
    const uint64_t peta = 1000000000000000ull;
    const uint64_t exa = 1000000000000000000ull;
    char suffix[2] = "";
    bool decimal = true;
    double dval;

    if (val >= exa) {
        val /= peta;
        dval = (double)val / dkilo;
        strcpy(suffix, "E");
    } else if (val >= peta) {
        val /= tera;
        dval = (double)val / dkilo;
        strcpy(suffix, "P");
    } else if (val >= tera) {
        val /= giga;
        dval = (double)val / dkilo;
        strcpy(suffix, "T");
    } else if (val >= giga) {
        val /= mega;
        dval = (double)val / dkilo;
        strcpy(suffix, "G");
    } else if (val >= mega) {
        val /= kilo;
        dval = (double)val / dkilo;
        strcpy(suffix, "M");
    } else if (val >= kilo) {
        dval = (double)val / dkilo;
        strcpy(suffix, "k");
    } else {
        dval = (double)val;
        decimal = false;
    }

    if (!sigdigits) {
        if (decimal) {
            snprintf(buf, bufsiz, "%.2f%s", dval, suffix);
        } else {
            snprintf(buf, bufsiz, "%d%s", (unsigned int)dval, suffix);
        }
    } else {
        int ndigits = sigdigits - 1 - (dval > 0.0 ? floor(log10(dval)) : 0);
        snprintf(buf, bufsiz, "%*.*f%s", sigdigits + 1, ndigits, dval, suffix);
    }
}

static esp_err_t ensure_overheat_mode_config(void)
{
    uint16_t overheat_mode = nvs_config_get_u16(NVS_CONFIG_OVERHEAT_MODE, UINT16_MAX);

    if (overheat_mode == UINT16_MAX) {
        nvs_config_set_u16(NVS_CONFIG_OVERHEAT_MODE, 0);
        ESP_LOGI(TAG, "Default value for overheat_mode set to 0");
    } else {
        ESP_LOGI(TAG, "Existing overheat_mode value: %d", overheat_mode);
    }

    return ESP_OK;
}
