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
static double estimate_hashrate_ghs(GlobalState *GLOBAL_STATE);

void SYSTEM_init_system(GlobalState *GLOBAL_STATE)
{
    SystemModule *module = &GLOBAL_STATE->SYSTEM_MODULE;

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
        case DEVICE_MAX:
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

    if (found_block) {
        module->FOUND_BLOCK = true;
    }

    if (found_diff >= 0.0) {
        _check_for_best_diff(GLOBAL_STATE, found_diff);
    }
}

void SYSTEM_update_hashrate_estimate(GlobalState *GLOBAL_STATE)
{
    GLOBAL_STATE->SYSTEM_MODULE.current_hashrate = estimate_hashrate_ghs(GLOBAL_STATE);
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

static double estimate_hashrate_ghs(GlobalState *GLOBAL_STATE)
{
    if (!GLOBAL_STATE->ASIC_initalized || !GLOBAL_STATE->job_queue_initalized) {
        return 0.0;
    }

    if (GLOBAL_STATE->sock < 0 || stratum_is_abandoning_work(GLOBAL_STATE)) {
        return 0.0;
    }

    uint8_t asic_count = ASIC_get_asic_count(GLOBAL_STATE);
    uint16_t small_core_count = ASIC_get_small_core_count(GLOBAL_STATE);
    double frequency_mhz = GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value;

    if (asic_count == 0 || small_core_count == 0 || frequency_mhz <= 0.0) {
        return 0.0;
    }

    return (frequency_mhz * (double)small_core_count * (double)asic_count) / 1000.0;
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
