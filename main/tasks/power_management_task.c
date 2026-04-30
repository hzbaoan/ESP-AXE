#include <math.h>
#include <string.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "asic.h"
#include "global_state.h"
#include "nvs_config.h"
#include "power.h"
#include "system.h"
#include "thermal.h"
#include "vcore.h"

#define POLL_RATE_MS 2000
#define THROTTLE_TEMP 79.0f
#define THROTTLE_VR_TEMP 105.0f
#define HARD_STOP_TEMP 85.0f
#define HARD_STOP_VR_TEMP 115.0f
#define OVERHEAT_RECOVERY_TEMP 74.0f
#define OVERHEAT_RECOVERY_VR_TEMP 100.0f
#define OVERHEAT_PROTECT_FREQUENCY_MHZ 50
#define OVERHEAT_PROTECT_VOLTAGE_MV 1000
#define HARD_STOP_TIMEOUT_MS (15ULL * 1000ULL)
#define RECOVERY_HOLD_MS (30ULL * 1000ULL)
#define THERMAL_FREQ_STEP_MHZ 5U

static const char *TAG = "power_management";

static uint64_t monotonic_time_ms(void)
{
    return (uint64_t)(esp_timer_get_time() / 1000ULL);
}

static float clamp_ratiof(float value)
{
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

static float calculate_throttle_ratio(float temperature, float throttle_temp, float hard_stop_temp)
{
    float range = hard_stop_temp - throttle_temp;

    if (range <= 0.0f) {
        return 1.0f;
    }

    return clamp_ratiof((temperature - throttle_temp) / range);
}

static uint16_t quantize_frequency_step(uint16_t frequency_mhz)
{
    if (frequency_mhz <= OVERHEAT_PROTECT_FREQUENCY_MHZ) {
        return OVERHEAT_PROTECT_FREQUENCY_MHZ;
    }

    frequency_mhz = (uint16_t)((frequency_mhz / THERMAL_FREQ_STEP_MHZ) * THERMAL_FREQ_STEP_MHZ);
    if (frequency_mhz < OVERHEAT_PROTECT_FREQUENCY_MHZ) {
        return OVERHEAT_PROTECT_FREQUENCY_MHZ;
    }

    return frequency_mhz;
}

static uint16_t calculate_thermal_frequency_cap(uint16_t requested_frequency_mhz, float chip_temp, float vr_temp)
{
    if (requested_frequency_mhz <= OVERHEAT_PROTECT_FREQUENCY_MHZ) {
        return requested_frequency_mhz;
    }

    float chip_ratio = calculate_throttle_ratio(chip_temp, THROTTLE_TEMP, HARD_STOP_TEMP);
    float vr_ratio = calculate_throttle_ratio(vr_temp, THROTTLE_VR_TEMP, HARD_STOP_VR_TEMP);
    float throttle_ratio = fmaxf(chip_ratio, vr_ratio);

    if (throttle_ratio <= 0.0f) {
        return requested_frequency_mhz;
    }

    uint32_t frequency_range = requested_frequency_mhz - OVERHEAT_PROTECT_FREQUENCY_MHZ;
    float capped_frequency_f =
        (float)requested_frequency_mhz - ((float)frequency_range * throttle_ratio);
    uint16_t capped_frequency = (uint16_t)capped_frequency_f;

    if (capped_frequency >= requested_frequency_mhz) {
        capped_frequency = requested_frequency_mhz - 1U;
    }

    capped_frequency = quantize_frequency_step(capped_frequency);
    if (capped_frequency >= requested_frequency_mhz) {
        if (requested_frequency_mhz > THERMAL_FREQ_STEP_MHZ) {
            capped_frequency =
                quantize_frequency_step((uint16_t)(requested_frequency_mhz - THERMAL_FREQ_STEP_MHZ));
        } else {
            capped_frequency = OVERHEAT_PROTECT_FREQUENCY_MHZ;
        }
    }

    return capped_frequency;
}

bool POWER_MANAGEMENT_should_apply_startup_warmup(uint8_t asic_count, uint16_t requested_core_voltage_mv)
{
    return asic_count > 1 &&
           requested_core_voltage_mv < POWER_MANAGEMENT_STARTUP_WARMUP_VOLTAGE_MV;
}

uint16_t POWER_MANAGEMENT_get_startup_voltage_mv(uint8_t asic_count, uint16_t requested_core_voltage_mv)
{
    if (POWER_MANAGEMENT_should_apply_startup_warmup(asic_count, requested_core_voltage_mv)) {
        return POWER_MANAGEMENT_STARTUP_WARMUP_VOLTAGE_MV;
    }

    return requested_core_voltage_mv;
}

// Set the fan speed between 20% min and 100% max based on chip temperature as input.
// The fan speed increases from 20% to 100% proportionally to the temperature increase from 50 and THROTTLE_TEMP
static double automatic_fan_speed(float chip_temp, GlobalState *GLOBAL_STATE)
{
    double result = 0.0;
    double min_temp = 40.0;
    double min_fan_speed = 38.0;

    if (chip_temp < min_temp) {
        result = min_fan_speed;
    } else if (chip_temp >= THROTTLE_TEMP) {
        result = 100.0;
    } else {
        double temp_range = THROTTLE_TEMP - min_temp;
        double fan_range = 100.0 - min_fan_speed;
        result = ((chip_temp - min_temp) / temp_range) * fan_range + min_fan_speed;
    }

    GLOBAL_STATE->POWER_MANAGEMENT_MODULE.fan_perc = (uint16_t)result;
    Thermal_set_fan_percent(GLOBAL_STATE->device_model, (float)(result / 100.0));

    return result;
}

void POWER_MANAGEMENT_task(void *pvParameters)
{
    ESP_LOGI(TAG, "Starting");

    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;
    PowerManagementModule *power_management = &GLOBAL_STATE->POWER_MANAGEMENT_MODULE;
    SystemModule *sys_module = &GLOBAL_STATE->SYSTEM_MODULE;

    power_management->frequency_multiplier = 1;
    power_management->thermal_protect_active = false;
    power_management->thermal_protect_since_ms = 0;
    sys_module->overheat_mode = 0;

    vTaskDelay(pdMS_TO_TICKS(500));

    uint8_t asic_count = ASIC_get_asic_count(GLOBAL_STATE);
    uint16_t last_core_voltage = 0;
    uint16_t last_asic_frequency = (uint16_t)power_management->frequency_value;
    uint64_t recovery_since_ms = 0;
    bool thermal_shutdown_latched = false;
    float protect_entry_chip_temp = 0.0f;
    float protect_entry_vr_temp = 0.0f;
    uint16_t startup_requested_voltage =
        nvs_config_get_u16_clamped(NVS_CONFIG_ASIC_VOLTAGE,
                                   CONFIG_ASIC_VOLTAGE,
                                   NVS_CONFIG_ASIC_VOLTAGE_MIN_MV,
                                   NVS_CONFIG_ASIC_VOLTAGE_MAX_MV);
    bool startup_warmup_active =
        POWER_MANAGEMENT_should_apply_startup_warmup(asic_count, startup_requested_voltage);
    uint64_t startup_warmup_started_ms = monotonic_time_ms();

    if (startup_warmup_active) {
        ESP_LOGI(TAG,
                 "Startup warm-up enabled for %u ASICs: forcing vcore to %umV for %llums",
                 asic_count,
                 POWER_MANAGEMENT_STARTUP_WARMUP_VOLTAGE_MV,
                 (unsigned long long)POWER_MANAGEMENT_STARTUP_WARMUP_DURATION_MS);
    }

    while (1) {
        power_management->voltage = Power_get_input_voltage(GLOBAL_STATE);
        power_management->power = Power_get_power(GLOBAL_STATE);
        power_management->current = Power_get_current(GLOBAL_STATE);
        power_management->fan_rpm = Thermal_get_fan_speed(GLOBAL_STATE->device_model);
        power_management->chip_temp_avg = Thermal_get_chip_temp(GLOBAL_STATE);
        power_management->vr_temp = Power_get_vreg_temp(GLOBAL_STATE);

        uint64_t now_ms = monotonic_time_ms();
        bool overheat_triggered =
            power_management->chip_temp_avg > THROTTLE_TEMP ||
            power_management->vr_temp > THROTTLE_VR_TEMP;
        bool overheat_cleared =
            power_management->chip_temp_avg < OVERHEAT_RECOVERY_TEMP &&
            power_management->vr_temp < OVERHEAT_RECOVERY_VR_TEMP;
        bool hard_stop_threshold_reached =
            power_management->chip_temp_avg > HARD_STOP_TEMP ||
            power_management->vr_temp > HARD_STOP_VR_TEMP;

        if (!thermal_shutdown_latched &&
                !power_management->thermal_protect_active &&
                overheat_triggered) {
            power_management->thermal_protect_active = true;
            power_management->thermal_protect_since_ms = now_ms;
            recovery_since_ms = 0;
            protect_entry_chip_temp = power_management->chip_temp_avg;
            protect_entry_vr_temp = power_management->vr_temp;

            ESP_LOGW(TAG,
                     "Thermal protection enabled. VR: %.1fC ASIC: %.1fC",
                     power_management->vr_temp,
                     power_management->chip_temp_avg);
        }

        if (!thermal_shutdown_latched && power_management->thermal_protect_active) {
            bool chip_not_cooling = protect_entry_chip_temp > THROTTLE_TEMP &&
                                    power_management->chip_temp_avg >= protect_entry_chip_temp;
            bool vr_not_cooling = protect_entry_vr_temp > THROTTLE_VR_TEMP &&
                                  power_management->vr_temp >= protect_entry_vr_temp;

            if (hard_stop_threshold_reached ||
                    ((now_ms - power_management->thermal_protect_since_ms) >= HARD_STOP_TIMEOUT_MS &&
                     (chip_not_cooling || vr_not_cooling))) {
                ESP_LOGE(TAG,
                         "Thermal hard stop triggered. VR: %.1fC ASIC: %.1fC",
                         power_management->vr_temp,
                         power_management->chip_temp_avg);
                Power_disable(GLOBAL_STATE);
                power_management->frequency_value = 0;
                SYSTEM_update_hashrate_estimate(GLOBAL_STATE);
                thermal_shutdown_latched = true;
                recovery_since_ms = 0;
                last_core_voltage = 0;
                last_asic_frequency = 0;
            } else if (overheat_cleared) {
                if (recovery_since_ms == 0) {
                    recovery_since_ms = now_ms;
                } else if ((now_ms - recovery_since_ms) >= RECOVERY_HOLD_MS) {
                    power_management->thermal_protect_active = false;
                    power_management->thermal_protect_since_ms = 0;
                    recovery_since_ms = 0;
                    ESP_LOGI(TAG,
                             "Thermal protection cleared. VR: %.1fC ASIC: %.1fC",
                             power_management->vr_temp,
                             power_management->chip_temp_avg);
                }
            } else {
                recovery_since_ms = 0;
            }
        }

        if (thermal_shutdown_latched) {
            if (overheat_cleared) {
                if (recovery_since_ms == 0) {
                    recovery_since_ms = now_ms;
                } else if ((now_ms - recovery_since_ms) >= RECOVERY_HOLD_MS) {
                    ESP_LOGW(TAG,
                             "Thermal hard stop cooled down. Restarting controller to safely reinitialize ASICs.");
                    vTaskDelay(pdMS_TO_TICKS(100));
                    esp_restart();
                }
            } else {
                recovery_since_ms = 0;
            }
        }

        sys_module->overheat_mode =
            (power_management->thermal_protect_active || thermal_shutdown_latched) ? 1 : 0;

        if (sys_module->overheat_mode) {
            power_management->fan_perc = 100;
            Thermal_set_fan_percent(GLOBAL_STATE->device_model, 1.0f);
        } else if (nvs_config_get_u16(NVS_CONFIG_AUTO_FAN_SPEED, 1) == 1) {
            power_management->fan_perc =
                (uint16_t)automatic_fan_speed(power_management->chip_temp_avg, GLOBAL_STATE);
        } else {
            float fan_speed =
                (float)nvs_config_get_u16_clamped(NVS_CONFIG_FAN_SPEED,
                                                  100,
                                                  NVS_CONFIG_FAN_SPEED_MIN_PERCENT,
                                                  NVS_CONFIG_FAN_SPEED_MAX_PERCENT);
            power_management->fan_perc = (uint16_t)fan_speed;
            Thermal_set_fan_percent(GLOBAL_STATE->device_model, fan_speed / 100.0f);
        }

        uint16_t user_core_voltage =
            nvs_config_get_u16_clamped(NVS_CONFIG_ASIC_VOLTAGE,
                                       CONFIG_ASIC_VOLTAGE,
                                       NVS_CONFIG_ASIC_VOLTAGE_MIN_MV,
                                       NVS_CONFIG_ASIC_VOLTAGE_MAX_MV);
        uint16_t user_asic_frequency =
            nvs_config_get_u16_clamped(NVS_CONFIG_ASIC_FREQ,
                                       CONFIG_ASIC_FREQUENCY,
                                       NVS_CONFIG_ASIC_FREQUENCY_MIN_MHZ,
                                       NVS_CONFIG_ASIC_FREQUENCY_MAX_MHZ);
        uint16_t target_core_voltage = user_core_voltage;
        uint16_t target_asic_frequency = user_asic_frequency;
        bool startup_warmup_forcing_voltage = false;

        if (startup_warmup_active) {
            uint64_t warmup_elapsed_ms = now_ms - startup_warmup_started_ms;
            if (warmup_elapsed_ms < POWER_MANAGEMENT_STARTUP_WARMUP_DURATION_MS) {
                uint16_t warmup_voltage =
                    POWER_MANAGEMENT_get_startup_voltage_mv(asic_count, user_core_voltage);
                if (warmup_voltage > target_core_voltage) {
                    target_core_voltage = warmup_voltage;
                    startup_warmup_forcing_voltage = true;
                }
            } else {
                startup_warmup_active = false;
                ESP_LOGI(TAG,
                         "Startup warm-up window expired after %llums. Returning to normal vcore control (configured %umV)",
                         (unsigned long long)warmup_elapsed_ms,
                         user_core_voltage);
            }
        }

        if (power_management->thermal_protect_active) {
            target_asic_frequency = calculate_thermal_frequency_cap(
                user_asic_frequency,
                power_management->chip_temp_avg,
                power_management->vr_temp);
        }

        if (thermal_shutdown_latched) {
            target_core_voltage = 0;
            target_asic_frequency = 0;
        }

        if (target_core_voltage != last_core_voltage) {
            if (thermal_shutdown_latched) {
                ESP_LOGW(TAG, "Thermal hard stop leaving ASIC core voltage disabled");
            } else if (startup_warmup_forcing_voltage) {
                ESP_LOGI(TAG, "Startup warm-up active: forcing vcore voltage to %umV", target_core_voltage);
            } else {
                ESP_LOGI(TAG, "Setting new vcore voltage to %umV", target_core_voltage);
            }

            if (VCORE_set_voltage((float)target_core_voltage / 1000.0f, GLOBAL_STATE) == ESP_OK) {
                last_core_voltage = target_core_voltage;
            }
        }

        if (!thermal_shutdown_latched && target_asic_frequency != last_asic_frequency) {
            if (power_management->thermal_protect_active) {
                ESP_LOGW(TAG,
                         "Thermal protection capping ASIC frequency to %uMHz (requested %uMHz, VR %.1fC, ASIC %.1fC)",
                         target_asic_frequency,
                         user_asic_frequency,
                         power_management->vr_temp,
                         power_management->chip_temp_avg);
            } else {
                ESP_LOGI(TAG,
                         "New ASIC frequency requested: %uMHz (current: %uMHz)",
                         target_asic_frequency,
                         last_asic_frequency);
            }

            if (ASIC_set_frequency(GLOBAL_STATE, (float)target_asic_frequency)) {
                last_asic_frequency = target_asic_frequency;
            }
        }

        if (!thermal_shutdown_latched) {
            VCORE_check_fault(GLOBAL_STATE);
        }
        vTaskDelay(pdMS_TO_TICKS(POLL_RATE_MS));
    }
}
