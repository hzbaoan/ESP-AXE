#ifndef POWER_MANAGEMENT_TASK_H_
#define POWER_MANAGEMENT_TASK_H_

#include <stdbool.h>
#include <stdint.h>

#define POWER_MANAGEMENT_STARTUP_WARMUP_VOLTAGE_MV 1250U
#define POWER_MANAGEMENT_STARTUP_WARMUP_DURATION_MS (60ULL * 1000ULL)

typedef struct
{
    uint16_t fan_perc;
    uint16_t fan_rpm;
    float chip_temp[6];
    float chip_temp_avg;
    float vr_temp;
    float voltage;
    float frequency_multiplier;
    float frequency_value;
    float power;
    float current;
    bool thermal_protect_active;
    uint64_t thermal_protect_since_ms;
} PowerManagementModule;

bool POWER_MANAGEMENT_should_apply_startup_warmup(uint8_t asic_count, uint16_t requested_core_voltage_mv);
uint16_t POWER_MANAGEMENT_get_startup_voltage_mv(uint8_t asic_count, uint16_t requested_core_voltage_mv);
void POWER_MANAGEMENT_task(void * pvParameters);

#endif
