#include "frequency_transition_bmXX.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <math.h>

const char *FREQUENCY_TRANSITION_TAG = "frequency_transition";

static float current_frequency = 56.25;

void reset_frequency_transition(void)
{
    current_frequency = 56.25f;
}

bool do_frequency_transition(float target_frequency, set_hash_frequency_fn set_frequency_fn,
                             int asic_type, float *actual_frequency)
{
    float command_frequency;
    float applied_frequency = current_frequency;
    const float step = 6.25f;

    if (actual_frequency != NULL) {
        *actual_frequency = current_frequency;
    }
    if (set_frequency_fn == NULL || target_frequency <= 0.0f) {
        ESP_LOGE(FREQUENCY_TRANSITION_TAG, "Invalid function pointer provided");
        return false;
    }

    command_frequency = current_frequency;
    while (fabsf(command_frequency - target_frequency) > 0.001f) {
        float delta = target_frequency - command_frequency;
        float next_command = command_frequency + (delta > 0.0f ? step : -step);

        if ((delta > 0.0f && next_command > target_frequency) ||
                (delta < 0.0f && next_command < target_frequency)) {
            next_command = target_frequency;
        }

        applied_frequency = set_frequency_fn(next_command);
        if (applied_frequency <= 0.0f) {
            ESP_LOGE(FREQUENCY_TRANSITION_TAG,
                     "ASIC type %d frequency transition stopped at %.2f MHz while requesting %.2f MHz",
                     asic_type,
                     current_frequency,
                     next_command);
            if (actual_frequency != NULL) {
                *actual_frequency = current_frequency;
            }
            return false;
        }

        command_frequency = next_command;
        current_frequency = applied_frequency;
        if (fabsf(command_frequency - target_frequency) > 0.001f) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }

    if (actual_frequency != NULL) {
        *actual_frequency = applied_frequency;
    }
    ESP_LOGI(FREQUENCY_TRANSITION_TAG,
             "ASIC type %d frequency transition complete: requested %.2f MHz, applied %.2f MHz",
             asic_type,
             target_frequency,
             applied_frequency);
    return true;
}
