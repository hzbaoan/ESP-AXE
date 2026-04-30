#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "asic.h"
#include "global_state.h"
#include "stratum_task.h"
#include "system.h"
#include "work_queue.h"

static const char *TAG = "ASIC_task";
static const uint32_t ASIC_FEEDBACK_STEP_US = 250;

#ifdef CONFIG_STRICT_HEADER_COVERAGE
#define STRICT_HEADER_COVERAGE_ENABLED 1
#else
#define STRICT_HEADER_COVERAGE_ENABLED 0
#endif

static uint32_t clamp_u32(uint32_t value, uint32_t min_value, uint32_t max_value)
{
    if (value < min_value) {
        return min_value;
    }
    if (value > max_value) {
        return max_value;
    }
    return value;
}

static void ASIC_feedback_update_interval(GlobalState *GLOBAL_STATE, uint32_t dequeue_wait_us, int queue_depth_after_send)
{
    AsicTaskModule *module = &GLOBAL_STATE->ASIC_TASK_MODULE;
    uint32_t current_us = module->dispatch_interval_current_us;
    uint32_t target_us = module->dispatch_interval_target_us;
    uint32_t step;

    if (current_us == 0 || target_us == 0) {
        return;
    }

    if (STRICT_HEADER_COVERAGE_ENABLED) {
        (void)dequeue_wait_us;
        (void)queue_depth_after_send;

        if (current_us != target_us) {
            ASIC_set_dispatch_interval(GLOBAL_STATE, target_us);
        }
        return;
    }

    if (stratum_is_abandoning_work(GLOBAL_STATE) || queue_count(&GLOBAL_STATE->stratum_queue) > 0) {
        if (current_us != target_us) {
            ASIC_set_dispatch_interval(GLOBAL_STATE, target_us);
        }
        return;
    }

    if (dequeue_wait_us > (current_us / 2) || queue_depth_after_send <= 1) {
        step = current_us / 8;
        if (step < ASIC_FEEDBACK_STEP_US) {
            step = ASIC_FEEDBACK_STEP_US;
        }
        current_us = clamp_u32(current_us + step, module->dispatch_interval_min_us, module->dispatch_interval_max_us);
    } else if (queue_depth_after_send > module->queue_high_water_mark) {
        step = current_us / 10;
        if (step < ASIC_FEEDBACK_STEP_US) {
            step = ASIC_FEEDBACK_STEP_US;
        }
        if (current_us > step) {
            current_us -= step;
        }
        current_us = clamp_u32(current_us, module->dispatch_interval_min_us, module->dispatch_interval_max_us);
    } else if (current_us > target_us && queue_depth_after_send >= module->queue_low_water_mark) {
        step = (current_us - target_us) / 4;
        if (step < ASIC_FEEDBACK_STEP_US) {
            step = ASIC_FEEDBACK_STEP_US;
        }
        if (current_us > step) {
            current_us -= step;
        }
        if (current_us < target_us) {
            current_us = target_us;
        }
    } else if (current_us < target_us && queue_depth_after_send < module->queue_low_water_mark) {
        step = (target_us - current_us) / 4;
        if (step < ASIC_FEEDBACK_STEP_US) {
            step = ASIC_FEEDBACK_STEP_US;
        }
        current_us += step;
        if (current_us > target_us) {
            current_us = target_us;
        }
    }

    if (current_us != module->dispatch_interval_current_us) {
        ASIC_set_dispatch_interval(GLOBAL_STATE, current_us);
    }
}

static bool job_is_from_pool(GlobalState *GLOBAL_STATE, const bm_job *job)
{
    if (GLOBAL_STATE->ASIC_TASK_MODULE.job_pool == NULL) {
        return false;
    }

    uintptr_t pool_start = (uintptr_t)GLOBAL_STATE->ASIC_TASK_MODULE.job_pool;
    uintptr_t pool_end = (uintptr_t)(GLOBAL_STATE->ASIC_TASK_MODULE.job_pool + ASIC_JOB_POOL_SIZE);
    uintptr_t job_ptr = (uintptr_t)job;

    return job_ptr >= pool_start && job_ptr < pool_end;
}

bool ASIC_init_job_resources(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;

    if (GLOBAL_STATE->job_queue_initalized) {
        return true;
    }

    if (GLOBAL_STATE->ASIC_TASK_MODULE.job_pool == NULL) {
        const size_t pool_size = ASIC_JOB_POOL_SIZE * sizeof(bm_job);

        if (!GLOBAL_STATE->psram_is_available) {
            ESP_LOGE(TAG, "PSRAM is required for ASIC job pool (%u bytes)", (unsigned int)pool_size);
            return false;
        }

        GLOBAL_STATE->ASIC_TASK_MODULE.job_pool = heap_caps_calloc(
            ASIC_JOB_POOL_SIZE, sizeof(bm_job), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (GLOBAL_STATE->ASIC_TASK_MODULE.job_pool != NULL) {
            ESP_LOGD(TAG, "Allocated ASIC job pool in PSRAM (%u bytes)", (unsigned int)pool_size);
        }

        if (GLOBAL_STATE->ASIC_TASK_MODULE.job_pool == NULL) {
            ESP_LOGE(TAG, "Failed to allocate ASIC job pool in PSRAM (%u bytes)", (unsigned int)pool_size);
            return false;
        }
    }

    memset(GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs, 0, sizeof(GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs));
    memset(GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_in_use, 0, sizeof(GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_in_use));
    memset(GLOBAL_STATE->valid_jobs, 0, sizeof(GLOBAL_STATE->valid_jobs));
    GLOBAL_STATE->ASIC_TASK_MODULE.job_generator_task_handle = NULL;

    pthread_mutex_init(&GLOBAL_STATE->stratum_state_lock, NULL);
    pthread_mutex_init(&GLOBAL_STATE->valid_jobs_lock, NULL);
    pthread_mutex_init(&GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_lock, NULL);

    GLOBAL_STATE->job_queue_initalized = true;
    return true;
}

bm_job *ASIC_job_pool_acquire(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;
    bm_job *slot = NULL;

    if (GLOBAL_STATE->ASIC_TASK_MODULE.job_pool == NULL) {
        return NULL;
    }

    pthread_mutex_lock(&GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_lock);
    for (int i = 0; i < ASIC_JOB_POOL_SIZE; i++) {
        if (GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_in_use[i] == 0) {
            GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_in_use[i] = 1;
            slot = &GLOBAL_STATE->ASIC_TASK_MODULE.job_pool[i];
            memset(slot, 0, sizeof(*slot));
            break;
        }
    }
    pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_lock);

    return slot;
}

void ASIC_job_pool_release(void *pvParameters, bm_job *job)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;

    if (job == NULL || !job_is_from_pool(GLOBAL_STATE, job)) {
        return;
    }

    size_t index = (size_t)(job - GLOBAL_STATE->ASIC_TASK_MODULE.job_pool);

    pthread_mutex_lock(&GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_lock);
    if (GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_in_use[index] == 0) {
        pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_lock);
        ESP_LOGW(TAG, "Ignoring duplicate release for ASIC job pool slot %u", (unsigned int)index);
        return;
    }
    memset(job, 0, sizeof(*job));
    GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_in_use[index] = 0;
    pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_lock);
}

void ASIC_task(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;

    if (!ASIC_init_job_resources(GLOBAL_STATE)) {
        ESP_LOGE(TAG, "ASIC job resources unavailable");
        vTaskDelete(NULL);
        return;
    }

    if (GLOBAL_STATE->ASIC_TASK_MODULE.semaphore == NULL) {
        GLOBAL_STATE->ASIC_TASK_MODULE.semaphore = xSemaphoreCreateBinary();
    }

    if (GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_current_us == 0) {
        ASIC_refresh_job_interval(GLOBAL_STATE);
    }

    ESP_LOGI(TAG, "ASIC Job Interval: %.2f ms", (double)GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_current_us / 1000.0);
    SYSTEM_notify_mining_started(GLOBAL_STATE);
    ESP_LOGI(TAG, "ASIC Ready!");

    while (1)
    {
        int64_t dequeue_start_us = esp_timer_get_time();
        int queue_depth_after_send = 0;
        bm_job *next_bm_job = (bm_job *)queue_dequeue_with_count(
            &GLOBAL_STATE->ASIC_jobs_queue,
            &queue_depth_after_send);
        uint32_t dequeue_wait_us = (uint32_t)(esp_timer_get_time() - dequeue_start_us);
        uint32_t wait_us;
        TickType_t wait_ticks;

        ASIC_send_work(GLOBAL_STATE, next_bm_job);

        if (GLOBAL_STATE->ASIC_TASK_MODULE.job_generator_task_handle != NULL &&
                queue_depth_after_send <= GLOBAL_STATE->ASIC_TASK_MODULE.queue_low_water_mark) {
            xTaskNotifyGive(GLOBAL_STATE->ASIC_TASK_MODULE.job_generator_task_handle);
        }

        ASIC_feedback_update_interval(GLOBAL_STATE, dequeue_wait_us, queue_depth_after_send);

        wait_us = GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_current_us;
        if (wait_us == 0) {
            wait_us = GLOBAL_STATE->ASIC_TASK_MODULE.dispatch_interval_target_us;
        }
        if (wait_us == 0) {
            wait_us = 1000;
        }

        wait_ticks = pdMS_TO_TICKS((wait_us + 999) / 1000);
        if (wait_ticks == 0) {
            wait_ticks = 1;
        }
        xSemaphoreTake(GLOBAL_STATE->ASIC_TASK_MODULE.semaphore, wait_ticks);
    }
}
