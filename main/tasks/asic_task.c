#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "asic.h"
#include "global_state.h"
#include "system.h"
#include "work_queue.h"

static const char *TAG = "ASIC_task";

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
    memset(GLOBAL_STATE->ASIC_TASK_MODULE.retired_jobs, 0, sizeof(GLOBAL_STATE->ASIC_TASK_MODULE.retired_jobs));
    memset(GLOBAL_STATE->ASIC_TASK_MODULE.retired_job_next, 0, sizeof(GLOBAL_STATE->ASIC_TASK_MODULE.retired_job_next));
    memset(GLOBAL_STATE->ASIC_TASK_MODULE.job_history_revision, 0,
           sizeof(GLOBAL_STATE->ASIC_TASK_MODULE.job_history_revision));
    memset(GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_in_use, 0, sizeof(GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_in_use));
    GLOBAL_STATE->ASIC_TASK_MODULE.job_generator_task_handle = NULL;

    pthread_mutex_init(&GLOBAL_STATE->stratum_state_lock, NULL);
    pthread_mutex_init(&GLOBAL_STATE->stratum_socket_lock, NULL);
    pthread_mutex_init(&GLOBAL_STATE->job_history_lock, NULL);
    pthread_mutex_init(&GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_lock, NULL);
    pthread_mutex_init(&GLOBAL_STATE->ASIC_TASK_MODULE.asic_tx_lock, NULL);

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
    ASICDispatchConfig dispatch_config;

    if (!ASIC_init_job_resources(GLOBAL_STATE)) {
        ESP_LOGE(TAG, "ASIC job resources unavailable");
        vTaskDelete(NULL);
        return;
    }

    if (GLOBAL_STATE->ASIC_TASK_MODULE.semaphore == NULL) {
        GLOBAL_STATE->ASIC_TASK_MODULE.semaphore = xSemaphoreCreateBinary();
        if (GLOBAL_STATE->ASIC_TASK_MODULE.semaphore == NULL) {
            ESP_LOGE(TAG, "Failed to create ASIC dispatch semaphore");
            vTaskDelete(NULL);
            return;
        }
    }

    ASIC_get_dispatch_config(GLOBAL_STATE, &dispatch_config);
    if (dispatch_config.current_interval_us == 0) {
        ASIC_refresh_job_interval(GLOBAL_STATE);
        ASIC_get_dispatch_config(GLOBAL_STATE, &dispatch_config);
    }

    ESP_LOGI(TAG, "ASIC Job Interval: %.2f ms", (double)dispatch_config.current_interval_us / 1000.0);
    SYSTEM_notify_mining_started(GLOBAL_STATE);
    ESP_LOGI(TAG, "ASIC Ready!");

    while (1)
    {
        int queue_depth_after_send = 0;
        bm_job *next_bm_job = (bm_job *)queue_dequeue_with_count(
            &GLOBAL_STATE->ASIC_jobs_queue,
            &queue_depth_after_send);
        int64_t dispatch_started_us = esp_timer_get_time();
        uint32_t wait_us;
        TickType_t wait_ticks;
        BaseType_t wait_interrupted;

        ASIC_send_work(GLOBAL_STATE, next_bm_job);

        ASIC_get_dispatch_config(GLOBAL_STATE, &dispatch_config);

        if (GLOBAL_STATE->ASIC_TASK_MODULE.job_generator_task_handle != NULL &&
                queue_depth_after_send <= dispatch_config.queue_low_water_mark) {
            xTaskNotifyGive(GLOBAL_STATE->ASIC_TASK_MODULE.job_generator_task_handle);
        }

        wait_us = dispatch_config.current_interval_us;
        if (wait_us == 0) {
            wait_us = dispatch_config.target_interval_us;
        }
        if (wait_us == 0) {
            wait_us = 1000;
        }

        int64_t elapsed_us = esp_timer_get_time() - dispatch_started_us;
        uint32_t remaining_us = elapsed_us < (int64_t)wait_us
                                    ? wait_us - (uint32_t)elapsed_us
                                    : 0;
        wait_ticks = pdMS_TO_TICKS(remaining_us / 1000U);
        wait_interrupted = xSemaphoreTake(GLOBAL_STATE->ASIC_TASK_MODULE.semaphore,
                                          wait_ticks);
        if (wait_interrupted == pdFALSE) {
            int64_t deadline_us = dispatch_started_us + wait_us;
            int64_t precise_remaining_us = deadline_us - esp_timer_get_time();

            if (precise_remaining_us > 0) {
                esp_rom_delay_us((uint32_t)precise_remaining_us);
            }
        }
    }
}
