#include <math.h>
#include <string.h>

#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "asic.h"
#include "global_state.h"
#include "system.h"
#include "work_queue.h"

static const char *TAG = "ASIC_task";

static bool job_is_from_pool(GlobalState *GLOBAL_STATE, const bm_job *job)
{
    uintptr_t pool_start = (uintptr_t)GLOBAL_STATE->ASIC_TASK_MODULE.job_pool;
    uintptr_t pool_end = (uintptr_t)(GLOBAL_STATE->ASIC_TASK_MODULE.job_pool + ASIC_JOB_POOL_SIZE);
    uintptr_t job_ptr = (uintptr_t)job;

    return job_ptr >= pool_start && job_ptr < pool_end;
}

void ASIC_init_job_resources(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;

    if (GLOBAL_STATE->job_queue_initalized) {
        return;
    }

    memset(GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs, 0, sizeof(GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs));
    memset(GLOBAL_STATE->ASIC_TASK_MODULE.job_pool, 0, sizeof(GLOBAL_STATE->ASIC_TASK_MODULE.job_pool));
    memset(GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_in_use, 0, sizeof(GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_in_use));
    memset(GLOBAL_STATE->valid_jobs, 0, sizeof(GLOBAL_STATE->valid_jobs));

    pthread_mutex_init(&GLOBAL_STATE->valid_jobs_lock, NULL);
    pthread_mutex_init(&GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_lock, NULL);

    GLOBAL_STATE->job_queue_initalized = true;
}

bm_job *ASIC_job_pool_acquire(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;
    bm_job *slot = NULL;

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
    memset(job, 0, sizeof(*job));
    GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_in_use[index] = 0;
    pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_lock);
}

void ASIC_task(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;

    ASIC_init_job_resources(GLOBAL_STATE);

    if (GLOBAL_STATE->ASIC_TASK_MODULE.semaphore == NULL) {
        GLOBAL_STATE->ASIC_TASK_MODULE.semaphore = xSemaphoreCreateBinary();
    }

    ESP_LOGI(TAG, "ASIC Job Interval: %.2f ms", GLOBAL_STATE->asic_job_frequency_ms);
    SYSTEM_notify_mining_started(GLOBAL_STATE);
    ESP_LOGI(TAG, "ASIC Ready!");

    while (1)
    {
        bm_job *next_bm_job = (bm_job *)queue_dequeue(&GLOBAL_STATE->ASIC_jobs_queue);

        ASIC_send_work(GLOBAL_STATE, next_bm_job);

        TickType_t wait_ticks = pdMS_TO_TICKS((uint32_t)ceil(GLOBAL_STATE->asic_job_frequency_ms));
        if (wait_ticks == 0) {
            wait_ticks = 1;
        }
        xSemaphoreTake(GLOBAL_STATE->ASIC_TASK_MODULE.semaphore, wait_ticks);
    }
}
