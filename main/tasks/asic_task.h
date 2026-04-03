#ifndef ASIC_TASK_H_
#define ASIC_TASK_H_

#include <stdbool.h>
#include <pthread.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "mining.h"

#define ASIC_ACTIVE_JOB_SLOTS 128
#define ASIC_JOB_POOL_SIZE 160

typedef struct
{
    bm_job *active_jobs[ASIC_ACTIVE_JOB_SLOTS];
    bm_job *job_pool;
    uint8_t job_pool_in_use[ASIC_JOB_POOL_SIZE];
    pthread_mutex_t job_pool_lock;
    SemaphoreHandle_t semaphore;
    uint32_t dispatch_interval_target_us;
    uint32_t dispatch_interval_current_us;
    uint32_t dispatch_interval_min_us;
    uint32_t dispatch_interval_max_us;
    uint16_t queue_low_water_mark;
    uint16_t queue_high_water_mark;
} AsicTaskModule;

bool ASIC_init_job_resources(void *pvParameters);
bm_job *ASIC_job_pool_acquire(void *pvParameters);
void ASIC_job_pool_release(void *pvParameters, bm_job *job);
void ASIC_task(void *pvParameters);

#endif /* ASIC_TASK_H_ */
