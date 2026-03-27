#ifndef ASIC_TASK_H_
#define ASIC_TASK_H_

#include <pthread.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "mining.h"

#define ASIC_ACTIVE_JOB_SLOTS 128
#define ASIC_JOB_POOL_SIZE 160

typedef struct
{
    bm_job *active_jobs[ASIC_ACTIVE_JOB_SLOTS];
    bm_job job_pool[ASIC_JOB_POOL_SIZE];
    uint8_t job_pool_in_use[ASIC_JOB_POOL_SIZE];
    pthread_mutex_t job_pool_lock;
    SemaphoreHandle_t semaphore;
} AsicTaskModule;

void ASIC_init_job_resources(void *pvParameters);
bm_job *ASIC_job_pool_acquire(void *pvParameters);
void ASIC_job_pool_release(void *pvParameters, bm_job *job);
void ASIC_task(void *pvParameters);

#endif /* ASIC_TASK_H_ */
