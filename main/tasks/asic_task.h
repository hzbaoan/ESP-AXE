#ifndef ASIC_TASK_H_
#define ASIC_TASK_H_

#include <stdbool.h>
#include <pthread.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mining.h"
#include "work_queue.h"

#define ASIC_ACTIVE_JOB_SLOTS 128
#define ASIC_JOB_HISTORY_DEPTH 8
#define ASIC_JOB_CANDIDATE_COUNT (ASIC_JOB_HISTORY_DEPTH + 1)
#define ASIC_JOB_POOL_HEADROOM 64
#define ASIC_JOB_POOL_SIZE \
    (ASIC_ACTIVE_JOB_SLOTS * (ASIC_JOB_HISTORY_DEPTH + 1) + QUEUE_SIZE + ASIC_JOB_POOL_HEADROOM)

typedef struct
{
    bm_job *active_jobs[ASIC_ACTIVE_JOB_SLOTS];
    bm_job *retired_jobs[ASIC_ACTIVE_JOB_SLOTS][ASIC_JOB_HISTORY_DEPTH];
    uint8_t retired_job_next[ASIC_ACTIVE_JOB_SLOTS];
    uint32_t job_history_revision[ASIC_ACTIVE_JOB_SLOTS];
    bm_job *job_pool;
    uint8_t job_pool_in_use[ASIC_JOB_POOL_SIZE];
    pthread_mutex_t job_pool_lock;
    pthread_mutex_t asic_tx_lock;
    SemaphoreHandle_t semaphore;
    TaskHandle_t job_generator_task_handle;
    // current mirrors target until adaptive dispatch pacing is introduced.
    uint32_t dispatch_interval_target_us;
    uint32_t dispatch_interval_current_us;
    uint16_t queue_low_water_mark;
    uint16_t queue_high_water_mark;
    uint64_t raw_result_count;
    uint64_t duplicate_result_count;
    uint64_t job_lookup_miss_count;
    uint64_t valid_result_count;
    uint64_t invalid_result_count;
    uint64_t retired_job_match_count;
} AsicTaskModule;

bool ASIC_init_job_resources(void *pvParameters);
bm_job *ASIC_job_pool_acquire(void *pvParameters);
void ASIC_job_pool_release(void *pvParameters, bm_job *job);
void ASIC_task(void *pvParameters);

#endif /* ASIC_TASK_H_ */
