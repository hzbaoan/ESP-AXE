#include <stdint.h>
#include <string.h>

#include "asic_task.h"
#include "stratum_task.h"
#include "system.h"

void SYSTEM_update_hashrate_estimate(GlobalState *GLOBAL_STATE)
{
    (void)GLOBAL_STATE;
}

void SYSTEM_reset_hashrate_estimate(GlobalState *GLOBAL_STATE)
{
    (void)GLOBAL_STATE;
}

bool stratum_is_abandoning_work(GlobalState *GLOBAL_STATE)
{
    return GLOBAL_STATE == NULL || GLOBAL_STATE->abandon_work != 0;
}

void ASIC_job_pool_release(void *pvParameters, bm_job *job)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;

    if (GLOBAL_STATE == NULL || job == NULL ||
            GLOBAL_STATE->ASIC_TASK_MODULE.job_pool == NULL) {
        return;
    }

    uintptr_t pool_start = (uintptr_t)GLOBAL_STATE->ASIC_TASK_MODULE.job_pool;
    uintptr_t pool_end =
        (uintptr_t)(GLOBAL_STATE->ASIC_TASK_MODULE.job_pool + ASIC_JOB_POOL_SIZE);
    uintptr_t job_address = (uintptr_t)job;

    if (job_address < pool_start || job_address >= pool_end) {
        return;
    }

    size_t index = (size_t)(job - GLOBAL_STATE->ASIC_TASK_MODULE.job_pool);

    pthread_mutex_lock(&GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_lock);
    memset(job, 0, sizeof(*job));
    GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_in_use[index] = 0;
    pthread_mutex_unlock(&GLOBAL_STATE->ASIC_TASK_MODULE.job_pool_lock);
}
