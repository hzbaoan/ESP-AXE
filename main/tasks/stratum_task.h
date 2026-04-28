#ifndef STRATUM_TASK_H_
#define STRATUM_TASK_H_

#include "global_state.h"

#define STRATUM_SUBMIT_SKIPPED 0
#define STRATUM_SUBMIT_QUEUE_LENGTH 64
#define STRATUM_USERNAME_MAX_LEN 192

typedef struct
{
    char username[STRATUM_USERNAME_MAX_LEN];
    char jobid[BM_JOB_ID_MAX_LEN];
    char extranonce_2[BM_EXTRANONCE2_HEX_MAX_LEN + 1];
    uint32_t ntime;
    uint32_t nonce;
    uint32_t version;
} stratum_share_submission;

bool stratum_is_abandoning_work(GlobalState *GLOBAL_STATE);
int stratum_next_uid(GlobalState *GLOBAL_STATE);
int stratum_submit_share(GlobalState *GLOBAL_STATE, const char *username, const char *jobid,
                         const char *extranonce_2, uint32_t ntime,
                         uint32_t nonce, uint32_t version);
bool stratum_queue_share(GlobalState *GLOBAL_STATE, const stratum_share_submission *share);
void stratum_set_abandon_work(GlobalState *GLOBAL_STATE, int abandon_work);
void stratum_submit_task(void *pvParameters);
void stratum_task(void *pvParameters);
void stratum_close_connection(GlobalState * GLOBAL_STATE);

#endif
