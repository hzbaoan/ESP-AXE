#ifndef WORK_QUEUE_H
#define WORK_QUEUE_H

#include <pthread.h>
#include "mining.h"

#define QUEUE_SIZE 64
#define QUEUE_LOW_WATER_HEADROOM 8
#define QUEUE_LOW_WATER_MARK_MAX ((QUEUE_SIZE > QUEUE_LOW_WATER_HEADROOM) ? (QUEUE_SIZE - QUEUE_LOW_WATER_HEADROOM) : 1)

typedef struct
{
    void *buffer[QUEUE_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} work_queue;

void queue_init(work_queue *queue);
void queue_enqueue(work_queue *queue, void *new_work);
void *queue_dequeue(work_queue *queue);
void *queue_try_dequeue(work_queue *queue);
int queue_count(work_queue *queue);
void queue_clear(work_queue *queue);
void ASIC_jobs_queue_clear(work_queue *queue, void *pvParameters);

#endif // WORK_QUEUE_H
