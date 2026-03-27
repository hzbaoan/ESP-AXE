#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <arpa/inet.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#include "serial.h"
#include "bm1397.h"
#include "utils.h"
#include "crc.h"
#include "mining.h"
#include "global_state.h"

#define BM1397_CHIP_ID 0x1397
#define BM1397_CHIP_ID_RESPONSE_LENGTH 9

#ifdef CONFIG_GPIO_ASIC_RESET
#define GPIO_ASIC_RESET CONFIG_GPIO_ASIC_RESET
#else
#define GPIO_ASIC_RESET 1
#endif

#define TYPE_JOB 0x20
#define TYPE_CMD 0x40

#define GROUP_SINGLE 0x00
#define GROUP_ALL 0x10

#define CMD_JOB 0x01

#define CMD_SETADDRESS 0x00
#define CMD_WRITE 0x01
#define CMD_READ 0x02
#define CMD_INACTIVE 0x03

#define RESPONSE_CMD 0x00
#define RESPONSE_JOB 0x80

#define SLEEP_TIME 20
#define FREQ_MULT 25.0

#define CLOCK_ORDER_CONTROL_0 0x80
#define CLOCK_ORDER_CONTROL_1 0x84
#define ORDERED_CLOCK_ENABLE 0x20
#define CORE_REGISTER_CONTROL 0x3C
#define PLL3_PARAMETER 0x68
#define FAST_UART_CONFIGURATION 0x28
#define TICKET_MASK 0x14
#define MISC_CONTROL 0x18

typedef struct __attribute__((__packed__))
{
    uint16_t preamble;
    uint32_t nonce;
    uint8_t midstate_num;
    uint8_t job_id;
    uint8_t crc;
} bm1397_asic_result_t;

static const char *TAG = "bm1397Module";

static uint32_t prev_nonce = 0;
static task_result result;

static void _send_BM1397(uint8_t header, uint8_t *data, uint8_t data_len, bool debug)
{
    packet_type_t packet_type = (header & TYPE_JOB) ? JOB_PACKET : CMD_PACKET;
    uint8_t total_length = (packet_type == JOB_PACKET) ? (data_len + 6) : (data_len + 5);

    uint8_t buf[128];

    if (total_length > sizeof(buf)) {
        ESP_LOGE(TAG, "TX buffer overflow! Length: %d", total_length);
        return;
    }

    buf[0] = 0x55;
    buf[1] = 0xAA;
    buf[2] = header;
    buf[3] = (packet_type == JOB_PACKET) ? (data_len + 4) : (data_len + 3);

    memcpy(buf + 4, data, data_len);

    if (packet_type == JOB_PACKET)
    {
        uint16_t crc16_total = crc16_false(buf + 2, data_len + 2);
        buf[4 + data_len] = (crc16_total >> 8) & 0xFF;
        buf[5 + data_len] = crc16_total & 0xFF;
    }
    else
    {
        buf[4 + data_len] = crc5(buf + 2, data_len + 2);
    }

    SERIAL_send(buf, total_length, debug);
}

static void _send_read_address(void)
{
    unsigned char read_address[2] = {0x00, 0x00};
    _send_BM1397((TYPE_CMD | GROUP_ALL | CMD_READ), read_address, 2, BM1937_SERIALTX_DEBUG);
}

static void _send_chain_inactive(void)
{
    unsigned char read_address[2] = {0x00, 0x00};
    _send_BM1397((TYPE_CMD | GROUP_ALL | CMD_INACTIVE), read_address, 2, BM1937_SERIALTX_DEBUG);
}

static void _set_chip_address(uint8_t chipAddr)
{
    unsigned char read_address[2] = {chipAddr, 0x00};
    _send_BM1397((TYPE_CMD | GROUP_SINGLE | CMD_SETADDRESS), read_address, 2, BM1937_SERIALTX_DEBUG);
}

void BM1397_set_version_mask(uint32_t version_mask) {
    // placeholder
}

void BM1397_send_hash_frequency(float frequency)
{
    unsigned char prefreq1[9] = {0x00, 0x70, 0x0F, 0x0F, 0x0F, 0x00}; 
    unsigned char freqbuf[9] = {0x00, 0x08, 0x40, 0xA0, 0x02, 0x25}; 

    float deffreq = 200.0;
    float fa, fb, fc1, fc2, newf;
    float f1, basef, famax = 0x104, famin = 0x10;
    int i;

    if (frequency < 50) f1 = 50;
    else if (frequency > 650) f1 = 650;
    else f1 = frequency;

    fb = 2;
    fc1 = 1;
    fc2 = 5; 
    if (f1 >= 500) fb = 1;
    else if (f1 <= 150) fc1 = 3;
    else if (f1 <= 250) fc1 = 2;
    
    basef = FREQ_MULT * ceil(f1 * fb * fc1 * fc2 / FREQ_MULT);
    fa = basef / FREQ_MULT;

    if (fa < famin || fa > famax) {
        newf = deffreq;
    } else {
        freqbuf[2] = 0x40 + (unsigned char)((int)fa >> 8);
        freqbuf[3] = (unsigned char)((int)fa & 0xff);
        freqbuf[4] = (unsigned char)fb;
        freqbuf[5] = (((unsigned char)fc1 & 0x7) << 4) + ((unsigned char)fc2 & 0x7);
        newf = basef / ((float)fb * (float)fc1 * (float)fc2);
    }

    for (i = 0; i < 2; i++) {
        vTaskDelay(10 / portTICK_PERIOD_MS);
        _send_BM1397((TYPE_CMD | GROUP_ALL | CMD_WRITE), prefreq1, 6, BM1937_SERIALTX_DEBUG);
    }
    for (i = 0; i < 2; i++) {
        vTaskDelay(10 / portTICK_PERIOD_MS);
        _send_BM1397((TYPE_CMD | GROUP_ALL | CMD_WRITE), freqbuf, 6, BM1937_SERIALTX_DEBUG);
    }

    vTaskDelay(10 / portTICK_PERIOD_MS);
    ESP_LOGI(TAG, "Setting Frequency to %.2fMHz (%.2f)", frequency, newf);
}

static uint8_t _send_init(uint64_t frequency, uint16_t asic_count)
{
    _send_read_address();

    int chip_counter = count_asic_chips(asic_count, BM1397_CHIP_ID, BM1397_CHIP_ID_RESPONSE_LENGTH);
    if (chip_counter == 0) return 0;

    vTaskDelay(SLEEP_TIME / portTICK_PERIOD_MS);
    _send_chain_inactive();

    for (uint8_t i = 0; i < asic_count; i++) {
        _set_chip_address(i * (256 / asic_count));
    }

    unsigned char init[6] = {0x00, CLOCK_ORDER_CONTROL_0, 0x00, 0x00, 0x00, 0x00}; 
    _send_BM1397((TYPE_CMD | GROUP_ALL | CMD_WRITE), init, 6, BM1937_SERIALTX_DEBUG);

    unsigned char init2[6] = {0x00, CLOCK_ORDER_CONTROL_1, 0x00, 0x00, 0x00, 0x00}; 
    _send_BM1397((TYPE_CMD | GROUP_ALL | CMD_WRITE), init2, 6, BM1937_SERIALTX_DEBUG);

    unsigned char init3[9] = {0x00, ORDERED_CLOCK_ENABLE, 0x00, 0x00, 0x00, 0x01}; 
    _send_BM1397((TYPE_CMD | GROUP_ALL | CMD_WRITE), init3, 6, BM1937_SERIALTX_DEBUG);

    unsigned char init4[9] = {0x00, CORE_REGISTER_CONTROL, 0x80, 0x00, 0x80, 0x74}; 
    _send_BM1397((TYPE_CMD | GROUP_ALL | CMD_WRITE), init4, 6, BM1937_SERIALTX_DEBUG);

    BM1397_set_job_difficulty_mask(BM1397_ASIC_DIFFICULTY);

    unsigned char init5[9] = {0x00, PLL3_PARAMETER, 0xC0, 0x70, 0x01, 0x11}; 
    _send_BM1397((TYPE_CMD | GROUP_ALL | CMD_WRITE), init5, 6, BM1937_SERIALTX_DEBUG);

    unsigned char init6[9] = {0x00, FAST_UART_CONFIGURATION, 0x06, 0x00, 0x00, 0x0F}; 
    _send_BM1397((TYPE_CMD | GROUP_ALL | CMD_WRITE), init6, 6, BM1937_SERIALTX_DEBUG);

    BM1397_set_default_baud();
    BM1397_send_hash_frequency(frequency);

    return chip_counter;
}

static void _reset(void)
{
    gpio_set_level(GPIO_ASIC_RESET, 0);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    gpio_set_level(GPIO_ASIC_RESET, 1);
    vTaskDelay(100 / portTICK_PERIOD_MS);
}

uint8_t BM1397_init(uint64_t frequency, uint16_t asic_count)
{
    ESP_LOGI(TAG, "Initializing BM1397");
    esp_rom_gpio_pad_select_gpio(GPIO_ASIC_RESET);
    gpio_set_direction(GPIO_ASIC_RESET, GPIO_MODE_OUTPUT);
    _reset();
    return _send_init(frequency, asic_count);
}

int BM1397_set_default_baud(void)
{
    unsigned char baudrate[9] = {0x00, MISC_CONTROL, 0x00, 0x00, 0b01111010, 0b00110001}; 
    _send_BM1397((TYPE_CMD | GROUP_ALL | CMD_WRITE), baudrate, 6, BM1937_SERIALTX_DEBUG);
    return 115749;
}

int BM1397_set_max_baud(void)
{
    ESP_LOGI(TAG, "Setting max baud of 3125000");
    unsigned char baudrate[9] = {0x00, MISC_CONTROL, 0x00, 0x00, 0b01100000, 0b00110001};
    _send_BM1397((TYPE_CMD | GROUP_ALL | CMD_WRITE), baudrate, 6, BM1937_SERIALTX_DEBUG);
    return 3125000;
}

void BM1397_set_job_difficulty_mask(int difficulty)
{
    unsigned char job_difficulty_mask[9] = {0x00, TICKET_MASK, 0b00000000, 0b00000000, 0b00000000, 0b11111111};
    difficulty = _largest_power_of_two(difficulty) - 1; 

    for (int i = 0; i < 4; i++) {
        char value = (difficulty >> (8 * i)) & 0xFF;
        job_difficulty_mask[5 - i] = _reverse_bits(value);
    }

    ESP_LOGI(TAG, "Setting job ASIC mask to %d", difficulty);
    _send_BM1397((TYPE_CMD | GROUP_ALL | CMD_WRITE), job_difficulty_mask, 6, BM1937_SERIALTX_DEBUG);
}

static uint8_t id = 0;

void BM1397_send_work(void *pvParameters, bm_job *next_bm_job)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;

    job_packet job;
    id = (id + 4) % 128;

    job.job_id = id;
    job.num_midstates = next_bm_job->num_midstates;
    memcpy(&job.starting_nonce, &next_bm_job->starting_nonce, 4);
    memcpy(&job.nbits, &next_bm_job->target, 4);
    memcpy(&job.ntime, &next_bm_job->ntime, 4);
    memcpy(&job.merkle4, next_bm_job->merkle_root + 28, 4);
    memcpy(job.midstate, next_bm_job->midstate, 32);

    if (job.num_midstates == 4)
    {
        memcpy(job.midstate1, next_bm_job->midstate1, 32);
        memcpy(job.midstate2, next_bm_job->midstate2, 32);
        memcpy(job.midstate3, next_bm_job->midstate3, 32);
    }

    // [终极修复]: 大范围锁定覆盖，防止 Use-After-Free 崩溃
    pthread_mutex_lock(&GLOBAL_STATE->valid_jobs_lock);
    
    if (GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job.job_id] != NULL)
    {
        ASIC_job_pool_release(GLOBAL_STATE, GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job.job_id]);
    }
    GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job.job_id] = next_bm_job;
    GLOBAL_STATE->valid_jobs[job.job_id] = 1;
    
    pthread_mutex_unlock(&GLOBAL_STATE->valid_jobs_lock);

    #if BM1397_DEBUG_JOBS
    ESP_LOGI(TAG, "Send Job: %02X", job.job_id);
    #endif

    _send_BM1397((TYPE_JOB | GROUP_SINGLE | CMD_WRITE), (uint8_t *)&job, sizeof(job_packet), BM1397_DEBUG_WORK);
}

task_result *BM1397_process_work(void *pvParameters)
{
    bm1397_asic_result_t asic_result = {0};

    if (receive_work((uint8_t *)&asic_result, sizeof(asic_result)) == ESP_FAIL) {
        return NULL;
    }

    uint8_t rx_job_id = asic_result.job_id & 0xfc;
    
    // [修复边界防护]: 防止脏数据越界
    if (rx_job_id >= 128) {
        ESP_LOGE(TAG, "Corrupted ASIC data, job_id %d out of bounds!", rx_job_id);
        return NULL;
    }
    
    uint8_t rx_midstate_index = asic_result.job_id & 0x03;

    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;
    if (GLOBAL_STATE->valid_jobs[rx_job_id] == 0)
    {
        ESP_LOGW(TAG, "Invalid job nonce found, id=%d", rx_job_id);
        return NULL;
    }

    uint32_t rolled_version = GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[rx_job_id]->version;
    for (int i = 0; i < rx_midstate_index; i++)
    {
        rolled_version = increment_bitmask(rolled_version, GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[rx_job_id]->version_mask);
    }

    // [终极修复]: 删除了之前残留的永远失效的 nonce_found == 0 死代码，仅保留有效的 prev_nonce
    if (asic_result.nonce == prev_nonce)
    {
        return NULL;
    }
    else
    {
        prev_nonce = asic_result.nonce;
    }

    result.job_id = rx_job_id;
    result.nonce = asic_result.nonce;
    result.rolled_version = rolled_version;

    return &result;
}
