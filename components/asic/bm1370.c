#include "bm1370.h"

#include "crc.h"
#include "global_state.h"
#include "asic.h"
#include "serial.h"
#include "utils.h"

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "frequency_transition_bmXX.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define BM1370_CHIP_ID 0x1370
#define BM1370_CHIP_ID_RESPONSE_LENGTH 11

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

#define TICKET_MASK 0x14
#define BM1370_JOB_ID_STEP 24

typedef struct __attribute__((__packed__))
{
    uint16_t preamble;
    uint32_t nonce;
    uint8_t midstate_num;
    uint8_t job_id;
    uint16_t version;
    uint8_t crc;
} bm1370_asic_result_t;

static const char * TAG = "bm1370Module";

static task_result result;
static recent_result_cache recent_results;

static bool _send_BM1370(uint8_t header, uint8_t * data, uint8_t data_len, bool debug)
{
    packet_type_t packet_type = (header & TYPE_JOB) ? JOB_PACKET : CMD_PACKET;
    uint8_t total_length = (packet_type == JOB_PACKET) ? (data_len + 6) : (data_len + 5);
    int sent;

    uint8_t buf[128];

    if (total_length > sizeof(buf)) {
        ESP_LOGE(TAG, "TX buffer overflow! Length: %d", total_length);
        return false;
    }

    buf[0] = 0x55;
    buf[1] = 0xAA;
    buf[2] = header;
    buf[3] = (packet_type == JOB_PACKET) ? (data_len + 4) : (data_len + 3);

    memcpy(buf + 4, data, data_len);

    if (packet_type == JOB_PACKET) {
        uint16_t crc16_total = crc16_false(buf + 2, data_len + 2);
        buf[4 + data_len] = (crc16_total >> 8) & 0xFF;
        buf[5 + data_len] = crc16_total & 0xFF;
    } else {
        buf[4 + data_len] = crc5(buf + 2, data_len + 2);
    }

    sent = SERIAL_send(buf, total_length, debug);
    if (sent != total_length) {
        ESP_LOGE(TAG, "UART send failed: expected %u bytes, wrote %d", (unsigned int)total_length, sent);
        return false;
    }

    return true;
}

static void _send_simple(uint8_t * data, uint8_t total_length)
{
    uint8_t buf[128];
    if (total_length > sizeof(buf)) return;
    memcpy(buf, data, total_length);
    SERIAL_send(buf, total_length, BM1370_SERIALTX_DEBUG);
}

static void _send_chain_inactive(void)
{
    unsigned char read_address[2] = {0x00, 0x00};
    _send_BM1370((TYPE_CMD | GROUP_ALL | CMD_INACTIVE), read_address, 2, BM1370_SERIALTX_DEBUG);
}

static void _set_chip_address(uint8_t chipAddr)
{
    unsigned char read_address[2] = {chipAddr, 0x00};
    _send_BM1370((TYPE_CMD | GROUP_SINGLE | CMD_SETADDRESS), read_address, 2, BM1370_SERIALTX_DEBUG);
}

void BM1370_set_version_mask(uint32_t version_mask) 
{
    int versions_to_roll = version_mask >> 13;
    uint8_t version_byte0 = (versions_to_roll >> 8);
    uint8_t version_byte1 = (versions_to_roll & 0xFF); 
    uint8_t version_cmd[] = {0x00, 0xA4, 0x90, 0x00, version_byte0, version_byte1};
    _send_BM1370(TYPE_CMD | GROUP_ALL | CMD_WRITE, version_cmd, 6, BM1370_SERIALTX_DEBUG);
}

void BM1370_send_hash_frequency(float target_freq) {
    unsigned char freqbuf[6] = {0x00, 0x08, 0x40, 0xA0, 0x02, 0x41};
    float newf = 200.0;

    uint8_t fb_divider = 0;
    uint8_t post_divider1 = 0, post_divider2 = 0;
    uint8_t ref_divider = 0;
    float min_difference = 10;
    float max_diff = 1.0;

    for (uint8_t refdiv_loop = 2; refdiv_loop > 0 && fb_divider == 0; refdiv_loop--) {
        for (uint8_t postdiv1_loop = 7; postdiv1_loop > 0 && fb_divider == 0; postdiv1_loop--) {
            for (uint8_t postdiv2_loop = 7; postdiv2_loop > 0 && fb_divider == 0; postdiv2_loop--) {
                if (postdiv1_loop >= postdiv2_loop) {
                    int temp_fb_divider = round(((float) (postdiv1_loop * postdiv2_loop * target_freq * refdiv_loop) / 25.0));

                    if (temp_fb_divider >= 0xa0 && temp_fb_divider <= 0xef) {
                        float temp_freq = 25.0 * (float) temp_fb_divider / (float) (refdiv_loop * postdiv2_loop * postdiv1_loop);
                        float freq_diff = fabs(target_freq - temp_freq);

                        if (freq_diff < min_difference && freq_diff < max_diff) {
                            fb_divider = temp_fb_divider;
                            post_divider1 = postdiv1_loop;
                            post_divider2 = postdiv2_loop;
                            ref_divider = refdiv_loop;
                            min_difference = freq_diff;
                            newf = temp_freq;
                        }
                    }
                }
            }
        }
    }

    if (fb_divider == 0) {
        ESP_LOGE(TAG, "Failed to find PLL settings for target frequency %.2f", target_freq);
        return;
    }

    freqbuf[3] = fb_divider;
    freqbuf[4] = ref_divider;
    freqbuf[5] = (((post_divider1 - 1) & 0xf) << 4) + ((post_divider2 - 1) & 0xf);

    if (fb_divider * 25 / (float) ref_divider >= 2400) {
        freqbuf[2] = 0x50;
    }

    _send_BM1370(TYPE_CMD | GROUP_ALL | CMD_WRITE, freqbuf, 6, BM1370_SERIALTX_DEBUG);
    ESP_LOGI(TAG, "Setting Frequency to %.2fMHz (%.2f)", target_freq, newf);
}

static void do_frequency_ramp_up(float target_frequency) {
    if (target_frequency == 0) {
        ESP_LOGI(TAG, "Skipping frequency ramp");
        return;
    }
    ESP_LOGI(TAG, "Ramping up frequency from 56.25 MHz to %.2f MHz", target_frequency);
    do_frequency_transition(target_frequency, BM1370_send_hash_frequency, 1370);
}

bool BM1370_set_frequency(float target_freq) {
    return do_frequency_transition(target_freq, BM1370_send_hash_frequency, 1370);
}

static uint8_t _send_init(uint64_t frequency, uint16_t asic_count)
{
    for (int i = 0; i < 3; i++) {
        BM1370_set_version_mask(STRATUM_DEFAULT_VERSION_MASK);
    }

    unsigned char init3[7] = {0x55, 0xAA, 0x52, 0x05, 0x00, 0x00, 0x0A};
    _send_simple(init3, 7);

    int chip_counter = count_asic_chips(asic_count, BM1370_CHIP_ID, BM1370_CHIP_ID_RESPONSE_LENGTH);
    if (chip_counter == 0) return 0;

    BM1370_set_version_mask(STRATUM_DEFAULT_VERSION_MASK);

    _send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE), (uint8_t[]){0x00, 0xA8, 0x00, 0x07, 0x00, 0x00}, 6, BM1370_SERIALTX_DEBUG);
    _send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE), (uint8_t[]){0x00, 0x18, 0xF0, 0x00, 0xC1, 0x00}, 6, BM1370_SERIALTX_DEBUG); 

    _send_chain_inactive();

    uint8_t address_interval = (uint8_t) (256 / chip_counter);
    for (uint8_t i = 0; i < chip_counter; i++) {
        _set_chip_address(i * address_interval);
    }

    _send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE), (uint8_t[]){0x00, 0x3C, 0x80, 0x00, 0x8B, 0x00}, 6, BM1370_SERIALTX_DEBUG);
    _send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE), (uint8_t[]){0x00, 0x3C, 0x80, 0x00, 0x80, 0x0C}, 6, BM1370_SERIALTX_DEBUG); 

    BM1370_set_job_difficulty_mask(BM1370_ASIC_DIFFICULTY);

    _send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE), (uint8_t[]){0x00, 0x58, 0x00, 0x01, 0x11, 0x11}, 6, BM1370_SERIALTX_DEBUG); 

    for (uint8_t i = 0; i < chip_counter; i++) {
        unsigned char set_a8_register[6] = {i * address_interval, 0xA8, 0x00, 0x07, 0x01, 0xF0};
        _send_BM1370((TYPE_CMD | GROUP_SINGLE | CMD_WRITE), set_a8_register, 6, BM1370_SERIALTX_DEBUG);
        unsigned char set_18_register[6] = {i * address_interval, 0x18, 0xF0, 0x00, 0xC1, 0x00};
        _send_BM1370((TYPE_CMD | GROUP_SINGLE | CMD_WRITE), set_18_register, 6, BM1370_SERIALTX_DEBUG);
        unsigned char set_3c_register_first[6] = {i * address_interval, 0x3C, 0x80, 0x00, 0x8B, 0x00};
        _send_BM1370((TYPE_CMD | GROUP_SINGLE | CMD_WRITE), set_3c_register_first, 6, BM1370_SERIALTX_DEBUG);
        unsigned char set_3c_register_second[6] = {i * address_interval, 0x3C, 0x80, 0x00, 0x80, 0x0C};
        _send_BM1370((TYPE_CMD | GROUP_SINGLE | CMD_WRITE), set_3c_register_second, 6, BM1370_SERIALTX_DEBUG);
        unsigned char set_3c_register_third[6] = {i * address_interval, 0x3C, 0x80, 0x00, 0x82, 0xAA};
        _send_BM1370((TYPE_CMD | GROUP_SINGLE | CMD_WRITE), set_3c_register_third, 6, BM1370_SERIALTX_DEBUG);
    }

    _send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE), (uint8_t[]){0x00, 0xB9, 0x00, 0x00, 0x44, 0x80}, 6, BM1370_SERIALTX_DEBUG);
    _send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE), (uint8_t[]){0x00, 0x54, 0x00, 0x00, 0x00, 0x02}, 6, BM1370_SERIALTX_DEBUG);
    _send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE), (uint8_t[]){0x00, 0xB9, 0x00, 0x00, 0x44, 0x80}, 6, BM1370_SERIALTX_DEBUG);
    _send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE), (uint8_t[]){0x00, 0x3C, 0x80, 0x00, 0x8D, 0xEE}, 6, BM1370_SERIALTX_DEBUG);

    do_frequency_ramp_up(frequency);

    unsigned char set_10_hash_counting[6] = {0x00, 0x10, 0x00, 0x00, 0x1E, 0xB5}; 
    _send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE), set_10_hash_counting, 6, BM1370_SERIALTX_DEBUG);

    return chip_counter;
}

static void _reset(void)
{
    gpio_set_level(GPIO_ASIC_RESET, 0);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    gpio_set_level(GPIO_ASIC_RESET, 1);
    vTaskDelay(100 / portTICK_PERIOD_MS);
}

uint8_t BM1370_init(uint64_t frequency, uint16_t asic_count)
{
    ESP_LOGI(TAG, "Initializing BM1370");
    esp_rom_gpio_pad_select_gpio(GPIO_ASIC_RESET);
    gpio_set_direction(GPIO_ASIC_RESET, GPIO_MODE_OUTPUT);
    _reset();
    recent_result_cache_clear(&recent_results);
    return _send_init(frequency, asic_count);
}

int BM1370_set_max_baud(void)
{
    ESP_LOGI(TAG, "Setting max baud of 1000000 ");
    unsigned char init8[11] = {0x55, 0xAA, 0x51, 0x09, 0x00, 0x28, 0x11, 0x30, 0x02, 0x00, 0x03};
    _send_simple(init8, 11);
    return 1000000;
}


void BM1370_set_job_difficulty_mask(uint32_t difficulty)
{
    unsigned char job_difficulty_mask[9] = {0x00, TICKET_MASK, 0b00000000, 0b00000000, 0b00000000, 0b11111111};
    difficulty = _largest_power_of_two_u32(difficulty) - 1U;

    for (int i = 0; i < 4; i++) {
        char value = (char)((difficulty >> (8 * i)) & 0xFFU);
        job_difficulty_mask[5 - i] = _reverse_bits(value);
    }

    ESP_LOGI(TAG, "Setting ASIC difficulty mask to %" PRIu32, difficulty);
    _send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE), job_difficulty_mask, 6, BM1370_SERIALTX_DEBUG);
}

static uint8_t id = 0;

void BM1370_send_work(void * pvParameters, bm_job * next_bm_job)
{
    GlobalState * GLOBAL_STATE = (GlobalState *) pvParameters;

    BM1370_job job = {0};
    id = (id + BM1370_JOB_ID_STEP) % 128;
    job.job_id = id;
    job.num_midstates = 0x01;
    memcpy(&job.starting_nonce, &next_bm_job->starting_nonce, 4);
    memcpy(&job.nbits, &next_bm_job->target, 4);
    memcpy(&job.ntime, &next_bm_job->ntime, 4);
    memcpy(job.merkle_root, next_bm_job->merkle_root_be, 32);
    memcpy(job.prev_block_hash, next_bm_job->prev_block_hash_be, 32);
    memcpy(&job.version, &next_bm_job->version, 4);

    // [终极修复]: 大范围锁定覆盖，防止 Use-After-Free 崩溃
    #if BM1370_DEBUG_JOBS
    ESP_LOGI(TAG, "Send Job: %02X", job.job_id);
    #endif

    if (!_send_BM1370((TYPE_JOB | GROUP_SINGLE | CMD_WRITE), (uint8_t *)&job, sizeof(BM1370_job), BM1370_DEBUG_WORK)) {
        ASIC_job_pool_release(GLOBAL_STATE, next_bm_job);
        return;
    }

    pthread_mutex_lock(&GLOBAL_STATE->valid_jobs_lock);
    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    bool abandon_work = GLOBAL_STATE->abandon_work != 0;
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);

    if (abandon_work) {
        pthread_mutex_unlock(&GLOBAL_STATE->valid_jobs_lock);
        ASIC_job_pool_release(GLOBAL_STATE, next_bm_job);
        return;
    }

    if (GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job.job_id] != NULL) {
        ASIC_job_pool_release(GLOBAL_STATE, GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job.job_id]);
    }
    GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job.job_id] = next_bm_job;
    GLOBAL_STATE->valid_jobs[job.job_id] = 1;

    pthread_mutex_unlock(&GLOBAL_STATE->valid_jobs_lock);
}

task_result * BM1370_process_work(void * pvParameters)
{
    bm1370_asic_result_t asic_result = {0};

    if (receive_work((uint8_t *)&asic_result, sizeof(asic_result)) == ESP_FAIL) {
        return NULL;
    }

    if (!recent_result_cache_add(&recent_results, asic_result.job_id, asic_result.nonce, asic_result.version, asic_result.midstate_num)) {
        return NULL;
    }

    uint8_t job_id = (asic_result.job_id & 0xf0) >> 1;
    
    // [修复边界防护]: 强边界检查
    if (job_id >= 128) {
        ESP_LOGE(TAG, "Corrupted ASIC data, job_id %d out of bounds!", job_id);
        return NULL;
    }
    
    uint8_t core_id = (uint8_t)((ntohl(asic_result.nonce) >> 25) & 0x7f); 
    uint8_t small_core_id = asic_result.job_id & 0x0f; 
    uint32_t version_bits = (ntohs(asic_result.version) << 13); 
    ESP_LOGD(TAG, "Job ID: %02X, Core: %d/%d, Ver: %08" PRIX32, job_id, core_id, small_core_id, version_bits);

    GlobalState * GLOBAL_STATE = (GlobalState *) pvParameters;
    bm_job active_job;

    if (!ASIC_copy_active_job(GLOBAL_STATE, job_id, &active_job)) {
        ESP_LOGW(TAG, "Invalid job nonce found, 0x%02X", job_id);
        return NULL;
    }

    uint32_t rolled_version = rolled_version_from_bits(
        active_job.version,
        active_job.version_mask,
        version_bits);

    result.job_id = job_id;
    result.nonce = asic_result.nonce;
    result.rolled_version = rolled_version;
    result.active_job = active_job;

    return &result;
}
