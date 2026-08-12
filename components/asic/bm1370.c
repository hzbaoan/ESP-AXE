#include "bm1370.h"

#include "crc.h"
#include "global_state.h"
#include "asic.h"
#include "serial.h"
#include "stratum_task.h"
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
#define BM1370_HCN_CORRECTION 268

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
static uint16_t address_interval = 256U;
static uint32_t nonce_count = 0;

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

static bool _send_simple(const uint8_t *data, uint8_t total_length)
{
    uint8_t buf[128];
    int sent;

    if (total_length > sizeof(buf)) {
        ESP_LOGE(TAG, "TX buffer overflow! Length: %u", (unsigned int)total_length);
        return false;
    }
    memcpy(buf, data, total_length);
    sent = SERIAL_send(buf, total_length, BM1370_SERIALTX_DEBUG);
    if (sent != total_length) {
        ESP_LOGE(TAG, "UART send failed: expected %u bytes, wrote %d",
                 (unsigned int)total_length, sent);
        return false;
    }
    return true;
}

static bool _send_chain_inactive(void)
{
    unsigned char read_address[2] = {0x00, 0x00};
    return _send_BM1370((TYPE_CMD | GROUP_ALL | CMD_INACTIVE), read_address, 2, BM1370_SERIALTX_DEBUG);
}

static bool _set_chip_address(uint8_t chipAddr)
{
    unsigned char read_address[2] = {chipAddr, 0x00};
    return _send_BM1370((TYPE_CMD | GROUP_SINGLE | CMD_SETADDRESS), read_address, 2, BM1370_SERIALTX_DEBUG);
}

bool BM1370_set_version_mask(uint32_t version_mask)
{
    int versions_to_roll = version_mask >> 13;
    uint8_t version_byte0 = (versions_to_roll >> 8);
    uint8_t version_byte1 = (versions_to_roll & 0xFF); 
    uint8_t version_cmd[] = {0x00, 0xA4, 0x90, 0x00, version_byte0, version_byte1};
    return _send_BM1370(TYPE_CMD | GROUP_ALL | CMD_WRITE,
                        version_cmd, 6, BM1370_SERIALTX_DEBUG);
}

static bool BM1370_set_hash_counting_number(uint32_t hcn)
{
    uint8_t command[6] = {
        0x00,
        0x10,
        (uint8_t)(hcn >> 24),
        (uint8_t)(hcn >> 16),
        (uint8_t)(hcn >> 8),
        (uint8_t)hcn,
    };

    ESP_LOGI(TAG, "Setting HCN to %" PRIu32, hcn);
    return _send_BM1370(TYPE_CMD | GROUP_ALL | CMD_WRITE,
                        command,
                        sizeof(command),
                        BM1370_SERIALTX_DEBUG);
}

bool BM1370_set_nonce_space(float frequency, uint16_t asic_count, double nonce_scale)
{
    uint32_t hcn;

    if (!calculate_hcn(frequency,
                       (uint16_t)BM1370_CORE_COUNT,
                       asic_count,
                       BM1370_HCN_CORRECTION,
                       nonce_scale,
                       &hcn)) {
        ESP_LOGE(TAG, "Unable to calculate HCN for %.2f MHz, %u ASICs and %.3fx scale",
                 frequency, asic_count, nonce_scale);
        return false;
    }

    return BM1370_set_hash_counting_number(hcn);
}

float BM1370_send_hash_frequency(float target_freq) {
    uint8_t fb_divider;
    uint8_t ref_divider;
    uint8_t post_divider1;
    uint8_t post_divider2;
    float actual_frequency;

    if (!calculate_pll_parameters(target_freq, 160, 239,
                                  &fb_divider, &ref_divider,
                                  &post_divider1, &post_divider2,
                                  &actual_frequency)) {
        ESP_LOGE(TAG, "Failed to find PLL settings for target frequency %.2f", target_freq);
        return 0.0f;
    }

    uint8_t vco_scale = fb_divider * 25.0f / ref_divider >= 2400.0f ? 0x50 : 0x40;
    uint8_t post_divider = (((post_divider1 - 1U) & 0x0fU) << 4U) |
                           ((post_divider2 - 1U) & 0x0fU);
    uint8_t freqbuf[6] = {0x00, 0x08, vco_scale, fb_divider, ref_divider, post_divider};

    if (!_send_BM1370(TYPE_CMD | GROUP_ALL | CMD_WRITE, freqbuf, 6, BM1370_SERIALTX_DEBUG)) {
        return 0.0f;
    }
    ESP_LOGI(TAG, "Setting Frequency to %.2fMHz (%.2f)", target_freq, actual_frequency);
    return actual_frequency;
}

static bool do_frequency_ramp_up(float target_frequency, float *actual_frequency) {
    if (target_frequency == 0) {
        ESP_LOGI(TAG, "Skipping frequency ramp");
        return true;
    }
    ESP_LOGI(TAG, "Ramping up frequency from 56.25 MHz to %.2f MHz", target_frequency);
    return do_frequency_transition(target_frequency, BM1370_send_hash_frequency, 1370, actual_frequency);
}

static uint8_t _send_init(float frequency, uint16_t asic_count, float *actual_frequency)
{
    for (int i = 0; i < 3; i++) {
        if (!BM1370_set_version_mask(STRATUM_DEFAULT_VERSION_MASK)) {
            ESP_LOGE(TAG, "Initialization failed while setting the version mask");
            return 0;
        }
    }

    unsigned char init3[7] = {0x55, 0xAA, 0x52, 0x05, 0x00, 0x00, 0x0A};
    if (!_send_simple(init3, 7)) {
        ESP_LOGE(TAG, "Initialization failed while requesting chip IDs");
        return 0;
    }

    int chip_counter = count_asic_chips(asic_count, BM1370_CHIP_ID, BM1370_CHIP_ID_RESPONSE_LENGTH);
    if (chip_counter == 0) return 0;

    if (!BM1370_set_version_mask(STRATUM_DEFAULT_VERSION_MASK)) {
        ESP_LOGE(TAG, "Initialization failed while setting the version mask");
        return 0;
    }

    if (!_send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE),
                      (uint8_t[]){0x00, 0xA8, 0x00, 0x07, 0x00, 0x00},
                      6, BM1370_SERIALTX_DEBUG)) {
        ESP_LOGE(TAG, "Initialization failed while setting register 0xA8");
        return 0;
    }
    if (!_send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE),
                      (uint8_t[]){0x00, 0x18, 0xF0, 0x00, 0xC1, 0x00},
                      6, BM1370_SERIALTX_DEBUG)) {
        ESP_LOGE(TAG, "Initialization failed while setting register 0x18");
        return 0;
    }

    if (!_send_chain_inactive()) {
        ESP_LOGE(TAG, "Initialization failed while deactivating the ASIC chain");
        return 0;
    }

    address_interval = 256U / (uint16_t)chip_counter;
    for (uint8_t i = 0; i < chip_counter; i++) {
        if (!_set_chip_address((uint8_t)(i * address_interval))) {
            ESP_LOGE(TAG, "Initialization failed while assigning address to chip %u", (unsigned int)i);
            return 0;
        }
    }

    if (!_send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE),
                      (uint8_t[]){0x00, 0x3C, 0x80, 0x00, 0x8B, 0x00},
                      6, BM1370_SERIALTX_DEBUG)) {
        ESP_LOGE(TAG, "Initialization failed while setting register 0x3C (1)");
        return 0;
    }
    if (!_send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE),
                      (uint8_t[]){0x00, 0x3C, 0x80, 0x00, 0x80, 0x0C},
                      6, BM1370_SERIALTX_DEBUG)) {
        ESP_LOGE(TAG, "Initialization failed while setting register 0x3C (2)");
        return 0;
    }

    if (!BM1370_set_job_difficulty_mask(BM1370_ASIC_DIFFICULTY)) {
        ESP_LOGE(TAG, "Initialization failed while setting the difficulty mask");
        return 0;
    }

    if (!_send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE),
                      (uint8_t[]){0x00, 0x58, 0x00, 0x01, 0x11, 0x11},
                      6, BM1370_SERIALTX_DEBUG)) {
        ESP_LOGE(TAG, "Initialization failed while setting register 0x58");
        return 0;
    }

    for (uint8_t i = 0; i < chip_counter; i++) {
        unsigned char set_a8_register[6] = {(uint8_t)(i * address_interval), 0xA8, 0x00, 0x07, 0x01, 0xF0};
        if (!_send_BM1370((TYPE_CMD | GROUP_SINGLE | CMD_WRITE), set_a8_register, 6, BM1370_SERIALTX_DEBUG)) {
            ESP_LOGE(TAG, "Initialization failed while setting chip %u register 0xA8", (unsigned int)i);
            return 0;
        }
        unsigned char set_18_register[6] = {(uint8_t)(i * address_interval), 0x18, 0xF0, 0x00, 0xC1, 0x00};
        if (!_send_BM1370((TYPE_CMD | GROUP_SINGLE | CMD_WRITE), set_18_register, 6, BM1370_SERIALTX_DEBUG)) {
            ESP_LOGE(TAG, "Initialization failed while setting chip %u register 0x18", (unsigned int)i);
            return 0;
        }
        unsigned char set_3c_register_first[6] = {(uint8_t)(i * address_interval), 0x3C, 0x80, 0x00, 0x8B, 0x00};
        if (!_send_BM1370((TYPE_CMD | GROUP_SINGLE | CMD_WRITE), set_3c_register_first, 6, BM1370_SERIALTX_DEBUG)) {
            ESP_LOGE(TAG, "Initialization failed while setting chip %u register 0x3C (1)", (unsigned int)i);
            return 0;
        }
        unsigned char set_3c_register_second[6] = {(uint8_t)(i * address_interval), 0x3C, 0x80, 0x00, 0x80, 0x0C};
        if (!_send_BM1370((TYPE_CMD | GROUP_SINGLE | CMD_WRITE), set_3c_register_second, 6, BM1370_SERIALTX_DEBUG)) {
            ESP_LOGE(TAG, "Initialization failed while setting chip %u register 0x3C (2)", (unsigned int)i);
            return 0;
        }
        unsigned char set_3c_register_third[6] = {(uint8_t)(i * address_interval), 0x3C, 0x80, 0x00, 0x82, 0xAA};
        if (!_send_BM1370((TYPE_CMD | GROUP_SINGLE | CMD_WRITE), set_3c_register_third, 6, BM1370_SERIALTX_DEBUG)) {
            ESP_LOGE(TAG, "Initialization failed while setting chip %u register 0x3C (3)", (unsigned int)i);
            return 0;
        }
    }

    if (!_send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE),
                      (uint8_t[]){0x00, 0xB9, 0x00, 0x00, 0x44, 0x80},
                      6, BM1370_SERIALTX_DEBUG)) {
        ESP_LOGE(TAG, "Initialization failed while setting register 0xB9 (1)");
        return 0;
    }
    if (!_send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE),
                      (uint8_t[]){0x00, 0x54, 0x00, 0x00, 0x00, 0x02},
                      6, BM1370_SERIALTX_DEBUG)) {
        ESP_LOGE(TAG, "Initialization failed while setting register 0x54");
        return 0;
    }
    if (!_send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE),
                      (uint8_t[]){0x00, 0xB9, 0x00, 0x00, 0x44, 0x80},
                      6, BM1370_SERIALTX_DEBUG)) {
        ESP_LOGE(TAG, "Initialization failed while setting register 0xB9 (2)");
        return 0;
    }
    if (!_send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE),
                      (uint8_t[]){0x00, 0x3C, 0x80, 0x00, 0x8D, 0xEE},
                      6, BM1370_SERIALTX_DEBUG)) {
        ESP_LOGE(TAG, "Initialization failed while setting register 0x3C (3)");
        return 0;
    }

    if (!do_frequency_ramp_up(frequency, actual_frequency)) {
        ESP_LOGE(TAG, "Initialization failed while setting the hash frequency");
        return 0;
    }
    if (!BM1370_set_nonce_space(*actual_frequency, (uint16_t)chip_counter, 1.0)) {
        return 0;
    }

    return chip_counter;
}

static void _reset(void)
{
    gpio_set_level(GPIO_ASIC_RESET, 0);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    gpio_set_level(GPIO_ASIC_RESET, 1);
    vTaskDelay(100 / portTICK_PERIOD_MS);
}

uint8_t BM1370_init(float frequency, uint16_t asic_count, float *actual_frequency)
{
    float applied_frequency = 56.25f;

    ESP_LOGI(TAG, "Initializing BM1370");
    esp_rom_gpio_pad_select_gpio(GPIO_ASIC_RESET);
    gpio_set_direction(GPIO_ASIC_RESET, GPIO_MODE_OUTPUT);
    _reset();
    reset_frequency_transition();
    nonce_count = 0;
    if (actual_frequency == NULL) {
        actual_frequency = &applied_frequency;
    }
    *actual_frequency = applied_frequency;
    return _send_init(frequency, asic_count, actual_frequency);
}

int BM1370_set_max_baud(void)
{
    ESP_LOGI(TAG, "Setting max baud of 1000000 ");
    unsigned char init8[11] = {0x55, 0xAA, 0x51, 0x09, 0x00, 0x28, 0x11, 0x30, 0x02, 0x00, 0x03};
    return _send_simple(init8, 11) ? 1000000 : 0;
}


bool BM1370_set_job_difficulty_mask(uint32_t difficulty)
{
    unsigned char job_difficulty_mask[9] = {0x00, TICKET_MASK, 0b00000000, 0b00000000, 0b00000000, 0b11111111};
    difficulty = _largest_power_of_two_u32(difficulty) - 1U;

    for (int i = 0; i < 4; i++) {
        char value = (char)((difficulty >> (8 * i)) & 0xFFU);
        job_difficulty_mask[5 - i] = _reverse_bits(value);
    }

    ESP_LOGI(TAG, "Setting ASIC difficulty mask to %" PRIu32, difficulty);
    return _send_BM1370((TYPE_CMD | GROUP_ALL | CMD_WRITE),
                        job_difficulty_mask, 6, BM1370_SERIALTX_DEBUG);
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

    if (stratum_is_abandoning_work(GLOBAL_STATE)) {
        ASIC_job_pool_release(GLOBAL_STATE, next_bm_job);
        return;
    }

    bm_job *replaced_job = NULL;
    if (!ASIC_begin_active_job_send(GLOBAL_STATE, job.job_id, next_bm_job, &replaced_job)) {
        ASIC_job_pool_release(GLOBAL_STATE, next_bm_job);
        return;
    }

    bool send_ok = !stratum_is_abandoning_work(GLOBAL_STATE) &&
                   _send_BM1370((TYPE_JOB | GROUP_SINGLE | CMD_WRITE), (uint8_t *)&job, sizeof(BM1370_job), BM1370_DEBUG_WORK);
    ASIC_finish_active_job_send(GLOBAL_STATE, job.job_id, next_bm_job, replaced_job, send_ok);
}

task_result * BM1370_process_work(void * pvParameters)
{
    bm1370_asic_result_t asic_result = {0};
    GlobalState * GLOBAL_STATE = (GlobalState *) pvParameters;

    memset(&result, 0, sizeof(result));

    if (receive_work((uint8_t *)&asic_result, sizeof(asic_result)) == ESP_FAIL) {
        return NULL;
    }
    GLOBAL_STATE->ASIC_TASK_MODULE.raw_result_count++;

    uint8_t job_id = (asic_result.job_id & 0xf0) >> 1;
    
    // [修复边界防护]: 强边界检查
    if (job_id >= ASIC_ACTIVE_JOB_SLOTS) {
        ESP_LOGE(TAG, "Corrupted ASIC data, job_id %d out of bounds!", job_id);
        return NULL;
    }
    
    uint32_t nonce_host = ntohl(asic_result.nonce);
    uint8_t core_id = (uint8_t)((nonce_host >> 25) & 0x7f);
    uint8_t small_core_id = asic_result.job_id & 0x0f; 
    uint32_t version_bits = (ntohs(asic_result.version) << 13); 
    ESP_LOGD(TAG, "Job ID: %02X, Core: %d/%d, Ver: %08" PRIX32, job_id, core_id, small_core_id, version_bits);

    result.job_id = job_id;
    result.nonce = asic_result.nonce;
    result.version_bits = version_bits;

    uint8_t asic_address = (uint8_t)((nonce_host >> 17) & 0xffU);
    uint8_t asic_nr = address_interval > 0 ? (uint8_t)(asic_address / address_interval) : 0;
    if (asic_nr < ASIC_get_asic_count(GLOBAL_STATE) && asic_nr < 6) {
        GLOBAL_STATE->chip_submit[asic_nr]++;
    }
    nonce_count++;
    if ((nonce_count % 20U) == 0U) {
        snprintf(GLOBAL_STATE->chip_submit_srt,
                 sizeof(GLOBAL_STATE->chip_submit_srt),
                 "[%lu, %lu, %lu, %lu, %lu, %lu]",
                 GLOBAL_STATE->chip_submit[0], GLOBAL_STATE->chip_submit[1],
                 GLOBAL_STATE->chip_submit[2], GLOBAL_STATE->chip_submit[3],
                 GLOBAL_STATE->chip_submit[4], GLOBAL_STATE->chip_submit[5]);
    }

    return &result;
}
