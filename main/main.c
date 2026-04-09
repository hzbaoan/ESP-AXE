#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_psram.h"
#include "nvs_flash.h"

// #include "protocol_examples_common.h"
#include "main.h"

#include "asic_result_task.h"
#include "asic_task.h"
#include "create_jobs_task.h"
#include "esp_netif.h"
#include "system.h"
#include "http_server.h"
#include "nvs_config.h"
#include "serial.h"
#include "stratum_task.h"
#include "i2c_bitaxe.h"
#include "adc.h"
#include "nvs_device.h"
#include "self_test.h"
#include "asic.h"

#define WIFI_INITIAL_CONNECT_TIMEOUT_MS 15000
#define ASIC_INIT_RETRY_DELAY_MS 5000

static GlobalState GLOBAL_STATE = {
    .extranonce_str = NULL, 
    .extranonce_2_len = 0, 
    .abandon_work = 0, 
    .version_mask = 0,
    .pending_version_mask = 0,
    .ASIC_initalized = false,
    .sock = -1,
    .send_uid = 1
};

static const char * TAG = "bitaxe";

static bool log_task_create_result(const char *task_name, BaseType_t rc)
{
    unsigned long free_heap = (unsigned long)esp_get_free_heap_size();
    unsigned long free_internal = (unsigned long)heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    unsigned long largest_internal_block = (unsigned long)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);

    if (rc == pdPASS) {
        ESP_LOGD(TAG, "%s rc=%d heap=%lu internal=%lu largest_internal=%lu",
                 task_name, (int)rc, free_heap, free_internal, largest_internal_block);
        return true;
    }

    ESP_LOGE(TAG, "%s rc=%d heap=%lu internal=%lu largest_internal=%lu",
             task_name, (int)rc, free_heap, free_internal, largest_internal_block);
    ESP_LOGE(TAG, "Aborting miner startup after %s creation failed. Internal RAM is exhausted.", task_name);
    return false;
}

static bool wait_for_initial_wifi_connection(GlobalState *global_state, const char *wifi_ssid)
{
    if (wifi_ssid == NULL || wifi_ssid[0] == '\0') {
        snprintf(global_state->SYSTEM_MODULE.wifi_status,
                 sizeof(global_state->SYSTEM_MODULE.wifi_status),
                 "AP mode");
        return false;
    }

    EventBits_t result_bits = wifi_connect(pdMS_TO_TICKS(WIFI_INITIAL_CONNECT_TIMEOUT_MS));
    if (result_bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Connected to SSID: %s", wifi_ssid);
        strncpy(global_state->SYSTEM_MODULE.wifi_status, "Connected!", 20);
        return true;
    }

    ESP_LOGW(TAG,
             "Initial Wi-Fi connection to SSID: %s did not complete within %u ms. Continuing startup with AP enabled and background retries.",
             wifi_ssid,
             WIFI_INITIAL_CONNECT_TIMEOUT_MS);
    strncpy(global_state->SYSTEM_MODULE.wifi_status, "AP mode / retry", 20);
    return false;
}

static void wait_for_asic_ready(GlobalState *global_state)
{
    SERIAL_init();

    while (1) {
        SERIAL_clear_buffer();

        if (ASIC_init(global_state) != 0) {
            global_state->SYSTEM_MODULE.asic_status = NULL;
            return;
        }

        global_state->SYSTEM_MODULE.asic_status = "Chip count 0";
        ESP_LOGE(TAG, "ASIC init failed, retrying in %u ms", ASIC_INIT_RETRY_DELAY_MS);
        vTaskDelay(pdMS_TO_TICKS(ASIC_INIT_RETRY_DELAY_MS));
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "Welcome to the bitaxe - FOSS || GTFO!");

    if (!esp_psram_is_initialized()) {
        ESP_LOGE(TAG, "No PSRAM available on ESP32 device!");
        GLOBAL_STATE.psram_is_available = false;
    } else {
        GLOBAL_STATE.psram_is_available = true;
    }

    // Init I2C
    ESP_ERROR_CHECK(i2c_bitaxe_init());
    ESP_LOGI(TAG, "I2C initialized successfully");

    //wait for I2C to init
    vTaskDelay(100 / portTICK_PERIOD_MS);

    //Init ADC
    ADC_init();

    //initialize the ESP32 NVS
    if (NVSDevice_init() != ESP_OK){
        ESP_LOGE(TAG, "Failed to init NVS");
        return;
    }

    //parse the NVS config into GLOBAL_STATE
    if (NVSDevice_parse_config(&GLOBAL_STATE) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to parse NVS config");
        return;
    }

    if (ASIC_set_device_model(&GLOBAL_STATE) != ESP_OK) {
        ESP_LOGE(TAG, "Error setting ASIC model");
        return;
    }

    // Optionally hold the boot button
    bool pressed = gpio_get_level(CONFIG_GPIO_BUTTON_BOOT) == 0; // LOW when pressed
    //should we run the self test?
    if (should_test(&GLOBAL_STATE) || pressed) {
        self_test((void *) &GLOBAL_STATE);
        return;
    }

    SYSTEM_init_system(&GLOBAL_STATE);

    // pull the wifi credentials and hostname out of NVS
    char * wifi_ssid = nvs_config_get_string(NVS_CONFIG_WIFI_SSID, WIFI_SSID);
    char * wifi_pass = nvs_config_get_string(NVS_CONFIG_WIFI_PASS, WIFI_PASS);
    char * hostname  = nvs_config_get_string(NVS_CONFIG_HOSTNAME, HOSTNAME);

    // copy the wifi ssid to the global state
    strncpy(GLOBAL_STATE.SYSTEM_MODULE.ssid, wifi_ssid, sizeof(GLOBAL_STATE.SYSTEM_MODULE.ssid));
    GLOBAL_STATE.SYSTEM_MODULE.ssid[sizeof(GLOBAL_STATE.SYSTEM_MODULE.ssid)-1] = 0;

    // init AP and connect to wifi
    wifi_init(wifi_ssid, wifi_pass, hostname, GLOBAL_STATE.SYSTEM_MODULE.ip_addr_str);

    generate_ssid(GLOBAL_STATE.SYSTEM_MODULE.ap_ssid);

    SYSTEM_init_peripherals(&GLOBAL_STATE);

    // [优化]: 电源与温度管理属于硬件控制，绑定到 Core 1 (APP_CPU)
    xTaskCreatePinnedToCore(POWER_MANAGEMENT_task, "power management", 4096, (void *) &GLOBAL_STATE, 10, NULL, 0);

    //start the API for AxeOS
    start_rest_server((void *) &GLOBAL_STATE);
    bool initial_wifi_connected = wait_for_initial_wifi_connection(&GLOBAL_STATE, wifi_ssid);

    free(wifi_ssid);
    free(wifi_pass);
    free(hostname);

    GLOBAL_STATE.new_stratum_version_rolling_msg = false;

    if (initial_wifi_connected) {
        wifi_softap_off();
    }

    queue_init(&GLOBAL_STATE.stratum_queue);
    queue_init(&GLOBAL_STATE.ASIC_jobs_queue);
    GLOBAL_STATE.stratum_submit_queue = xQueueCreate(
        STRATUM_SUBMIT_QUEUE_LENGTH, sizeof(stratum_share_submission));
    if (GLOBAL_STATE.stratum_submit_queue == NULL) {
        ESP_LOGE(TAG, "Failed to initialize stratum submit queue");
        return;
    }
    if (!ASIC_init_job_resources(&GLOBAL_STATE)) {
        ESP_LOGE(TAG, "Failed to initialize ASIC job resources");
        return;
    }

    wait_for_asic_ready(&GLOBAL_STATE);

    SERIAL_set_baud(ASIC_set_max_baud(&GLOBAL_STATE));
    SERIAL_clear_buffer();

    GLOBAL_STATE.ASIC_initalized = true;

    ESP_LOGD(TAG, "before miner tasks: heap=%lu internal=%lu largest_internal=%lu",
             (unsigned long)esp_get_free_heap_size(),
             (unsigned long)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned long)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));

    // =========================================================================
    // [优化]: 核心任务物理隔离与双核亲和性绑定 (Core Affinity Binding)
    // =========================================================================
    
    // Core 1 (APP_CPU): 绑定算力层。专门伺候 ASIC 芯片
    // 包含区块组装、哈希计算、串口任务下发和 Nonce 结果接收，独占该核心算力
    BaseType_t rc = xTaskCreatePinnedToCore(create_jobs_task, "stratum miner", 5120, (void *)&GLOBAL_STATE, 6, NULL, 0);
    if (!log_task_create_result("create_jobs_task", rc)) {
        return;
    }

    // Core 0 (PRO_CPU): 绑定网络层。矿池协议通信、JSON解析
    // 即使 WiFi 信号差导致重传或掉线，也不会阻塞挖矿哈希和串口下发
    rc = xTaskCreatePinnedToCore(stratum_task, "stratum admin", 5120, (void *) &GLOBAL_STATE, 8, NULL, 0);
    if (!log_task_create_result("stratum_task", rc)) {
        return;
    }

    rc = xTaskCreatePinnedToCore(stratum_submit_task, "stratum submit", 4096, (void *)&GLOBAL_STATE, 9, NULL, 0);
    if (!log_task_create_result("stratum_submit_task", rc)) {
        return;
    }

    rc = xTaskCreatePinnedToCore(ASIC_task, "asic", 4096, (void *)&GLOBAL_STATE, 12, NULL, 1);
    if (!log_task_create_result("ASIC_task", rc)) {
        return;
    }

    rc = xTaskCreatePinnedToCore(ASIC_result_task, "asic result", 4096, (void *)&GLOBAL_STATE, 14, NULL, 1);
    if (!log_task_create_result("ASIC_result_task", rc)) {
        return;
    }
}

void MINER_set_wifi_status(wifi_status_t status, int retry_count, int reason)
{
    switch(status) {
        case WIFI_CONNECTING:
            snprintf(GLOBAL_STATE.SYSTEM_MODULE.wifi_status, 20, "Connecting...");
            return;
        case WIFI_CONNECTED:
            snprintf(GLOBAL_STATE.SYSTEM_MODULE.wifi_status, 20, "Connected!");
            return;
        case WIFI_RETRYING:
            // See https://github.com/espressif/esp-idf/blob/master/components/esp_wifi/include/esp_wifi_types_generic.h for codes
            switch(reason) {
                case 201:
                    snprintf(GLOBAL_STATE.SYSTEM_MODULE.wifi_status, 20, "No AP found (%d)", retry_count);
                    return;
                case 15:
                case 205:
                    snprintf(GLOBAL_STATE.SYSTEM_MODULE.wifi_status, 20, "Password error (%d)", retry_count);
                    return;
                default:
                    snprintf(GLOBAL_STATE.SYSTEM_MODULE.wifi_status, 20, "Error %d (%d)", reason, retry_count);
                    return;
            }
    }
    ESP_LOGW(TAG, "Unknown status: %d", status);
}

void MINER_set_ap_status(bool enabled) {
    GLOBAL_STATE.SYSTEM_MODULE.ap_enabled = enabled;
}
