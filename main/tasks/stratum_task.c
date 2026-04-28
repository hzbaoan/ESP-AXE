#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
// #include "addr_from_stdin.h"
#include "asic_result_task.h"
#include "connect.h"
#include "system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "global_state.h"
#include "lwip/dns.h"
#include "lwip/sockets.h"
#if defined(__has_include)
#if __has_include(<netinet/tcp.h>)
#include <netinet/tcp.h>
#endif
#else
#include <netinet/tcp.h>
#endif
#include <lwip/tcpip.h>
#include "nvs_config.h"
#include "stratum_task.h"
#include "work_queue.h"
#include "esp_wifi.h"
#include <errno.h>
#include <esp_sntp.h>
#include <string.h>
#include <time.h>
#include "mining.h"
#include "asic.h"

#define STRATUM_DIFFICULTY CONFIG_STRATUM_DIFFICULTY

#define MAX_RETRY_ATTEMPTS 3

#define BUFFER_SIZE 1024
#define FALLBACK_SELECT_TIMEOUT_SEC 1
#define PRIMARY_PROBE_INTERVAL_MS (60 * 1000)

static const char * TAG = "stratum_task";
static StratumApiV1Message stratum_api_v1_message = {};

static struct timeval tcp_snd_timeout = {
    .tv_sec = 5,
    .tv_usec = 0
};

static struct timeval tcp_rcv_timeout = {
    .tv_sec = 60 * 10,
    .tv_usec = 0
};

static const int tcp_nodelay = 1;
static const int tcp_keepalive = 1;
static const int tcp_keepidle_sec = 30;
static const int tcp_keepintvl_sec = 10;
static const int tcp_keepcnt = 3;

static void stratum_set_abandon_work_locked(GlobalState *GLOBAL_STATE, int abandon_work)
{
    GLOBAL_STATE->abandon_work = abandon_work;
}

static int stratum_next_uid_locked(GlobalState *GLOBAL_STATE)
{
    return GLOBAL_STATE->send_uid++;
}

static void log_stack_watermark(const char *phase)
{
    unsigned long free_bytes = (unsigned long)uxTaskGetStackHighWaterMark(NULL);

    ESP_LOGD(TAG, "Stack watermark %s: %lu bytes free", phase, free_bytes);
}

static void log_heap_snapshot(const char *phase)
{
    ESP_LOGW(TAG,
             "%s heap=%lu internal=%lu largest_internal=%lu",
             phase,
             (unsigned long)esp_get_free_heap_size(),
             (unsigned long)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned long)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
}

static void stratum_set_socket_opt_int(int sock, int level, int option_name, int value,
                                       const char *socket_name, const char *option_label)
{
    if (setsockopt(sock, level, option_name, &value, sizeof(value)) != 0) {
        ESP_LOGE(TAG, "%s failed to set %s (errno %d: %s)",
                 socket_name, option_label, errno, strerror(errno));
    }
}

static void stratum_set_socket_opt_timeval(int sock, int option_name, const struct timeval *timeout,
                                           const char *socket_name, const char *option_label)
{
    if (timeout == NULL) {
        return;
    }

    if (setsockopt(sock, SOL_SOCKET, option_name, timeout, sizeof(*timeout)) != 0) {
        ESP_LOGE(TAG, "%s failed to set %s (errno %d: %s)",
                 socket_name, option_label, errno, strerror(errno));
    }
}

static void stratum_configure_socket(int sock, const char *socket_name,
                                     const struct timeval *snd_timeout,
                                     const struct timeval *rcv_timeout)
{
    stratum_set_socket_opt_timeval(sock, SO_SNDTIMEO, snd_timeout, socket_name, "SO_SNDTIMEO");
    stratum_set_socket_opt_timeval(sock, SO_RCVTIMEO, rcv_timeout, socket_name, "SO_RCVTIMEO");

#if defined(TCP_NODELAY)
    stratum_set_socket_opt_int(sock, IPPROTO_TCP, TCP_NODELAY, tcp_nodelay, socket_name, "TCP_NODELAY");
#endif

    stratum_set_socket_opt_int(sock, SOL_SOCKET, SO_KEEPALIVE, tcp_keepalive, socket_name, "SO_KEEPALIVE");

#if defined(TCP_KEEPIDLE)
    stratum_set_socket_opt_int(sock, IPPROTO_TCP, TCP_KEEPIDLE, tcp_keepidle_sec, socket_name, "TCP_KEEPIDLE");
#elif defined(TCP_KEEPALIVE)
    stratum_set_socket_opt_int(sock, IPPROTO_TCP, TCP_KEEPALIVE, tcp_keepidle_sec, socket_name, "TCP_KEEPALIVE");
#endif

#if defined(TCP_KEEPINTVL)
    stratum_set_socket_opt_int(sock, IPPROTO_TCP, TCP_KEEPINTVL, tcp_keepintvl_sec, socket_name, "TCP_KEEPINTVL");
#endif

#if defined(TCP_KEEPCNT)
    stratum_set_socket_opt_int(sock, IPPROTO_TCP, TCP_KEEPCNT, tcp_keepcnt, socket_name, "TCP_KEEPCNT");
#endif
}

static bool stratum_send_checked(GlobalState *GLOBAL_STATE, int ret, const char *message_name)
{
    if (ret >= 0) {
        return true;
    }

    ESP_LOGE(TAG, "%s send failed (errno %d: %s)", message_name, errno, strerror(errno));
    log_heap_snapshot(message_name);
    stratum_close_connection(GLOBAL_STATE);
    return false;
}

static bool is_wifi_connected(void)
{
    wifi_ap_record_t ap_info;
    return esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK;
}

bool stratum_is_abandoning_work(GlobalState *GLOBAL_STATE)
{
    bool abandon_work;

    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    abandon_work = GLOBAL_STATE->abandon_work != 0;
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);

    return abandon_work;
}

void stratum_set_abandon_work(GlobalState *GLOBAL_STATE, int abandon_work)
{
    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    stratum_set_abandon_work_locked(GLOBAL_STATE, abandon_work);
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
}

int stratum_next_uid(GlobalState *GLOBAL_STATE)
{
    int send_uid;

    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    send_uid = stratum_next_uid_locked(GLOBAL_STATE);
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);

    return send_uid;
}

int stratum_submit_share(GlobalState *GLOBAL_STATE, const char *username, const char *jobid,
                         const char *extranonce_2, uint32_t ntime,
                         uint32_t nonce, uint32_t version)
{
    int socket;
    int send_uid;
    int ret;

    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    if (GLOBAL_STATE->sock < 0 || GLOBAL_STATE->abandon_work) {
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
        return STRATUM_SUBMIT_SKIPPED;
    }

    socket = GLOBAL_STATE->sock;
    send_uid = stratum_next_uid_locked(GLOBAL_STATE);
    ret = STRATUM_V1_submit_share(socket, send_uid, username, jobid, extranonce_2, ntime, nonce, version);
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);

    return ret;
}

bool stratum_queue_share(GlobalState *GLOBAL_STATE, const stratum_share_submission *share)
{
    if (GLOBAL_STATE->stratum_submit_queue == NULL || share == NULL) {
        return false;
    }

    return xQueueSend(
               GLOBAL_STATE->stratum_submit_queue,
               share,
               pdMS_TO_TICKS(10)) == pdTRUE;
}

void stratum_submit_task(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;
    stratum_share_submission share = {0};

    while (1) {
        if (GLOBAL_STATE->stratum_submit_queue == NULL) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        if (xQueueReceive(GLOBAL_STATE->stratum_submit_queue, &share, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        int ret = stratum_submit_share(
            GLOBAL_STATE,
            share.username,
            share.jobid,
            share.extranonce_2,
            share.ntime,
            share.nonce,
            share.version);

        if (ret < 0) {
            ESP_LOGW(TAG,
                     "Share submit failed: id=%s nonce=%08lx ver=%08lx (errno %d: %s)",
                     share.jobid,
                     (unsigned long)share.nonce,
                     (unsigned long)share.version,
                     errno,
                     strerror(errno));
            stratum_close_connection(GLOBAL_STATE);
        } else if (ret == STRATUM_SUBMIT_SKIPPED) {
            ESP_LOGD(TAG,
                     "Share submit skipped: id=%s nonce=%08lx ver=%08lx",
                     share.jobid,
                     (unsigned long)share.nonce,
                     (unsigned long)share.version);
        }
    }
}

static void cleanQueue(GlobalState * GLOBAL_STATE)
{
    ESP_LOGI(TAG, "Clean Jobs: clearing queue");
    stratum_set_abandon_work(GLOBAL_STATE, 1);
    ASIC_result_reset_recent_shares();

    if (GLOBAL_STATE->stratum_submit_queue != NULL) {
        xQueueReset(GLOBAL_STATE->stratum_submit_queue);
    }

    queue_clear(&GLOBAL_STATE->stratum_queue);

    pthread_mutex_lock(&GLOBAL_STATE->valid_jobs_lock);

    ASIC_jobs_queue_clear(&GLOBAL_STATE->ASIC_jobs_queue, GLOBAL_STATE);

    for (int i = 0; i < ASIC_ACTIVE_JOB_SLOTS; i++) {
        ASIC_job_pool_release(GLOBAL_STATE, GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[i]);
        GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[i] = NULL;
    }

    memset(GLOBAL_STATE->valid_jobs, 0, sizeof(GLOBAL_STATE->valid_jobs));
    pthread_mutex_unlock(&GLOBAL_STATE->valid_jobs_lock);

    SYSTEM_update_hashrate_estimate(GLOBAL_STATE);
}

static void stratum_reset_uid(GlobalState * GLOBAL_STATE)
{
    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    ESP_LOGI(TAG, "Resetting stratum uid");
    GLOBAL_STATE->send_uid = 1;
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
}

void stratum_close_connection(GlobalState * GLOBAL_STATE)
{
    int sock;

    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    if (GLOBAL_STATE->sock < 0) {
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
        ESP_LOGE(TAG, "Socket already shutdown, not shutting down again..");
        return;
    }

    stratum_set_abandon_work_locked(GLOBAL_STATE, 1);
    sock = GLOBAL_STATE->sock;
    GLOBAL_STATE->sock = -1;
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);

    SYSTEM_update_hashrate_estimate(GLOBAL_STATE);

    ESP_LOGE(TAG, "Shutting down socket and reconnecting...");
    shutdown(sock, SHUT_RDWR);
    close(sock);

    cleanQueue(GLOBAL_STATE);
    vTaskDelay(1000 / portTICK_PERIOD_MS);
}

static bool stratum_primary_probe(GlobalState * GLOBAL_STATE)
{
    const char *primary_stratum_url = GLOBAL_STATE->SYSTEM_MODULE.pool_url;
    uint16_t primary_stratum_port = GLOBAL_STATE->SYSTEM_MODULE.pool_port;
    int addr_family = AF_INET;
    int ip_protocol = IPPROTO_IP;
    struct timeval tcp_timeout = {
        .tv_sec = 5,
        .tv_usec = 0
    };

    if (!is_wifi_connected()) {
        ESP_LOGD(TAG, "Primary probe skipped because WiFi is disconnected");
        return false;
    }

    struct hostent *primary_dns_addr = gethostbyname(primary_stratum_url);
    if (primary_dns_addr == NULL) {
        ESP_LOGD(TAG, "Primary probe DNS lookup failed for %s", primary_stratum_url);
        return false;
    }

    char host_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, (void *)primary_dns_addr->h_addr_list[0], host_ip, sizeof(host_ip));

    struct sockaddr_in dest_addr = {0};
    dest_addr.sin_addr.s_addr = inet_addr(host_ip);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(primary_stratum_port);

    int sock = socket(addr_family, SOCK_STREAM, ip_protocol);
    if (sock < 0) {
        ESP_LOGD(TAG, "Primary probe socket creation failed");
        return false;
    }

    stratum_configure_socket(sock, "Primary probe", &tcp_timeout, &tcp_timeout);

    int err = connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err != 0) {
        ESP_LOGD(TAG, "Primary probe connect failed: %s:%d (errno %d: %s)",
                host_ip, primary_stratum_port, errno, strerror(errno));
        close(sock);
        return false;
    }

    int send_uid = 1;
    if (STRATUM_V1_subscribe(sock, send_uid++, GLOBAL_STATE->asic_model_str) < 0 ||
            STRATUM_V1_authorize(sock, send_uid++, GLOBAL_STATE->SYSTEM_MODULE.pool_user, GLOBAL_STATE->SYSTEM_MODULE.pool_pass) < 0) {
        shutdown(sock, SHUT_RDWR);
        close(sock);
        return false;
    }

    const char *probe_success_marker = "mining.notify";
    char recv_buffer[BUFFER_SIZE];
    char tail[sizeof("mining.notify")] = {0};
    size_t tail_len = 0;
    bool probe_success = false;

    while (!probe_success) {
        memset(recv_buffer, 0, sizeof(recv_buffer));
        int bytes_received = recv(sock, recv_buffer, sizeof(recv_buffer) - 1, 0);
        if (bytes_received <= 0) {
            break;
        }

        recv_buffer[bytes_received] = '\0';
        if (strstr(recv_buffer, probe_success_marker) != NULL) {
            probe_success = true;
            break;
        }

        size_t prefix_len = (size_t)bytes_received;
        if (prefix_len > sizeof(tail) - 1) {
            prefix_len = sizeof(tail) - 1;
        }

        char boundary_buffer[sizeof(tail) * 2] = {0};
        memcpy(boundary_buffer, tail, tail_len);
        memcpy(boundary_buffer + tail_len, recv_buffer, prefix_len);
        boundary_buffer[tail_len + prefix_len] = '\0';

        if (strstr(boundary_buffer, probe_success_marker) != NULL) {
            probe_success = true;
            break;
        }

        tail_len = (size_t)bytes_received;
        if (tail_len > sizeof(tail) - 1) {
            tail_len = sizeof(tail) - 1;
        }
        memcpy(tail, recv_buffer + bytes_received - tail_len, tail_len);
        tail[tail_len] = '\0';
    }

    shutdown(sock, SHUT_RDWR);
    close(sock);

    return probe_success;
}

void stratum_task(void * pvParameters)
{
    GlobalState * GLOBAL_STATE = (GlobalState *) pvParameters;
    char * stratum_url = GLOBAL_STATE->SYSTEM_MODULE.pool_url;
    uint16_t port = GLOBAL_STATE->SYSTEM_MODULE.pool_port;

    char host_ip[INET_ADDRSTRLEN];
    int addr_family = AF_INET;
    int ip_protocol = IPPROTO_IP;
    int retry_attempts = 0;
    bool primary_supports_suggest_difficulty = true;
    bool fallback_supports_suggest_difficulty = true;

    ESP_LOGI(TAG, "Opening connection to pool: %s:%d", stratum_url, port);
    log_stack_watermark("after init");
    while (!GLOBAL_STATE->job_queue_initalized) {
        ESP_LOGI(TAG, "Waiting for jobs queres to init....");
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }

    while (1) {
        if (!STRATUM_V1_initialize_buffer()) {
            ESP_LOGE(TAG, "Stratum buffers unavailable, retrying without restarting");
            log_heap_snapshot("stratum buffer alloc");
            vTaskDelay(5000 / portTICK_PERIOD_MS);
            continue;
        }

        if (!is_wifi_connected()) {
            ESP_LOGI(TAG, "WiFi disconnected, attempting to reconnect...");
            vTaskDelay(10000 / portTICK_PERIOD_MS);
            continue;
        }

        if (retry_attempts >= MAX_RETRY_ATTEMPTS) {
            if (GLOBAL_STATE->SYSTEM_MODULE.fallback_pool_url == NULL ||
                    GLOBAL_STATE->SYSTEM_MODULE.fallback_pool_url[0] == '\0') {
                ESP_LOGI(TAG, "Unable to switch to fallback. No url configured. (retries: %d)...", retry_attempts);
                GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback = false;
                retry_attempts = 0;
                continue;
            }

            GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback = !GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback;
            ESP_LOGI(TAG, "Switching target due to too many failures (retries: %d)...", retry_attempts);
            retry_attempts = 0;
        }

        stratum_url = GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback ?
            GLOBAL_STATE->SYSTEM_MODULE.fallback_pool_url : GLOBAL_STATE->SYSTEM_MODULE.pool_url;
        port = GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback ?
            GLOBAL_STATE->SYSTEM_MODULE.fallback_pool_port : GLOBAL_STATE->SYSTEM_MODULE.pool_port;

        struct hostent *dns_addr = gethostbyname(stratum_url);
        if (dns_addr == NULL) {
            retry_attempts++;
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            continue;
        }
        inet_ntop(AF_INET, (void *)dns_addr->h_addr_list[0], host_ip, sizeof(host_ip));

        ESP_LOGI(TAG, "Connecting to: stratum+tcp://%s:%d (%s)", stratum_url, port, host_ip);

        struct sockaddr_in dest_addr = {0};
        dest_addr.sin_addr.s_addr = inet_addr(host_ip);
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);

        GLOBAL_STATE->sock = socket(addr_family, SOCK_STREAM, ip_protocol);
        if (GLOBAL_STATE->sock < 0) {
            ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
            log_heap_snapshot("socket create failed");
            vTaskDelay(5000 / portTICK_PERIOD_MS);
            continue;
        }

        ESP_LOGI(TAG, "Socket created, connecting to %s:%d", host_ip, port);
        log_stack_watermark("before connect");
        int err = connect(GLOBAL_STATE->sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (err != 0) {
            retry_attempts++;
            ESP_LOGE(TAG, "Socket unable to connect to %s:%d (errno %d: %s)",
                    stratum_url, port, errno, strerror(errno));
            shutdown(GLOBAL_STATE->sock, SHUT_RDWR);
            close(GLOBAL_STATE->sock);
            GLOBAL_STATE->sock = -1;
            vTaskDelay(5000 / portTICK_PERIOD_MS);
            continue;
        }
        log_stack_watermark("after connect");

        stratum_configure_socket(GLOBAL_STATE->sock, "Stratum socket", &tcp_snd_timeout, &tcp_rcv_timeout);

        cleanQueue(GLOBAL_STATE);
        stratum_reset_uid(GLOBAL_STATE);

        uint32_t supported_version_mask = ASIC_get_supported_version_mask(GLOBAL_STATE);
        int configure_message_id = stratum_next_uid(GLOBAL_STATE);
        if (!stratum_send_checked(GLOBAL_STATE,
                                  STRATUM_V1_configure_version_rolling(GLOBAL_STATE->sock,
                                                                       configure_message_id,
                                                                       &supported_version_mask),
                                  "mining.configure")) {
            retry_attempts++;
            continue;
        }

        int subscribe_message_id = stratum_next_uid(GLOBAL_STATE);
        if (!stratum_send_checked(GLOBAL_STATE,
                                  STRATUM_V1_subscribe(GLOBAL_STATE->sock,
                                                       subscribe_message_id,
                                                       GLOBAL_STATE->asic_model_str),
                                  "mining.subscribe")) {
            retry_attempts++;
            continue;
        }

        char * username = GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback ?
            GLOBAL_STATE->SYSTEM_MODULE.fallback_pool_user : GLOBAL_STATE->SYSTEM_MODULE.pool_user;
        char * password = GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback ?
            GLOBAL_STATE->SYSTEM_MODULE.fallback_pool_pass : GLOBAL_STATE->SYSTEM_MODULE.pool_pass;
        bool *supports_suggest_difficulty = GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback ?
            &fallback_supports_suggest_difficulty : &primary_supports_suggest_difficulty;
        const char *pool_name = GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback ? "fallback" : "primary";

        int authorize_message_id = stratum_next_uid(GLOBAL_STATE);
        int suggest_difficulty_message_id = -1;
        TickType_t next_primary_probe_tick = xTaskGetTickCount() + pdMS_TO_TICKS(PRIMARY_PROBE_INTERVAL_MS);

        if (!stratum_send_checked(GLOBAL_STATE,
                                  STRATUM_V1_authorize(GLOBAL_STATE->sock,
                                                       authorize_message_id,
                                                       username,
                                                       password),
                                  "mining.authorize")) {
            retry_attempts++;
            continue;
        }
        log_stack_watermark("after setup tx");

        stratum_set_abandon_work(GLOBAL_STATE, 0);

        while (1) {
            if (GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback) {
                TickType_t now = xTaskGetTickCount();
                if ((int32_t)(now - next_primary_probe_tick) >= 0) {
                    if (stratum_primary_probe(GLOBAL_STATE)) {
                        ESP_LOGI(TAG, "Primary probe succeeded while mining on fallback. Reconnecting to primary.");
                        GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback = false;
                        retry_attempts = 0;
                        stratum_close_connection(GLOBAL_STATE);
                        break;
                    }

                    next_primary_probe_tick = now + pdMS_TO_TICKS(PRIMARY_PROBE_INTERVAL_MS);
                }

                fd_set readfds;
                FD_ZERO(&readfds);
                FD_SET(GLOBAL_STATE->sock, &readfds);

                struct timeval select_timeout = {
                    .tv_sec = FALLBACK_SELECT_TIMEOUT_SEC,
                    .tv_usec = 0
                };

                int ready = select(GLOBAL_STATE->sock + 1, &readfds, NULL, NULL, &select_timeout);
                if (ready < 0) {
                    if (errno == EINTR) {
                        continue;
                    }

                    ESP_LOGE(TAG, "select() failed on fallback socket: errno %d: %s", errno, strerror(errno));
                    retry_attempts++;
                    stratum_close_connection(GLOBAL_STATE);
                    break;
                }

                if (ready == 0 || !FD_ISSET(GLOBAL_STATE->sock, &readfds)) {
                    continue;
                }
            }

            char * line = STRATUM_V1_receive_jsonrpc_line(GLOBAL_STATE->sock);
            if (!line) {
                ESP_LOGE(TAG, "Failed to receive JSON-RPC line, reconnecting...");
                retry_attempts++;
                stratum_close_connection(GLOBAL_STATE);
                break;
            }

            ESP_LOGI(TAG, "rx: %s", line);
            STRATUM_V1_parse(&stratum_api_v1_message, line);
            free(line);

            if (stratum_api_v1_message.method == MINING_NOTIFY) {
                if (stratum_api_v1_message.mining_notification == NULL) {
                    const char *error_str = stratum_api_v1_message.error_str != NULL ?
                        stratum_api_v1_message.error_str : "missing_payload";
                    ESP_LOGE(TAG, "mining.notify parsed without a payload: %s", error_str);
                    free(stratum_api_v1_message.error_str);
                    stratum_api_v1_message.error_str = NULL;
                    retry_attempts++;
                    stratum_close_connection(GLOBAL_STATE);
                    break;
                } else {
                    SYSTEM_notify_new_ntime(GLOBAL_STATE, stratum_api_v1_message.mining_notification->ntime);
                    if (should_clean_jobs(stratum_api_v1_message.should_abandon_work)) {
                        cleanQueue(GLOBAL_STATE);
                    }
                    if (queue_count(&GLOBAL_STATE->stratum_queue) == QUEUE_SIZE) {
                        mining_notify * next_notify_json_str = (mining_notify *) queue_try_dequeue(&GLOBAL_STATE->stratum_queue);
                        STRATUM_V1_free_mining_notify(next_notify_json_str);
                    }
                    queue_enqueue(&GLOBAL_STATE->stratum_queue, stratum_api_v1_message.mining_notification);
                    stratum_api_v1_message.mining_notification = NULL;
                }
            } else if (stratum_api_v1_message.method == MINING_SET_DIFFICULTY) {
                uint32_t new_difficulty = stratum_api_v1_message.new_difficulty;

                if (new_difficulty == 0) {
                    ESP_LOGW(TAG, "Pool sent difficulty 0. Falling back to difficulty 1 until a valid update arrives.");
                    new_difficulty = 1;
                }

                ESP_LOGI(TAG, "Set stratum difficulty: %lu", (unsigned long)new_difficulty);
                GLOBAL_STATE->stratum_difficulty = new_difficulty;
                GLOBAL_STATE->new_set_mining_difficulty_msg = true;
            } else if (stratum_api_v1_message.method == MINING_SET_VERSION_MASK ||
                    stratum_api_v1_message.method == STRATUM_RESULT_VERSION_MASK) {
                uint32_t supported_mask = ASIC_get_supported_version_mask(GLOBAL_STATE);
                uint32_t effective_mask = stratum_api_v1_message.version_mask & supported_mask;

                ESP_LOGI(TAG, "Set version mask: %08lx -> %08lx", stratum_api_v1_message.version_mask, effective_mask);
                pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
                GLOBAL_STATE->pending_version_mask = effective_mask;
                GLOBAL_STATE->new_stratum_version_rolling_msg = true;
                pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
            } else if (stratum_api_v1_message.method == STRATUM_RESULT_SUBSCRIBE) {
                if (!stratum_api_v1_message.response_success ||
                        stratum_api_v1_message.extranonce_str == NULL ||
                        stratum_api_v1_message.extranonce_bin == NULL ||
                        stratum_api_v1_message.extranonce_2_len <= 0) {
                    ESP_LOGE(TAG, "Subscribe handshake incomplete, reconnecting");
                    retry_attempts++;
                    stratum_close_connection(GLOBAL_STATE);
                    break;
                }

                retry_attempts = 0;
                free(GLOBAL_STATE->extranonce_str);
                free(GLOBAL_STATE->extranonce_bin);
                GLOBAL_STATE->extranonce_str = stratum_api_v1_message.extranonce_str;
                GLOBAL_STATE->extranonce_2_len = stratum_api_v1_message.extranonce_2_len;
                GLOBAL_STATE->extranonce_bin = stratum_api_v1_message.extranonce_bin;
                GLOBAL_STATE->extranonce_bin_len = stratum_api_v1_message.extranonce_bin_len;
                stratum_api_v1_message.extranonce_str = NULL;
                stratum_api_v1_message.extranonce_bin = NULL;
                stratum_api_v1_message.extranonce_bin_len = 0;
            } else if (stratum_api_v1_message.method == CLIENT_RECONNECT) {
                ESP_LOGE(TAG, "Pool requested client reconnect...");
                stratum_close_connection(GLOBAL_STATE);
                break;
            } else if (stratum_api_v1_message.method == STRATUM_RESULT ||
                    stratum_api_v1_message.method == STRATUM_RESULT_SETUP) {
                const char *error_str = stratum_api_v1_message.error_str != NULL ?
                    stratum_api_v1_message.error_str : "unknown";

                if (stratum_api_v1_message.message_id == suggest_difficulty_message_id) {
                    if (stratum_api_v1_message.response_success) {
                        ESP_LOGI(TAG, "%s pool accepted mining.suggest_difficulty=%d", pool_name, STRATUM_DIFFICULTY);
                    } else {
                        *supports_suggest_difficulty = false;
                        ESP_LOGW(TAG, "%s pool rejected mining.suggest_difficulty: %s. Disabling it for this pool.",
                                pool_name, error_str);
                    }
                    suggest_difficulty_message_id = -1;
                } else if (stratum_api_v1_message.message_id == configure_message_id ||
                        stratum_api_v1_message.message_id == subscribe_message_id ||
                        stratum_api_v1_message.message_id == authorize_message_id) {
                    if (stratum_api_v1_message.response_success) {
                        retry_attempts = 0;
                        ESP_LOGI(TAG, "setup message %lld accepted",
                                (long long)stratum_api_v1_message.message_id);
                        if (stratum_api_v1_message.message_id == authorize_message_id &&
                                STRATUM_DIFFICULTY > 0 &&
                                *supports_suggest_difficulty) {
                            suggest_difficulty_message_id = stratum_next_uid(GLOBAL_STATE);
                            if (!stratum_send_checked(GLOBAL_STATE,
                                                      STRATUM_V1_suggest_difficulty(GLOBAL_STATE->sock,
                                                                                    suggest_difficulty_message_id,
                                                                                    STRATUM_DIFFICULTY),
                                                      "mining.suggest_difficulty")) {
                                retry_attempts++;
                                break;
                            }
                        }
                    } else {
                        ESP_LOGE(TAG, "setup message %lld rejected: %s",
                                (long long)stratum_api_v1_message.message_id, error_str);
                        retry_attempts++;
                        stratum_close_connection(GLOBAL_STATE);
                        break;
                    }
                } else {
                    if (stratum_api_v1_message.response_success) {
                        ESP_LOGI(TAG, "message result accepted");
                        SYSTEM_notify_accepted_share(GLOBAL_STATE);
                    } else {
                        ESP_LOGW(TAG, "message result rejected: %s", error_str);
                        SYSTEM_notify_rejected_share(GLOBAL_STATE, (char *)error_str);
                    }
                }
            }

            free(stratum_api_v1_message.error_str);
            stratum_api_v1_message.error_str = NULL;
        }
    }

    vTaskDelete(NULL);
}
