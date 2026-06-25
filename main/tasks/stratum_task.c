#include "esp_heap_caps.h"
#include "esp_transport.h"
#include "esp_transport_tcp.h"
#include "esp_log.h"
#include "esp_system.h"
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
#include "socks5_client.h"
#include "stratum_api.h"
#include "stratum_task.h"
#include "work_queue.h"
#include "esp_wifi.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mbedtls/sha256.h"
#include "mining.h"
#include "asic.h"
#include "libbase58.h"
#include "sv2_noise.h"
#include "sv2_protocol.h"
#include "utils.h"

#define STRATUM_DIFFICULTY CONFIG_STRATUM_DIFFICULTY

#define MAX_RETRY_ATTEMPTS 3

#define BUFFER_SIZE 1024
#define FALLBACK_SELECT_TIMEOUT_SEC 1
#define PRIMARY_PROBE_INTERVAL_MS (60 * 1000)
#define SV2_TRANSPORT_TIMEOUT_MS 5000
#define SV2_RX_MAX_PAYLOAD_SIZE 4096
#define SV2_MIN_EXTRANONCE2_SIZE 4
#define SV2_SETUP_REQUIRES_VERSION_ROLLING 0x04U

static const char * TAG = "stratum_task";
static StratumApiV1Message stratum_api_v1_message = {};

typedef struct
{
    sv2_noise_ctx_t *noise;
    esp_transport_handle_t transport;
    uint32_t channel_id;
    uint32_t sequence_number;
    uint16_t extranonce_size;
    uint8_t extranonce_prefix[32];
    uint8_t extranonce_prefix_len;
    uint8_t target[32];
    bool channel_opened;
} stratum_v2_runtime_t;

static stratum_v2_runtime_t stratum_v2_runtime = {};

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

static void cleanQueue(GlobalState * GLOBAL_STATE);
static void stratum_sv2_cache_job(sv2_conn_t *conn, sv2_ext_job_t *job);
static sv2_ext_job_t *stratum_sv2_take_job(sv2_conn_t *conn, uint32_t job_id);
static void stratum_sv2_free_cached_jobs(sv2_conn_t *conn);
static mining_notify *stratum_sv2_ext_job_to_notify(const sv2_ext_job_t *job,
                                                    const uint8_t prev_hash[32],
                                                    uint32_t min_ntime,
                                                    uint32_t nbits);
static void stratum_sv2_handle_submit_success(GlobalState *GLOBAL_STATE,
                                              const uint8_t *payload,
                                              uint32_t payload_len);
static void stratum_sv2_handle_submit_error(GlobalState *GLOBAL_STATE,
                                            const uint8_t *payload,
                                            uint32_t payload_len);
static bool stratum_sv2_store_extranonce_values(GlobalState *GLOBAL_STATE,
                                                uint16_t extranonce_size,
                                                const uint8_t extranonce_prefix[32],
                                                uint8_t extranonce_prefix_len);

static socks5_proxy_config_t stratum_socks5_proxy_config(GlobalState *GLOBAL_STATE)
{
    SystemModule *module = &GLOBAL_STATE->SYSTEM_MODULE;

    return (socks5_proxy_config_t) {
        .enabled = module->socks5_proxy_enabled,
        .host = module->socks5_proxy_host,
        .port = module->socks5_proxy_port,
        .username = module->socks5_proxy_user,
        .password = module->socks5_proxy_pass
    };
}

static void stratum_set_abandon_work_locked(GlobalState *GLOBAL_STATE, int abandon_work)
{
    GLOBAL_STATE->abandon_work = abandon_work;
}

static int stratum_next_uid_locked(GlobalState *GLOBAL_STATE)
{
    return GLOBAL_STATE->send_uid++;
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

static void stratum_log_hex_preview(const char *label, const uint8_t *data, size_t len)
{
    enum { PREVIEW_BYTES = 32 };
    char first_hex[(PREVIEW_BYTES * 2) + 1] = {0};
    char last_hex[(PREVIEW_BYTES * 2) + 1] = {0};
    size_t preview_len;

    if (data == NULL || len == 0) {
        ESP_LOGI(TAG, "%s_len=0", label);
        return;
    }

    preview_len = len < PREVIEW_BYTES ? len : PREVIEW_BYTES;
    if (bin2hex(data, preview_len, first_hex, sizeof(first_hex)) == 0) {
        ESP_LOGW(TAG, "%s_len=%u preview_unavailable", label, (unsigned int)len);
        return;
    }

    if (len <= PREVIEW_BYTES) {
        ESP_LOGI(TAG, "%s_len=%u hex=%s",
                 label,
                 (unsigned int)len,
                 first_hex);
        return;
    }

    if (bin2hex(data + len - preview_len, preview_len, last_hex, sizeof(last_hex)) == 0) {
        ESP_LOGI(TAG, "%s_len=%u first_%u=%s",
                 label,
                 (unsigned int)len,
                 (unsigned int)preview_len,
                 first_hex);
        return;
    }

    ESP_LOGI(TAG, "%s_len=%u first_%u=%s last_%u=%s",
             label,
             (unsigned int)len,
             (unsigned int)preview_len,
             first_hex,
             (unsigned int)preview_len,
             last_hex);
}

static void stratum_log_socket_peer(int sock, const char *label)
{
    struct sockaddr_storage peer_addr = {0};
    socklen_t peer_len = sizeof(peer_addr);
    char peer_ip[64] = {0};
    uint16_t peer_port = 0;

    if (getpeername(sock, (struct sockaddr *)&peer_addr, &peer_len) != 0) {
        ESP_LOGW(TAG, "%s connected; peer address unavailable (errno %d: %s)",
                 label, errno, strerror(errno));
        return;
    }

    if (peer_addr.ss_family == AF_INET) {
        const struct sockaddr_in *addr = (const struct sockaddr_in *)&peer_addr;
        inet_ntop(AF_INET, &addr->sin_addr, peer_ip, sizeof(peer_ip));
        peer_port = ntohs(addr->sin_port);
    } else if (peer_addr.ss_family == AF_INET6) {
        const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)&peer_addr;
        inet_ntop(AF_INET6, &addr->sin6_addr, peer_ip, sizeof(peer_ip));
        peer_port = ntohs(addr->sin6_port);
    } else {
        ESP_LOGW(TAG, "%s connected; unsupported peer family %d",
                 label, peer_addr.ss_family);
        return;
    }

    ESP_LOGI(TAG, "%s connected peer: %s:%u", label, peer_ip, peer_port);
}

static void stratum_set_socket_opt_int(int sock, int level, int option_name, int value,
                                       const char *socket_name, const char *option_label)
{
    if (setsockopt(sock, level, option_name, &value, sizeof(value)) != 0) {
        ESP_LOGE(TAG, "%s failed to set %s (errno %d: %s)",
                 socket_name, option_label, errno, strerror(errno));
    }
}

static bool mining_notify_prev_block_changed(const mining_notify *notify,
                                             const uint8_t last_prev_block_hash[32],
                                             bool have_last_prev_block_hash)
{
    if (notify == NULL || !have_last_prev_block_hash) {
        return false;
    }

    return memcmp(last_prev_block_hash, notify->prev_block_hash, 32) != 0;
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

static bool stratum_sv2_config_is_complete(const SystemModule *module)
{
    const char *host = module->is_using_fallback ? module->fallback_sv2_host : module->sv2_host;
    uint16_t port = module->is_using_fallback ? module->fallback_sv2_port : module->sv2_port;

    return host != NULL && host[0] != '\0' &&
           port > 0;
}

static bool stratum_current_target_is_sv2(const SystemModule *module)
{
    uint16_t protocol = module->is_using_fallback ?
        module->fallback_pool_protocol : module->pool_protocol;

    return protocol == STRATUM_PROTOCOL_V2;
}

static bool sv2_sha256_impl(void *hash, const void *data, size_t data_len)
{
    mbedtls_sha256(data, data_len, hash, 0);
    return true;
}

static bool stratum_sv2_decode_authority_public_key(const char *key, uint8_t out[32])
{
    uint8_t decoded[64] = {0};
    size_t decoded_len = sizeof(decoded);
    uint8_t *data;

    if (key == NULL || key[0] == '\0' || out == NULL) {
        return false;
    }

    b58_sha256_impl = sv2_sha256_impl;
    if (!b58tobin(decoded, &decoded_len, key, 0) || decoded_len != 38U) {
        ESP_LOGE(TAG, "Invalid SV2 authority public key encoding");
        return false;
    }

    data = decoded + (sizeof(decoded) - decoded_len);
    if (b58check(data, decoded_len, key, strlen(key)) < 0) {
        ESP_LOGE(TAG, "Invalid SV2 authority public key checksum");
        return false;
    }
    if (data[0] != 0x01 || data[1] != 0x00) {
        ESP_LOGE(TAG, "Invalid SV2 authority public key version");
        return false;
    }

    memcpy(out, data + 2, 32);
    return true;
}

static void stratum_copy_reverse_32bit_words(const uint8_t src[32], uint8_t dest[32])
{
    for (size_t i = 0; i < 8; i++) {
        memcpy(dest + (i * 4U), src + ((7U - i) * 4U), 4U);
    }
}

static float stratum_nominal_hashrate_hs(GlobalState *GLOBAL_STATE)
{
    uint8_t asic_count = ASIC_get_asic_count(GLOBAL_STATE);
    uint16_t small_core_count = ASIC_get_small_core_count(GLOBAL_STATE);
    double frequency_mhz = GLOBAL_STATE->POWER_MANAGEMENT_MODULE.frequency_value;

    if (asic_count == 0) {
        asic_count = 1;
    }
    if (small_core_count == 0 || frequency_mhz <= 0.0) {
        return 1.0e12f;
    }

    return (float)((double)asic_count * (double)small_core_count * frequency_mhz * 1000000.0);
}

static void stratum_sv2_reset_runtime_unlocked(void)
{
    esp_transport_handle_t transport = NULL;
    sv2_noise_ctx_t *noise = NULL;

    noise = stratum_v2_runtime.noise;
    transport = stratum_v2_runtime.transport;
    memset(&stratum_v2_runtime, 0, sizeof(stratum_v2_runtime));

    if (noise != NULL) {
        sv2_noise_destroy(noise);
    }
    if (transport != NULL) {
        esp_transport_close(transport);
        esp_transport_destroy(transport);
    }
}

static void stratum_sv2_reset_runtime_locked(GlobalState *GLOBAL_STATE)
{
    pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
    stratum_sv2_reset_runtime_unlocked();
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
}

static bool stratum_sv2_send_frame(esp_transport_handle_t transport,
                                   uint8_t *frame, int frame_len,
                                   const char *label)
{
    sv2_noise_ctx_t *noise = stratum_v2_runtime.noise;
    if (frame_len <= 0 ||
            noise == NULL ||
            sv2_noise_send(noise, transport, frame, frame_len) != 0) {
        ESP_LOGE(TAG, "SV2 send failed: %s", label);
        return false;
    }
    return true;
}

static bool stratum_sv2_recv_frame(esp_transport_handle_t transport,
                                   sv2_frame_header_t *header,
                                   uint8_t payload[SV2_RX_MAX_PAYLOAD_SIZE],
                                   int *payload_len)
{
    uint8_t header_bytes[SV2_FRAME_HEADER_SIZE];
    sv2_noise_ctx_t *noise = stratum_v2_runtime.noise;

    if (noise == NULL ||
            sv2_noise_recv(noise, transport, header_bytes, payload,
                       SV2_RX_MAX_PAYLOAD_SIZE, payload_len) != 0) {
        return false;
    }

    return sv2_parse_frame_header(header_bytes, header) == 0 &&
           header->msg_length == (uint32_t)*payload_len;
}

static bool stratum_sv2_runtime_channel_matches_locked(uint32_t channel_id)
{
    return stratum_v2_runtime.channel_opened &&
           channel_id == stratum_v2_runtime.channel_id;
}

static bool stratum_sv2_receive_expected(esp_transport_handle_t transport,
                                          uint8_t expected_msg_type,
                                          uint8_t payload[SV2_RX_MAX_PAYLOAD_SIZE],
                                          int *payload_len)
{
    sv2_frame_header_t header;

    while (stratum_sv2_recv_frame(transport, &header, payload, payload_len)) {
        if (header.msg_type == expected_msg_type) {
            return true;
        }
        if (header.msg_type == SV2_MSG_SETUP_CONNECTION_ERROR ||
                header.msg_type == SV2_MSG_OPEN_MINING_CHANNEL_ERROR) {
            ESP_LOGE(TAG, "SV2 setup rejected with msg_type=0x%02x", header.msg_type);
            return false;
        }
        ESP_LOGW(TAG, "Ignoring SV2 msg_type=0x%02x while waiting for 0x%02x",
                 header.msg_type,
                 expected_msg_type);
    }

    return false;
}

static bool stratum_sv2_store_extranonce_values(GlobalState *GLOBAL_STATE,
                                                uint16_t extranonce_size,
                                                const uint8_t extranonce_prefix[32],
                                                uint8_t extranonce_prefix_len)
{
    uint8_t *new_extranonce_bin = NULL;
    int extranonce2_len = (int)extranonce_size;
    bool changed;

    if (extranonce_prefix_len > 0) {
        new_extranonce_bin = malloc(extranonce_prefix_len);
        if (new_extranonce_bin == NULL) {
            ESP_LOGE(TAG, "SV2 extranonce prefix allocation failed");
            log_heap_snapshot("SV2 extranonce prefix alloc");
            return false;
        }
        memcpy(new_extranonce_bin, extranonce_prefix, extranonce_prefix_len);
    }

    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    // SV2 extended-channel extranonce_size is the miner's rollable portion.
    // It is independent from extranonce_prefix_len.
    changed = GLOBAL_STATE->extranonce_bin_len != extranonce_prefix_len ||
              GLOBAL_STATE->extranonce_2_len != extranonce2_len ||
              (extranonce_prefix_len > 0 &&
               (GLOBAL_STATE->extranonce_bin == NULL ||
                memcmp(GLOBAL_STATE->extranonce_bin,
                       extranonce_prefix,
                       extranonce_prefix_len) != 0));

    free(GLOBAL_STATE->extranonce_str);
    free(GLOBAL_STATE->extranonce_bin);
    GLOBAL_STATE->extranonce_str = NULL;
    GLOBAL_STATE->extranonce_bin = new_extranonce_bin;
    GLOBAL_STATE->extranonce_bin_len = extranonce_prefix_len;
    GLOBAL_STATE->extranonce_2_len = extranonce2_len;
    if (changed) {
        GLOBAL_STATE->extranonce_generation++;
    }
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
    return true;
}

static bool stratum_sv2_update_extranonce_prefix(GlobalState *GLOBAL_STATE,
                                                 uint32_t channel_id,
                                                 const uint8_t *prefix,
                                                 uint8_t prefix_len)
{
    uint16_t extranonce_size;
    uint8_t old_prefix[32] = {0};
    uint8_t old_prefix_len;
    uint8_t prefix_snapshot[32] = {0};
    bool stored;

    if (prefix_len > sizeof(stratum_v2_runtime.extranonce_prefix)) {
        return false;
    }

    pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
    if (!stratum_sv2_runtime_channel_matches_locked(channel_id)) {
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
        return false;
    }
    memcpy(old_prefix, stratum_v2_runtime.extranonce_prefix, sizeof(old_prefix));
    old_prefix_len = stratum_v2_runtime.extranonce_prefix_len;
    memset(stratum_v2_runtime.extranonce_prefix, 0, sizeof(stratum_v2_runtime.extranonce_prefix));
    if (prefix_len > 0) {
        memcpy(stratum_v2_runtime.extranonce_prefix, prefix, prefix_len);
        memcpy(prefix_snapshot, prefix, prefix_len);
    }
    stratum_v2_runtime.extranonce_prefix_len = prefix_len;
    extranonce_size = stratum_v2_runtime.extranonce_size;
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);

    stored = stratum_sv2_store_extranonce_values(GLOBAL_STATE,
                                                 extranonce_size,
                                                 prefix_snapshot,
                                                 prefix_len);
    if (!stored) {
        pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
        if (stratum_sv2_runtime_channel_matches_locked(channel_id)) {
            memset(stratum_v2_runtime.extranonce_prefix, 0, sizeof(stratum_v2_runtime.extranonce_prefix));
            memcpy(stratum_v2_runtime.extranonce_prefix, old_prefix, old_prefix_len);
            stratum_v2_runtime.extranonce_prefix_len = old_prefix_len;
        }
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
    }
    return stored;
}

static bool stratum_sv2_setup_channel(GlobalState *GLOBAL_STATE,
                                      esp_transport_handle_t transport,
                                      const char *host, uint16_t port,
                                      const char *user)
{
    uint8_t frame[512];
    uint8_t *payload = malloc(SV2_RX_MAX_PAYLOAD_SIZE);
    int payload_len = 0;
    int frame_len;
    uint16_t used_version = 0;
    uint32_t flags = 0;
    uint32_t request_id = 1;
    uint32_t response_request_id = 0;
    uint32_t group_channel_id = 0;
    uint32_t channel_id = 0;
    uint16_t extranonce_size = 0;
    uint8_t extranonce_prefix[32] = {0};
    uint8_t extranonce_prefix_len = 0;
    uint8_t target[32] = {0};
    bool success = false;

    if (payload == NULL) {
        ESP_LOGE(TAG, "SV2 setup payload allocation failed");
        log_heap_snapshot("SV2 setup payload alloc");
        return false;
    }

    frame_len = sv2_build_setup_connection(frame,
                                           sizeof(frame),
                                           host,
                                           port,
                                           STRATUM_CLIENT_NAME,
                                           GLOBAL_STATE->asic_model_str != NULL ? GLOBAL_STATE->asic_model_str : "",
                                           "",
                                           "",
                                           SV2_SETUP_REQUIRES_VERSION_ROLLING);
    ESP_LOGI(TAG, "Sending SV2 SetupConnection");
    if (!stratum_sv2_send_frame(transport, frame, frame_len, "SetupConnection") ||
            !stratum_sv2_receive_expected(transport, SV2_MSG_SETUP_CONNECTION_SUCCESS, payload, &payload_len) ||
            sv2_parse_setup_connection_success(payload, payload_len, &used_version, &flags) != 0) {
        goto cleanup;
    }
    ESP_LOGI(TAG, "SV2 SetupConnection accepted: version=%u flags=0x%08lx",
             used_version,
             (unsigned long)flags);

    frame_len = sv2_build_open_extended_mining_channel(frame,
                                                       sizeof(frame),
                                                       request_id,
                                                       user != NULL ? user : "",
                                                       stratum_nominal_hashrate_hs(GLOBAL_STATE),
                                                       SV2_MIN_EXTRANONCE2_SIZE);
    ESP_LOGI(TAG,
             "Sending SV2 OpenExtendedMiningChannel min_extranonce_size=%u",
             (unsigned int)SV2_MIN_EXTRANONCE2_SIZE);
    if (!stratum_sv2_send_frame(transport, frame, frame_len, "OpenExtendedMiningChannel") ||
            !stratum_sv2_receive_expected(transport,
                                           SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                                           payload,
                                           &payload_len) ||
            sv2_parse_open_extended_channel_success(payload,
                                                    payload_len,
                                                    &response_request_id,
                                                    &channel_id,
                                                    target,
                                                    &extranonce_size,
                                                    extranonce_prefix,
                                                    &extranonce_prefix_len,
                                                    &group_channel_id) != 0 ||
            response_request_id != request_id) {
        goto cleanup;
    }
    if (extranonce_size < SV2_MIN_EXTRANONCE2_SIZE ||
            extranonce_size > ASIC_EXTRANONCE2_COUNTER_MAX_BYTES) {
        ESP_LOGE(TAG,
                 "SV2 extended channel extranonce_size=%u outside supported range [%u,%u]",
                 (unsigned int)extranonce_size,
                 (unsigned int)SV2_MIN_EXTRANONCE2_SIZE,
                 (unsigned int)ASIC_EXTRANONCE2_COUNTER_MAX_BYTES);
        goto cleanup;
    }

    if (!stratum_sv2_store_extranonce_values(GLOBAL_STATE,
                                             extranonce_size,
                                             extranonce_prefix,
                                             extranonce_prefix_len)) {
        goto cleanup;
    }

    pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
    stratum_v2_runtime.channel_id = channel_id;
    memcpy(stratum_v2_runtime.target, target, sizeof(stratum_v2_runtime.target));
    stratum_v2_runtime.extranonce_size = extranonce_size;
    memcpy(stratum_v2_runtime.extranonce_prefix,
           extranonce_prefix,
           sizeof(stratum_v2_runtime.extranonce_prefix));
    stratum_v2_runtime.extranonce_prefix_len = extranonce_prefix_len;
    stratum_v2_runtime.channel_opened = true;
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);

    GLOBAL_STATE->stratum_difficulty = sv2_target_to_pdiff(target);
    if (GLOBAL_STATE->stratum_difficulty == 0) {
        GLOBAL_STATE->stratum_difficulty = 1;
    }
    GLOBAL_STATE->new_set_mining_difficulty_msg = true;
    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    GLOBAL_STATE->pending_version_mask = ASIC_get_supported_version_mask(GLOBAL_STATE);
    GLOBAL_STATE->new_stratum_version_rolling_msg = true;
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);

    ESP_LOGI(TAG,
             "SV2 extended channel opened: channel=%lu extranonce_prefix=%u extranonce2_size=%u diff=%lu",
             (unsigned long)channel_id,
             extranonce_prefix_len,
             (unsigned int)extranonce_size,
             (unsigned long)GLOBAL_STATE->stratum_difficulty);
    success = true;

cleanup:
    free(payload);
    return success;
}

static void stratum_sv2_enqueue_notify(GlobalState *GLOBAL_STATE,
                                       mining_notify *notify,
                                       bool replace_current_work)
{
    if (notify == NULL) {
        return;
    }

    SYSTEM_notify_new_ntime(GLOBAL_STATE, notify->ntime);
    if (replace_current_work) {
        cleanQueue(GLOBAL_STATE);
    }
    stratum_set_abandon_work(GLOBAL_STATE, 0);

    if (queue_count(&GLOBAL_STATE->stratum_queue) == QUEUE_SIZE) {
        mining_notify *old_notify = (mining_notify *) queue_try_dequeue(&GLOBAL_STATE->stratum_queue);
        STRATUM_V1_free_mining_notify(old_notify);
    }
    queue_enqueue(&GLOBAL_STATE->stratum_queue, notify);
}

static void stratum_sv2_connection_loop(GlobalState *GLOBAL_STATE,
                                        esp_transport_handle_t transport)
{
    sv2_conn_t conn = {0};
    uint8_t *payload = malloc(SV2_RX_MAX_PAYLOAD_SIZE);
    uint8_t current_prev_hash[32] = {0};
    uint32_t current_min_ntime = 0;
    uint32_t current_nbits = 0;
    bool have_current_prev_hash = false;

    if (payload == NULL) {
        ESP_LOGE(TAG, "SV2 connection payload allocation failed");
        log_heap_snapshot("SV2 connection payload alloc");
        stratum_close_connection(GLOBAL_STATE);
        return;
    }

    conn.channel_type = SV2_CHANNEL_EXTENDED;
    stratum_set_abandon_work(GLOBAL_STATE, 0);

    while (1) {
        sv2_frame_header_t header;
        int payload_len = 0;

        if (!stratum_sv2_recv_frame(transport, &header, payload, &payload_len)) {
            ESP_LOGE(TAG, "Failed to receive SV2 frame");
            stratum_close_connection(GLOBAL_STATE);
            break;
        }

        switch (header.msg_type) {
            case SV2_MSG_RECONNECT: {
                char reconnect_host[256] = {0};
                uint16_t reconnect_port = 0;

                if (sv2_parse_reconnect(payload,
                                        payload_len,
                                        reconnect_host,
                                        sizeof(reconnect_host),
                                        &reconnect_port) == 0) {
                    ESP_LOGW(TAG,
                             "SV2 pool requested reconnect to %s:%u; reconnecting current target",
                             reconnect_host,
                             reconnect_port);
                } else {
                    ESP_LOGW(TAG, "SV2 pool requested reconnect with malformed payload");
                }
                stratum_close_connection(GLOBAL_STATE);
                break;
            }
            case SV2_MSG_CHANNEL_ENDPOINT_CHANGED: {
                uint32_t channel_id = 0;
                if (payload_len >= 4) {
                    channel_id = (uint32_t)payload[0] |
                                 ((uint32_t)payload[1] << 8) |
                                 ((uint32_t)payload[2] << 16) |
                                 ((uint32_t)payload[3] << 24);
                    ESP_LOGI(TAG,
                             "SV2 channel endpoint changed: channel=%lu",
                             (unsigned long)channel_id);
                }
                break;
            }
            case SV2_MSG_NEW_EXTENDED_MINING_JOB: {
                uint32_t channel_id = 0;
                sv2_ext_job_t *job = sv2_parse_new_extended_mining_job(payload,
                                                                       payload_len,
                                                                       &channel_id);
                if (job == NULL) {
                    ESP_LOGE(TAG, "Failed to parse SV2 NewExtendedMiningJob");
                    stratum_close_connection(GLOBAL_STATE);
                    break;
                }
                pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
                bool channel_matches = stratum_sv2_runtime_channel_matches_locked(channel_id);
                pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
                if (!channel_matches) {
                    ESP_LOGW(TAG, "Ignoring SV2 job for unexpected channel %lu",
                             (unsigned long)channel_id);
                    sv2_ext_job_free(job);
                    break;
                }
                ESP_LOGI(TAG,
                         "SV2 NewExtendedMiningJob: channel=%lu job=%lu min_ntime_set=%d min_ntime=%08lx version=%08lx rolling=%d merkle_path=%u coinbase_prefix=%u coinbase_suffix=%u",
                         (unsigned long)channel_id,
                         (unsigned long)job->job_id,
                         job->min_ntime_set,
                         (unsigned long)job->ntime,
                         (unsigned long)job->version,
                         job->version_rolling_allowed,
                         job->merkle_path_count,
                         job->coinbase_prefix_len,
                         job->coinbase_suffix_len);
                stratum_log_hex_preview("SV2 coinbase_prefix", job->coinbase_prefix, job->coinbase_prefix_len);
                stratum_log_hex_preview("SV2 coinbase_suffix", job->coinbase_suffix, job->coinbase_suffix_len);
                if (job->min_ntime_set && have_current_prev_hash) {
                    mining_notify *notify;
                    uint32_t job_min_ntime = job->ntime;

                    if (job_min_ntime < current_min_ntime) {
                        job_min_ntime = current_min_ntime;
                    }
                    notify = stratum_sv2_ext_job_to_notify(job,
                                                           current_prev_hash,
                                                           job_min_ntime,
                                                           current_nbits);
                    sv2_ext_job_free(job);
                    if (notify == NULL) {
                        ESP_LOGE(TAG, "Failed to convert current SV2 job");
                        stratum_close_connection(GLOBAL_STATE);
                        break;
                    }

                    ESP_LOGI(TAG, "SV2 current job queued without clearing active work: job=%s ntime=%08lx",
                             notify->job_id,
                             (unsigned long)notify->ntime);
                    stratum_sv2_enqueue_notify(GLOBAL_STATE, notify, false);
                    break;
                }
                stratum_sv2_cache_job(&conn, job);
                break;
            }
            case SV2_MSG_SET_NEW_PREV_HASH: {
                uint32_t channel_id;
                uint32_t job_id;
                uint8_t prev_hash[32];
                uint32_t min_ntime;
                uint32_t nbits;
                sv2_ext_job_t *job;
                mining_notify *notify;
                char prev_hash_hex[65] = {0};

                if (sv2_parse_set_new_prev_hash(payload,
                                                payload_len,
                                                &channel_id,
                                                &job_id,
                                                prev_hash,
                                                &min_ntime,
                                                &nbits) != 0) {
                    ESP_LOGE(TAG, "Failed to parse SV2 SetNewPrevHash");
                    stratum_close_connection(GLOBAL_STATE);
                    break;
                }
                pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
                bool channel_matches = stratum_sv2_runtime_channel_matches_locked(channel_id);
                pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
                if (!channel_matches) {
                    ESP_LOGW(TAG, "Ignoring SV2 prevhash for unexpected channel %lu",
                             (unsigned long)channel_id);
                    break;
                }
                bin2hex(prev_hash, sizeof(prev_hash), prev_hash_hex, sizeof(prev_hash_hex));
                ESP_LOGI(TAG,
                         "SV2 SetNewPrevHash: channel=%lu job=%lu clean=1 ntime=%08lx nbits=%08lx prev_hash=%s",
                         (unsigned long)channel_id,
                         (unsigned long)job_id,
                         (unsigned long)min_ntime,
                         (unsigned long)nbits,
                         prev_hash_hex);
                memcpy(current_prev_hash, prev_hash, sizeof(current_prev_hash));
                current_min_ntime = min_ntime;
                current_nbits = nbits;
                have_current_prev_hash = true;

                job = stratum_sv2_take_job(&conn, job_id);
                if (job == NULL) {
                    ESP_LOGW(TAG, "SV2 SetNewPrevHash references unknown job %lu",
                             (unsigned long)job_id);
                    cleanQueue(GLOBAL_STATE);
                    break;
                }
                stratum_sv2_free_cached_jobs(&conn);

                if (job->min_ntime_set && job->ntime > min_ntime) {
                    min_ntime = job->ntime;
                }
                notify = stratum_sv2_ext_job_to_notify(job, prev_hash, min_ntime, nbits);
                sv2_ext_job_free(job);
                if (notify == NULL) {
                    ESP_LOGE(TAG, "Failed to convert SV2 job");
                    stratum_close_connection(GLOBAL_STATE);
                    break;
                }

                stratum_sv2_enqueue_notify(GLOBAL_STATE, notify, true);
                break;
            }
            case SV2_MSG_SET_TARGET: {
                uint32_t channel_id;
                uint8_t target[32];
                if (sv2_parse_set_target(payload, payload_len, &channel_id, target) == 0) {
                    pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
                    bool channel_matches = stratum_sv2_runtime_channel_matches_locked(channel_id);
                    if (channel_matches) {
                        memcpy(stratum_v2_runtime.target, target, sizeof(stratum_v2_runtime.target));
                    }
                    pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
                    if (!channel_matches) {
                        ESP_LOGW(TAG, "Ignoring SV2 target for unexpected channel %lu",
                                 (unsigned long)channel_id);
                        break;
                    }
                    GLOBAL_STATE->stratum_difficulty = sv2_target_to_pdiff(target);
                    if (GLOBAL_STATE->stratum_difficulty == 0) {
                        GLOBAL_STATE->stratum_difficulty = 1;
                    }
                    GLOBAL_STATE->new_set_mining_difficulty_msg = true;
                    ESP_LOGI(TAG, "SV2 SetTarget difficulty=%lu",
                             (unsigned long)GLOBAL_STATE->stratum_difficulty);
                }
                break;
            }
            case SV2_MSG_SET_EXTRANONCE_PREFIX: {
                uint32_t channel_id = 0;
                uint8_t prefix[32] = {0};
                uint8_t prefix_len = 0;

                if (sv2_parse_set_extranonce_prefix(payload,
                                                    payload_len,
                                                    &channel_id,
                                                    prefix,
                                                    &prefix_len) != 0) {
                    ESP_LOGE(TAG, "Failed to parse SV2 SetExtranoncePrefix");
                    stratum_close_connection(GLOBAL_STATE);
                    break;
                }
                if (!stratum_sv2_update_extranonce_prefix(GLOBAL_STATE, channel_id, prefix, prefix_len)) {
                    ESP_LOGE(TAG, "Failed to apply SV2 SetExtranoncePrefix for channel %lu",
                             (unsigned long)channel_id);
                    stratum_close_connection(GLOBAL_STATE);
                    break;
                }
                ESP_LOGI(TAG,
                         "SV2 SetExtranoncePrefix: channel=%lu prefix_len=%u",
                         (unsigned long)channel_id,
                         (unsigned int)prefix_len);
                cleanQueue(GLOBAL_STATE);
                break;
            }
            case SV2_MSG_SUBMIT_SHARES_SUCCESS:
                stratum_sv2_handle_submit_success(GLOBAL_STATE, payload, payload_len);
                break;
            case SV2_MSG_SUBMIT_SHARES_ERROR:
                stratum_sv2_handle_submit_error(GLOBAL_STATE, payload, payload_len);
                break;
            case SV2_MSG_UPDATE_CHANNEL:
            case SV2_MSG_UPDATE_CHANNEL_ERROR:
            case SV2_MSG_CLOSE_CHANNEL:
                ESP_LOGW(TAG, "SV2 channel management msg_type=0x%02x requires reconnect", header.msg_type);
                stratum_close_connection(GLOBAL_STATE);
                break;
            case SV2_MSG_SETUP_CONNECTION_ERROR:
            case SV2_MSG_OPEN_MINING_CHANNEL_ERROR:
                ESP_LOGE(TAG, "SV2 pool returned error msg_type=0x%02x", header.msg_type);
                stratum_close_connection(GLOBAL_STATE);
                break;
            default:
                ESP_LOGD(TAG, "Ignoring SV2 msg_type=0x%02x", header.msg_type);
                break;
        }

        if (stratum_is_abandoning_work(GLOBAL_STATE) && GLOBAL_STATE->sock < 0) {
            break;
        }
    }

    stratum_sv2_free_cached_jobs(&conn);
    free(payload);
}

static mining_notify *stratum_sv2_ext_job_to_notify(const sv2_ext_job_t *job,
                                                    const uint8_t prev_hash[32],
                                                    uint32_t min_ntime,
                                                    uint32_t nbits)
{
    mining_notify *notify;
    char job_id_text[11];

    if (job == NULL) {
        return NULL;
    }

    notify = calloc(1, sizeof(*notify));
    if (notify == NULL) {
        return NULL;
    }

    snprintf(job_id_text, sizeof(job_id_text), "%lu", (unsigned long)job->job_id);
    notify->job_id = strdup(job_id_text);
    if (notify->job_id == NULL) {
        STRATUM_V1_free_mining_notify(notify);
        return NULL;
    }

    notify->version = job->version;
    notify->ntime = min_ntime;
    notify->target = nbits;
    notify->version_rolling_allowed_set = true;
    notify->version_rolling_allowed = job->version_rolling_allowed;
    notify->coinbase_1_len = job->coinbase_prefix_len;
    notify->coinbase_2_len = job->coinbase_suffix_len;
    notify->n_merkle_branches = job->merkle_path_count;

    if (job->coinbase_prefix_len > 0) {
        notify->coinbase_1_bin = malloc(job->coinbase_prefix_len);
        if (notify->coinbase_1_bin == NULL) {
            STRATUM_V1_free_mining_notify(notify);
            return NULL;
        }
        memcpy(notify->coinbase_1_bin, job->coinbase_prefix, job->coinbase_prefix_len);
    }

    if (job->coinbase_suffix_len > 0) {
        notify->coinbase_2_bin = malloc(job->coinbase_suffix_len);
        if (notify->coinbase_2_bin == NULL) {
            STRATUM_V1_free_mining_notify(notify);
            return NULL;
        }
        memcpy(notify->coinbase_2_bin, job->coinbase_suffix, job->coinbase_suffix_len);
    }

    if (job->merkle_path_count > 0) {
        notify->merkle_branches = malloc((size_t)job->merkle_path_count * HASH_SIZE);
        if (notify->merkle_branches == NULL) {
            STRATUM_V1_free_mining_notify(notify);
            return NULL;
        }
        memcpy(notify->merkle_branches, job->merkle_path, (size_t)job->merkle_path_count * HASH_SIZE);
    }

    memcpy(notify->prev_block_hash_bin, prev_hash, 32);
    memcpy(notify->prev_block_hash, prev_hash, 32);
    stratum_copy_reverse_32bit_words(notify->prev_block_hash, notify->prev_block_hash_be);

    return notify;
}

static void stratum_sv2_cache_job(sv2_conn_t *conn, sv2_ext_job_t *job)
{
    if (conn == NULL || job == NULL) {
        sv2_ext_job_free(job);
        return;
    }

    for (int i = 0; i < SV2_PENDING_JOBS_SIZE; i++) {
        if (conn->ext_pending_jobs[i] == NULL) {
            conn->ext_pending_jobs[i] = job;
            return;
        }
    }

    sv2_ext_job_free(conn->ext_pending_jobs[0]);
    memmove(&conn->ext_pending_jobs[0],
            &conn->ext_pending_jobs[1],
            sizeof(conn->ext_pending_jobs[0]) * (SV2_PENDING_JOBS_SIZE - 1));
    conn->ext_pending_jobs[SV2_PENDING_JOBS_SIZE - 1] = job;
}

static sv2_ext_job_t *stratum_sv2_take_job(sv2_conn_t *conn, uint32_t job_id)
{
    if (conn == NULL) {
        return NULL;
    }

    for (int i = 0; i < SV2_PENDING_JOBS_SIZE; i++) {
        sv2_ext_job_t *job = conn->ext_pending_jobs[i];
        if (job != NULL && job->job_id == job_id) {
            conn->ext_pending_jobs[i] = NULL;
            return job;
        }
    }

    return NULL;
}

static void stratum_sv2_free_cached_jobs(sv2_conn_t *conn)
{
    if (conn == NULL) {
        return;
    }

    for (int i = 0; i < SV2_PENDING_JOBS_SIZE; i++) {
        sv2_ext_job_free(conn->ext_pending_jobs[i]);
        conn->ext_pending_jobs[i] = NULL;
    }
}

static void stratum_sv2_handle_submit_success(GlobalState *GLOBAL_STATE,
                                              const uint8_t *payload,
                                              uint32_t payload_len)
{
    uint32_t channel_id;
    uint32_t last_sequence_number;
    uint32_t accepted_count;

    if (sv2_parse_submit_shares_success(payload,
                                        payload_len,
                                        &channel_id,
                                        &last_sequence_number,
                                        &accepted_count) != 0) {
        ESP_LOGW(TAG, "Failed to parse SV2 SubmitShares.Success");
        return;
    }
    pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
    bool channel_matches = stratum_sv2_runtime_channel_matches_locked(channel_id);
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
    if (!channel_matches) {
        ESP_LOGW(TAG, "Ignoring SV2 SubmitShares.Success for unexpected channel %lu",
                 (unsigned long)channel_id);
        return;
    }

    for (uint32_t i = 0; i < accepted_count; i++) {
        SYSTEM_notify_accepted_share(GLOBAL_STATE);
    }
    ESP_LOGI(TAG, "SV2 shares accepted: channel=%lu last_seq=%lu count=%lu",
             (unsigned long)channel_id,
             (unsigned long)last_sequence_number,
             (unsigned long)accepted_count);
}

static void stratum_sv2_handle_submit_error(GlobalState *GLOBAL_STATE,
                                            const uint8_t *payload,
                                            uint32_t payload_len)
{
    uint32_t channel_id;
    uint32_t sequence_number;
    char error_code[64] = {0};

    if (sv2_parse_submit_shares_error(payload,
                                      payload_len,
                                      &channel_id,
                                      &sequence_number,
                                      error_code,
                                      sizeof(error_code)) != 0) {
        ESP_LOGW(TAG, "Failed to parse SV2 SubmitShares.Error");
        return;
    }
    pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
    bool channel_matches = stratum_sv2_runtime_channel_matches_locked(channel_id);
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
    if (!channel_matches) {
        ESP_LOGW(TAG, "Ignoring SV2 SubmitShares.Error for unexpected channel %lu",
                 (unsigned long)channel_id);
        return;
    }

    ESP_LOGW(TAG, "SV2 share rejected: channel=%lu seq=%lu error=%s",
             (unsigned long)channel_id,
             (unsigned long)sequence_number,
             error_code);
    SYSTEM_notify_rejected_share(GLOBAL_STATE, error_code);
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

    pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    if (GLOBAL_STATE->sock < 0 || GLOBAL_STATE->abandon_work) {
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
        return STRATUM_SUBMIT_SKIPPED;
    }

    socket = GLOBAL_STATE->sock;
    send_uid = stratum_next_uid_locked(GLOBAL_STATE);
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);

    if (stratum_current_target_is_sv2(&GLOBAL_STATE->SYSTEM_MODULE)) {
        uint8_t frame[SV2_FRAME_HEADER_SIZE + 24 + 1 + 32];
        uint8_t extranonce[32] = {0};
        size_t extranonce_len = strlen(extranonce_2) / 2U;
        uint32_t sv2_job_id = (uint32_t)strtoul(jobid, NULL, 10);
        esp_transport_handle_t transport = stratum_v2_runtime.transport;
        sv2_noise_ctx_t *noise = stratum_v2_runtime.noise;
        uint32_t channel_id = stratum_v2_runtime.channel_id;
        uint16_t expected_extranonce_size = stratum_v2_runtime.extranonce_size;
        uint32_t sequence_number;
        int frame_len;

        (void)username;
        (void)send_uid;

        if (transport == NULL ||
                noise == NULL ||
                !stratum_v2_runtime.channel_opened ||
                extranonce_len == 0U ||
                extranonce_len > sizeof(extranonce)) {
            pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
            return -1;
        }

        if (extranonce_len != expected_extranonce_size) {
            ESP_LOGW(TAG, "SV2 submit extranonce length mismatch: got=%u expected=%u",
                     (unsigned int)extranonce_len,
                     (unsigned int)expected_extranonce_size);
            pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
            return -1;
        }

        if (!hex2bin_exact(extranonce_2, extranonce, extranonce_len)) {
            pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
            return -1;
        }

        sequence_number = stratum_v2_runtime.sequence_number++;
        ESP_LOGI(TAG,
                 "Sending SV2 SubmitSharesExtended: channel=%lu seq=%lu job=%lu nonce=%08lx ntime=%08lx version=%08lx extranonce_len=%u extranonce=%s",
                 (unsigned long)channel_id,
                 (unsigned long)sequence_number,
                 (unsigned long)sv2_job_id,
                 (unsigned long)nonce,
                 (unsigned long)ntime,
                 (unsigned long)version,
                 (unsigned int)extranonce_len,
                 extranonce_2);

        frame_len = sv2_build_submit_shares_extended(frame,
                                                     sizeof(frame),
                                                     channel_id,
                                                     sequence_number,
                                                     sv2_job_id,
                                                     nonce,
                                                     ntime,
                                                     version,
                                                     extranonce,
                                                     (uint8_t)extranonce_len);
        ret = frame_len > 0 &&
              sv2_noise_send(noise, transport, frame, frame_len) == 0 ?
              frame_len : -1;
    } else {
        ret = STRATUM_V1_submit_share(socket, send_uid, username, jobid, extranonce_2, ntime, nonce, version);
    }
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);

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
    esp_transport_handle_t sv2_transport = NULL;

    pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
    pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
    if (GLOBAL_STATE->sock < 0) {
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
        ESP_LOGE(TAG, "Socket already shutdown, not shutting down again..");
        return;
    }

    stratum_set_abandon_work_locked(GLOBAL_STATE, 1);
    sock = GLOBAL_STATE->sock;
    if (stratum_current_target_is_sv2(&GLOBAL_STATE->SYSTEM_MODULE)) {
        sv2_transport = stratum_v2_runtime.transport;
    }
    GLOBAL_STATE->sock = -1;
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);

    SYSTEM_update_hashrate_estimate(GLOBAL_STATE);

    ESP_LOGE(TAG, "Shutting down connection and reconnecting...");
    if (sv2_transport != NULL) {
        esp_transport_close(sv2_transport);
    } else {
        shutdown(sock, SHUT_RDWR);
        close(sock);
    }
    pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);

    cleanQueue(GLOBAL_STATE);
    vTaskDelay(1000 / portTICK_PERIOD_MS);
}

static bool stratum_primary_probe(GlobalState * GLOBAL_STATE)
{
    const char *primary_stratum_url = GLOBAL_STATE->SYSTEM_MODULE.pool_url;
    uint16_t primary_stratum_port = GLOBAL_STATE->SYSTEM_MODULE.pool_port;
    struct timeval tcp_timeout = {
        .tv_sec = 5,
        .tv_usec = 0
    };
    socks5_proxy_config_t proxy_config = stratum_socks5_proxy_config(GLOBAL_STATE);
    uint32_t primary_ipv4_addr = 0;
    bool used_proxy = false;

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
    memcpy(&primary_ipv4_addr, primary_dns_addr->h_addr_list[0], sizeof(primary_ipv4_addr));

    int sock = socks5_connect_socket_or_direct(&proxy_config,
                                               primary_stratum_url,
                                               primary_stratum_port,
                                               primary_ipv4_addr,
                                               &tcp_timeout,
                                               &used_proxy);
    if (sock < 0) {
        ESP_LOGD(TAG, "Primary probe connect failed: %s:%d (%s)",
                 host_ip,
                 primary_stratum_port,
                 used_proxy ? "proxy" : "direct");
        return false;
    }

    stratum_configure_socket(sock, "Primary probe", &tcp_timeout, &tcp_timeout);
    stratum_log_socket_peer(sock, used_proxy ? "Primary probe SOCKS5 tunnel" : "Primary probe");

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
    int retry_attempts = 0;
    bool primary_supports_suggest_difficulty = true;
    bool fallback_supports_suggest_difficulty = true;

    ESP_LOGI(TAG, "Stratum task started");
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
        SYSTEM_start_trusted_time_sync(GLOBAL_STATE);

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

        if (stratum_current_target_is_sv2(&GLOBAL_STATE->SYSTEM_MODULE)) {
            const char *authority_key;
            const char *username;
            uint8_t authority_pubkey[32];
            const uint8_t *authority_pubkey_ptr = NULL;
            esp_transport_handle_t transport;
            int sock;
            uint32_t target_ipv4_addr = 0;
            bool used_proxy = false;

            stratum_url = GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback ?
                GLOBAL_STATE->SYSTEM_MODULE.fallback_sv2_host : GLOBAL_STATE->SYSTEM_MODULE.sv2_host;
            port = GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback ?
                GLOBAL_STATE->SYSTEM_MODULE.fallback_sv2_port : GLOBAL_STATE->SYSTEM_MODULE.sv2_port;

            if (!stratum_sv2_config_is_complete(&GLOBAL_STATE->SYSTEM_MODULE)) {
                ESP_LOGE(TAG,
                         "SV2 selected but SV2 host or port is missing. "
                         "Refusing to use SV1 transport against an SV2 endpoint.");
                retry_attempts++;
                vTaskDelay(5000 / portTICK_PERIOD_MS);
                continue;
            }

            authority_key = GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback ?
                GLOBAL_STATE->SYSTEM_MODULE.fallback_sv2_authority_public_key :
                GLOBAL_STATE->SYSTEM_MODULE.sv2_authority_public_key;
            username = GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback ?
                GLOBAL_STATE->SYSTEM_MODULE.fallback_pool_user :
                GLOBAL_STATE->SYSTEM_MODULE.pool_user;

            stratum_sv2_reset_runtime_locked(GLOBAL_STATE);
            ESP_LOGI(TAG, "Connecting to: stratum+tcp://%s:%d", stratum_url, port);
            (void)socks5_parse_ipv4(stratum_url, &target_ipv4_addr);

            transport = esp_transport_tcp_init();
            if (transport == NULL) {
                ESP_LOGE(TAG, "Failed to create SV2 TCP transport");
                retry_attempts++;
                vTaskDelay(5000 / portTICK_PERIOD_MS);
                continue;
            }

            socks5_proxy_config_t proxy_config = stratum_socks5_proxy_config(GLOBAL_STATE);
            esp_err_t ret = socks5_connect_transport_or_direct(transport,
                                                               &proxy_config,
                                                               stratum_url,
                                                               port,
                                                               target_ipv4_addr,
                                                               SV2_TRANSPORT_TIMEOUT_MS,
                                                               &used_proxy);
            if (ret != ESP_OK) {
                ESP_LOGE(TAG, "SV2 transport unable to connect to %s:%d (err %d, errno %d: %s)",
                         stratum_url,
                         port,
                         ret,
                         errno,
                         strerror(errno));
                esp_transport_close(transport);
                esp_transport_destroy(transport);
                retry_attempts++;
                vTaskDelay(5000 / portTICK_PERIOD_MS);
                continue;
            }

            sock = esp_transport_get_socket(transport);
            if (sock < 0) {
                ESP_LOGE(TAG, "SV2 transport connected but socket fd is unavailable");
                esp_transport_close(transport);
                esp_transport_destroy(transport);
                retry_attempts++;
                vTaskDelay(5000 / portTICK_PERIOD_MS);
                continue;
            }

            stratum_log_socket_peer(sock, used_proxy ? "SV2 SOCKS5 tunnel" : "SV2 transport");
            stratum_configure_socket(sock, "SV2 transport socket",
                                     &tcp_snd_timeout, &tcp_rcv_timeout);

            pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
            pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
            GLOBAL_STATE->sock = sock;
            stratum_v2_runtime.transport = transport;
            pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
            pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);

            cleanQueue(GLOBAL_STATE);
            stratum_reset_uid(GLOBAL_STATE);

            ESP_LOGI(TAG, "Starting SV2 setup for %s:%d", stratum_url, port);
            pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
            stratum_v2_runtime.noise = sv2_noise_create();
            pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
            if (stratum_v2_runtime.noise == NULL) {
                ESP_LOGE(TAG, "SV2 Noise context creation failed");
                log_heap_snapshot("SV2 noise context create");
                retry_attempts++;
                stratum_close_connection(GLOBAL_STATE);
                stratum_sv2_reset_runtime_locked(GLOBAL_STATE);
                continue;
            }

            if (authority_key != NULL && authority_key[0] != '\0') {
                if (!stratum_sv2_decode_authority_public_key(authority_key, authority_pubkey)) {
                    ESP_LOGE(TAG, "SV2 authority public key decode failed");
                    retry_attempts++;
                    stratum_close_connection(GLOBAL_STATE);
                    stratum_sv2_reset_runtime_locked(GLOBAL_STATE);
                    continue;
                }
                authority_pubkey_ptr = authority_pubkey;
            } else {
                ESP_LOGW(TAG, "No SV2 authority public key configured; server certificate will not be verified");
            }

            ESP_LOGI(TAG, "Starting SV2 Noise handshake");
            pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
            sv2_noise_ctx_t *noise = stratum_v2_runtime.noise;
            pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
#ifdef CONFIG_SV2_ENFORCE_CERTIFICATE_TIME
            sv2_cert_time_check_t cert_time_check = SYSTEM_has_trusted_time(GLOBAL_STATE) ?
                SV2_CERT_TIME_CHECK_SYSTEM_CLOCK : SV2_CERT_TIME_CHECK_SKIP;
#else
            sv2_cert_time_check_t cert_time_check = SV2_CERT_TIME_CHECK_SKIP;
#endif
            if (sv2_noise_handshake(noise, transport, authority_pubkey_ptr,
                                    cert_time_check) != 0 ||
                    !stratum_sv2_setup_channel(GLOBAL_STATE, transport, stratum_url, port, username)) {
                ESP_LOGE(TAG, "SV2 setup failed");
                retry_attempts++;
                stratum_close_connection(GLOBAL_STATE);
                stratum_sv2_reset_runtime_locked(GLOBAL_STATE);
                continue;
            }

            retry_attempts = 0;
            stratum_sv2_connection_loop(GLOBAL_STATE, transport);
            stratum_sv2_reset_runtime_locked(GLOBAL_STATE);
            retry_attempts++;
            continue;
        }

        struct hostent *dns_addr = gethostbyname(stratum_url);
        if (dns_addr == NULL) {
            retry_attempts++;
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            continue;
        }
        inet_ntop(AF_INET, (void *)dns_addr->h_addr_list[0], host_ip, sizeof(host_ip));
        uint32_t target_ipv4_addr = 0;
        memcpy(&target_ipv4_addr, dns_addr->h_addr_list[0], sizeof(target_ipv4_addr));

        ESP_LOGI(TAG, "Connecting to: stratum+tcp://%s:%d (%s)", stratum_url, port, host_ip);

        socks5_proxy_config_t proxy_config = stratum_socks5_proxy_config(GLOBAL_STATE);
        bool used_proxy = false;
        int sock = socks5_connect_socket_or_direct(&proxy_config,
                                                   stratum_url,
                                                   port,
                                                   target_ipv4_addr,
                                                   &tcp_snd_timeout,
                                                   &used_proxy);
        if (sock < 0) {
            retry_attempts++;
            ESP_LOGE(TAG, "Socket unable to connect to %s:%d (%s)",
                     stratum_url,
                     port,
                     used_proxy ? "proxy" : "direct");
            vTaskDelay(5000 / portTICK_PERIOD_MS);
            continue;
        }

        stratum_log_socket_peer(sock, used_proxy ? "Stratum SOCKS5 tunnel" : "Stratum socket");
        stratum_configure_socket(sock, "Stratum socket", &tcp_snd_timeout, &tcp_rcv_timeout);

        pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
        pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
        GLOBAL_STATE->sock = sock;
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);

        cleanQueue(GLOBAL_STATE);
        stratum_reset_uid(GLOBAL_STATE);

        uint32_t supported_version_mask = ASIC_get_supported_version_mask(GLOBAL_STATE);
        int configure_message_id = stratum_next_uid(GLOBAL_STATE);
        pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
        int configure_ret = STRATUM_V1_configure_version_rolling(GLOBAL_STATE->sock,
                                                                 configure_message_id,
                                                                 &supported_version_mask);
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
        if (!stratum_send_checked(GLOBAL_STATE, configure_ret, "mining.configure")) {
            retry_attempts++;
            continue;
        }

        int subscribe_message_id = stratum_next_uid(GLOBAL_STATE);
        pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
        int subscribe_ret = STRATUM_V1_subscribe(GLOBAL_STATE->sock,
                                                 subscribe_message_id,
                                                 GLOBAL_STATE->asic_model_str);
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
        if (!stratum_send_checked(GLOBAL_STATE, subscribe_ret, "mining.subscribe")) {
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
        uint8_t last_prev_block_hash[32] = {0};
        bool have_last_prev_block_hash = false;

        int authorize_message_id = stratum_next_uid(GLOBAL_STATE);
        int suggest_difficulty_message_id = -1;
        TickType_t next_primary_probe_tick = xTaskGetTickCount() + pdMS_TO_TICKS(PRIMARY_PROBE_INTERVAL_MS);

        pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
        int authorize_ret = STRATUM_V1_authorize(GLOBAL_STATE->sock,
                                                 authorize_message_id,
                                                 username,
                                                 password);
        pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
        if (!stratum_send_checked(GLOBAL_STATE, authorize_ret, "mining.authorize")) {
            retry_attempts++;
            continue;
        }

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
                    mining_notify *notify = stratum_api_v1_message.mining_notification;
                    bool prev_block_changed = mining_notify_prev_block_changed(
                        notify,
                        last_prev_block_hash,
                        have_last_prev_block_hash);
                    bool clean_jobs = should_clean_jobs(stratum_api_v1_message.should_abandon_work) ||
                                      prev_block_changed;

                    SYSTEM_notify_new_ntime(GLOBAL_STATE, notify->ntime);
                    if (clean_jobs) {
                        if (prev_block_changed && !stratum_api_v1_message.should_abandon_work) {
                            ESP_LOGW(TAG, "Forcing clean jobs because prev_block_hash changed");
                        }
                        cleanQueue(GLOBAL_STATE);
                    }
                    memcpy(last_prev_block_hash, notify->prev_block_hash, sizeof(last_prev_block_hash));
                    have_last_prev_block_hash = true;
                    if (queue_count(&GLOBAL_STATE->stratum_queue) == QUEUE_SIZE) {
                        mining_notify * next_notify_json_str = (mining_notify *) queue_try_dequeue(&GLOBAL_STATE->stratum_queue);
                        STRATUM_V1_free_mining_notify(next_notify_json_str);
                    }
                    queue_enqueue(&GLOBAL_STATE->stratum_queue, notify);
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

                bool extranonce_changed;

                retry_attempts = 0;
                pthread_mutex_lock(&GLOBAL_STATE->stratum_state_lock);
                extranonce_changed =
                    GLOBAL_STATE->extranonce_bin == NULL ||
                    GLOBAL_STATE->extranonce_bin_len != stratum_api_v1_message.extranonce_bin_len ||
                    memcmp(GLOBAL_STATE->extranonce_bin,
                           stratum_api_v1_message.extranonce_bin,
                           stratum_api_v1_message.extranonce_bin_len) != 0;

                free(GLOBAL_STATE->extranonce_str);
                free(GLOBAL_STATE->extranonce_bin);
                GLOBAL_STATE->extranonce_str = stratum_api_v1_message.extranonce_str;
                GLOBAL_STATE->extranonce_2_len = stratum_api_v1_message.extranonce_2_len;
                GLOBAL_STATE->extranonce_bin = stratum_api_v1_message.extranonce_bin;
                GLOBAL_STATE->extranonce_bin_len = stratum_api_v1_message.extranonce_bin_len;
                if (extranonce_changed) {
                    GLOBAL_STATE->extranonce_generation++;
                }
                pthread_mutex_unlock(&GLOBAL_STATE->stratum_state_lock);
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
                            pthread_mutex_lock(&GLOBAL_STATE->stratum_socket_lock);
                            int suggest_ret = STRATUM_V1_suggest_difficulty(GLOBAL_STATE->sock,
                                                                            suggest_difficulty_message_id,
                                                                            STRATUM_DIFFICULTY);
                            pthread_mutex_unlock(&GLOBAL_STATE->stratum_socket_lock);
                            if (!stratum_send_checked(GLOBAL_STATE, suggest_ret, "mining.suggest_difficulty")) {
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
