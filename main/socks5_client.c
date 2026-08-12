#include "socks5_client.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "esp_log.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"

#define SOCKS5_VERSION 0x05
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_USERPASS 0x02
#define SOCKS5_AUTH_NO_ACCEPTABLE 0xff
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

static const char *TAG = "socks5_client";

typedef int (*socks5_read_fn_t)(void *ctx, uint8_t *buf, size_t len);
typedef int (*socks5_write_fn_t)(void *ctx, const uint8_t *buf, size_t len);

typedef struct
{
    int sock;
} socks5_socket_io_t;

typedef struct
{
    esp_transport_handle_t transport;
    int timeout_ms;
} socks5_transport_io_t;

static bool socks5_has_text(const char *value)
{
    return value != NULL && value[0] != '\0';
}

bool socks5_proxy_configured(const socks5_proxy_config_t *config)
{
    return config != NULL &&
           config->enabled &&
           socks5_has_text(config->host) &&
           config->port > 0;
}

bool socks5_parse_ipv4(const char *host, uint32_t *out_ipv4_addr)
{
    uint32_t addr;

    if (out_ipv4_addr != NULL) {
        *out_ipv4_addr = 0;
    }
    if (host == NULL) {
        return false;
    }

    addr = inet_addr(host);
    if (addr == INADDR_NONE) {
        return false;
    }
    if (out_ipv4_addr != NULL) {
        *out_ipv4_addr = addr;
    }
    return true;
}

bool socks5_should_bypass_ipv4(uint32_t ipv4_addr)
{
    uint32_t ip = ntohl(ipv4_addr);

    if (ip == 0U) {
        return true;
    }
    if ((ip & 0xff000000UL) == 0x0a000000UL) {
        return true;
    }
    if ((ip & 0xfff00000UL) == 0xac100000UL) {
        return true;
    }
    if ((ip & 0xffff0000UL) == 0xc0a80000UL) {
        return true;
    }
    if ((ip & 0xff000000UL) == 0x7f000000UL) {
        return true;
    }
    if ((ip & 0xffff0000UL) == 0xa9fe0000UL) {
        return true;
    }
    if ((ip & 0xf0000000UL) == 0xe0000000UL) {
        return true;
    }

    return false;
}

static int socket_read_exact(void *ctx, uint8_t *buf, size_t len)
{
    socks5_socket_io_t *io = (socks5_socket_io_t *)ctx;
    size_t received = 0;

    while (received < len) {
        int ret = recv(io->sock, buf + received, len - received, 0);
        if (ret <= 0) {
            return -1;
        }
        received += (size_t)ret;
    }

    return 0;
}

static int socket_write_all(void *ctx, const uint8_t *buf, size_t len)
{
    socks5_socket_io_t *io = (socks5_socket_io_t *)ctx;
    size_t sent = 0;

    while (sent < len) {
        int ret = send(io->sock, buf + sent, len - sent, 0);
        if (ret <= 0) {
            return -1;
        }
        sent += (size_t)ret;
    }

    return 0;
}

static int transport_read_exact(void *ctx, uint8_t *buf, size_t len)
{
    socks5_transport_io_t *io = (socks5_transport_io_t *)ctx;
    size_t received = 0;

    while (received < len) {
        int ret = esp_transport_read(io->transport,
                                     (char *)buf + received,
                                     (int)(len - received),
                                     io->timeout_ms);
        if (ret <= 0) {
            return -1;
        }
        received += (size_t)ret;
    }

    return 0;
}

static int transport_write_all(void *ctx, const uint8_t *buf, size_t len)
{
    socks5_transport_io_t *io = (socks5_transport_io_t *)ctx;
    size_t sent = 0;

    while (sent < len) {
        int ret = esp_transport_write(io->transport,
                                      (const char *)buf + sent,
                                      (int)(len - sent),
                                      io->timeout_ms);
        if (ret <= 0) {
            return -1;
        }
        sent += (size_t)ret;
    }

    return 0;
}

static int socks5_authenticate(void *io_ctx,
                               socks5_read_fn_t read_exact,
                               socks5_write_fn_t write_all,
                               const socks5_proxy_config_t *config)
{
    uint8_t greeting[4] = {SOCKS5_VERSION, 1, SOCKS5_AUTH_NONE, SOCKS5_AUTH_USERPASS};
    uint8_t response[2] = {0};
    const bool has_auth = socks5_has_text(config->username);

    if (has_auth) {
        greeting[1] = 2;
    }

    if (write_all(io_ctx, greeting, (size_t)greeting[1] + 2U) != 0 ||
            read_exact(io_ctx, response, sizeof(response)) != 0) {
        return -1;
    }

    if (response[0] != SOCKS5_VERSION || response[1] == SOCKS5_AUTH_NO_ACCEPTABLE) {
        return -1;
    }

    if (response[1] == SOCKS5_AUTH_NONE) {
        return 0;
    }

    if (response[1] != SOCKS5_AUTH_USERPASS || !has_auth) {
        return -1;
    }

    size_t username_len = strlen(config->username);
    const char *password = config->password == NULL ? "" : config->password;
    size_t password_len = strlen(password);
    uint8_t auth[513];
    uint8_t auth_response[2] = {0};
    size_t pos = 0;

    if (username_len > 255U || password_len > 255U) {
        return -1;
    }

    auth[pos++] = 0x01;
    auth[pos++] = (uint8_t)username_len;
    memcpy(auth + pos, config->username, username_len);
    pos += username_len;
    auth[pos++] = (uint8_t)password_len;
    memcpy(auth + pos, password, password_len);
    pos += password_len;

    if (write_all(io_ctx, auth, pos) != 0 ||
            read_exact(io_ctx, auth_response, sizeof(auth_response)) != 0) {
        return -1;
    }

    return auth_response[0] == 0x01 && auth_response[1] == 0x00 ? 0 : -1;
}

static int socks5_send_connect_request(void *io_ctx,
                                       socks5_read_fn_t read_exact,
                                       socks5_write_fn_t write_all,
                                       const char *target_host,
                                       uint16_t target_port,
                                       uint32_t target_ipv4_addr)
{
    uint8_t request[7 + 255];
    uint8_t header[4] = {0};
    size_t pos = 0;
    bool use_ipv4 = target_ipv4_addr != 0;

    request[pos++] = SOCKS5_VERSION;
    request[pos++] = SOCKS5_CMD_CONNECT;
    request[pos++] = 0x00;

    if (use_ipv4) {
        request[pos++] = SOCKS5_ATYP_IPV4;
        memcpy(request + pos, &target_ipv4_addr, sizeof(target_ipv4_addr));
        pos += sizeof(target_ipv4_addr);
    } else {
        size_t host_len = target_host == NULL ? 0 : strlen(target_host);
        if (host_len == 0 || host_len > 255U) {
            return -1;
        }
        request[pos++] = SOCKS5_ATYP_DOMAIN;
        request[pos++] = (uint8_t)host_len;
        memcpy(request + pos, target_host, host_len);
        pos += host_len;
    }

    request[pos++] = (uint8_t)(target_port >> 8);
    request[pos++] = (uint8_t)(target_port & 0xffU);

    if (write_all(io_ctx, request, pos) != 0 ||
            read_exact(io_ctx, header, sizeof(header)) != 0) {
        return -1;
    }

    if (header[0] != SOCKS5_VERSION || header[1] != 0x00 || header[2] != 0x00) {
        return -1;
    }

    if (header[3] == SOCKS5_ATYP_IPV4) {
        uint8_t discard[4 + 2];
        return read_exact(io_ctx, discard, sizeof(discard));
    }
    if (header[3] == SOCKS5_ATYP_DOMAIN) {
        uint8_t len;
        uint8_t discard[255 + 2];
        if (read_exact(io_ctx, &len, sizeof(len)) != 0) {
            return -1;
        }
        return read_exact(io_ctx, discard, (size_t)len + 2U);
    }
    if (header[3] == SOCKS5_ATYP_IPV6) {
        uint8_t discard[16 + 2];
        return read_exact(io_ctx, discard, sizeof(discard));
    }

    return -1;
}

static int socks5_handshake(void *io_ctx,
                            socks5_read_fn_t read_exact,
                            socks5_write_fn_t write_all,
                            const socks5_proxy_config_t *config,
                            const char *target_host,
                            uint16_t target_port,
                            uint32_t target_ipv4_addr)
{
    if (socks5_authenticate(io_ctx, read_exact, write_all, config) != 0) {
        return -1;
    }

    return socks5_send_connect_request(io_ctx,
                                       read_exact,
                                       write_all,
                                       target_host,
                                       target_port,
                                       target_ipv4_addr);
}

static int connect_socket_with_timeout(int sock,
                                       const struct sockaddr *address,
                                       socklen_t address_len,
                                       const struct timeval *timeout)
{
    if (timeout == NULL) {
        return connect(sock, address, address_len);
    }

    int original_flags = fcntl(sock, F_GETFL, 0);
    if (original_flags < 0 ||
            fcntl(sock, F_SETFL, original_flags | O_NONBLOCK) != 0) {
        return -1;
    }

    int ret = connect(sock, address, address_len);
    if (ret != 0 && errno != EINPROGRESS && errno != EWOULDBLOCK) {
        int connect_errno = errno;
        (void)fcntl(sock, F_SETFL, original_flags);
        errno = connect_errno;
        return -1;
    }

    if (ret != 0) {
        fd_set writefds;
        fd_set errorfds;
        struct timeval select_timeout = *timeout;

        FD_ZERO(&writefds);
        FD_ZERO(&errorfds);
        FD_SET(sock, &writefds);
        FD_SET(sock, &errorfds);

        ret = select(sock + 1,
                     NULL,
                     &writefds,
                     &errorfds,
                     &select_timeout);
        if (ret <= 0) {
            int connect_errno = ret == 0 ? ETIMEDOUT : errno;
            (void)fcntl(sock, F_SETFL, original_flags);
            errno = connect_errno;
            return -1;
        }

        int socket_error = 0;
        socklen_t socket_error_len = sizeof(socket_error);
        if (getsockopt(sock,
                       SOL_SOCKET,
                       SO_ERROR,
                       &socket_error,
                       &socket_error_len) != 0 ||
                socket_error != 0) {
            int connect_errno = socket_error != 0 ? socket_error : errno;
            (void)fcntl(sock, F_SETFL, original_flags);
            errno = connect_errno;
            return -1;
        }
    }

    if (fcntl(sock, F_SETFL, original_flags) != 0) {
        return -1;
    }
    return 0;
}

static int connect_direct_ipv4(uint32_t target_ipv4_addr,
                               uint16_t target_port,
                               const struct timeval *connect_timeout)
{
    struct sockaddr_in dest_addr = {0};
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

    if (sock < 0) {
        return -1;
    }

    dest_addr.sin_addr.s_addr = target_ipv4_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(target_port);

    if (connect_socket_with_timeout(sock,
                                    (struct sockaddr *)&dest_addr,
                                    sizeof(dest_addr),
                                    connect_timeout) != 0) {
        ESP_LOGW(TAG, "Direct connect failed (errno %d: %s)", errno, strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

static bool resolve_target_ipv4(const char *target_host, uint32_t *target_ipv4_addr)
{
    struct hostent *target_addr;

    if (target_ipv4_addr == NULL || target_host == NULL) {
        return false;
    }
    if (*target_ipv4_addr != 0) {
        return true;
    }
    if (socks5_parse_ipv4(target_host, target_ipv4_addr)) {
        return true;
    }

    target_addr = gethostbyname(target_host);
    if (target_addr == NULL ||
            target_addr->h_addr_list == NULL ||
            target_addr->h_addr_list[0] == NULL) {
        ESP_LOGW(TAG, "Direct target DNS lookup failed for %s",
                 target_host == NULL ? "(null)" : target_host);
        return false;
    }

    memcpy(target_ipv4_addr,
           target_addr->h_addr_list[0],
           sizeof(*target_ipv4_addr));
    return true;
}

static int connect_proxy_socket(const socks5_proxy_config_t *config,
                                const char *target_host,
                                uint16_t target_port,
                                uint32_t target_ipv4_addr,
                                const struct timeval *io_timeout)
{
    struct hostent *proxy_addr = gethostbyname(config->host);
    struct sockaddr_in proxy_sockaddr = {0};
    socks5_socket_io_t io = {0};
    int sock;

    if (proxy_addr == NULL || proxy_addr->h_addr_list == NULL || proxy_addr->h_addr_list[0] == NULL) {
        ESP_LOGW(TAG, "SOCKS5 proxy DNS lookup failed for %s", config->host);
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGW(TAG, "SOCKS5 proxy socket create failed (errno %d: %s)", errno, strerror(errno));
        return -1;
    }

    if (io_timeout != NULL) {
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, io_timeout, sizeof(*io_timeout));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, io_timeout, sizeof(*io_timeout));
    }

    proxy_sockaddr.sin_family = AF_INET;
    memcpy(&proxy_sockaddr.sin_addr.s_addr, proxy_addr->h_addr_list[0], sizeof(proxy_sockaddr.sin_addr.s_addr));
    proxy_sockaddr.sin_port = htons(config->port);

    if (connect_socket_with_timeout(sock,
                                    (struct sockaddr *)&proxy_sockaddr,
                                    sizeof(proxy_sockaddr),
                                    io_timeout) != 0) {
        ESP_LOGW(TAG, "SOCKS5 proxy connect failed for %s:%u (errno %d: %s)",
                 config->host, (unsigned int)config->port, errno, strerror(errno));
        close(sock);
        return -1;
    }

    io.sock = sock;
    if (socks5_handshake(&io,
                         socket_read_exact,
                         socket_write_all,
                         config,
                         target_host,
                         target_port,
                         target_ipv4_addr) != 0) {
        ESP_LOGW(TAG, "SOCKS5 handshake failed for %s:%u through %s:%u",
                 target_host,
                 (unsigned int)target_port,
                 config->host,
                 (unsigned int)config->port);
        close(sock);
        return -1;
    }

    return sock;
}

int socks5_connect_socket_or_direct(const socks5_proxy_config_t *config,
                                    const char *target_host,
                                    uint16_t target_port,
                                    uint32_t target_ipv4_addr,
                                    const struct timeval *io_timeout,
                                    bool *used_proxy,
                                    bool *proxy_failed)
{
    if (used_proxy != NULL) {
        *used_proxy = false;
    }
    if (proxy_failed != NULL) {
        *proxy_failed = false;
    }

    bool bypass_proxy = target_ipv4_addr != 0 && socks5_should_bypass_ipv4(target_ipv4_addr);

    if (socks5_proxy_configured(config) && !bypass_proxy) {
        int proxy_sock = connect_proxy_socket(config,
                                              target_host,
                                              target_port,
                                              target_ipv4_addr,
                                              io_timeout);
        if (proxy_sock >= 0) {
            if (used_proxy != NULL) {
                *used_proxy = true;
            }
            ESP_LOGI(TAG, "Using SOCKS5 proxy %s:%u for %s:%u",
                     config->host,
                     (unsigned int)config->port,
                     target_host,
                     (unsigned int)target_port);
            return proxy_sock;
        }

        if (proxy_failed != NULL) {
            *proxy_failed = true;
        }
        ESP_LOGW(TAG, "SOCKS5 unavailable for %s:%u, falling back to direct",
                 target_host,
                 (unsigned int)target_port);
    }

    if (!resolve_target_ipv4(target_host, &target_ipv4_addr)) {
        return -1;
    }
    return connect_direct_ipv4(target_ipv4_addr, target_port, io_timeout);
}

esp_err_t socks5_connect_transport_or_direct(esp_transport_handle_t transport,
                                             const socks5_proxy_config_t *config,
                                             const char *target_host,
                                             uint16_t target_port,
                                             uint32_t target_ipv4_addr,
                                             int timeout_ms,
                                             bool *used_proxy,
                                             bool *proxy_failed)
{
    if (used_proxy != NULL) {
        *used_proxy = false;
    }
    if (proxy_failed != NULL) {
        *proxy_failed = false;
    }

    if (transport == NULL || target_host == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    bool bypass_proxy = target_ipv4_addr != 0 && socks5_should_bypass_ipv4(target_ipv4_addr);

    if (socks5_proxy_configured(config) && !bypass_proxy) {
        socks5_transport_io_t io = {
            .transport = transport,
            .timeout_ms = timeout_ms
        };

        esp_err_t ret = esp_transport_connect(transport, config->host, config->port, timeout_ms);
        if (ret == ESP_OK &&
                socks5_handshake(&io,
                                 transport_read_exact,
                                 transport_write_all,
                                 config,
                                 target_host,
                                 target_port,
                                 target_ipv4_addr) == 0) {
            if (used_proxy != NULL) {
                *used_proxy = true;
            }
            ESP_LOGI(TAG, "Using SOCKS5 proxy %s:%u for %s:%u",
                     config->host,
                     (unsigned int)config->port,
                     target_host,
                     (unsigned int)target_port);
            return ESP_OK;
        }

        if (proxy_failed != NULL) {
            *proxy_failed = true;
        }
        ESP_LOGW(TAG, "SOCKS5 unavailable for %s:%u, falling back to direct",
                 target_host,
                 (unsigned int)target_port);
        esp_transport_close(transport);
    }

    return esp_transport_connect(transport, target_host, target_port, timeout_ms);
}
