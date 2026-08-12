#ifndef MAIN_SOCKS5_CLIENT_H
#define MAIN_SOCKS5_CLIENT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>

#include "esp_err.h"
#include "esp_transport.h"

typedef struct
{
    bool enabled;
    const char *host;
    uint16_t port;
    const char *username;
    const char *password;
} socks5_proxy_config_t;

bool socks5_proxy_configured(const socks5_proxy_config_t *config);
bool socks5_should_bypass_ipv4(uint32_t ipv4_addr);
bool socks5_parse_ipv4(const char *host, uint32_t *out_ipv4_addr);

int socks5_connect_socket_or_direct(const socks5_proxy_config_t *config,
                                    const char *target_host,
                                    uint16_t target_port,
                                    uint32_t target_ipv4_addr,
                                    const struct timeval *io_timeout,
                                    bool *used_proxy,
                                    bool *proxy_failed);

esp_err_t socks5_connect_transport_or_direct(esp_transport_handle_t transport,
                                             const socks5_proxy_config_t *config,
                                             const char *target_host,
                                             uint16_t target_port,
                                             uint32_t target_ipv4_addr,
                                             int timeout_ms,
                                             bool *used_proxy,
                                             bool *proxy_failed);

#endif // MAIN_SOCKS5_CLIENT_H
