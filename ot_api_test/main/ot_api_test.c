/*
 * SPDX-FileCopyrightText: 2021-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * OpenThread Command Line Example
 *
 * This example code is in the Public Domain (or CC0 licensed, at your option.)
 *
 * Unless required by applicable law or agreed to in writing, this
 * software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.
*/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_types.h"
#include "ot_api_test.h"
#include "esp_openthread.h"
#include "esp_openthread_cli.h"
#include "esp_openthread_lock.h"
#include "esp_openthread_netif_glue.h"
#include "esp_openthread_types.h"
#include "esp_vfs_eventfd.h"
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "hal/uart_types.h"
#include "openthread/cli.h"
#include "openthread/instance.h"
#include "openthread/logging.h"
#include "openthread/tasklet.h"
#include "openthread/child_supervision.h"

#include "esp_system.h"

#define TCP_SOCKET_SERVER_TEST 0
#define TCP_SOCKET_CLIENT_TEST 0
#define COAP_CLIENT_TEST 0
#define HTTP_DOWNLOAD_TEST 0

#if TCP_SOCKET_SERVER_TEST
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>
#define PORT                        3333
#define KEEPALIVE_IDLE              5
#define KEEPALIVE_INTERVAL          5
#define KEEPALIVE_COUNT             3
#endif

#if TCP_SOCKET_CLIENT_TEST
#define TARGET_HOST "fd45:c28c:474f:0:c89f:e7ff:571b:9431"
#define TARGET_PORT 3334
// 64 bytes
static const char *payload_64 = "1111111111111111222222222222222233333333333333334444444444444444";
// 512 bytes
static const char *payload_512 = "111111111111111122222222222222223333333333333333444444444444444455555555555555556666666666666666777777777777777788888888888888889999999999999999AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF0000000000000000111111111111111122222222222222223333333333333333444444444444444455555555555555556666666666666666777777777777777788888888888888889999999999999999AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF0000000000000000";
// 1024 bytes
static const char *payload_1024 = "111111111111111122222222222222223333333333333333444444444444444455555555555555556666666666666666777777777777777788888888888888889999999999999999AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF0000000000000000111111111111111122222222222222223333333333333333444444444444444455555555555555556666666666666666777777777777777788888888888888889999999999999999AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF0000000000000000111111111111111122222222222222223333333333333333444444444444444455555555555555556666666666666666777777777777777788888888888888889999999999999999AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF0000000000000000111111111111111122222222222222223333333333333333444444444444444455555555555555556666666666666666777777777777777788888888888888889999999999999999AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF0000000000000000";
#endif

#if COAP_CLIENT_TEST
#include "coap3/coap.h"
#include <sys/socket.h>
#include <netdb.h>
#include <sys/param.h>
#endif

#if HTTP_DOWNLOAD_TEST
#include "esp_http_client.h"
#include "esp_tls.h"
#endif

#if COAP_CLIENT_TEST
#define COAP_UDP_IPv6_URI "coap://[fd45:c28c:474f:0:25f8:b1dc:bb24:42d6]/test-resource"
#define COAP_UDP_URI "coap://192.168.86.21/test-resource"
#define COAP_TCP_URI "coap+tcp://192.168.86.21/test-resource"
#define COAP_TLS_URI "coaps://192.168.86.21/test-resource"
#define COAP_DEFAULT_TIME_SEC 60
#ifdef CONFIG_COAP_MBEDTLS_PKI
/* CA cert, taken from coap_ca.pem
   Client cert, taken from coap_client_task.crt
   Client key, taken from coap_client_task.key

   To embed it in the app binary, the PEM, CRT and KEY file is named
   in the component.mk COMPONENT_EMBED_TXTFILES variable.
 */
extern uint8_t ca_pem_start[] asm("_binary_coap_ca_pem_start");
extern uint8_t ca_pem_end[]   asm("_binary_coap_ca_pem_end");
extern uint8_t client_crt_start[] asm("_binary_coap_client_crt_start");
extern uint8_t client_crt_end[]   asm("_binary_coap_client_crt_end");
extern uint8_t client_key_start[] asm("_binary_coap_client_key_start");
extern uint8_t client_key_end[]   asm("_binary_coap_client_key_end");
#endif /* CONFIG_COAP_MBEDTLS_PKI */
#ifdef CONFIG_COAP_MBEDTLS_PSK
#define COAP_PSK_KEY "1234567890abcdef1234567890abcdef"
#define COAP_PSK_IDENTITY "CoAP"
#endif /* CONFIG_COAP_MBEDTLS_PSK */
#endif

static esp_netif_t *netif_custom = NULL;

const static char *TAG = "ot_esp_cli_coap_tcp";

#if COAP_CLIENT_TEST
static int resp_wait = 1;
static coap_optlist_t *optlist = NULL;
static int wait_ms;
#endif

const char *ipv6_addr_types_to_str[6] = {"ESP_IP6_ADDR_IS_UNKNOWN", "ESP_IP6_ADDR_IS_GLOBAL", "ESP_IP6_ADDR_IS_LINK_LOCAL", "ESP_IP6_ADDR_IS_SITE_LOCAL", "ESP_IP6_ADDR_IS_UNIQUE_LOCAL", "ESP_IP6_ADDR_IS_IPV4_MAPPED_IPV6"};

EventGroupHandle_t evt_grp;
#define ACQ_IPV6_ADDRESS    (1 << 0)

#if TCP_SOCKET_SERVER_TEST
static void do_retransmit(const int sock)
{
    int len;
    char rx_buffer[1025];

    do {
        len = recv(sock, rx_buffer, sizeof(rx_buffer) - 1, 0);
        if (len < 0) {
            ESP_LOGE(TAG, "Error occurred during receiving: errno %d", errno);
        } else if (len == 0) {
            ESP_LOGW(TAG, "Connection closed");
        } else {
            rx_buffer[len] = 0; // Null-terminate whatever is received and treat it like a string
            ESP_LOGI(TAG, "Received %d bytes: %s", len, rx_buffer);

            // send() can return less bytes than supplied length.
            // Walk-around for robust implementation.
            int to_write = len;
            //while (to_write > 0) {
            //    int written = send(sock, rx_buffer + (len - to_write), to_write, 0);
            //    if (written < 0) {
            //        ESP_LOGE(TAG, "Error occurred during sending: errno %d", errno);
            //    }
            //    to_write -= written;
            //}
        }
    } while (len > 0);
}
static void tcp_server_task(void *pvParameters)
{
    char addr_str[128];
    int addr_family = (int)pvParameters;
    int ip_protocol = 0;
    int keepAlive = 1;
    int keepIdle = KEEPALIVE_IDLE;
    int keepInterval = KEEPALIVE_INTERVAL;
    int keepCount = KEEPALIVE_COUNT;
    struct sockaddr_storage dest_addr;

    if (addr_family == AF_INET6) {
        struct sockaddr_in6 *dest_addr_ip6 = (struct sockaddr_in6 *)&dest_addr;
        bzero(&dest_addr_ip6->sin6_addr.un, sizeof(dest_addr_ip6->sin6_addr.un));
        dest_addr_ip6->sin6_family = AF_INET6;
        dest_addr_ip6->sin6_port = htons(PORT);
        ip_protocol = IPPROTO_IPV6;
    }

    int listen_sock = socket(addr_family, SOCK_STREAM, ip_protocol);
    if (listen_sock < 0) {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    ESP_LOGI(TAG, "Socket created");

    int err = bind(listen_sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err != 0) {
        ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
        ESP_LOGE(TAG, "IPPROTO: %d", addr_family);
        goto CLEAN_UP;
    }
    ESP_LOGI(TAG, "Socket bound, port %d", PORT);

    err = listen(listen_sock, 1);
    if (err != 0) {
        ESP_LOGE(TAG, "Error occurred during listen: errno %d", errno);
        goto CLEAN_UP;
    }

    while (1) {

        ESP_LOGI(TAG, "Socket listening");

        struct sockaddr_storage source_addr; // Large enough for both IPv4 or IPv6
        socklen_t addr_len = sizeof(source_addr);
        int sock = accept(listen_sock, (struct sockaddr *)&source_addr, &addr_len);
        if (sock < 0) {
            ESP_LOGE(TAG, "Unable to accept connection: errno %d", errno);
            break;
        }

        // Set tcp keepalive option
        setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &keepAlive, sizeof(int));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepIdle, sizeof(int));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepInterval, sizeof(int));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keepCount, sizeof(int));
        // Convert ip address to string
        if (source_addr.ss_family == PF_INET6) {
            inet6_ntoa_r(((struct sockaddr_in6 *)&source_addr)->sin6_addr, addr_str, sizeof(addr_str) - 1);
        }
        ESP_LOGI(TAG, "Socket accepted ip address: %s", addr_str);

        do_retransmit(sock);

        shutdown(sock, 0);
        close(sock);
    }

CLEAN_UP:
    close(listen_sock);
    vTaskDelete(NULL);
}
#endif

#if TCP_SOCKET_CLIENT_TEST
static void connect_to_server_and_send_data_continuously()
{
    const char *netif_name = esp_netif_get_desc(netif_custom);

    /* Create a socket */
    int sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_IPV6);
    if (sock < 0) {
        ESP_LOGE(TAG, "\"%s\" Unable to create socket: errno %d", netif_name, errno);
        goto func_fail;
    }
    ESP_LOGI(TAG, "\"%s\" Socket created", netif_name);

     /* Bind to local interface */
    esp_netif_ip6_info_t ip;
    memset(&ip, 0, sizeof(esp_netif_ip6_info_t));
    ESP_ERROR_CHECK(esp_netif_get_ip6_linklocal(netif_custom, &ip));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(0);
    inet6_aton(ip.ip.addr, &addr.sin6_addr);

    int ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        ESP_LOGE(TAG, "\"%s\" Unable to bind socket: errno %d", netif_name, errno);
        goto func_fail;
    }

    /* Connect to host */
    struct sockaddr_in6 destAddr;
    inet6_aton(TARGET_HOST, &destAddr.sin6_addr);
    destAddr.sin6_family = AF_INET6;
    destAddr.sin6_port = htons(TARGET_PORT);
    ret = connect(sock, (struct sockaddr *)&destAddr, sizeof(destAddr));
    if (ret != 0) {
        ESP_LOGE(TAG, "\"%s\" Socket unable to connect: errno %d", netif_name, errno);
        goto func_fail;
    }
    ESP_LOGI(TAG, "\"%s\" Successfully connected", netif_name);

    while(1) {
        /* Send payload */
        ret = send(sock, payload_64, strlen(payload_64), 0);
        if (ret < 0) {
            ESP_LOGE(TAG, "\"%s\" Error occured during sending: errno %d", netif_name, errno);
            goto func_fail;
        }
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
func_fail:
    close(sock);
}

static void tcp_client_task()
{
    bool try_again = false;
    esp_netif_t *netif = netif_custom;

    while(1) {
        EventBits_t eb = xEventGroupWaitBits(evt_grp, ACQ_IPV6_ADDRESS, pdFALSE, pdFALSE, portMAX_DELAY);
        if(eb && ACQ_IPV6_ADDRESS) {
            ESP_LOGI(TAG, "tcp client starting ...");
            break;
        }
    }

    ESP_LOGE(TAG, "netif described as \"%s\" corresponds to esp-netif ptr:%p", esp_netif_get_desc(netif), netif);

    while(netif) {
        /* Wait for the host name to get */
        const struct addrinfo hints = {.ai_family = AF_INET6, .ai_socktype = SOCK_STREAM};
        struct addrinfo *res;

        int err = getaddrinfo(TARGET_HOST, NULL, &hints, &res);
        if(err != 0 || res == NULL) {
            ESP_LOGE(TAG, "DNS lookup failed err = %d res = %p", err, res);
            try_again = true;
        }
        else {
            try_again = false;
            break;
        }

        if (!try_again) {
            freeaddrinfo(res);
            /* Delay 5 seconds before connecting to server */
            vTaskDelay(5000 / portTICK_PERIOD_MS);
        }
        else {
            /* Delay 10 seconds for every failed DNS query */
            vTaskDelay(10000 / portTICK_PERIOD_MS);
        }
    }

    if (!try_again) {
        connect_to_server_and_send_data_continuously();
    }
    ESP_LOGE(TAG, "%s with netif desc:%s Failed! exiting", __func__, esp_netif_get_desc(netif));
    vTaskDelete(NULL);
}
#endif

#if HTTP_DOWNLOAD_TEST
esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    static char *output_buffer;  // Buffer to store response of http request from event handler
    static int output_len;       // Stores number of bytes read
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            /*
             *  Check for chunked encoding is added as the URL for chunked encoding used in this example returns binary data.
             *  However, event handler can also be used in case chunked encoding is used.
             */
            if (!esp_http_client_is_chunked_response(evt->client)) {
                // If user_data buffer is configured, copy the response into the buffer
                if (evt->user_data) {
                    memcpy(evt->user_data + output_len, evt->data, evt->data_len);
                } else {
                    if (output_buffer == NULL) {
                        esp_http_client_get_content_length(evt->client);
                        // output_buffer = (char *) malloc(esp_http_client_get_content_length(evt->client));
                        output_len = 0;
                        // if (output_buffer == NULL) {
                        //     ESP_LOGE(TAG, "Failed to allocate memory for output buffer");
                        //     return ESP_FAIL;
                        // }
                    }
                    // memcpy(output_buffer + output_len, evt->data, evt->data_len);
                }
                // output_len += evt->data_len;
            }

            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
            if (output_buffer != NULL) {
                // Response is accumulated in output_buffer. Uncomment the below line to print the accumulated response
                ESP_LOG_BUFFER_HEX(TAG, output_buffer, output_len);
                free(output_buffer);
                output_buffer = NULL;
            }
            output_len = 0;
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
            int mbedtls_err = 0;
            esp_err_t err = esp_tls_get_and_clear_last_error((esp_tls_error_handle_t)evt->data, &mbedtls_err, NULL);
            if (err != 0) {
                ESP_LOGI(TAG, "Last esp error code: 0x%x", err);
                ESP_LOGI(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
            }
            if (output_buffer != NULL) {
                free(output_buffer);
                output_buffer = NULL;
            }
            output_len = 0;
            break;
        case HTTP_EVENT_REDIRECT:
            ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
            esp_http_client_set_header(evt->client, "From", "user@example.com");
            esp_http_client_set_header(evt->client, "Accept", "text/html");
            esp_http_client_set_redirection(evt->client);
            break;
    }
    return ESP_OK;
}

static void http_download_chunk() {
    ESP_LOGI(TAG, "Download starting!");
    esp_http_client_config_t config = {
        .url = "http://192.168.86.24:1111/two_mb.bin",
        .event_handler = _http_event_handler,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP chunk encoding Status = %d, content_length = %lld", esp_http_client_get_status_code(client), esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "Error perform http request %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
    ESP_LOGI(TAG, "Download finished!");
}

static void http_download_task(void) {
    // http_download_chunk();
    // vTaskDelete(NULL);
}
#endif

#if COAP_CLIENT_TEST
static coap_response_t message_handler(coap_session_t *session, const coap_pdu_t *sent, const coap_pdu_t *received, const coap_mid_t mid) {
    const unsigned char *data = NULL;
    size_t data_len;
    size_t offset;
    size_t total;
    coap_pdu_code_t rcvd_code = coap_pdu_get_code(received);

    if (COAP_RESPONSE_CLASS(rcvd_code) == 2) {
        if (coap_get_data_large(received, &data_len, &data, &offset, &total)) {
            if (data_len != total) {
                printf("Unexpected partial data received offset %u, length %u\n", offset, data_len);
            }
            printf("Received:\n%.*s\n", (int)data_len, data);
            resp_wait = 0;
        }
        return COAP_RESPONSE_OK;
    }
    printf("%d.%02d", (rcvd_code >> 5), rcvd_code & 0x1F);
    if (coap_get_data_large(received, &data_len, &data, &offset, &total)) {
        printf(": ");
        while(data_len--) {
            printf("%c", isprint(*data) ? *data : '.');
            data++;
        }
    }
    printf("\n");
    resp_wait = 0;
    return COAP_RESPONSE_OK;
}
#ifdef CONFIG_COAP_MBEDTLS_PKI

static int verify_cn_callback(const char *cn,
                   const uint8_t *asn1_public_cert,
                   size_t asn1_length,
                   coap_session_t *session,
                   unsigned depth,
                   int validated,
                   void *arg
                  ) {
    coap_log(LOG_INFO, "CN '%s' presented by server (%s)\n", cn, depth ? "CA" : "Certificate");
    return 1;
}
#endif /* CONFIG_COAP_MBEDTLS_PKI */

static void coap_log_handler (coap_log_t level, const char *message) {
    uint32_t esp_level = ESP_LOG_INFO;
    char *cp = strchr(message, '\n');

    if (cp)
        ESP_LOG_LEVEL(esp_level, TAG, "%.*s", (int)(cp-message), message);
    else
        ESP_LOG_LEVEL(esp_level, TAG, "%s", message);
}

static coap_address_t *coap_get_address(coap_uri_t *uri) {
    static coap_address_t dst_addr;
    char *phostname = NULL;
    const struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    struct addrinfo *res;
    char tmpbuf[INET6_ADDRSTRLEN];

    phostname = (char *)calloc(1, uri->host.length + 1);
    if (phostname == NULL) {
        ESP_LOGE(TAG, "calloc failed");
        return NULL;
    }
    memcpy(phostname, uri->host.s, uri->host.length);

    int err = getaddrinfo(phostname, NULL, &hints, &res);
    if (err != 0) {
        ESP_LOGE(TAG, "DNS lookup failed for destination address %s, error: %d", phostname, err);
        free(phostname);
        return NULL;
    }
    else if (res == NULL) {
        ESP_LOGE(TAG, "DNS lookup %s did not return any addresses", phostname);
        free(phostname);
        return NULL;
    }
    free(phostname);
    coap_address_init(&dst_addr);

    // inet6_aton(COAP_HOST, &dst_addr.addr.sin6.sin6_addr);
    // dst_addr.addr.sin6.sin6_family = AF_INET6;
    // dst_addr.addr.sin6.sin6_port = htons(COAP_PORT);
    // inet_ntop(AF_INET6, &dst_addr.addr.sin6.sin6_addr, tmpbuf, sizeof(tmpbuf));
    // ESP_LOGI(TAG, "DNS lookup succeeded. IP6 = %s port = %d", tmpbuf, uri->port);

    switch (res->ai_family) {
        case AF_INET:
            memcpy(&dst_addr.addr.sin, res->ai_addr, sizeof(dst_addr.addr.sin));
            dst_addr.addr.sin.sin_port        = htons(uri->port);
            inet_ntop(AF_INET, &dst_addr.addr.sin.sin_addr, tmpbuf, sizeof(tmpbuf));
            ESP_LOGI(TAG, "DNS lookup succeeded. IP4 = %s, port = %d", tmpbuf, uri->port);
            break;
        case AF_INET6:
            memcpy(&dst_addr.addr.sin6, res->ai_addr, sizeof(dst_addr.addr.sin6));
            dst_addr.addr.sin6.sin6_port        = htons(uri->port);
            inet_ntop(AF_INET6, &dst_addr.addr.sin6.sin6_addr, tmpbuf, sizeof(tmpbuf));
            ESP_LOGI(TAG, "DNS lookup succeeded. IP6 = %s, port = %d", tmpbuf, uri->port);
            break;
        default:
            ESP_LOGE(TAG, "DNS lookup response failed");
            return NULL;
    }
    freeaddrinfo(res);

    return &dst_addr;
}

static int coap_build_optlist(coap_uri_t *uri) {
#define BUFSIZE 40
    unsigned char _buf[BUFSIZE];
    unsigned char *buf;
    size_t buflen;
    int res;

    optlist = NULL;

    if (uri->scheme == COAP_URI_SCHEME_COAPS && !coap_dtls_is_supported()) {
        ESP_LOGE(TAG, "MbedTLS DTLS Client Mode not configured");
        return 0;
    }
    if (uri->scheme == COAP_URI_SCHEME_COAPS_TCP && !coap_tls_is_supported()) {
        ESP_LOGE(TAG, "MbedTLS TLS Client Mode not configured");
        return 0;
    }
    if (uri->scheme == COAP_URI_SCHEME_COAP_TCP && !coap_tcp_is_supported()) {
        ESP_LOGE(TAG, "TCP Client Mode not configured");
        return 0;
    }

    if (uri->path.length) {
        buflen = BUFSIZE;
        buf = _buf;
        res = coap_split_path(uri->path.s, uri->path.length, buf, &buflen);

        while (res--) {
            coap_insert_optlist(&optlist,
                                coap_new_optlist(COAP_OPTION_URI_PATH,
                                                 coap_opt_length(buf),
                                                 coap_opt_value(buf)));

            buf += coap_opt_size(buf);
        }
    }

    if (uri->query.length) {
        buflen = BUFSIZE;
        buf = _buf;
        res = coap_split_query(uri->query.s, uri->query.length, buf, &buflen);

        while (res--) {
            coap_insert_optlist(&optlist,
                                coap_new_optlist(COAP_OPTION_URI_QUERY,
                                                 coap_opt_length(buf),
                                                 coap_opt_value(buf)));

            buf += coap_opt_size(buf);
        }
    }
    return 1;
}
#ifdef CONFIG_COAP_MBEDTLS_PSK
static coap_session_t * coap_start_psk_session(coap_context_t *ctx, coap_address_t *dst_addr, coap_uri_t *uri)
{
 static coap_dtls_cpsk_t dtls_psk;
 static char client_sni[256];

    memset(client_sni, 0, sizeof(client_sni));
    memset (&dtls_psk, 0, sizeof(dtls_psk));
    dtls_psk.version = COAP_DTLS_CPSK_SETUP_VERSION;
    dtls_psk.validate_ih_call_back = NULL;
    dtls_psk.ih_call_back_arg = NULL;
    if (uri->host.length)
        memcpy(client_sni, uri->host.s, MIN(uri->host.length, sizeof(client_sni) - 1));
    else
        memcpy(client_sni, "localhost", 9);
    dtls_psk.client_sni = client_sni;
    dtls_psk.psk_info.identity.s = (const uint8_t *)COAP_PSK_IDENTITY;
    dtls_psk.psk_info.identity.length = sizeof(COAP_PSK_IDENTITY)-1;
    dtls_psk.psk_info.key.s = (const uint8_t *)COAP_PSK_KEY;
    dtls_psk.psk_info.key.length = sizeof(COAP_PSK_KEY)-1;
    return coap_new_client_session_psk2(ctx, NULL, dst_addr, uri->scheme == COAP_URI_SCHEME_COAPS ? COAP_PROTO_DTLS : COAP_PROTO_TLS, &dtls_psk);
}
#endif /* CONFIG_COAP_MBEDTLS_PSK */
#ifdef CONFIG_COAP_MBEDTLS_PKI
static coap_session_t * coap_start_pki_session(coap_context_t *ctx, coap_address_t *dst_addr, coap_uri_t *uri)
{
    unsigned int ca_pem_bytes = ca_pem_end - ca_pem_start;
    unsigned int client_crt_bytes = client_crt_end - client_crt_start;
    unsigned int client_key_bytes = client_key_end - client_key_start;
    static coap_dtls_pki_t dtls_pki;
    static char client_sni[256];

    memset (&dtls_pki, 0, sizeof(dtls_pki));
    dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
    if (ca_pem_bytes) {
        /*
         * Add in additional certificate checking.
         * This list of enabled can be tuned for the specific
         * requirements - see 'man coap_encryption'.
         *
         * Note: A list of root cas file can be setup separately using
         * coap_context_set_pki_root_cas(), but the below is used to
         * define what checking actually takes place.
         */
        dtls_pki.verify_peer_cert        = 1;
        dtls_pki.check_common_ca         = 1;
        dtls_pki.allow_self_signed       = 1;
        dtls_pki.allow_expired_certs     = 1;
        dtls_pki.cert_chain_validation   = 1;
        dtls_pki.cert_chain_verify_depth = 2;
        dtls_pki.check_cert_revocation   = 1;
        dtls_pki.allow_no_crl            = 1;
        dtls_pki.allow_expired_crl       = 1;
        dtls_pki.allow_bad_md_hash       = 1;
        dtls_pki.allow_short_rsa_length  = 1;
        dtls_pki.validate_cn_call_back   = verify_cn_callback;
        dtls_pki.cn_call_back_arg        = NULL;
        dtls_pki.validate_sni_call_back  = NULL;
        dtls_pki.sni_call_back_arg       = NULL;
        memset(client_sni, 0, sizeof(client_sni));
        if (uri->host.length) {
            memcpy(client_sni, uri->host.s, MIN(uri->host.length, sizeof(client_sni)));
        } else {
            memcpy(client_sni, "localhost", 9);
        }
        dtls_pki.client_sni = client_sni;
    }
    dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM_BUF;
    dtls_pki.pki_key.key.pem_buf.public_cert = client_crt_start;
    dtls_pki.pki_key.key.pem_buf.public_cert_len = client_crt_bytes;
    dtls_pki.pki_key.key.pem_buf.private_key = client_key_start;
    dtls_pki.pki_key.key.pem_buf.private_key_len = client_key_bytes;
    dtls_pki.pki_key.key.pem_buf.ca_cert = ca_pem_start;
    dtls_pki.pki_key.key.pem_buf.ca_cert_len = ca_pem_bytes;

    return coap_new_client_session_pki(ctx, NULL, dst_addr,
                                              uri->scheme == COAP_URI_SCHEME_COAPS ? COAP_PROTO_DTLS : COAP_PROTO_TLS,
                                              &dtls_pki);
}
#endif /* CONFIG_COAP_MBEDTLS_PKI */

static void coap_client_task(void *p)
{
    coap_address_t   *dst_addr = NULL;
    static coap_uri_t uri;
    const char *server_uri = COAP_TLS_URI;
    coap_context_t *ctx = NULL;
    coap_session_t *session = NULL;
    coap_pdu_t *request = NULL;
    unsigned char token[8];
    size_t tokenlength;

    int retry_count = 0;

    while(1) {
        EventBits_t eb = xEventGroupWaitBits(evt_grp, ACQ_IPV6_ADDRESS, pdFALSE, pdFALSE, portMAX_DELAY);
        if(eb && ACQ_IPV6_ADDRESS) {
            ESP_LOGI(TAG, "coap starting ...");
            break;
        }
    }

    /* Set up the CoAP logging */
    coap_set_log_handler(coap_log_handler);
    coap_set_log_level(0);

    /* Set up the CoAP context */
    ctx = coap_new_context(NULL);
    if (!ctx) {
        ESP_LOGE(TAG, "coap_new_context() failed");
        goto clean_up;
    }

    coap_context_set_block_mode(ctx, COAP_BLOCK_USE_LIBCOAP|COAP_BLOCK_SINGLE_BODY);

    coap_register_response_handler(ctx, message_handler);

    if (coap_split_uri((const uint8_t *)server_uri, strlen(server_uri), &uri) == -1) {
        ESP_LOGE(TAG, "CoAP server uri error");
        goto clean_up;
    }
    if (!coap_build_optlist(&uri))
        goto clean_up;

    while(1) {
        dst_addr = coap_get_address(&uri);
        if (dst_addr)
            break;
        ++retry_count;
        if(retry_count == 10){
            goto clean_up;
        }
        /* 10 second delay before retrying again */
        vTaskDelay(10000 / portTICK_PERIOD_MS);
    }

    http_download_chunk();

    /*
     * Note that if the URI starts with just coap:// (not coaps://) the
     * session will still be plain text.
     */
    if (uri.scheme == COAP_URI_SCHEME_COAPS || uri.scheme == COAP_URI_SCHEME_COAPS_TCP) {
#ifndef CONFIG_MBEDTLS_TLS_CLIENT
        ESP_LOGE(TAG, "MbedTLS (D)TLS Client Mode not configured");
        goto clean_up;
#endif /* CONFIG_MBEDTLS_TLS_CLIENT */
#ifdef CONFIG_COAP_MBEDTLS_PSK
        session = coap_start_psk_session(ctx, dst_addr, &uri);
#endif /* CONFIG_COAP_MBEDTLS_PSK */
#ifdef CONFIG_COAP_MBEDTLS_PKI
        session = coap_start_pki_session(ctx, dst_addr, &uri);
#endif /* CONFIG_COAP_MBEDTLS_PKI */
    } else {
        session = coap_new_client_session(ctx, NULL, dst_addr, uri.scheme == COAP_URI_SCHEME_COAP_TCP ? COAP_PROTO_TCP : COAP_PROTO_UDP);
    }
    if (!session) {
        ESP_LOGE(TAG, "coap_new_client_session() failed");
        goto clean_up;
    }

    while (1) {
        request = coap_new_pdu(coap_is_mcast(dst_addr) ? COAP_MESSAGE_NON : COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET, session);
        if (!request) {
            ESP_LOGE(TAG, "coap_new_pdu() failed");
            goto clean_up;
        }
        /* Add in an unique token */
        coap_session_new_token(session, &tokenlength, token);
        coap_add_token(request, tokenlength, token);

        /*
         * To make this a POST, you will need to do the following
         * Change COAP_REQUEST_CODE_GET to COAP_REQUEST_CODE_POST for coap_new_pdu()
         * Add in here a Content-Type Option based on the format of the POST text.  E.G. for JSON
         *   u_char buf[4];
         *   coap_insert_optlist(&optlist,
         *                       coap_new_optlist(COAP_OPTION_CONTENT_FORMAT,
         *                                        coap_encode_var_safe (buf, sizeof (buf),
         *                                                              COAP_MEDIATYPE_APPLICATION_JSON),
         *                                        buf));
         * Add in here the POST data of length length. E.G.
         *   coap_add_data_large_request(session, request length, data, NULL, NULL);
         */

        coap_add_optlist_pdu(request, &optlist);

        resp_wait = 1;
        coap_send(session, request);

        wait_ms = COAP_DEFAULT_TIME_SEC * 1000;

        while (resp_wait) {
            int result = coap_io_process(ctx, wait_ms > 1000 ? 1000 : wait_ms);
            if (result >= 0) {
                if (result >= wait_ms) {
                    ESP_LOGE(TAG, "No response from server");
                    break;
                } else {
                    wait_ms -= result;
                }
            }
        }
        for(int countdown = 10; countdown >= 0; countdown--) {
            ESP_LOGI(TAG, "%d... ", countdown);
            vTaskDelay(10000 / portTICK_PERIOD_MS);
        }
        // Simple demo of OpenThread API
        ESP_LOGI(TAG, "Starting again! childsupervisionchecktimeout = %u", otChildSupervisionGetCheckTimeout(esp_openthread_get_instance()));
        ESP_LOGI(TAG, "Free Heap: %u", (unsigned int)esp_get_free_heap_size());
    }

clean_up:
    if (optlist) {
        coap_delete_optlist(optlist);
        optlist = NULL;
    }
    if (session) {
        coap_session_release(session);
    }
    if (ctx) {
        coap_free_context(ctx);
    }
    coap_cleanup();

    ESP_LOGI(TAG, "Finished");
    vTaskDelete(NULL);
}
#endif

#if CONFIG_OPENTHREAD_CLI_ESP_EXTENSION
static esp_netif_t *init_openthread_netif(const esp_openthread_platform_config_t *config)
{
    esp_netif_config_t cfg = ESP_NETIF_DEFAULT_OPENTHREAD();
    netif_custom = esp_netif_new(&cfg);
    assert(netif_custom != NULL);
    ESP_ERROR_CHECK(esp_netif_attach(netif_custom, esp_openthread_netif_glue_init(config)));

    return netif_custom;
}
#endif // CONFIG_OPENTHREAD_CLI_ESP_EXTENSION

static void ot_task_worker(void *aContext)
{
    esp_openthread_platform_config_t config = {
        .radio_config = ESP_OPENTHREAD_DEFAULT_RADIO_CONFIG(),
        .host_config = ESP_OPENTHREAD_DEFAULT_HOST_CONFIG(),
        .port_config = ESP_OPENTHREAD_DEFAULT_PORT_CONFIG(),
    };

    // Initialize the OpenThread stack
    ESP_ERROR_CHECK(esp_openthread_init(&config));

    // The OpenThread log level directly matches ESP log level
    (void)otLoggingSetLevel(CONFIG_LOG_DEFAULT_LEVEL);
    // Initialize the OpenThread cli
    esp_openthread_cli_init();

#if CONFIG_OPENTHREAD_CLI_ESP_EXTENSION
    esp_netif_t *openthread_netif;
    // Initialize the esp_netif bindings
    openthread_netif = init_openthread_netif(&config);
    esp_cli_custom_command_init();
#endif // CONFIG_OPENTHREAD_CLI_ESP_EXTENSION

    // Run the main loop
    esp_openthread_cli_create_task();
    esp_openthread_launch_mainloop();

    // Clean up
#if CONFIG_OPENTHREAD_CLI_ESP_EXTENSION
    esp_netif_destroy(openthread_netif);
    esp_openthread_netif_glue_deinit();
#endif // CONFIG_OPENTHREAD_CLI_ESP_EXTENSION

    esp_vfs_eventfd_unregister();
    vTaskDelete(NULL);
}

static void ipv6_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    ip_event_got_ip6_t *event = (ip_event_got_ip6_t *)event_data;

    esp_ip6_addr_type_t ipv6_type = esp_netif_ip6_get_addr_type(&event->ip6_info.ip);

    // Allow only ESP_IP6_ADDR_IS_UNIQUE_LOCAL or ESP_IP6_ADDR_IS_GLOBAL because these addresses are routable
    if((ipv6_type == ESP_IP6_ADDR_IS_UNIQUE_LOCAL) || (ipv6_type == ESP_IP6_ADDR_IS_GLOBAL)) {
        ESP_LOGI(TAG, "[%d] Got IPv6 event: Interface \"%s\" address: " IPV6STR ", type: %s", ipv6_type, esp_netif_get_desc(event->esp_netif), IPV62STR(event->ip6_info.ip), ipv6_addr_types_to_str[ipv6_type]);

        xEventGroupSetBits(evt_grp, ACQ_IPV6_ADDRESS);
    }
}

void app_main(void)
{
    // Used eventfds:
    // * netif
    // * ot task queue
    // * radio driver
    esp_vfs_eventfd_config_t eventfd_config = {
        .max_fds = 3,
    };

    ESP_ERROR_CHECK(esp_event_loop_create_default());
#if CONFIG_OPENTHREAD_CLI_ESP_EXTENSION
    ESP_ERROR_CHECK(esp_netif_init());
#endif // CONFIG_OPENTHREAD_CLI_ESP_EXTENSION
    ESP_ERROR_CHECK(esp_vfs_eventfd_register(&eventfd_config));

    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_GOT_IP6, &ipv6_event_handler, NULL));

    xTaskCreate(ot_task_worker, "ot_cli_main", 10240, xTaskGetCurrentTaskHandle(), 5, NULL);

    evt_grp = xEventGroupCreate();

    // ESP_ERROR_CHECK(mdns_init());
    // ESP_ERROR_CHECK(mdns_hostname_set("esp-ot-mtd1"));

    #if TCP_SOCKET_SERVER_TEST
    xTaskCreate(tcp_server_task, "tcp_server", 8092, (void*)AF_INET6, 5, NULL);
    #endif
    #if TCP_SOCKET_CLIENT_TEST
    xTaskCreate(tcp_client_task, "tcp_client", 4096, NULL, 5, NULL);
    #endif
    #if COAP_CLIENT_TEST
    xTaskCreate(coap_client_task, "coap_client", 10 * 1024, NULL, 5, NULL);
    #endif
    #if HTTP_DOWNLOAD_TEST
    //xTaskCreate(http_download_task, "http_client", 8 * 1024, NULL, 5, NULL);
    #endif
}
