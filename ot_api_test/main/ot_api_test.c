
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
#include "esp_mac.h"
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

#include "openthread/ip6.h"
#include "openthread/thread.h"
#include "openthread/netdata_publisher.h"
#include "openthread/srp_client.h"
#include "openthread/srp_client_buffers.h"

static esp_netif_t *netif_custom = NULL;

const static char *TAG = "ot_api_test";

const char *ipv6_addr_types_to_str[6] = {"ESP_IP6_ADDR_IS_UNKNOWN", "ESP_IP6_ADDR_IS_GLOBAL", "ESP_IP6_ADDR_IS_LINK_LOCAL", "ESP_IP6_ADDR_IS_SITE_LOCAL", "ESP_IP6_ADDR_IS_UNIQUE_LOCAL", "ESP_IP6_ADDR_IS_IPV4_MAPPED_IPV6"};

static EventGroupHandle_t evt_grp;

#define ACQ_IPV6_ADDRESS (1 << 0)
#define ACQ_OT_INIT (1 << 1)

static void callback_srp(otNetDataPublisherEvent aEvent, void *aContext)
{
    ESP_LOGI(TAG, "%s otNetDataPublisherEvent = %d", __FUNCTION__, aEvent);
    switch (aEvent)
    {
    case OT_NETDATA_PUBLISHER_EVENT_ENTRY_ADDED:
        break;
    case OT_NETDATA_PUBLISHER_EVENT_ENTRY_REMOVED:
        break;
    default:
        break;
    }
}

static void callback_prefixpublish(otNetDataPublisherEvent aEvent, const otIp6Prefix *aPrefix, void *aContext)
{
    ESP_LOGI(TAG, "%s otNetDataPublisherEvent = %d", __FUNCTION__, aEvent);
    switch (aEvent)
    {
    case OT_NETDATA_PUBLISHER_EVENT_ENTRY_ADDED:
        break;
    case OT_NETDATA_PUBLISHER_EVENT_ENTRY_REMOVED:
        break;
    default:
        break;
    }
}

static void callback_discoveryrequest(const otThreadDiscoveryRequestInfo *aInfo, void *aContext)
{
    if (aInfo)
    {
        ESP_LOGI(TAG, "%s", __FUNCTION__);
        ESP_LOG_BUFFER_HEXDUMP(TAG, aInfo->mExtAddress.m8, OT_EXT_ADDRESS_SIZE, 1);
        ESP_LOGI(TAG, "mIsJoiner = %d, mVersion = %u", aInfo->mIsJoiner, aInfo->mVersion);
    }
}

static void callback_parentresponse(otThreadParentResponseInfo *aInfo, void *aContext)
{
    if (aInfo)
    {
        ESP_LOGI(TAG, "%s", __FUNCTION__);
        ESP_LOG_BUFFER_HEXDUMP(TAG, aInfo->mExtAddr.m8, OT_EXT_ADDRESS_SIZE, 1);
        ESP_LOGI(TAG, "mIsAttached = %d, mLinkQuality1 = %u, mLinkQuality2 = %u, mLinkQuality3 = %u, mPriority = %d, mRloc16 = %u, mRssi = %d", aInfo->mIsAttached, aInfo->mLinkQuality1, aInfo->mLinkQuality2, aInfo->mLinkQuality3, aInfo->mPriority, aInfo->mRloc16, aInfo->mRssi);
    }
}

static void callback_anycast_locator(void *aContext, otError aError, const otIp6Address *aMeshLocalAddress, uint16_t aRloc16)
{
}

static void callback_ipv6address(const otIp6AddressInfo *aAddressInfo, bool aIsAdded, void *aContext)
{
    char ipv6_unicast_addresses[OT_IP6_ADDRESS_STRING_SIZE] = {};
    // esp_openthread_lock_acquire(portMAX_DELAY);
    // otIp6AddressToString(aAddressInfo, ipv6_unicast_addresses, OT_IP6_ADDRESS_STRING_SIZE);
    // esp_openthread_lock_release();
    if (aIsAdded)
    {
        // ESP_LOGI(TAG, "%s added = %s", __FUNCTION__, ipv6_unicast_addresses);
    }
    else
    {
        // ESP_LOGI(TAG, "%s removed = %s", __FUNCTION__, ipv6_unicast_addresses);
    }
}

static void callback_statechanged(uint32_t aFlags, void *aContext)
{
    if ((aFlags & OT_CHANGED_THREAD_ROLE) != 0)
    {
        esp_openthread_lock_acquire(portMAX_DELAY);
        otDeviceRole _otDeviceRole = otThreadGetDeviceRole(aContext);
        esp_openthread_lock_release();

        switch (_otDeviceRole)
        {
        case OT_DEVICE_ROLE_LEADER:
            ESP_LOGI(TAG, "OT_DEVICE_ROLE_LEADER");
            break;
        case OT_DEVICE_ROLE_ROUTER:
            ESP_LOGI(TAG, "OT_DEVICE_ROLE_ROUTER");
            break;
        case OT_DEVICE_ROLE_CHILD:
            ESP_LOGI(TAG, "OT_DEVICE_ROLE_CHILD");
            break;
        case OT_DEVICE_ROLE_DETACHED:
            ESP_LOGI(TAG, "OT_DEVICE_ROLE_DETACHED");
            break;
        case OT_DEVICE_ROLE_DISABLED:
            ESP_LOGI(TAG, "OT_DEVICE_ROLE_DISABLED");
            break;
        }
    }
}

static void address_origin(char *addr, uint8_t aOrigin)
{
    const char *const kOriginStrings[4] = {
        "thread", /* 0, OT_ADDRESS_ORIGIN_THREAD */ "slaac", /* 1, OT_ADDRESS_ORIGIN_SLAAC */ "dhcp6", /* 2, OT_ADDRESS_ORIGIN_DHCPV6 */ "manual", /* 3, OT_ADDRESS_ORIGIN_MANUAL */
    };
    ESP_LOGI(TAG, "addr = %s origin:%s", addr, kOriginStrings[aOrigin]);
}

static esp_netif_t *init_openthread_netif(const esp_openthread_platform_config_t *config)
{
    esp_netif_config_t cfg = ESP_NETIF_DEFAULT_OPENTHREAD();
    netif_custom = esp_netif_new(&cfg);
    assert(netif_custom != NULL);
    ESP_ERROR_CHECK(esp_netif_attach(netif_custom, esp_openthread_netif_glue_init(config)));
    return netif_custom;
}

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

    esp_netif_t *openthread_netif;
    // Initialize the esp_netif bindings
    openthread_netif = init_openthread_netif(&config);

    
    // not all callbacks are supported
    // otNetDataDnsSrpServicePublisherCallback(callback_srp);
    // otNetDataPrefixPublisherCallback(callback_prefixpublish);
    otThreadDiscoveryRequestCallback(callback_discoveryrequest);
    otThreadParentResponseCallback(callback_parentresponse);
    otThreadAnycastLocatorCallback(callback_anycast_locator);

    vTaskDelay(500);

    xEventGroupSetBits(evt_grp, ACQ_OT_INIT);
    // Run the main loop
    esp_openthread_launch_mainloop();

    // Clean up
    esp_netif_destroy(openthread_netif);
    esp_openthread_netif_glue_deinit();

    esp_vfs_eventfd_unregister();
    vTaskDelete(NULL);
}

static void ipv6_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    static int numberOfIP = 0;

    ip_event_got_ip6_t *event = (ip_event_got_ip6_t *)event_data;
    esp_ip6_addr_type_t ipv6_type = esp_netif_ip6_get_addr_type(&event->ip6_info.ip);

    // Allow only ESP_IP6_ADDR_IS_UNIQUE_LOCAL or ESP_IP6_ADDR_IS_GLOBAL because these _otIp6Address_arr are routable
    if ((ipv6_type == ESP_IP6_ADDR_IS_UNIQUE_LOCAL) || (ipv6_type == ESP_IP6_ADDR_IS_GLOBAL))
    {
        ++numberOfIP;
        ESP_LOGI(TAG, "[%d] Got IPv6 event: Interface \"%s\" address: " IPV6STR ", type: %s", ipv6_type, esp_netif_get_desc(event->esp_netif), IPV62STR(event->ip6_info.ip), ipv6_addr_types_to_str[ipv6_type]);
        if (numberOfIP >= 4)
        {
            xEventGroupSetBits(evt_grp, ACQ_IPV6_ADDRESS);
        }
    }
}

static void custom_loop(void *aContext)
{
    // same dataset as ot_br
    char dset_extendedpanid[] = {0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0xca, 0xfe};
    char dset_meshlocalprefix[] = {0xfd, 0x93, 0x33, 0x50, 0x8a, 0x46, 0xc9, 0xf6};
    char dset_networkkey[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    char dset_networkname[] = {'O', 'p', 'e', 'n', 'T', 'h', 'r', 'e', 'a', 'd', '-', '1', '3', '5', '7'};
    char dset_pskc[] = {0x10, 0x48, 0x10, 0xe2, 0x31, 0x51, 0x00, 0xaf, 0xd6, 0xbc, 0x92, 0x15, 0xa6, 0xbf, 0xac, 0x53};

    EventBits_t eb;

    while (1)
    {
        eb = xEventGroupWaitBits(evt_grp, ACQ_OT_INIT | ACQ_IPV6_ADDRESS, pdFALSE, pdFALSE, portMAX_DELAY);

        otInstance *_otInstance = esp_openthread_get_instance();

        if (eb & ACQ_OT_INIT)
        {
            // otSetStateChangedCallback(_otInstance, callback_statechanged, NULL);
            otOperationalDataset aDataset = {
                .mComponents.mIsActiveTimestampPresent = true, 
                .mComponents.mIsNetworkKeyPresent = true, 
                .mComponents.mIsNetworkNamePresent = true, 
                .mComponents.mIsExtendedPanIdPresent = true, 
                .mComponents.mIsMeshLocalPrefixPresent = true, 
                .mComponents.mIsPanIdPresent = true, 
                .mComponents.mIsChannelPresent = true, 
                .mComponents.mIsPskcPresent = true, 
                .mComponents.mIsSecurityPolicyPresent = true, 
                .mComponents.mIsChannelMaskPresent = true,
            };
            aDataset.mActiveTimestamp.mSeconds = 1;
            aDataset.mChannel = 15;
            aDataset.mChannelMask = 0x07fff800;
            memcpy(aDataset.mExtendedPanId.m8, dset_extendedpanid, sizeof dset_extendedpanid);
            memcpy(aDataset.mMeshLocalPrefix.m8, dset_meshlocalprefix, sizeof dset_meshlocalprefix);
            memcpy(aDataset.mNetworkKey.m8, dset_networkkey, sizeof dset_networkkey);
            memcpy(aDataset.mNetworkName.m8, dset_networkname, sizeof dset_networkname);
            aDataset.mPanId = 0x1234;
            memcpy(aDataset.mPskc.m8, dset_pskc, sizeof dset_pskc);
            aDataset.mSecurityPolicy.mRotationTime = 672;
            aDataset.mSecurityPolicy.mObtainNetworkKeyEnabled = true;
            aDataset.mSecurityPolicy.mNativeCommissioningEnabled = true;
            aDataset.mSecurityPolicy.mRoutersEnabled = true;
            aDataset.mSecurityPolicy.mExternalCommissioningEnabled = true;

            esp_openthread_lock_acquire(portMAX_DELAY);

            otDatasetSetActive(_otInstance, &aDataset);
            otIp6SetEnabled(_otInstance, true);    //[cmd: ifconfig up]
            otThreadSetEnabled(_otInstance, true); //[cmd: thread start]

            // otSetStateChangedCallback(_otInstance, callback_statechanged, NULL);
            // otIp6SetAddressCallback(_otInstance, callback_ipv6address, NULL);

            // otNetDataSetDnsSrpServicePublisherCallback(_otInstance, callback_srp, NULL);     // not supported at the moment
            // otNetDataSetPrefixPublisherCallback(_otInstance, callback_prefixpublish, NULL);  // not supported at the moment

            esp_openthread_lock_release();

            ESP_LOGI(TAG, "Radio version: %s", otGetRadioVersionString(_otInstance));
            ESP_LOGI(TAG, "OT version: %s", otGetVersionString());

            xEventGroupClearBits(evt_grp, ACQ_OT_INIT);
        }

        if (eb & ACQ_IPV6_ADDRESS)
        {
            uint8_t numAddresses = 0;
            otIp6Address _otIp6Address_arr[2];
            uint8_t arrayLength;
            otIp6Address *_otIp6Address_ptr;

            uint8_t mac[6] = {};
            char uid_hex[18] = {};
            esp_read_mac((uint8_t *)mac, ESP_MAC_IEEE802154); // read 802.11.14 mac address
            sprintf(uid_hex, MACSTR, MAC2STR(mac));

            esp_openthread_lock_acquire(portMAX_DELAY);

            otSrpClientSetHostName(_otInstance, uid_hex); //[cmd: srp client host name] host name (must be unique)
            _otIp6Address_ptr = otSrpClientBuffersGetHostAddressesArray(_otInstance, &arrayLength);
            arrayLength = (arrayLength > 2) ? 2 : arrayLength;
            // otIp6AddressFromString("fd7c:7f10:0590:0001:143a:e1cc:df7c:cbb1", _otIp6Address_arr);    //[cmd: srp client host address fd7c:7f10:590:1:143a:e1cc:df7c:cbb1] host address
            // otSrpClientSetHostAddresses(_otInstance, _otIp6Address_arr, 1);
            otSrpClientEnableAutoHostAddress(_otInstance); //[cmd: srp client host address auto]

            uint16_t size;
            char *string;
            otSrpClientBuffersServiceEntry *entry = otSrpClientBuffersAllocateService(_otInstance); //[cmd: srp client service add nami _namicoaps._udp 65000]
            string = otSrpClientBuffersGetServiceEntryInstanceNameString(entry, &size);
            strncpy(string, uid_hex, size); // instance name (must be unique)
            string = otSrpClientBuffersGetServiceEntryServiceNameString(entry, &size);
            strncpy(string, "_namicoaps._udp", size); // service name
            entry->mService.mPort = 65000;            // port number
            otSrpClientAddService(_otInstance, &entry->mService);
            otSrpClientEnableAutoStartMode(_otInstance, NULL, NULL);

            char ipv6_unicast_addresses[OT_IP6_ADDRESS_STRING_SIZE] = {};
            const otNetifAddress *unicastAddrs = otIp6GetUnicastAddresses(_otInstance);
            for (const otNetifAddress *addr = unicastAddrs; addr; addr = addr->mNext)
            {
                otIp6AddressToString(&addr->mAddress, ipv6_unicast_addresses, OT_IP6_ADDRESS_STRING_SIZE);
                address_origin(ipv6_unicast_addresses, addr->mAddressOrigin); //[cmd: ipaddr]
            }

            esp_openthread_lock_release();

            xEventGroupClearBits(evt_grp, ACQ_IPV6_ADDRESS);
        }

        vTaskDelay(2000 / portTICK_PERIOD_MS);
    }
}

void app_main(void)
{
    // Used eventfds:
    // * netif
    // * ot task queue
    // * radio driver
    esp_vfs_eventfd_config_t eventfd_config = {.max_fds = 3,};

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_netif_init());

    ESP_ERROR_CHECK(esp_vfs_eventfd_register(&eventfd_config));

    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_GOT_IP6, &ipv6_event_handler, NULL));

    xTaskCreate(ot_task_worker, "ot_cli_main", 10 * 1024, NULL, 5, NULL);

    evt_grp = xEventGroupCreate();

    xTaskCreate(custom_loop, "ot_api", 10 * 1024, NULL, 5, NULL);
}

/*
 * References
 * https://openthread.io/codelabs/openthread-apis#6
 * https://openthread.io/reference/group/api-instance
 * https://github.com/openthread/openthread/blob/main/examples/apps/cli/main.c
 * https://openthread.io/codelabs/openthread-border-router#4
 */
