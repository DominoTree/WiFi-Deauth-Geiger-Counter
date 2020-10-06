#include <stdio.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_spi_flash.h"
#include "esp_wifi.h"
#include "driver/gpio.h"

const wifi_promiscuous_filter_t filt = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT //|WIFI_PROMIS_FILTER_MASK_DATA
};

typedef struct
{
    int16_t fctl;
    int16_t duration;
    uint8_t da[6];
    uint8_t sa[6];
    uint8_t bssid[6];
    int16_t seqctl;
    unsigned char payload[];
} __attribute__((packed)) WifiMgmtHdr;

char mactochar(uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return *buf;
}

void sniffer(void *buf, wifi_promiscuous_pkt_type_t type)
{
    //if (type == WIFI_PKT_MGMT) //should be able to remove this check with the filter modified above
    //{
        wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t *)buf;
        int len = p->rx_ctrl.sig_len;
        int rssi = p->rx_ctrl.rssi;
        WifiMgmtHdr *wh = (WifiMgmtHdr *)p->payload;
        char bssid = mactochar(wh->bssid);
        char src = mactochar(wh->sa);
        char dst = mactochar(wh->da);
        len -= sizeof(WifiMgmtHdr);
        if (len < 0)
            return;
        int fctl = ntohs(wh->fctl);
        if ((fctl & 0x0F00) == 0x0A00 || (fctl & 0x0F00) == 0x0C00)
        {
            gpio_set_level((gpio_num_t)16, 1);
            gpio_set_level((gpio_num_t)16, 0);
            printf("DEAUTH FRAME RECEIVED, BSSID: %s, SRC: %s, DST: %s, RSSI: %d\n", &bssid, &src, &dst, rssi);
        }
        if (p->payload[12] == 0xA0 || p->payload[12] == 0xC0) {
            gpio_set_level((gpio_num_t)16, 1);
            gpio_set_level((gpio_num_t)16, 0);
            printf("Method 2 \n");
        }
    //}
}

void app_main(void)
{
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(&sniffer);

    while (true)
    {
        for (int i = 0; i < 15; i++)
        {
            //channels are 0 indexed here
            esp_wifi_set_channel(i, WIFI_SECOND_CHAN_NONE);
            sleep(1);
        }
    }
}
