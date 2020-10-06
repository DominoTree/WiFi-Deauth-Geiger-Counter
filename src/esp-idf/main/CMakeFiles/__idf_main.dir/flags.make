# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.15

# compile C with /Users/nprice/.espressif/tools/xtensa-esp32-elf/esp32-2019r1-8.2.0/xtensa-esp32-elf/bin/xtensa-esp32-elf-gcc
C_FLAGS = -mlongcalls -Wno-frame-address   -ffunction-sections -fdata-sections -fstrict-volatile-bitfields -nostdlib -Wall -Werror=all -Wno-error=unused-function -Wno-error=unused-but-set-variable -Wno-error=unused-variable -Wno-error=deprecated-declarations -Wextra -Wno-unused-parameter -Wno-sign-compare -ggdb -Og -std=gnu99 -Wno-old-style-declaration -D_GNU_SOURCE -DIDF_VER=\"v4.0-dev-1443-g39f090a4f-dirty\" -DGCC_NOT_5_2_0 -DESP_PLATFORM

C_DEFINES = -DHAVE_CONFIG_H -DMBEDTLS_CONFIG_FILE=\"mbedtls/esp_config.h\" -DUNITY_INCLUDE_CONFIG_H -DWITH_POSIX

C_INCLUDES = -I/Users/nprice/Projects/tp27v2/src/config -I/Users/nprice/Projects/esp-idf/components/newlib/platform_include -I/Users/nprice/Projects/esp-idf/components/freertos/include -I/Users/nprice/Projects/esp-idf/components/heap/include -I/Users/nprice/Projects/esp-idf/components/log/include -I/Users/nprice/Projects/esp-idf/components/soc/esp32/include -I/Users/nprice/Projects/esp-idf/components/soc/include -I/Users/nprice/Projects/esp-idf/components/esp_rom/include -I/Users/nprice/Projects/esp-idf/components/esp_common/include -I/Users/nprice/Projects/esp-idf/components/xtensa/include -I/Users/nprice/Projects/esp-idf/components/xtensa/esp32/include -I/Users/nprice/Projects/esp-idf/components/esp32/include -I/Users/nprice/Projects/esp-idf/components/driver/include -I/Users/nprice/Projects/esp-idf/components/esp_ringbuf/include -I/Users/nprice/Projects/esp-idf/components/esp_event/include -I/Users/nprice/Projects/esp-idf/components/tcpip_adapter/include -I/Users/nprice/Projects/esp-idf/components/lwip/include/apps -I/Users/nprice/Projects/esp-idf/components/lwip/include/apps/sntp -I/Users/nprice/Projects/esp-idf/components/lwip/lwip/src/include -I/Users/nprice/Projects/esp-idf/components/lwip/port/esp32/include -I/Users/nprice/Projects/esp-idf/components/lwip/port/esp32/include/arch -I/Users/nprice/Projects/esp-idf/components/vfs/include -I/Users/nprice/Projects/esp-idf/components/esp_wifi/include -I/Users/nprice/Projects/esp-idf/components/esp_wifi/esp32/include -I/Users/nprice/Projects/esp-idf/components/esp_eth/include -I/Users/nprice/Projects/esp-idf/components/efuse/include -I/Users/nprice/Projects/esp-idf/components/efuse/esp32/include -I/Users/nprice/Projects/esp-idf/components/app_trace/include -I/Users/nprice/Projects/esp-idf/components/mbedtls/port/include -I/Users/nprice/Projects/esp-idf/components/mbedtls/mbedtls/include -I/Users/nprice/Projects/esp-idf/components/wpa_supplicant/include -I/Users/nprice/Projects/esp-idf/components/wpa_supplicant/port/include -I/Users/nprice/Projects/esp-idf/components/wpa_supplicant/include/esp_supplicant -I/Users/nprice/Projects/esp-idf/components/bootloader_support/include -I/Users/nprice/Projects/esp-idf/components/app_update/include -I/Users/nprice/Projects/esp-idf/components/spi_flash/include -I/Users/nprice/Projects/esp-idf/components/nvs_flash/include -I/Users/nprice/Projects/esp-idf/components/smartconfig_ack/include -I/Users/nprice/Projects/esp-idf/components/pthread/include -I/Users/nprice/Projects/esp-idf/components/espcoredump/include -I/Users/nprice/Projects/esp-idf/components/asio/asio/asio/include -I/Users/nprice/Projects/esp-idf/components/asio/port/include -I/Users/nprice/Projects/esp-idf/components/coap/port/include -I/Users/nprice/Projects/esp-idf/components/coap/port/include/coap -I/Users/nprice/Projects/esp-idf/components/coap/libcoap/include -I/Users/nprice/Projects/esp-idf/components/coap/libcoap/include/coap2 -I/Users/nprice/Projects/esp-idf/components/console/. -I/Users/nprice/Projects/esp-idf/components/nghttp/port/include -I/Users/nprice/Projects/esp-idf/components/nghttp/nghttp2/lib/includes -I/Users/nprice/Projects/esp-idf/components/esp-tls/. -I/Users/nprice/Projects/esp-idf/components/esp-tls/PRIVATE_INCLUDE_DIRS -I/Users/nprice/Projects/esp-idf/components/esp-tls/private_include -I/Users/nprice/Projects/esp-idf/components/esp_adc_cal/include -I/Users/nprice/Projects/esp-idf/components/esp_gdbstub/include -I/Users/nprice/Projects/esp-idf/components/tcp_transport/include -I/Users/nprice/Projects/esp-idf/components/tcp_transport/PRIVATE_INCLUDE_DIRS -I/Users/nprice/Projects/esp-idf/components/tcp_transport/private_include -I/Users/nprice/Projects/esp-idf/components/esp_http_client/include -I/Users/nprice/Projects/esp-idf/components/esp_http_server/include -I/Users/nprice/Projects/esp-idf/components/esp_https_ota/include -I/Users/nprice/Projects/esp-idf/components/protobuf-c/protobuf-c -I/Users/nprice/Projects/esp-idf/components/protocomm/include/common -I/Users/nprice/Projects/esp-idf/components/protocomm/include/security -I/Users/nprice/Projects/esp-idf/components/protocomm/include/transports -I/Users/nprice/Projects/esp-idf/components/mdns/include -I/Users/nprice/Projects/esp-idf/components/esp_local_ctrl/include -I/Users/nprice/Projects/esp-idf/components/esp_websocket_client/include -I/Users/nprice/Projects/esp-idf/components/expat/expat/expat/lib -I/Users/nprice/Projects/esp-idf/components/expat/port/include -I/Users/nprice/Projects/esp-idf/components/wear_levelling/include -I/Users/nprice/Projects/esp-idf/components/sdmmc/include -I/Users/nprice/Projects/esp-idf/components/fatfs/diskio -I/Users/nprice/Projects/esp-idf/components/fatfs/vfs -I/Users/nprice/Projects/esp-idf/components/fatfs/src -I/Users/nprice/Projects/esp-idf/components/freemodbus/common/include -I/Users/nprice/Projects/esp-idf/components/idf_test/include -I/Users/nprice/Projects/esp-idf/components/jsmn/include -I/Users/nprice/Projects/esp-idf/components/json/cJSON -I/Users/nprice/Projects/esp-idf/components/libsodium/libsodium/src/libsodium/include -I/Users/nprice/Projects/esp-idf/components/libsodium/port_include -I/Users/nprice/Projects/esp-idf/components/mqtt/esp-mqtt/include -I/Users/nprice/Projects/esp-idf/components/openssl/include -I/Users/nprice/Projects/esp-idf/components/spiffs/include -I/Users/nprice/Projects/esp-idf/components/ulp/include -I/Users/nprice/Projects/esp-idf/components/unity/include -I/Users/nprice/Projects/esp-idf/components/unity/unity/src -I/Users/nprice/Projects/esp-idf/components/wifi_provisioning/include 

