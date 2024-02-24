#include <stdio.h>
#include <string.h>

#include "xtimer.h"
#include "thread.h"

#include "bmx280.h"

#include "cayenne_lpp.h"

#include "sx127x.h"
#include "sx127x_netdev.h"
#include "sx127x_params.h"
#include "net/loramac.h"     /* core loramac definitions */
#include "semtech_loramac.h" /* package API */

typedef enum {
    APP_MSG_SEND,
} app_message_types_t;

typedef struct {
    uint8_t *buffer;
    uint32_t length;
} lora_data_t;

static msg_t recv_queue[4];
static msg_t send_queue[4];

static semtech_loramac_t loramac;  /* The loramac stack device descriptor */
static sx127x_t sx127x;            /* SX127x device descriptor            */
static kernel_pid_t sender_pid;    /* Pid of a thread which controls data sending */
static kernel_pid_t loramac_pid;   /* Pid of a thread which controls LoRaWAN stack */

/* define the required keys for activation */
static const uint8_t deveui[LORAMAC_DEVEUI_LEN] = { 0x80, 0x7b, 0x85, 0x90, 0x20, 0x00, 0x00, 0x00 };
static const uint8_t appeui[LORAMAC_APPEUI_LEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/* we need AppKey for OTAA */
static const uint8_t appkey[LORAMAC_APPKEY_LEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static bmx280_t dev_bmx280;
static bmx280_params_t bme280_params = {
    .i2c_dev = I2C_DEV(1),
    .i2c_addr = 0x76,
    .t_sb = BMX280_SB_0_5,
    .filter = BMX280_FILTER_OFF,
    .run_mode = BMX280_MODE_FORCED,
    .temp_oversample = BMX280_OSRS_X1,
    .press_oversample = BMX280_OSRS_X1,
    .humid_oversample = BMX280_OSRS_X1,
};

static char recv_stack[THREAD_STACKSIZE_DEFAULT];
static char bmp280_stack[THREAD_STACKSIZE_DEFAULT];
static cayenne_lpp_t bmp_lpp;

static void *bmp280_thread(void *arg) {
    (void) arg;
    static msg_t data_msg = { .type = APP_MSG_SEND };
    static lora_data_t data;
    
    if (bmx280_init(&dev_bmx280, &bme280_params) == BMX280_OK) {
        puts("BME280 succesfully initialised!\r");
        
        xtimer_ticks32_t last_wakeup = xtimer_now();
        
        while(1){
            int t = bmx280_read_temperature(&dev_bmx280); /* degrees C * 100 */
            int h = bme280_read_humidity(&dev_bmx280); /* percents * 100 */
            int p = bmx280_read_pressure(&dev_bmx280)/10; /* Pa -> 0.1 mbar */

            printf("T = %i.%i C, H = %i.%i %%, P = %i mbar\r\n", t/100, t%100, h/100, h%100, p/10);
            
            /* Put data into Cayenne LPP buffer */
            cayenne_lpp_reset(&bmp_lpp);
            cayenne_lpp_add_temperature(&bmp_lpp, 1, (int16_t) (t/10)); /* degrees C * 10 */
            cayenne_lpp_add_barometric_pressure(&bmp_lpp, 2, p);
            cayenne_lpp_add_relative_humidity(&bmp_lpp, 3, (int16_t) (h/50)); /* 1/2% */

            /* Send a message to a LoRaWAN thread */
            data.buffer = bmp_lpp.buffer;
            data.length = bmp_lpp.cursor;
            data_msg.content.ptr = &data;
            msg_send(&data_msg, sender_pid);
            
            xtimer_periodic_wakeup(&last_wakeup, 60*1000*1000);
        }
    }
    
    return NULL;
}

static void *recv_thread(void *arg) {
    (void) arg;
    int res;
    msg_init_queue(recv_queue, 4);
 
    while (1) {
        /* blocks until some data is received */
        res = semtech_loramac_recv(&loramac);
        
        switch (res) {
        case SEMTECH_LORAMAC_RX_DATA:
            printf("[LoRa] Data received: %d bytes, port %d\n",
                            loramac.rx_data.payload_len,
                            loramac.rx_data.port);

            printf("[LoRa] Hex data: ");
            for (int l = 0; l < loramac.rx_data.payload_len; l++) {
                printf("%02X ", loramac.rx_data.payload[l]);
            }
            printf("\n");

            /* TODO: process data here */
            break;

        case SEMTECH_LORAMAC_RX_CONFIRMED:
            printf("[LoRa] Acknowledgement received\n");
            break;
        }
    }

    return NULL;
}

int main(void){
    int res;
    msg_t msg;
    
    /* Adjust message queue size */
    msg_init_queue(send_queue, 4);
    
    /* Setup the transceiver and the LoRaWAN stack */
    sx127x_setup(&sx127x, &sx127x_params[0], 0);
    loramac.netdev = &sx127x.netdev;
    loramac.netdev->driver = &sx127x_driver;
    loramac_pid = semtech_loramac_init(&loramac);
    sender_pid = thread_getpid();
    
    /* Set the keys identifying the device */
    semtech_loramac_set_deveui(&loramac, deveui);
    semtech_loramac_set_appeui(&loramac, appeui);
    semtech_loramac_set_appkey(&loramac, appkey);
        
    /* Additional LoRaWAN setup */    
    semtech_loramac_set_tx_power(&loramac, -5);
    semtech_loramac_set_dr(&loramac, LORAMAC_DR_1);
    semtech_loramac_set_tx_mode(&loramac, LORAMAC_TX_CNF);   /* confirmed packets */
    semtech_loramac_set_tx_port(&loramac, 2); /* port 2 */
    semtech_loramac_set_class(&loramac, LORAMAC_CLASS_C); /* Always listen */
    
    puts("[LoRa] LoRaMAC initialised");
    
    do{
        res = semtech_loramac_join(&loramac, LORAMAC_JOIN_OTAA);
                    
        switch (res) {
        case SEMTECH_LORAMAC_JOIN_SUCCEEDED: 
            puts("[LoRa] successfully joined to the network");
            break;
        
        case SEMTECH_LORAMAC_ALREADY_JOINED:
            /* ignore, can't be */
            break;
        
        case SEMTECH_LORAMAC_BUSY:
        case SEMTECH_LORAMAC_NOT_JOINED:
        case SEMTECH_LORAMAC_JOIN_FAILED:
        case SEMTECH_LORAMAC_DUTYCYCLE_RESTRICTED:
            printf("[LoRa] LoRaMAC join failed: code %d\n", res);
            xtimer_sleep(10);
            break;
        
        default:
            printf("[LoRa] join request: unknown response %d\n", res);
            break;
        }
    } while (res != SEMTECH_LORAMAC_JOIN_SUCCEEDED);
    
    /* Start another thread for sensor measurements */
    thread_create(bmp280_stack, sizeof(bmp280_stack),
              THREAD_PRIORITY_MAIN-1,
              THREAD_CREATE_STACKTEST,
              bmp280_thread,
              NULL,
              "Sensor thread");

    /* Start another thread for data receiving */
    thread_create(recv_stack, sizeof(recv_stack),
            THREAD_PRIORITY_MAIN-2,
            THREAD_CREATE_STACKTEST,
            recv_thread,
            NULL,
            "Receiving thread");
    
    while (1) {
        msg_receive(&msg);

        /* Application message */
        if (msg.type == APP_MSG_SEND) {
            lora_data_t *data = msg.content.ptr;
            (void) data;
            res = semtech_loramac_send(&loramac, data->buffer, data->length);

            switch (res) {
            case SEMTECH_LORAMAC_TX_DONE:
                puts("[LoRa] TX done");
                break;
            case SEMTECH_LORAMAC_TX_CNF_FAILED:
                puts("[LoRa] Uplink confirmation failed");
                /* TODO: rejoin if there are too many failures */
                break;
            case SEMTECH_LORAMAC_BUSY:
                puts("[LoRa] MAC already busy");
                break;
            case SEMTECH_LORAMAC_NOT_JOINED: 
                puts("[LoRa] Not joined to the network");
                break;
            case SEMTECH_LORAMAC_TX_OK:
                puts("[LoRa] TX is in progress");
                break;
            case SEMTECH_LORAMAC_DUTYCYCLE_RESTRICTED:
                puts("[LoRa] TX duty cycle restricted");
                break;
            default:
                printf("[LoRa] Unknown send() response %d\n", res);
                break;
            }
        }
    }
}
