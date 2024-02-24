#include <stdio.h>
#include "board.h"
#include "st95.h"

st95_t dev;
st95_params_t st95_params = { 
    .iface = ST95_IFACE_UART,
    .uart = 1,
    .baudrate = 57600, 
    .irq_in = UNWD_GPIO_25,
    .irq_out = UNWD_GPIO_26, 
    .ssi_0 = UNWD_GPIO_6,
    .ssi_1 = GPIO_UNDEF,
    .vcc = UNWD_GPIO_24
};

static msg_t msg_wu = { .type = 4567, };
static kernel_pid_t nfc_pid;

static void st95_cb(void * arg) {
    (void) arg;

    msg_try_send(&msg_wu, nfc_pid);
}

int main(void) {
    msg_t msg;
    msg_t msg_queue[8];
    msg_init_queue(msg_queue, 8);

    /* Set up a callback for ST95 */
    dev.cb = st95_cb;
    nfc_pid = thread_getpid();
  
    if(st95_init(&dev, &st95_params) != ST95_OK){
        puts("ST95 driver initialization error");
        return 1;
    } else {
        puts("ST95 ready");
    }
    st95_sleep(&dev);

    while (1) {
        msg_receive(&msg);
    
        /* This thread receives messages only from ST95 callback */
        uint8_t length_uid = 0;
        uint8_t uid_full[10] = {0};
        uint8_t sak = 0;
        if(st95_get_uid(&dev, &length_uid, uid_full, &sak) == ST95_OK) {
            printf("Read card UID: ");
            for(uint32_t i = 0; i < length_uid; i++) {
                printf("%02X ", uid_full[i]);
            }
            printf("\n");       
        }  
        st95_sleep(&dev);                     
    }

    return 0;
}
