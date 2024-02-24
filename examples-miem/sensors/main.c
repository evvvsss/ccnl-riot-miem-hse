#include <stdio.h>

#include "xtimer.h"
#include "periph/i2c.h"
#include "bmx280.h"
#include "opt3001.h"

static char lum_stack[THREAD_STACKSIZE_DEFAULT];

static opt3001_t opt3001;
static const opt3001_params_t opt3001_params = {
    .i2c_dev = I2C_DEV(1),
    .i2c_addr = 0x44,
};

static bmx280_t bmx280;
static const bmx280_params_t bmx280_params = {
    .i2c_dev = I2C_DEV(1),
    .i2c_addr = 0x76,
    .t_sb = BMX280_SB_0_5,
    .filter = BMX280_FILTER_OFF,
    .run_mode = BMX280_MODE_FORCED,
    .temp_oversample = BMX280_OSRS_X1,
    .press_oversample = BMX280_OSRS_X1,
    .humid_oversample = BMX280_OSRS_X1,
};

void *lum_thread(void *arg) {
    (void) arg;
    int res;
    
    if (opt3001_init(&opt3001, &opt3001_params) == OPT3001_OK) {
        puts("OPT3001 succesfully initialised!\r");

        res = opt3001_set_active(&opt3001);
        if(res == OPT3001_OK) {    
            while(1){
                uint32_t luminocity;
                res = opt3001_read_lux(&opt3001, &luminocity);

                if(res == OPT3001_OK){
                    printf("lum = %lu mlux\r\n", luminocity);
                }
                xtimer_msleep(1000);
            }
        }
    }

    return NULL;
}

int main(void) {
    /* Start another thread for luminocity measurements */
    thread_create(lum_stack, sizeof(lum_stack),
              THREAD_PRIORITY_MAIN+1,
              THREAD_CREATE_STACKTEST,
              lum_thread,
              NULL,
              "Luminoсity");

    if (bmx280_init(&bmx280, &bmx280_params) == BMX280_OK) {
        puts("BME280 succesfully initialised!\r");
        
        while(1){
            int t = bmx280_read_temperature(&bmx280); /* degrees C * 100 */
            int h = bme280_read_humidity(&bmx280); /* percents * 100 */
            int p = bmx280_read_pressure(&bmx280)/100; /* Pa -> mbar */

            printf("T = %i.%i C, H = %i.%i %%, P = %i mbar\r\n", t/100, t%100, h/100, h%100, p);
            
            xtimer_msleep(10000);
        }
    }

    return 0;
}
