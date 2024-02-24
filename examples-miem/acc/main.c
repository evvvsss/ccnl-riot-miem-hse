#include <stdio.h>

#include "xtimer.h"
#include "periph/i2c.h"
#include "lsm6ds3.h"
#include "lsm6ds3_regs.h"

static lsm6ds3_t acc;

int main(void) {
    static lsm6ds3_param_t lsm_params;
    lsm_params.i2c_addr = 0x6A;
    lsm_params.i2c = I2C_DEV(1);

    /* Configure the default settings */
    lsm_params.gyro_enabled = true;
    lsm_params.gyro_range = LSM6DS3_ACC_GYRO_FS_G_500dps;
    lsm_params.gyro_sample_rate = LSM6DS3_ACC_GYRO_ODR_XL_1660Hz;
    lsm_params.gyro_bandwidth = LSM6DS3_ACC_GYRO_BW_XL_400Hz;
    lsm_params.gyro_fifo_enabled = true;
    lsm_params.gyro_fifo_decimation = true;

    lsm_params.accel_enabled = true;
    lsm_params.accel_odr_off = true;
    lsm_params.accel_range = LSM6DS3_ACC_GYRO_FS_XL_16g;
    lsm_params.accel_sample_rate = LSM6DS3_ACC_GYRO_ODR_XL_1660Hz;
    lsm_params.accel_bandwidth = LSM6DS3_ACC_GYRO_BW_XL_400Hz;
    lsm_params.accel_fifo_enabled = true;
    lsm_params.accel_fifo_decimation = true;

    lsm_params.temp_enabled = true;

    lsm_params.comm_mode = 1;

    lsm_params.fifo_threshold = 3000;
    lsm_params.fifo_sample_rate = LSM6DS3_ACC_GYRO_ODR_FIFO_1600Hz;
    lsm_params.fifo_mode_word = 0;

    acc.params = lsm_params;

    if (lsm6ds3_init(&acc) == 0) {
        puts("ST LSM6DS3 sensor found");

        while(1){
            int16_t x, y, z;
            lsm6ds3_data_t lsm6ds3_data;
            lsm6ds3_poweron(&acc);
            lsm6ds3_read_acc(&acc, &lsm6ds3_data);
            lsm6ds3_poweroff(&acc);
            
            x = lsm6ds3_data.acc_x;
            y = lsm6ds3_data.acc_y;
            z = lsm6ds3_data.acc_z;

            xtimer_sleep(1);

            printf("Acceleration: X %i, Y %i, Z %i\n", x, y, z);
        }
    }

    return 0;
}
