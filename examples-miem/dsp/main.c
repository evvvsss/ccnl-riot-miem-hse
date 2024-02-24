#include <stdio.h>

#include "board.h"
#include "periph/gpio.h"
#include "xtimer.h"

#include "arm_math.h"

#include "ecg.h"

q31_t pad[500] = {0};

#define STAGES 6

/* 5 coefficients each stage */
q31_t filter_coeffs[STAGES*5] = {
    1027080468,  // 1 Hz Butterworth high-pass
    -2054160935,
    1027080468,
    2052132225,
    -982447822,
    29794094,    // 60 Hz Butterworth low-pass
    59588187,
    29794094,
    1586460278,
    -631894829,
    1057895428,  // 50 Hz notch
    -2015208065,
    1057895428,
    2017613793,
    -1041084974,
    1055838009,
    -2005272285,
    1055838009,
    2002709966,
    -1039060248,
    1069836749,
    -2036220071,
    1069836749,
    2043955687,
    -1065779498,
    1069095489,
    -2032256517,
    1069095489,
    2024104799,
    -1065041049
};
q31_t filter_state[STAGES*4]; /* 4 ints for each state */
arm_biquad_casd_df1_inst_q31  filter;

int main(void) {
    int total_elapsed_time = 0;
    arm_biquad_cascade_df1_init_q31(&filter, STAGES, filter_coeffs, filter_state, 1);

    for(int i = 0; i < 10; i++){
        int32_t start = xtimer_now();
        //memcpy(pad, ecg_data + i*500, 500*sizeof(q31_t));
        arm_biquad_cascade_df1_q31(&filter, (q31_t*) (ecg_data + i*500), pad, 500);
        int32_t elapsed = xtimer_now() - start;
        total_elapsed_time += elapsed;

        for(int j = 0; j < 500; j++){
            printf("%i\t%li\n", i*500 + j, pad[j]);
        }
    }

    printf("Total elapsed time %i us\n", total_elapsed_time);

    return 0;
}
