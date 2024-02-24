#include <stdio.h>
#include <string.h>
#include "arm_math.h"

#include "eeg.h"

q31_t pad[500] = {0};

int main(void) {
    for(int i = 0; i < 10; i++){
        memcpy(pad, eeg_data + i*500, 500*sizeof(q31_t));
        
        for(int j = 0; j < 500; j++){
            printf("%i\t%li\n", (i*500 + j)*2, pad[j]);
        }
    }

    return 0;
}
