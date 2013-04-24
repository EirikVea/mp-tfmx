#ifndef __TFMX_AUDIO_H__
#define __TFMX_AUDIO_H__

#include <stdlib.h>
#include <stdio.h>
#include <memory.h>

#include <unistd.h>

//#include <sys/types.h>
//#include <sys/stat.h>

#include <fcntl.h>
#include <errno.h>

#include "main.h"
#include "tfmx_player.h"

#ifdef __cplusplus__
extern "C" {
#endif

    void tfmx_calc_sizes(void);
    long tfmx_get_block_size(void);
    int  tfmx_get_block(void *buffer);
    int  tfmx_try_to_make_block(void);
    void TfmxTakedown(void);
    void TfmxResetBuffers(void);

#ifdef __cplusplus__
}
#endif

#endif /* __TFMX_AUDIO_H__ */

