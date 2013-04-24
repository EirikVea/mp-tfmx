/* Miscellaneous functions for using & implementing the general
 * interface to TFMXPlay
 */

#ifndef _TFMXIFACE_H_
#define _TFMXIFACE_H_

#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
	#include <wtypes.h>
	#define strncasecmp strnicmp
	#define DIRDELIM '\\'
#else
	#include <unistd.h>
	#define DIRDELIM '\\'
#endif

#include "tfmx.h"

/* Error function definition */
#define TFMXERR(x) printf(x)
void printf(char *err);

/* TFMX file & playing management */
int IsTFMXFilename(char *fName);
char LoadTFMXFile(char *fName);
void TFMXRewind();
void TFMXStop();
void TFMXQuit();

/* Per-module info */
void tfmx_fill_module_info(char *textBuffer);
void tfmx_get_module_info(char *info);
int TFMXGetSubSongs();

/* TFMX player settings read/write */
int TFMXGetSubSong();
void TFMXSetSubSong(int num);
void SetFilterState(char state);
void SetBlendState(char state);
void SetLoopState(char state);
char GetFilterState();
char GetBlendState();
char GetLoopState();

/* Sample buffer handling */
long tfmx_get_block_size();
int tfmx_get_block(void *buffer);
int tfmx_try_to_make_block();


void player_TfmxInit();
void player_StartSong(int, int);
void TfmxTakedown();
void tfmxIrqIn();


#endif
