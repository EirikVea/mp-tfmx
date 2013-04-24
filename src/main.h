#ifndef __MAIN_H__
#define __MAIN_H__

#include <windows.h>
#include <math.h>

#include "tfmx.h"
#include "tfmx_iface.h"
#include "tfmx_audio.h"

#define CLAMP(x, low, high)  (((x) > (high)) ? (high) : (((x) < (low)) ? (low) : (x)))

struct MyTFMXConfig {
    int freq;
    int loop_subsong;
    int over;
    int blend;
    int filt;
};

extern struct MyTFMXConfig plugin_cfg;

void tfmx_cfg_load(void);
void tfmx_cfg_save(void);

#define STREAM_PUSH -1
#define STREAM_PULL 0

struct mp_plugin_info
{
    char name[100];
    DWORD version;
    DWORD stream_type;
};

struct mp_song_info
{
    char *format;
    char *name;
    char *artist;
    int duration;
    int subsongs;
    int voices;
    int steps;
    char *info;
};

#ifdef BUILD_DLL
    #define DLL_EXPORT __declspec(dllexport)
#else
    #define DLL_EXPORT __declspec(dllimport)
#endif


#ifdef __cplusplus
extern "C"
{
#endif

void DLL_EXPORT mp_PluginInfo(struct mp_plugin_info *info);
bool DLL_EXPORT mp_Detect(char *filename, struct mp_song_info *songinfo);
bool DLL_EXPORT mp_InitPlugin(char *filename, int frequency, int bps, int channels);
DWORD DLL_EXPORT mp_FillBuffer(void *buffer, DWORD length);

DWORD DLL_EXPORT mp_NextSubsong();
DWORD DLL_EXPORT mp_PreviousSubsong();

#ifdef __cplusplus
}
#endif

#endif // __MAIN_H__
