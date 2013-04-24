#include "main.h"

struct MyTFMXConfig plugin_cfg;

DWORD g_remaining = 0;
char *g_rembuf;

void DLL_EXPORT mp_PluginInfo(struct mp_plugin_info *info)
{
    strcpy(info->name,"TFMX plugin");
    info->version = 0x00000101;
}

bool DLL_EXPORT mp_Detect(char *filename, struct mp_song_info *songinfo)
{
	if(!IsTFMXFilename(filename))
	{
	    return false;
	}
    if(LoadTFMXFile(filename) != 0)
	{
	    return false;
	}

    songinfo->format = (char*)malloc(strlen("TFMX xV") * sizeof(char));
    wsprintf(songinfo->format,"TFMX %iV",player_TFMXVoices());
    songinfo->name = NULL;
    songinfo->artist = NULL;
    songinfo->duration = -1;
    songinfo->info = (char*)malloc(6 * 40 * sizeof(char));
    tfmx_get_module_info(songinfo->info);
    songinfo->subsongs = TFMXGetSubSongs();
    songinfo->voices = player_TFMXVoices();
    songinfo->steps = -1;

    TfmxTakedown();

    return true;
}

bool DLL_EXPORT mp_InitPlugin(char* filename, int frequency, int bps, int channels)
{
    if(g_rembuf)
    {
        free(g_rembuf);
        g_rembuf = NULL;
        g_remaining = 0;
    }

	if(!IsTFMXFilename(filename))
	{
	    return false;
	}
    if(LoadTFMXFile(filename) != 0)
	{
	    return false;
	}

    plugin_cfg.freq = frequency;
    plugin_cfg.loop_subsong = 1;
    plugin_cfg.over = 0;
    plugin_cfg.blend = 0;
    plugin_cfg.filt = 2;

	TFMXSetSubSong(0);
    TFMXRewind();

    return true;
}

//DWORD DLL_EXPORT mp_SetPluginParams()
//{
//
//}
//
//DWORD DLL_EXPORT mp_SetPluginParams()
//{
//
//}
//
//void DLL_EXPORT mp_GetSongInfo(struct mp_song_info *songinf)
//{
//
//}

DWORD DLL_EXPORT mp_GetPosition()
{
    return 0;
}

void DLL_EXPORT mp_SetPosition(DWORD pos)
{

}

DWORD DLL_EXPORT mp_NextSubsong()
{
    TFMXSetSubSong(min(TFMXGetSubSong() + 1,TFMXGetSubSongs()));

    g_remaining = 0;
    if(g_rembuf)
    {
        free(g_rembuf);
        g_rembuf = NULL;
    }

    return TFMXGetSubSong();
}

DWORD DLL_EXPORT mp_PreviousSubsong()
{
    TFMXSetSubSong(max(TFMXGetSubSong() - 1,0));

    g_remaining = 0;
    if(g_rembuf)
    {
        free(g_rembuf);
        g_rembuf = NULL;
    }

    return TFMXGetSubSong();
}

void mp_RemoveStereoSep16(short *buffer, DWORD length, float factor)
{
    short t1;
    for(int i = 0; i < (length >> 1) - 1; i += 1)
    {
        buffer[i] = ((float)buffer[i] * factor);
        buffer[i + 1] = (float)buffer[i + 1] * factor;
        t1 = buffer[i];
        buffer[i] += buffer[i + 1];
        buffer[i + 1] += t1;
    }
}

DWORD DLL_EXPORT mp_FillBuffer(void *buffer, DWORD length)
{
    int workbuf_length;

    if(g_remaining < length)
        workbuf_length = g_remaining + ceil((float)length / (float)tfmx_get_block_size()) * tfmx_get_block_size();
    else
        workbuf_length = g_remaining;

    char *workbuf = (char*)calloc(workbuf_length,sizeof(char));

    // Copy the remaining bytes from last time over to buffer
    if(g_remaining)
    {
        memcpy(workbuf,g_rembuf,g_remaining);
        free(g_rembuf);
        g_rembuf = NULL;
    }

    if(g_remaining < length)
    {
        for(int i = 0; i < ceil((float)length / (float)tfmx_get_block_size()); i++)
        {
            tfmx_try_to_make_block();
            tfmx_get_block((i * tfmx_get_block_size()) + g_remaining + workbuf);
            mp_RemoveStereoSep16((short*)((i * tfmx_get_block_size()) + g_remaining + workbuf),tfmx_get_block_size(),0.5);
        }
    }

    memcpy(buffer,workbuf,length);

    // The remaining number of bytes that didn't fit in the requested buffer
    // we need to hold on to these until next time
    g_remaining = workbuf_length - length;

    g_rembuf = (char*)calloc(g_remaining * sizeof(char),sizeof(char));
    memcpy(g_rembuf,length + workbuf, g_remaining);
    free(workbuf);

    return length;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // attach to process
            // return FALSE to fail DLL load
            break;

        case DLL_PROCESS_DETACH:
            // detach from process
            break;

        case DLL_THREAD_ATTACH:
            // attach to thread
            break;

        case DLL_THREAD_DETACH:
            // detach from thread
            break;
    }
    return TRUE; // succesful
}
