/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_SEWindowsKernelService,
    0xcc582c0c,0x82db,0x410f,0xa4,0xeb,0x21,0x2f,0xba,0xdf,0xff,0xcf);
// {cc582c0c-82db-410f-a4eb-212fbadfffcf}
