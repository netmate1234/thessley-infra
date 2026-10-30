//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

// The test-ticket provider has a separate CLSID so its registration and
// rollback can never replace the established TPM/VSC lab provider.
#ifdef THESSLEY_TICKET_LOGON_TEST
// {8A2755BF-64B7-4D39-9C48-67A6A27F5E91} -- isolated ticket-logon experiment
DEFINE_GUID(CLSID_ThessleyAD, 0x8a2755bf, 0x64b7, 0x4d39, 0x9c, 0x48, 0x67, 0xa6, 0xa2, 0x7f, 0x5e, 0x91);
#else
// {2678765D-9F74-4BDE-A4DA-2B53234BE053} -- isolated Thessley AD VSC test provider
DEFINE_GUID(CLSID_ThessleyAD, 0x2678765d, 0x9f74, 0x4bde, 0xa4, 0xda, 0x2b, 0x53, 0x23, 0x4b, 0xe0, 0x53);
#endif
