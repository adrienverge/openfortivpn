/*
 * Wintun API declarations for dynamic loading.
 * Based on the Wintun API (https://www.wintun.net/).
 * The actual wintun.dll is loaded at runtime via LoadLibrary.
 *
 * Wintun is licensed under the MIT license.
 */

#ifndef OPENFORTIVPN_WINTUN_H
#define OPENFORTIVPN_WINTUN_H

#ifdef _WIN32

#include <windows.h>
#include <ipexport.h>
#include <ifdef.h>

typedef void *WINTUN_ADAPTER_HANDLE;
typedef void *WINTUN_SESSION_HANDLE;

/*
 * Wintun API function types and pointer typedefs.
 * Two-step typedefs avoid checkpatch false positives on WINAPI
 * calling convention syntax.
 */
typedef WINTUN_ADAPTER_HANDLE WINAPI
WINTUN_CREATE_ADAPTER_FN(const WCHAR *, const WCHAR *,
                         const GUID *);
typedef WINTUN_CREATE_ADAPTER_FN *WINTUN_CREATE_ADAPTER_FUNC;

typedef void WINAPI
WINTUN_CLOSE_ADAPTER_FN(WINTUN_ADAPTER_HANDLE);
typedef WINTUN_CLOSE_ADAPTER_FN *WINTUN_CLOSE_ADAPTER_FUNC;

typedef WINTUN_SESSION_HANDLE WINAPI
WINTUN_START_SESSION_FN(WINTUN_ADAPTER_HANDLE, DWORD);
typedef WINTUN_START_SESSION_FN *WINTUN_START_SESSION_FUNC;

typedef void WINAPI WINTUN_END_SESSION_FN(WINTUN_SESSION_HANDLE);
typedef WINTUN_END_SESSION_FN *WINTUN_END_SESSION_FUNC;

typedef HANDLE WINAPI WINTUN_GET_READ_WAIT_EVENT_FN(WINTUN_SESSION_HANDLE);
typedef WINTUN_GET_READ_WAIT_EVENT_FN *WINTUN_GET_READ_WAIT_EVENT_FUNC;

typedef BYTE *WINAPI WINTUN_RECEIVE_PACKET_FN(WINTUN_SESSION_HANDLE, DWORD *);
typedef WINTUN_RECEIVE_PACKET_FN *WINTUN_RECEIVE_PACKET_FUNC;

typedef void WINAPI WINTUN_RELEASE_RECEIVE_PACKET_FN(WINTUN_SESSION_HANDLE, const BYTE *);
typedef WINTUN_RELEASE_RECEIVE_PACKET_FN *WINTUN_RELEASE_RECEIVE_PACKET_FUNC;

typedef BYTE *WINAPI WINTUN_ALLOCATE_SEND_PACKET_FN(WINTUN_SESSION_HANDLE, DWORD);
typedef WINTUN_ALLOCATE_SEND_PACKET_FN *WINTUN_ALLOCATE_SEND_PACKET_FUNC;

typedef void WINAPI WINTUN_SEND_PACKET_FN(WINTUN_SESSION_HANDLE, const BYTE *);
typedef WINTUN_SEND_PACKET_FN *WINTUN_SEND_PACKET_FUNC;

typedef void WINAPI WINTUN_GET_ADAPTER_LUID_FN(WINTUN_ADAPTER_HANDLE, NET_LUID *);
typedef WINTUN_GET_ADAPTER_LUID_FN *WINTUN_GET_ADAPTER_LUID_FUNC;

typedef DWORD WINAPI WINTUN_GET_RUNNING_DRIVER_VERSION_FN(void);
typedef WINTUN_GET_RUNNING_DRIVER_VERSION_FN *WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC;

/* Function pointer table loaded from wintun.dll */
struct wintun_api {
	HMODULE module;
	WINTUN_CREATE_ADAPTER_FUNC CreateAdapter;
	WINTUN_CLOSE_ADAPTER_FUNC CloseAdapter;
	WINTUN_START_SESSION_FUNC StartSession;
	WINTUN_END_SESSION_FUNC EndSession;
	WINTUN_GET_READ_WAIT_EVENT_FUNC GetReadWaitEvent;
	WINTUN_RECEIVE_PACKET_FUNC ReceivePacket;
	WINTUN_RELEASE_RECEIVE_PACKET_FUNC ReleaseReceivePacket;
	WINTUN_ALLOCATE_SEND_PACKET_FUNC AllocateSendPacket;
	WINTUN_SEND_PACKET_FUNC SendPacket;
	WINTUN_GET_ADAPTER_LUID_FUNC GetAdapterLUID;
	WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC GetRunningDriverVersion;
};

/*
 * Load wintun.dll and resolve all function pointers.
 * Returns 0 on success, -1 on failure.
 */
static inline int wintun_load(struct wintun_api *api)
{
	HMODULE mod = LoadLibraryW(L"wintun.dll");

	if (!mod)
		return -1;

	api->module = mod;

	api->CreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC)
	                     GetProcAddress(mod, "WintunCreateAdapter");
	api->CloseAdapter = (WINTUN_CLOSE_ADAPTER_FUNC)
	                    GetProcAddress(mod, "WintunCloseAdapter");
	api->StartSession = (WINTUN_START_SESSION_FUNC)
	                    GetProcAddress(mod, "WintunStartSession");
	api->EndSession = (WINTUN_END_SESSION_FUNC)
	                  GetProcAddress(mod, "WintunEndSession");
	api->GetReadWaitEvent = (WINTUN_GET_READ_WAIT_EVENT_FUNC)
	                        GetProcAddress(mod, "WintunGetReadWaitEvent");
	api->ReceivePacket = (WINTUN_RECEIVE_PACKET_FUNC)
	                     GetProcAddress(mod, "WintunReceivePacket");
	api->ReleaseReceivePacket = (WINTUN_RELEASE_RECEIVE_PACKET_FUNC)
	                            GetProcAddress(mod, "WintunReleaseReceivePacket");
	api->AllocateSendPacket = (WINTUN_ALLOCATE_SEND_PACKET_FUNC)
	                          GetProcAddress(mod, "WintunAllocateSendPacket");
	api->SendPacket = (WINTUN_SEND_PACKET_FUNC)
	                  GetProcAddress(mod, "WintunSendPacket");
	api->GetAdapterLUID = (WINTUN_GET_ADAPTER_LUID_FUNC)
	                      GetProcAddress(mod, "WintunGetAdapterLUID");
	api->GetRunningDriverVersion = (WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC)
	                               GetProcAddress(mod, "WintunGetRunningDriverVersion");

	if (!api->CreateAdapter || !api->CloseAdapter ||
	    !api->StartSession || !api->EndSession ||
	    !api->GetReadWaitEvent || !api->ReceivePacket ||
	    !api->ReleaseReceivePacket || !api->AllocateSendPacket ||
	    !api->SendPacket || !api->GetAdapterLUID ||
	    !api->GetRunningDriverVersion) {
		FreeLibrary(mod);
		return -1;
	}

	return 0;
}

static inline void wintun_unload(struct wintun_api *api)
{
	if (api->module) {
		FreeLibrary(api->module);
		api->module = NULL;
	}
}

#endif /* _WIN32 */

#endif /* OPENFORTIVPN_WINTUN_H */
