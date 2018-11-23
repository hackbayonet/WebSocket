// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <winsock2.h>
#include <stdio.h>
#include <winsock.h>
#include <stdlib.h>
#include <string>

BYTE JmpWASSendBYTE[5];
BYTE OldWASSendBYTE[5];

BYTE JmpSendBYTE[5];
BYTE OldSendBYTE[5];

DWORD OldWASSendProtect;
DWORD OldSendProtect;

void *WASSendAddress;
void *SendAddress;


void HookWASSend();
void UnHookWASSend();

void HookSend();
void UnHookSend();

#pragma comment(lib, "ws2_32.lib")

BYTE g_dec[4];
BOOL status = false;
BOOL status1 = false;

void Decrypt(LPCSTR buf, int len) {

	if (len == 24) {
		status = true;
	}

	if (status) {
		std::string s;
		if (len == 4) {
			strncpy((char *)g_dec, buf, 4);
			status1 = true;
		}
		else {
			if (status1) {
				for (int i = 0; i < len; i++) {
					s += buf[i] ^ g_dec[i % 4];
				}
				FILE *fp = fopen("dec.txt", "a");
				fprintf(fp, "%s\n", s.c_str());
				fclose(fp);
				status1 = false;
			}
		}
	}
}

int PASCAL My_Send(SOCKET s, const char FAR* buf, int len, int flags) {
	Decrypt(buf, len);
	
	UnHookSend();
	FILE *fp = fopen("3.txt", "a");
	fprintf(fp, "%d\n", s);
	fclose(fp);
	int res = send(s, buf, len, flags);
	HookSend();
	return res;
}

int WINAPI My_WasSend(
	SOCKET s, 
	LPWSABUF lpBuffers, 
	DWORD dwBufferCount, 
	LPDWORD lpNumberOfBytesSent, 
	DWORD dwFlags, 
	LPWSAOVERLAPPED lpOverlapped, 
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
	FILE *fp = fopen("send.txt", "a");
	fprintf(fp, "%s\n", lpBuffers->buf);
	fclose(fp);
	UnHookWASSend();
	int res = WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
	HookWASSend();
	return res;
}

void *Find(LPCSTR dll, LPCSTR func) { 
	void *addr = 0;
	HMODULE hModule = LoadLibraryA(dll);
	addr = (void *)GetProcAddress(hModule, func);
	return addr;
}

void HookSend() {
	void *addr = Find("Ws2_32.dll", "send");
	SendAddress = addr;
	if (addr == 0) {
		MessageBoxA(0, "HOOK send Error!", "", MB_OK);
	}

	VirtualProtect((void *)addr, 5, PAGE_EXECUTE_READWRITE, &OldSendProtect);
	JmpSendBYTE[0] = 0xE9;
	*(DWORD *)&JmpSendBYTE[1] = (DWORD)((long long)My_Send - (long long)addr - 5);
	memcpy(OldSendBYTE, (void *)addr, 5);

	memcpy((void *)addr, JmpSendBYTE, 5);
}

void UnHookSend() {
	memcpy((void *)SendAddress, OldSendBYTE, 5);
	DWORD p;
	VirtualProtect((void *)SendAddress, 5, OldSendProtect, &p);
}


void HookWASSend() {
	void *addr = Find("Ws2_32.dll", "WSASend");
	WASSendAddress = addr;
	if (addr == 0) {
		MessageBoxA(0, "HOOK WASSend Error!", "", MB_OK);
	}

	VirtualProtect((void *) addr, 5, PAGE_EXECUTE_READWRITE, &OldWASSendProtect);
	JmpWASSendBYTE[0] = 0xE9;
	*(DWORD *)&JmpWASSendBYTE[1] = (DWORD)((long long)My_WasSend - (long long)addr - 5);
	memcpy(OldWASSendBYTE, (void *)addr, 5);

	memcpy((void *)addr, JmpWASSendBYTE, 5);
}

void UnHookWASSend() {
	memcpy((void *)WASSendAddress, OldWASSendBYTE, 5);
	DWORD p;
	VirtualProtect((void *)WASSendAddress, 5, OldWASSendProtect, &p);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		HookWASSend();
		HookSend();
		break;
    case DLL_PROCESS_DETACH:
		UnHookWASSend();
		UnHookSend();
        break;
    }
    return TRUE;
}

