// webradar.c : CS:GO Webradar functionality
//
// (c) EngineOwning Software UG (haftungsbeschränkt), 2018
// Author: Valentin Rick, valentin.rick@engineowning.software
//

#ifndef WIN32
#pragma error("webradar can only be compiled on and for WIN32")
#endif

#include "webradar.h"
#include "memdump.h"
#include "device.h"
#include "statistics.h"
#include "util.h"
#include "vmm.h"
#include "vmmproc.h"
#include <http.h>
#include <parson.h>
#include <math.h>

#pragma comment(lib, "Httpapi.lib")

typedef float vmatrix_t[4][4];

BOOL g_webRadarExit = FALSE;
HANDLE g_webRadarExitEvent = NULL;
HANDLE g_webRadarWSThread = NULL;

typedef struct _GameOffsets
{
	DWORD GO_EntityList;
	DWORD GO_ViewMatrix;
	DWORD GO_ClientState;
	DWORD GO_ClientState_LocalPlayer;
	DWORD GO_ClientState_ViewAngle;
	DWORD GO_ClientState_Map;
	DWORD GO_ClientState_PlayerInfo;
	DWORD GO_Lifestate;
	DWORD GO_AngEyeAngle;
	DWORD GO_Dormant;
	DWORD GO_Team;
	DWORD GO_Health;
	DWORD GO_Origin;
} GameOffsets;

typedef struct _EntityInfo
{
	int team;
	int health;
	unsigned char lifestate;
	float origin[3];
	float origin_forward[3];
	float viewAngles[2];
	unsigned char local;
	unsigned char valid;
	char name[33];
} EntityInfo;

unsigned char clientStateBuffer[0x4000 * 2];
char mapName[64];
EntityInfo entities[64];

BOOL WINAPI ControlHandler(DWORD signal)
{
	// Clean shutdown
	if ((signal == CTRL_C_EVENT || signal == CTRL_LOGOFF_EVENT || signal == CTRL_SHUTDOWN_EVENT) &&
		g_webRadarExitEvent != NULL)
	{
		printf("[WebRadar by Skyfail] Shutting down\n");

		g_webRadarExit = TRUE;

		HANDLE events[2] = {
			g_webRadarExitEvent,
			g_webRadarWSThread
		};

		WaitForMultipleObjects(ARRAYSIZE(events), (const HANDLE *)&events, TRUE, 5000);

		for (int i = 0u; i < ARRAYSIZE(events); i++)
		{
			CloseHandle(events[i]);
		}

		ExitProcess(EXIT_SUCCESS);
	}

	return FALSE;
}

void AngleVectors(const float angles[2], float forward[3], float right[3], float up[3])
{
	float sp, sy, sr, cp, cy, cr;

	float angX = (3.14159265358979323846f / 180.f) * (angles[0]);
	float angY = (3.14159265358979323846f / 180.f) * (angles[1]);

	sy = sinf(angY);
	cy = cosf(angY);

	sp = sinf(angX);
	cp = cosf(angX);

	sr = sinf(0.f);
	cr = sinf(0.f);

	forward[0] = cp*cy;
	forward[1] = cp*sy;
	forward[2] = -sp;

	right[0] = -1 * sr*sp*cy + -1 * cr * -sy;
	right[1] = -1 * sr*sp*sy + -1 * cr*cy;
	right[2] = -1 * sr*cp;

	up[0] = cr*sp*cy + -sr*-sy;
	up[1] = cr*sp*sy + -sr*cy;
	up[2] = cr*cp;
}

void LookupMimeType(const char *szExtension, char result[64])
{
	if (!_stricmp(szExtension, ".js"))
	{
		// special case woah too lazy to implement proper MIME Type handling
		strcpy_s(result, 64, "application/javascript");
		return;
	}

	HKEY hKey = NULL;
	strcpy_s(result, 64, "application/unknown");

	if (RegOpenKeyExA(HKEY_CLASSES_ROOT, szExtension, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		DWORD dwBuffSize = 64;

		RegQueryValueExA(hKey, "Content Type", NULL, NULL, (LPBYTE)result, &dwBuffSize);
		RegCloseKey(hKey);
	}
}

DWORD WINAPI WebServerThread(LPVOID param)
{
	UNREFERENCED_PARAMETER(param);

	HANDLE reqQueueHandle = NULL;
	HTTPAPI_VERSION httpApiVersion = HTTPAPI_VERSION_2;
	HTTP_SERVER_SESSION_ID serverSessionId = HTTP_NULL_ID;

	HttpInitialize(httpApiVersion, HTTP_INITIALIZE_SERVER, NULL);
	HttpCreateServerSession(httpApiVersion, &serverSessionId, 0);
	HttpCreateHttpHandle(&reqQueueHandle, 0);

	HttpAddUrl(reqQueueHandle, L"http://+:8008/info", NULL);
	HttpAddUrl(reqQueueHandle, L"http://+:8008/static/", NULL);
	HttpAddUrl(reqQueueHandle, L"http://+:8008/", NULL);

	ULONG reqSize = sizeof(HTTP_REQUEST_V2) + 2048;
	HTTP_REQUEST_V2 *req = (HTTP_REQUEST_V2*)malloc(reqSize);

	while (!g_webRadarExit)
	{
		ULONG headerSz = 0;

		memset(req, 0, reqSize);
		ULONG status = HttpReceiveHttpRequest(reqQueueHandle, HTTP_NULL_ID, 0, req, reqSize, &headerSz, NULL);
		
		if (status != NO_ERROR && status != ERROR_MORE_DATA) // we don't care about body data
		{
			printf("[WebRadar by Skyfail] HttpReceiveHttpRequest() returned error: %i\n", status);
			Sleep(5);
			continue;
		}

		HTTP_RESPONSE response;
		HTTP_DATA_CHUNK dataChunk;
		memset(&response, 0, sizeof(response));
		memset(&dataChunk, 0, sizeof(dataChunk));

		// Set response status
		response.StatusCode = 200;
		response.pReason = "OK";
		
		const char *contentType = "application/json; charset=ASCII";

		response.EntityChunkCount = 1;
		response.pEntityChunks = &dataChunk;

		// Add default headers
		response.Headers.KnownHeaders[HttpHeaderServer].pRawValue = "SkyfailWebRadar";
		response.Headers.KnownHeaders[HttpHeaderServer].RawValueLength = (USHORT)strlen("SkyfailWebRadar");

		if (strcmp(req->pRawUrl, "/") == 0)
		{
			req->pRawUrl = "/static/index.htm";
			req->RawUrlLength = (USHORT)strlen("/static/index.htm");
		}

		if (strcmp(req->pRawUrl, "/info") == 0)
		{
			// Serialize response data
			JSON_Value *root_value = json_value_init_object();
			JSON_Object *root_object = json_value_get_object(root_value);

			JSON_Value *playersVal = json_value_init_array();
			JSON_Array *players = json_value_get_array(playersVal);
		
			for (size_t i = 0; i < ARRAYSIZE(entities); i++)
			{
				EntityInfo *ent = &entities[i];

				if (!ent->valid)
				{
					continue;
				}

				JSON_Value *playerValue = json_value_init_object();
				JSON_Object *player = json_value_get_object(playerValue);

				json_object_set_boolean(player, "local", ent->local);
				json_object_set_boolean(player, "alive", ent->lifestate == 0 ? 1 : 0);
				json_object_set_number(player, "health", (double)ent->health);
				json_object_set_number(player, "team", (double)ent->team);
				json_object_set_number(player, "origin_x", (double)ent->origin[0]);
				json_object_set_number(player, "origin_y", (double)ent->origin[1]);
				// json_object_set_number(player, "origin_z", (double)ent->origin[2]);
				json_object_set_number(player, "forward_x", (double)ent->origin_forward[0]);
				json_object_set_number(player, "forward_y", (double)ent->origin_forward[1]);
				//json_object_set_number(player, "forward_z", (double)ent->origin_forward[2]);
				json_object_set_number(player, "viewangle_x", (double)ent->viewAngles[0]);
				json_object_set_number(player, "viewangle_y", (double)ent->viewAngles[1]);
				json_object_set_string(player, "name", ent->name);
				json_object_set_number(player, "index", (double)i);

				json_array_append_value(players, playerValue);
			}

			char *serializedString = NULL;
			json_object_set_string(root_object, "map", mapName);
			json_object_set_value(root_object, "players", playersVal);

			serializedString = json_serialize_to_string_pretty(root_value);
			ULONG serializedLen = (USHORT)strlen(serializedString);
		
			// Add response data
			dataChunk.DataChunkType = HttpDataChunkFromMemory;
			dataChunk.FromMemory.pBuffer = serializedString;
			dataChunk.FromMemory.BufferLength = serializedLen;

			response.Headers.KnownHeaders[HttpHeaderContentType].pRawValue = contentType;
			response.Headers.KnownHeaders[HttpHeaderContentType].RawValueLength = (USHORT)strlen(contentType);
			status = HttpSendHttpResponse(reqQueueHandle, req->RequestId, 0, &response, 0, NULL, NULL, 0, NULL, NULL);

			// Make sure to free previously allocated memory
			json_free_serialized_string(serializedString);

			json_value_free(root_value);
		}
		else if (strncmp(req->pRawUrl, "/static/", strlen("/static/")) == 0)
		{
			const char *file = req->pRawUrl + strlen("/static/");
			if (file[0] == 0 || strstr(file, "..") != NULL || strpbrk(file, "/\\") != NULL)
			{
				response.StatusCode = 500;
				response.pReason = "Internal server error";

				dataChunk.DataChunkType = HttpDataChunkFromMemory;
				dataChunk.FromMemory.pBuffer = "Internal server error";
				dataChunk.FromMemory.BufferLength = (USHORT)strlen("Internal server error");

				status = HttpSendHttpResponse(reqQueueHandle, req->RequestId, 0, &response, 0, NULL, NULL, 0, NULL, NULL);
			}
			else
			{
				char localPath[MAX_PATH];
				memset(&localPath, 0, sizeof(localPath));
				GetCurrentDirectoryA(ARRAYSIZE(localPath), localPath);
				localPath[strlen(localPath)] = '\\';

				strcat_s(localPath, sizeof(localPath), "static\\");
				strcat_s(localPath, sizeof(localPath), file);

				if (GetFileAttributesA(localPath) == INVALID_FILE_ATTRIBUTES)
				{
					response.StatusCode = 404;
					response.pReason = "Not found";

					dataChunk.DataChunkType = HttpDataChunkFromMemory;
					dataChunk.FromMemory.pBuffer = "404 Not Found";
					dataChunk.FromMemory.BufferLength = (USHORT)strlen("404 Not Found");

					status = HttpSendHttpResponse(reqQueueHandle, req->RequestId, 0, &response, 0, NULL, NULL, 0, NULL, NULL);
				}
				else
				{
					char *extension = strrchr(file, '.');
					if (extension == NULL || extension >= file + strlen(file))
					{
						extension = "txt";
					}

					char contentType[64];
					memset(&contentType, 0, sizeof(contentType));
					LookupMimeType(extension, contentType);

					dataChunk.DataChunkType = HttpDataChunkFromFileHandle;
					dataChunk.FromFileHandle.FileHandle = CreateFileA(localPath, FILE_READ_ACCESS, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
					dataChunk.FromFileHandle.ByteRange.StartingOffset.QuadPart = 0;
					dataChunk.FromFileHandle.ByteRange.Length.QuadPart = (ULONGLONG)GetFileSize(dataChunk.FromFileHandle.FileHandle, NULL);

					response.Headers.KnownHeaders[HttpHeaderContentType].pRawValue = contentType;
					response.Headers.KnownHeaders[HttpHeaderContentType].RawValueLength = (USHORT)strlen(contentType);
					status = HttpSendHttpResponse(reqQueueHandle, req->RequestId, 0, &response, 0, NULL, NULL, 0, NULL, NULL);

					CloseHandle(dataChunk.FromFileHandle.FileHandle);
				}
			}
		}

		if (status != NO_ERROR)
		{
			printf("[WebRadar by Skyfail] HttpSendHttpResponse() returned error: %i\n", status);
			Sleep(5);
			continue;
		}
	}

	CloseHandle(reqQueueHandle);
	HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);

	free(req);

	ExitThread(0);
	return 0;
}

VOID ActionWebRadar(_Inout_ PPCILEECH_CONTEXT ctx)
{
	GameOffsets offsets;

	memset(&mapName, 0, sizeof(mapName));
	memset(&entities, 0, sizeof(entities));
	memset(&offsets, 0, sizeof(offsets));

	// Load hazedumper offsets
	printf("[WebRadar by Skyfail] Loading offsets\n");
	
	JSON_Value *root_value = json_parse_file("hazedumper/csgo.min.json");
	if (!root_value)
	{
		printf("[WebRadar by Skyfail] Failed to open csgo.min.json make sure to recursively clone this repository\n");
		return;
	}

	JSON_Object *base_object = json_value_get_object(root_value);
	JSON_Object *signatures = json_object_get_object(base_object, "signatures");
	JSON_Object *netvars = json_object_get_object(base_object, "netvars");

	offsets.GO_EntityList = (DWORD)json_object_get_number(signatures, "dwEntityList");
	offsets.GO_ViewMatrix = (DWORD)json_object_get_number(signatures, "dwViewMatrix");
	offsets.GO_ClientState = (DWORD)json_object_get_number(signatures, "dwClientState");
	offsets.GO_ClientState_LocalPlayer = (DWORD)json_object_get_number(signatures, "dwClientState_GetLocalPlayer");
	offsets.GO_ClientState_ViewAngle = (DWORD)json_object_get_number(signatures, "dwClientState_ViewAngles");
	offsets.GO_ClientState_Map = (DWORD)json_object_get_number(signatures, "dwClientState_Map");
	offsets.GO_ClientState_PlayerInfo = (DWORD)json_object_get_number(signatures, "dwClientState_PlayerInfo");

	offsets.GO_Lifestate = (DWORD)json_object_get_number(netvars, "m_lifeState");
	offsets.GO_AngEyeAngle = 0xB274;
	offsets.GO_Dormant = 0xE9;
	offsets.GO_Team = (DWORD)json_object_get_number(netvars, "m_iTeamNum");
	offsets.GO_Health = (DWORD)json_object_get_number(netvars, "m_iHealth");
	offsets.GO_Origin = (DWORD)json_object_get_number(netvars, "m_vecOrigin");

	json_value_free(root_value);

	// Launch webserver thread
	g_webRadarExitEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	SetConsoleCtrlHandler(ControlHandler, TRUE);

	printf("[WebRadar by Skyfail] Launching HTTP server\n");
	g_webRadarWSThread = CreateThread(NULL, 0, WebServerThread, NULL, 0, NULL);

	printf("[WebRadar by Skyfail] Initializing VMM context\n");

	if (!VmmProcInitialize(ctx)) {
		printf("[WebRadar by Skyfail] Failed to initialize\n");
		return;
	}

	PVMM_CONTEXT ctxVmm = (PVMM_CONTEXT)ctx->hVMM;
	PVMM_PROCESS targetProcess = NULL;
	QWORD pEngineDll = 0;
	QWORD pClientDll = 0;

	BOOLEAN readSuccess = TRUE;

	EnterCriticalSection(&ctxVmm->MasterLock);

	while (!g_webRadarExit)
	{
		Sleep(10);

		DWORD64 now = GetTickCount64();

		// Get target process
		if (targetProcess == NULL)
		{
			VmmCacheClear(ctxVmm, TRUE, TRUE);

			LeaveCriticalSection(&ctxVmm->MasterLock);
			Sleep(500); // sleep to let the cache thread acquire the critical section
			EnterCriticalSection(&ctxVmm->MasterLock);

			pEngineDll = 0;
			pClientDll = 0;
			targetProcess = VmmProcessGetByName(ctxVmm, "csgo.exe");
			
			if (targetProcess == NULL)
			{
				continue;
			}
		}

		// Get required modules
		if (pEngineDll == 0 || pClientDll == 0)
		{
			VmmCacheClear(ctxVmm, TRUE, TRUE);
			VmmProc_InitializeModuleNames(ctxVmm, targetProcess);

			for (size_t i = 0; i < targetProcess->cModuleMap; i++)
			{
				if (!_strnicmp(targetProcess->pModuleMap[i].szName, "engine.dll", sizeof(targetProcess->pModuleMap[i].szName)))
				{
					pEngineDll = targetProcess->pModuleMap[i].BaseAddress;
				}
				else if (!_strnicmp(targetProcess->pModuleMap[i].szName, "client_panorama.dll", sizeof(targetProcess->pModuleMap[i].szName)))
				{
					pClientDll = targetProcess->pModuleMap[i].BaseAddress;
				}

				if (pClientDll && pEngineDll)
				{
					printf("[WebRadar by Skyfail] client_panorama.dll: 0x%p\n", pClientDll);
					printf("[WebRadar by Skyfail] engine.dll: 0x%p\n", pEngineDll);

					break;
				}
			}
		}

		if (pEngineDll == 0 || pClientDll == 0)
		{
			// Modules not loaded yet

			VmmCacheClear(ctxVmm, TRUE, TRUE);
			LeaveCriticalSection(&ctxVmm->MasterLock);
			Sleep(5000);
			EnterCriticalSection(&ctxVmm->MasterLock);
			continue;
		}

		if (!readSuccess)
		{
			printf("[WebRadar by Skyfail] Read failed, flushing TLB cache\n");
		}

		// Clear memory cache
		// Maybe use VmmReadEx with VMM_FLAG_NOCACHE, but this way it allows us to be lazy about
		// memory reading as pages will be cached by pcileech, causing no device communication to
		// be required when doing multiple small reads instead of one big
		// Example: read(entity + 0x50) + read(entity + 0x100) does not have to be
		// combined
		VmmCacheClear(ctxVmm, !readSuccess, TRUE);
		readSuccess = TRUE;

		// Read data
	
		DWORD dwClientState = 0;

		if (!VmmRead(ctxVmm, targetProcess, pEngineDll + offsets.GO_ClientState, (PBYTE)&dwClientState, sizeof(dwClientState)) ||
			!VmmRead(ctxVmm, targetProcess, (QWORD)dwClientState, (PBYTE)&clientStateBuffer, sizeof(clientStateBuffer)))
		{
			// If the read failed our process might not be valid anymore
			targetProcess = NULL;
			memset(&entities, 0, sizeof(entities));
			memset(&clientStateBuffer, 0, sizeof(clientStateBuffer));
			memset(&mapName, 0, sizeof(mapName));
			continue;
		}

		memcpy(mapName, (const void *)&clientStateBuffer[offsets.GO_ClientState_Map], sizeof(mapName));

		if (mapName[0] == 0)
		{
			// No map loaded, nothing to do for us
			VmmCacheClear(ctxVmm, TRUE, TRUE);
			memset(&entities, 0, sizeof(entities));
			continue;
		}

		DWORD dwPlayerinfo = *(DWORD*)(&clientStateBuffer[offsets.GO_ClientState_PlayerInfo]);
		readSuccess = readSuccess && VmmRead(ctxVmm, targetProcess, dwPlayerinfo + 0x40, (PBYTE)&dwPlayerinfo, sizeof(dwPlayerinfo));
		readSuccess = readSuccess && VmmRead(ctxVmm, targetProcess, dwPlayerinfo + 0xC, (PBYTE)&dwPlayerinfo, sizeof(dwPlayerinfo));

		unsigned int localPlayer = *(unsigned int *)(&clientStateBuffer[offsets.GO_ClientState_LocalPlayer]);

		for (unsigned int i = 0u; i < ARRAYSIZE(entities); i++)
		{
			EntityInfo *ent = &entities[i];

			DWORD entityBase = (DWORD)pClientDll + offsets.GO_EntityList + (i * 0x10);
			readSuccess = readSuccess && VmmRead(ctxVmm, targetProcess, entityBase, (PBYTE)&entityBase, sizeof(entityBase));

			if (entityBase == 0)
			{
				ent->valid = 0;
				continue;
			}

			if (i == localPlayer)
			{
				ent->local = 1;

				memcpy(&ent->viewAngles, (void *)&clientStateBuffer[offsets.GO_ClientState_ViewAngle], sizeof(&ent->viewAngles)); // use viewangle from clientstate
			}
			else
			{
				ent->local = 0;

				readSuccess = readSuccess && VmmRead(ctxVmm, targetProcess, entityBase + offsets.GO_AngEyeAngle, (PBYTE)&ent->viewAngles, sizeof(ent->viewAngles)); // use angEyeAngle netvar
			}

			unsigned char isDormant = 0;
			readSuccess = readSuccess && VmmRead(ctxVmm, targetProcess, entityBase + offsets.GO_Lifestate, (PBYTE)&ent->lifestate, sizeof(ent->lifestate));
			readSuccess = readSuccess && VmmRead(ctxVmm, targetProcess, entityBase + offsets.GO_Dormant, (PBYTE)&isDormant, sizeof(isDormant));

			if (isDormant)
			{
				// No need to read outdated information
				ent->valid = 0;
				continue;
			}

			ent->valid = 1;

			readSuccess = readSuccess && VmmRead(ctxVmm, targetProcess, entityBase + offsets.GO_Team, (PBYTE)&ent->team, sizeof(ent->team));
			readSuccess = readSuccess && VmmRead(ctxVmm, targetProcess, entityBase + offsets.GO_Health, (PBYTE)&ent->health, sizeof(ent->health));
			readSuccess = readSuccess && VmmRead(ctxVmm, targetProcess, entityBase + offsets.GO_Origin, (PBYTE)&ent->origin, sizeof(ent->origin));

			DWORD dwPlayerInfoEntry = 0;
			readSuccess = readSuccess && VmmRead(ctxVmm, targetProcess, dwPlayerinfo + 0x28 + i * 0x34, (PBYTE)&dwPlayerInfoEntry, sizeof(dwPlayerInfoEntry));
			readSuccess = readSuccess && VmmRead(ctxVmm, targetProcess, dwPlayerInfoEntry + 0x10, (PBYTE)&ent->name, sizeof(ent->name) - 1);

			// quick maths
			float forward[3];
			float right[3];
			float up[3];

			AngleVectors(ent->viewAngles, forward, right, up);

			ent->origin_forward[0] = ent->origin[0] + (forward[0] * 256.f + right[0] + up[0]);
			ent->origin_forward[1] = ent->origin[1] + (forward[1] * 256.f + right[1] + up[1]);
			ent->origin_forward[2] = ent->origin[2] + (forward[2] * 256.f + right[2] + up[2]);
		}
	}

	LeaveCriticalSection(&ctxVmm->MasterLock);
	VmmClose(ctx);
	SetEvent(g_webRadarExitEvent);
}