// pcileech_gensig.c : kernel module signature generator for PCILeech
//
// PCILeech require code pages from the ntfs.sys kernel driver to hi-jack the
// execution flow in Windows 10. To avoid copyright infringement the end user
// must create the kmd signature files together with supported ntfs.sys files
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
// Github: github.com/ufrisk/pcileech
//
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "bcrypt.lib")

typedef struct tdSIGNATURE{
	DWORD dwOffset1;
	DWORD dwOffset2;
	LPSTR szHash1;
	LPSTR szHash2;
	LPSTR szFileName;
	LPSTR szSignatureInfoDisplay;
	LPSTR szSignatureInfo;
	LPSTR szSignatureData;
} SIGNATURE, *PSIGNATURE;

#define MAX_SIGNATURES 64

VOID Util_GetFileInDirectory(_Out_ CHAR szPath[MAX_PATH], _In_ LPSTR szFileName)
{
	SIZE_T i, cchFileName = strlen(szFileName);
	GetModuleFileNameA(NULL, (LPSTR)szPath, (DWORD)(MAX_PATH - cchFileName - 4));
	for(i = strlen(szPath) - 1; i > 0; i--) {
		if(szPath[i] == '/' || szPath[i] == '\\') {
			strcpy_s(&szPath[i + 1], MAX_PATH - i - 5, szFileName);
			return;
		}
	}
}

_Success_(return) BOOL Util_ParseSignatureLine(_In_ PSTR szLine, _In_ PSIGNATURE pSignature) {
	LPSTR szToken, szContext = NULL;
	SIZE_T i;
	if(!szLine || !strlen(szLine) || szLine[0] == '#') { return FALSE; }
	szToken = strtok_s(szLine, ";", &szContext);
	for(i = 0; i < 8; i++) {
		if(!szToken) { return FALSE; }
		switch(i) {
			case 0:
				pSignature->szSignatureInfoDisplay = szToken;
				break;
			case 1:
				pSignature->szFileName = szToken;
				break;
			case 2:
				pSignature->szSignatureInfo = szToken;
				break;
			case 3:
				pSignature->dwOffset1 = strtoul(szToken, NULL, 16);
				break;
			case 4:
				pSignature->dwOffset2 = strtoul(szToken, NULL, 16);
				break;
			case 5:
				pSignature->szHash1 = szToken;
				break;
			case 6:
				pSignature->szHash2 = szToken;
				break;
			case 7:
				pSignature->szSignatureData = szToken;
				break;
		}
		szToken = strtok_s(NULL, ";", &szContext);
	}
	return (i == 8);
}

VOID GetSignaturesFromConfigFile(_Out_ PSIGNATURE pSignatures, _Out_ PDWORD pcSignatures)
{
	PBYTE pbFile;
	DWORD cbFile;
	FILE *pFile;
	CHAR szFile[MAX_PATH];
	LPSTR szContext = NULL, szLine;
	*pcSignatures = 0;
	// 1: Open configuration file containing signatures
	pbFile = LocalAlloc(LMEM_ZEROINIT, 0x00100000);
	if(!pbFile) { return; }
	Util_GetFileInDirectory(szFile, "pcileech_gensig.cfg");
	if(fopen_s(&pFile, szFile, "rb") || !pFile) { goto error; }
	cbFile = (DWORD)fread(pbFile, 1, 0x00100000, pFile);
	fclose(pFile);
	if(!cbFile || (cbFile == 0x00100000)) { goto error; }
	// 2: Parse signature file on a per-line level
	szLine = strtok_s(pbFile, "\r\n", &szContext);
	while(szLine && (*pcSignatures < MAX_SIGNATURES)) {
		if(Util_ParseSignatureLine(szLine, &pSignatures[*pcSignatures])) {
			*pcSignatures = *pcSignatures + 1;
		}
		szLine = strtok_s(NULL, "\r\n", &szContext);
	}
error:
	;
	//LocalFree(pbFile); // buffer is leaked (is used by the tokenized fragments)
}

const LPSTR SIGNATURE_FILE_HEADER = \
"# PCILeech kernel module signature                                            \r\n" \
"# syntax(exactly one signature is only allowed) :                             \r\n" \
"#                                                                             \r\n" \
"# chunk[0] = <page_offset_stage1_signature>, <signature>                      \r\n" \
"# chunk[1] = <page_offset_stage2_siganture>, <signature>                      \r\n" \
"# chunk[2] = <shellcode1_module_RVA>, <stage1 shellcode*>                     \r\n" \
"# chunk[3] = <shellcode2_module_RVA>, <stage2 shellcode*>                     \r\n" \
"# chunk[4] = <NA>, <stage3 shellcode*>                                        \r\n" \
"# chunk[5] = <NA>, <Page Table signature of module>                           \r\n" \
"# *) shellcode can be given as hexascii, internal reference or file name.     \r\n" \
"#                                                                             \r\n";

VOID Util_SHA256(_In_ PBYTE pb, _In_ DWORD cb, _Out_ __bcount(32) PBYTE pbHash)
{
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
	BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
	BCryptHashData(hHash, pb, cb, 0);
	BCryptFinishHash(hHash, pbHash, 32, 0);
	BCryptDestroyHash(hHash);
	BCryptCloseAlgorithmProvider(hAlg, 0);
}

_Success_(return) BOOL Util_SHA256CMP(_In_ __bcount(4096) PBYTE pb, _In_ LPSTR szHash)
{
	BYTE pbHash1[32], pbHash2[32];
	DWORD cb = 32;
	Util_SHA256(pb, 4096, pbHash1);
	CryptStringToBinaryA(szHash, 0, CRYPT_STRING_HEXRAW, pbHash2, &cb, NULL, NULL);
	return 0 == memcmp(pbHash1, pbHash2, 32);
}

DWORD PEGetImageSize(_In_ HMODULE hModule)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	if(!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { return 0; }
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)hModule + dosHeader->e_lfanew);
	if(!ntHeader || ntHeader->Signature != IMAGE_NT_SIGNATURE) { return 0; }
	return ntHeader->OptionalHeader.SizeOfImage;
}

_Success_(return) BOOL WriteSignatureFile(_In_ PSIGNATURE pSignature, _In_ __bcount(4096) PBYTE pb1, _In_ __bcount(4096) PBYTE pb2)
{
	DWORD cbWritten, csz1 = 0x2001, csz2 = 0x2001;
	HANDLE hFile;
	BOOL result;
	CHAR sz[0x2001];
	hFile = CreateFileA(
		pSignature->szFileName,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if(!hFile) { return FALSE; }
	HRESULT hr = GetLastError();
	result =
		WriteFile(hFile, SIGNATURE_FILE_HEADER, (DWORD)strlen(SIGNATURE_FILE_HEADER), &cbWritten, NULL) &&
		WriteFile(hFile, pSignature->szSignatureInfo, (DWORD)strlen(pSignature->szSignatureInfo), &cbWritten, NULL) &&
		WriteFile(hFile, "\r\n0,", 4, &cbWritten, NULL) &&
		CryptBinaryToStringA(pb1, 4096, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, sz, &csz1) &&
		WriteFile(hFile, sz, 8192, &cbWritten, NULL) &&
		WriteFile(hFile, ",0,", 3, &cbWritten, NULL) &&
		CryptBinaryToStringA(pb2, 4096, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, sz, &csz2) &&
		WriteFile(hFile, sz, 8192, &cbWritten, NULL) &&
		WriteFile(hFile, pSignature->szSignatureData, (DWORD)strlen(pSignature->szSignatureData), &cbWritten, NULL);
	CloseHandle(hFile);
	return result;
}

VOID ShowInfo(_In_ PSIGNATURE pS, _In_ DWORD cS)
{
	printf(
		"The PCILeech signature generator  -  generate Windows kernel module signatures \n" \
		"===============================================================================\n" \
		"Syntax: pcileech_gensig <path_to_ntfs.sys>                                     \n" \
		"                                                                               \n" \
		"Some Windows kernel module signatures must be generated since they contain 8192\n" \
		"bytes of microsoft copyrighted code. In order to avoid copyright issues one has\n" \
		"to generate the signatures by themselves. Please start pcileech_gensig with the\n" \
		"path to the ntfs.sys file to generate the signature for.   The ntfs.sys file is\n" \
		"generally found at c:\\Windows\\System32\\drivers\\ntfs.sys. In order to generate a\n" \
		"a signature please run:  'pcileech_gensig.exe c:\\path_to_ntfs_sys\\ntfs.sys' and\n" \
		"a .kmd signature file will be created on success.                              \n" \
		"Supported ntfs.sys file versions:                                              \n" \
		"=================================                                              \n");
	for(DWORD i = 0; i < cS; i++) {
		printf("%s\n", pS[i].szSignatureInfoDisplay);
	}
	printf("\n");
}

int main(_In_ int argc, _In_ char* argv[])
{
	BOOL result;
	SIGNATURE pS[MAX_SIGNATURES];
	HMODULE hModule;
	DWORD i, dwSizeMax, cS;
	GetSignaturesFromConfigFile(pS, &cS);
	if(!cS) {
		printf("pcileech_gensig: failed! cannot load signatures from configuration file: pcileech_gensig.cfg\n\n");
		return 1;
	}
	if(argc != 2) {
		ShowInfo(pS, cS);
		return 1;
	}
	hModule = LoadLibraryA(argv[1]);
	if(!hModule) {
		printf("pcileech_gensig: failed! cannot load the file: %s\n\n", argv[1]);
		return 1;
	}
	dwSizeMax = PEGetImageSize(hModule);
	if(!dwSizeMax) {
		printf("pcileech_gensig: failed! cannot interpret the file: %s\n\n", argv[1]);
		return 1;
	}
	for(i = 0; i < cS; i++) {
		if(pS[i].dwOffset1 > dwSizeMax || pS[i].dwOffset2 > dwSizeMax) {
			continue;
		}
		if(!Util_SHA256CMP((PBYTE)hModule + pS[i].dwOffset1, pS[i].szHash1)) {
			continue;
		}
		if(!Util_SHA256CMP((PBYTE)hModule + pS[i].dwOffset2, pS[i].szHash2)) {
			continue;
		}
		result = WriteSignatureFile(&pS[i], (PBYTE)hModule + pS[i].dwOffset1, (PBYTE)hModule + pS[i].dwOffset2);
		if(result) {
			printf("pcileech_gensig: successfully wrote signatute to file: %s\n\n", pS[i].szFileName);
			return 0;
		} else {
			printf("pcileech_gensig: failed! failed writing to file: %s\n\n", pS[i].szFileName);
			return 1;
		}
	}
	printf("pcileech_gensig: failed! no signature matches file: %s\n\n", argv[1]);
	return 1;
}
