// pcileech_gensig.c : kernel module signature generator for PCILeech
//
// PCILeech require code pages from the ntfs.sys kernel driver to hi-jack the
// execution flow in Windows 10. To avoid copyright infringement the end user
// must create the kmd signature files together with supported ntfs.sys files
//
// (c) Ulf Frisk, 2016
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

#define NUMBER_OF_SIGNATURES	15

const SIGNATURE SIGNATURES[NUMBER_OF_SIGNATURES] = {
	{
		.szSignatureInfoDisplay = "ntfs.sys signed on 2014-10-15 (Windows 8.1 x64)",
		.szFileName = "win8x64_ntfs_20141015.kmd",
		.szSignatureInfo = "# ntfs.sys signed on 2014-10-15 (MJ_CREATE)",
		.dwOffset1 = 0xd3000,
		.dwOffset2 = 0x4a000,
		.szHash1 = "1ac5c0df47e153480fc49bb3687df84473168bd65b4bb58ab3885f47a6116d1b",
		.szHash2 = "a65cf907fb5aecb5d2a256b8a49706469025c740a896e3a8d0b27537f6fbbc6f",
		.szSignatureData = ",d3920,DEFAULT_WINX64_STAGE1,4ad80,DEFAULT_WINX64_STAGE2,0,DEFAULT_WINX64_STAGE3,0,010003804a000100210001800a0003800c00018054010100080000001b00018001000000"
	},
	{
		.szSignatureInfoDisplay = "ntfs.sys signed on 2015-12-30 (Windows 8.1 x64)",
		.szFileName = "win8x64_ntfs_20151230.kmd",
		.szSignatureInfo = "# ntfs.sys signed on 2016-12-30 (MJ_CREATE)",
		.dwOffset1 = 0xd1000,
		.dwOffset2 = 0x49000,
		.szHash1 = "65b0b0cf8a508d20cb6906fe4fea9e10a1c4398c4f5c4bbbc366383e06572695",
		.szHash2 = "6387547a0a12d5814681f0ed5fc47cd6aa31e8b4428bee8cf18081bb8ab57d67",
		.szSignatureData = ",d1190,DEFAULT_WINX64_STAGE1,49d80,DEFAULT_WINX64_STAGE2,0,DEFAULT_WINX64_STAGE3,0,0100038049000100200001800a0003800c00018054010100080000001b00018001000000"
	},
	{
		.szSignatureInfoDisplay = "ntfs.sys signed on 2016-02-23 (Windows 10 x64)",
		.szFileName = "win10x64_ntfs_20160223.kmd",
		.szSignatureInfo = "# ntfs.sys signed on 2016-02-23 (MJ_CREATE)",
		.dwOffset1 = 0xca000,
		.dwOffset2 = 0x4f000,
		.szHash1 = "0592b0387ec943697dd0f552564e087c8dd385b25db565ffb11fa6bd1cf10b14",
		.szHash2 = "218325e192e8146883054359e984376be0d13486c05d31ab4a23ff834ebb623e",
		.szSignatureData = ",ca770,DEFAULT_WINX64_STAGE1,4fe38,DEFAULT_WINX64_STAGE2,0,DEFAULT_WINX64_STAGE3,0,010003804f00010023000180080003801400018066010100050000001d00018001000000"
	},
	{
		.szSignatureInfoDisplay = "ntfs.sys signed on 2015-12-01 (Windows 10 x64)",
		.szFileName = "win10x64_ntfs_20151201.kmd",
		.szSignatureInfo = "# ntfs.sys signed on 2015-12-01 (MJ_CREATE)",
		.dwOffset1 = 0xc5000,
		.dwOffset2 = 0x4d000,
		.szHash1 = "3bac25cd0e0cfc45dcb7efa67200e4800ffe8278fd3249a382bd4403f3309756",
		.szHash2 = "fcc23d38f37141010e2985cc2c7babc8796c36e85b820d77d5c6b4fe66c6caf0",
		.szSignatureData = ",c51e0,DEFAULT_WINX64_STAGE1,4dd30,DEFAULT_WINX64_STAGE2,0,DEFAULT_WINX64_STAGE3,0,010003804d00010022000180080003801400018061010100050000001d00018001000000"
	},
	{
		.szSignatureInfoDisplay = "ntfs.sys signed on 2015-07-30 (Windows 10 x64)",
		.szFileName = "win10x64_ntfs_20150730.kmd",
		.szSignatureInfo = "# ntfs.sys signed on 2015-07-30 (MJ_CREATE)",
		.dwOffset1 = 0xc4000,
		.dwOffset2 = 0x4d000,
		.szHash1 = "cd135fc58b88f96abff0ddb1207cb9e84e5b2f040607d0500de0018d32ad1572",
		.szHash2 = "2cfd3b597b341c056a30a186b1347d82d211cf1319464ad1f13cfa525891e409",
		.szSignatureData = ",c4dc0,DEFAULT_WINX64_STAGE1,4dd20,DEFAULT_WINX64_STAGE2,0,DEFAULT_WINX64_STAGE3,0,010003804d00010022000180080003801400018061010100050000001d00018001000000"
	},
	{
		.szSignatureInfoDisplay = "ntfs.sys signed on 2015-07-17 (Windows 10 x64)",
		.szFileName = "win10x64_ntfs_20150717.kmd",
		.szSignatureInfo = "# ntfs.sys signed on 2015-07-17 (MJ_CREATE)",
		.dwOffset1 = 0x1f000,
		.dwOffset2 = 0x4d000,
		.szHash1 = "9ac57fa7e7d8d92e066c6ce9c76c82fc3afccc1e6211eb4d9b03ea79c8a70b3b",
		.szHash2 = "2cfd3b597b341c056a30a186b1347d82d211cf1319464ad1f13cfa525891e409",
		.szSignatureData = ",1fb90,DEFAULT_WINX64_STAGE1,4dd20,DEFAULT_WINX64_STAGE2.bin,0,DEFAULT_WINX64_STAGE3,0,010003804d00010022000180080003801400018061010100050000001d00018001000000"
	},
	{
		.szSignatureInfoDisplay = "ntfs.sys signed on 2015-07-10 (Windows 10 x64)",
		.szFileName = "win10x64_ntfs_20150710.kmd",
		.szSignatureInfo = "# ntfs.sys signed on 2015-07-10 (MJ_CREATE)",
		.dwOffset1 = 0xc4000,
		.dwOffset2 = 0x4d000,
		.szHash1 = "a8a4e0d7963c2652226064c674b7ed38b1f84a8661e8f63663783dafb83271fc",
		.szHash2 = "95964341fb3121baf303037a3796bd98c4167261ead9a4b4587a31e8a546dda1",
		.szSignatureData = ",c4ec0,DEFAULT_WINX64_STAGE1,4dd20,DEFAULT_WINX64_STAGE2,0,DEFAULT_WINX64_STAGE3,0,010003804d00010022000180080003801400018062010100050000001d000180"
	},
	{
		.szSignatureInfoDisplay = "ntfs.sys signed on 2016-03-29 (Windows 10 x64)",
		.szFileName = "win10x64_ntfs_20160329.kmd",
		.szSignatureInfo = "# ntfs.sys signed on 2016-03-29 (MJ_CREATE)",
		.dwOffset1 = 0xca000,
		.dwOffset2 = 0x4f000,
		.szHash1 = "d091d4d5452ef388c6ff22780922f3f944a8439e5109dae207151f7f4fd23991",
		.szHash2 = "84b0ffd20272e8757023975ef52132c9e82df7e81da537cf436407733a1f4957",
		.szSignatureData = ",ca770,DEFAULT_WINX64_STAGE1,4fe38,DEFAULT_WINX64_STAGE2,0,DEFAULT_WINX64_STAGE3,0,010003804f00010023000180080003801400018066010100050000001d000180"
	},
	{
		.szSignatureInfoDisplay = "ntfs.sys signed on 2016-07-16 (Windows 10 x64) [10.0.14393.0]",
		.szFileName = "win10x64_ntfs_20160716_14393.kmd",
		.szSignatureInfo = "# ntfs.sys signed on 2016-07-16 (MJ_CREATE) [10.0.14393.0]",
		.dwOffset1 = 0xf6000,
		.dwOffset2 = 0x53000,
		.szHash1 = "5cadebe69115cc66e07f7d1e3f97ad0522840c1c648d33b37d8fe9f9a36ae413",
		.szHash2 = "04d501dae7a097b649edc0bb68dc02036e31ece8c30ee48ab24ac8fb3095fe46",
		.szSignatureData = ",f6b70,DEFAULT_WINX64_STAGE1,53e38,DEFAULT_WINX64_STAGE2,0,DEFAULT_WINX64_STAGE3,0,0100038053000100240001800800038014000180760101000500000022000180"
	},
	{
		.szSignatureInfoDisplay = "ntfs.sys signed on 2016-08-03 (Windows 10 x64) [10.0.10240.17071]",
		.szFileName = "win10x64_ntfs_20160803_10240.kmd",
		.szSignatureInfo = "# ntfs.sys signed on 2016-08-03 (MJ_CREATE) [10.0.10240.17071]",
		.dwOffset1 = 0xc5000,
		.dwOffset2 = 0x4d000,
		.szHash1 = "c80d2ff8c58669a539ecc636103a73eb8c65a4568c81d6627a9b14f428d0207f",
		.szHash2 = "bafe68ca0561d5137504c53360cdec01b8d522eade7e558b90231fdaf53a66a5",
		.szSignatureData = ",c51e0,DEFAULT_WINX64_STAGE1,4de38,DEFAULT_WINX64_STAGE2,0,DEFAULT_WINX64_STAGE3,0,010003804d00010022000180080003801400018061010100050000001d00018001000000"
	},
	{
		.szSignatureInfoDisplay = "ntfs.sys signed on 2016-08-20 (Windows 10 x64) [10.0.14393.103]",
		.szFileName = "win10x64_ntfs_20160820_14393.kmd",
		.szSignatureInfo = "# ntfs.sys signed on 2016-08-20 (MJ_CREATE) [10.0.14393.103]",
		.dwOffset1 = 0xf6000,
		.dwOffset2 = 0x53000,
		.szHash1 = "c6b3a2c6a9d19798b9974704e551a4798d0f2098279a67924eebcb03cee07590",
		.szHash2 = "04d501dae7a097b649edc0bb68dc02036e31ece8c30ee48ab24ac8fb3095fe46",
		.szSignatureData = ",f6b70,DEFAULT_WINX64_STAGE1,53e38,DEFAULT_WINX64_STAGE2,0,DEFAULT_WINX64_STAGE3,0,0100038053000100240001800800038014000180760101000500000022000180"
	},
	{
		.szSignatureInfoDisplay = "ntfs.sys signed on 2016-09-07 (Windows 10 x64) [10.0.14393.187]",
		.szFileName = "win10x64_ntfs_20160907_14393.kmd",
		.szSignatureInfo = "# ntfs.sys signed on 2016-09-07 (MJ_CREATE) [10.0.14393.187]",
		.dwOffset1 = 0xf7000,
		.dwOffset2 = 0x53000,
		.szHash1 = "e6f94244f8ab0cb45a2509679a15ebbb933c936c23d0c600116124b4aebf67d5",
		.szHash2 = "04d501dae7a097b649edc0bb68dc02036e31ece8c30ee48ab24ac8fb3095fe46",
		.szSignatureData = ",f78e0,DEFAULT_WINX64_STAGE1,53e38,DEFAULT_WINX64_STAGE2,0,DEFAULT_WINX64_STAGE3,0,0100038053000100240001800800038014000180760101000500000022000180"
	},
	{
		.szSignatureInfoDisplay = "ntfs.sys signed on 2016-11-02 (Windows 10 x64) [10.0.14393.447]",
		.szFileName = "win10x64_ntfs_20161102_14393.kmd",
		.szSignatureInfo = "# ntfs.sys signed on 2016-11-02 (MJ_CREATE) [10.0.14393.447]",
		.dwOffset1 = 0xf7000,
		.dwOffset2 = 0x53000,
		.szHash1 = "e044cff9460a778a04e75081dbfa7441bd1b142a9798a2c978c28612f33682c3",
		.szHash2 = "04d501dae7a097b649edc0bb68dc02036e31ece8c30ee48ab24ac8fb3095fe46",
		.szSignatureData = ",f78e0,DEFAULT_WINX64_STAGE1,53e38,DEFAULT_WINX64_STAGE2,0,DEFAULT_WINX64_STAGE3,0,0100038053000100240001800800038014000180760101000500000022000180"
	},
	{
		.szSignatureInfoDisplay = "ntfs.sys signed on 2017-03-04 (Windows 10 x64) [10.0.14393.953]",
		.szFileName = "win10x64_ntfs_20170304_14393.kmd",
		.szSignatureInfo = "# ntfs.sys signed on 2017-03-04 (MJ_CREATE) [10.0.14393.953]",
		.dwOffset1 = 0xf7000,
		.dwOffset2 = 0x53000,
		.szHash1 = "228a30faacc59dd6b41fab0a5eab73e30ee774fde51e4ee30a8501f81cfe8e54",
		.szHash2 = "6c4742133e9409255abb3c3d21eca24e7f303b4968e703acfe4f3e3f4e39ce36",
		.szSignatureData = ",f78f0,DEFAULT_WINX64_STAGE1,53e38,DEFAULT_WINX64_STAGE2,0,DEFAULT_WINX64_STAGE3,0,0100038053000100240001800800038014000180760101000500000022000180"
	},
	{
		.szSignatureInfoDisplay = "ntfs.sys signed on 2017-03-18 (Windows 10 x64) [10.0.15063.0]",
		.szFileName = "win10x64_ntfs_20170318_15063.kmd",
		.szSignatureInfo = "# ntfs.sys signed on 2017-03-18 (MJ_CREATE) [10.0.15063.0]",
		.dwOffset1 = 0xcb000,
		.dwOffset2 = 0x55000,
		.szHash1 = "f190019c227cbbbd19e9ed6fb840e9838afab598b9ac23a3008d60fb3b139845",
		.szHash2 = "b48ce1f64615ae1e734d36f94c0c41cce4e5f6caab58df0121ca6f27e8569599",
		.szSignatureData = ",cb2e0,DEFAULT_WINX64_STAGE1,55e38,DEFAULT_WINX64_STAGE2,0,DEFAULT_WINX64_STAGE3,0,01000380550001002800018008000380150001807f0101000500000023000180"
	}
};

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

VOID ShowInfo()
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
	for(DWORD i = 0; i < NUMBER_OF_SIGNATURES; i++) {
		printf("%s\n", SIGNATURES[i].szSignatureInfoDisplay);
	}
	printf("\n");
}

int main(_In_ int argc, _In_ char* argv[])
{
	BOOL result;
	PSIGNATURE pS;
	HMODULE hModule;
	DWORD i, dwSizeMax;
	if(argc != 2) {
		ShowInfo();
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
	for(i = 0; i < sizeof(SIGNATURES) / sizeof(SIGNATURE); i++) {
		pS = SIGNATURES + i;
		if(pS->dwOffset1 > dwSizeMax || pS->dwOffset2 > dwSizeMax) {
			continue;
		}
		if(!Util_SHA256CMP((PBYTE)hModule + pS->dwOffset1, pS->szHash1)) {
			continue;
		}
		if(!Util_SHA256CMP((PBYTE)hModule + pS->dwOffset2, pS->szHash2)) {
			continue;
		}
		result = WriteSignatureFile(pS, (PBYTE)hModule + pS->dwOffset1, (PBYTE)hModule + pS->dwOffset2);
		if(result) {
			printf("pcileech_gensig: successfully wrote signatute to file: %s\n\n", pS->szFileName);
			return 0;
		} else {
			printf("pcileech_gensig: failed! failed writing to file: %s\n\n", pS->szFileName);
			return 1;
		}
	}
	printf("pcileech_gensig: failed! no signature matches file: %s\n\n", argv[1]);
	return 1;
}
