// statuscodes_common.h : status codes for non-windows kernel implants.
//
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __STATUSCODES_H__
#define __STATUSCODES_H__

#define STATUS_SUCCESS						0x00000000
#define STATUS_FAIL_BASE					0xf0000000
#define STATUS_FAIL_FUNCTION_LOOKUP			0xf0000001
#define STATUS_FAIL_FILE_CANNOT_OPEN		0xf0000002
#define STATUS_FAIL_FILE_SIZE				0xf0000003
#define STATUS_FAIL_INPPARAMS_BAD			0xf0000004
#define STATUS_FAIL_ACTION					0xf0000005
#define STATUS_FAIL_SIGNATURE_NOT_FOUND		0xf0000006
#define STATUS_FAIL_OUTOFMEMORY				0xf0000007
#define STATUS_FAIL_MEMORYMAP_NOT_FOUND		0xf0000008
#define STATUS_FAIL_FILE_READWRITE			0xf0000009
#define STATUS_FAIL_PCILEECH_CORE			0xf000000a
#define STATUS_FAIL_NOT_IMPLEMENTED			0xf000000b

#define KMD_CMD_VOID						0xffff
#define KMD_CMD_COMPLETED					0
#define KMD_CMD_READ						1
#define KMD_CMD_WRITE						2
#define KMD_CMD_TERMINATE					3
#define KMD_CMD_MEM_INFO					4
#define KMD_CMD_EXEC						5
#define KMD_CMD_READ_VA						6
#define KMD_CMD_WRITE_VA					7
#define KMD_CMD_EXEC_EXTENDED				8

#endif /* __STATUSCODES_H__ */
