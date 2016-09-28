// statuscodes_common.h : status codes for non-windows kernel implants.
//
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __STATUSCODES_H__
#define __STATUSCODES_H__

#define STATUS_FAIL_FUNCTION_LOOKUP			0xf0000001
#define STATUS_FAIL_FILE_CANNOT_OPEN		0xf0000002
#define STATUS_FAIL_FILE_SIZE				0xf0000003
#define STATUS_FAIL_INPPARAMS_BAD			0xf0000004
#define STATUS_FAIL_ACTION					0xf0000005
#define STATUS_FAIL_SIGNATURE_NOT_FOUND		0xf0000006
#define STATUS_FAIL_OUTOFMEMORY				0xf0000007
#define STATUS_FAIL_MEMORYMAP_NOT_FOUND		0xf0000008
#define STATUS_FAIL_FILE_READWRITE			0xf0000009

#endif /* __STATUSCODES_H__ */
