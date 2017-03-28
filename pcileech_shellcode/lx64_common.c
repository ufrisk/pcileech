// lx64_common.c : support functions used by Linux x64 KMDs started by stage3 EXEC.
// Compatible with Linux x64.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "lx64_common.h"

BOOL _WriteLargeOutput_WaitForAck(PKMDDATA pk)
{
	PEXEC_IO pis = (PEXEC_IO)(pk->DMAAddrVirtual + EXEC_IO_DMAOFFSET_IS);
	PEXEC_IO pos = (PEXEC_IO)(pk->DMAAddrVirtual + EXEC_IO_DMAOFFSET_OS);
	while((pk->_op == KMD_CMD_EXEC_EXTENDED) && ((pis->magic != EXEC_IO_MAGIC) || (!pis->bin.fCompletedAck && (pis->bin.seqAck != pos->bin.seq)))) {
		SysVCall((QWORD)pk->fn[0] /* msleep */, 25);
	}
	return (pk->_op == KMD_CMD_EXEC_EXTENDED) && !pis->bin.fCompletedAck;
}

BOOL WriteLargeOutput_WaitNext(PKMDDATA pk)
{
	PEXEC_IO pos = (PEXEC_IO)(pk->DMAAddrVirtual + EXEC_IO_DMAOFFSET_OS);
	pos->magic = EXEC_IO_MAGIC;
	CacheFlush();
	pos->bin.seq++;
	pk->_op = KMD_CMD_EXEC_EXTENDED;
	return _WriteLargeOutput_WaitForAck(pk);
}

VOID WriteLargeOutput_Finish(PKMDDATA pk)
{
	PEXEC_IO pos = (PEXEC_IO)(pk->DMAAddrVirtual + EXEC_IO_DMAOFFSET_OS);
	WriteLargeOutput_WaitNext(pk);
	pk->dataOutExtraLength = 0;
	CacheFlush();
	pos->bin.fCompleted = TRUE;
	pos->bin.seq++;
	_WriteLargeOutput_WaitForAck(pk);
	pk->_op = KMD_CMD_EXEC;
}
