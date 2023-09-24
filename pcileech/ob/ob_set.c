// ob_set.c : implementation of object manager hashed value set functionality.
//
// The hashed value set (ObSet) provides thread safe efficient access to a set
// which is containing _NON_ZERO_ values (64-bit unsigned integers). The ObSet
// may hold a maximum capacity of 0x01000000 (~16M) entries - which are UNIQUE
// and _NON_ZERO_.
// The hashed value set (ObSet) guarantees order amongst values unless the
// function ObSet_Remove is called - in which order may change and on-going
// iterations of the set with ObSet_Get/ObSet_GetNext may fail.
// The ObSet is an object manager object and must be DECREF'ed when required.
//
// (c) Ulf Frisk, 2019-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "ob.h"
#include <stdio.h>

#define OB_SET_ENTRIES_DIRECTORY        0x100
#define OB_SET_ENTRIES_TABLE            0x80
#define OB_SET_ENTRIES_STORE            0x200
#define OB_SET_IS_VALID(p)              (p && (p->ObHdr._magic2 == OB_HEADER_MAGIC) && (p->ObHdr._magic1 == OB_HEADER_MAGIC) && (p->ObHdr._tag == OB_TAG_CORE_SET))
#define OB_SET_TABLE_MAX_CAPACITY       OB_SET_ENTRIES_DIRECTORY * OB_SET_ENTRIES_TABLE * OB_SET_ENTRIES_STORE
#define OB_SET_HASH_FUNCTION(v)         (13 * (v + _rotr16((WORD)v, 9) + _rotr((DWORD)v, 17) + _rotr64(v, 31)))

#define OB_SET_INDEX_DIRECTORY(i)       ((i >> 16) & (OB_SET_ENTRIES_DIRECTORY - 1))
#define OB_SET_INDEX_TABLE(i)           ((i >> 9) & (OB_SET_ENTRIES_TABLE - 1))
#define OB_SET_INDEX_STORE(i)           (i & (OB_SET_ENTRIES_STORE - 1))

typedef struct tdOB_SET_TABLE_ENTRY {
    union {
        PQWORD pValues;                 // ptr to QWORD[OB_SET_ENTRIES_STORE]
        QWORD _Filler;
    };
} OB_SET_TABLE_ENTRY, *POB_SET_TABLE_ENTRY;

typedef struct tdOB_SET_TABLE_DIRECTORY_ENTRY {
    union {
        POB_SET_TABLE_ENTRY pTable;     // ptr to OB_SET_TABLE_ENTRY[OB_SET_ENTRIES_TABLE]
        QWORD _Filler;
    };
} OB_SET_TABLE_DIRECTORY_ENTRY, *POB_SET_TABLE_DIRECTORY_ENTRY;

typedef struct tdOB_SET {
    OB ObHdr;
    SRWLOCK LockSRW;
    DWORD c;
    DWORD cHashMax;
    DWORD cHashGrowThreshold;
    BOOL fLargeMode;
    PDWORD pHashMapLarge;
    union {
        WORD pHashMapSmall[0x400];
        OB_SET_TABLE_DIRECTORY_ENTRY pDirectory[OB_SET_ENTRIES_DIRECTORY];
    };
    OB_SET_TABLE_ENTRY pTable0[OB_SET_ENTRIES_TABLE];
    QWORD pStore00[OB_SET_ENTRIES_STORE];
} OB_SET, *POB_SET;

#define OB_SET_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pvs, RetTp, RetValFail, fn) {     \
    if(!OB_SET_IS_VALID(pvs)) { return RetValFail; }                                    \
    RetTp retVal;                                                                       \
    AcquireSRWLockExclusive(&pvs->LockSRW);                                             \
    retVal = fn;                                                                        \
    ReleaseSRWLockExclusive(&pvs->LockSRW);                                             \
    return retVal;                                                                      \
}

#define OB_SET_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pvs, RetTp, RetValFail, fn) {      \
    if(!OB_SET_IS_VALID(pvs)) { return RetValFail; }                                    \
    RetTp retVal;                                                                       \
    AcquireSRWLockShared(&pvs->LockSRW);                                                \
    retVal = fn;                                                                        \
    ReleaseSRWLockShared(&pvs->LockSRW);                                                \
    return retVal;                                                                      \
}

/*
* Object Container object manager cleanup function to be called when reference
* count reaches zero.
* -- pObSet
*/
VOID _ObSet_ObCloseCallback(_In_ POB_SET pObSet)
{
    DWORD iDirectory, iTable;
    if(pObSet->fLargeMode) {
        for(iDirectory = 0; iDirectory < OB_SET_ENTRIES_DIRECTORY; iDirectory++) {
            if(!pObSet->pDirectory[iDirectory].pTable) { break; }
            for(iTable = 0; iTable < OB_SET_ENTRIES_TABLE; iTable++) {
                if(!pObSet->pDirectory[iDirectory].pTable[iTable].pValues) { break; }
                if(iDirectory || iTable) {
                    LocalFree(pObSet->pDirectory[iDirectory].pTable[iTable].pValues);
                }
            }
            if(iDirectory) {
                LocalFree(pObSet->pDirectory[iDirectory].pTable);
            }
        }
        LocalFree(pObSet->pHashMapLarge);
    } else {
        for(iTable = 1; iTable < OB_SET_ENTRIES_TABLE; iTable++) {
            if(!pObSet->pTable0[iTable].pValues) { break; }
            LocalFree(pObSet->pTable0[iTable].pValues);
        }
    }
}

/*
* Create a new hashed value set. A hashed value set (ObSet) provides atomic
* ways to store unique 64-bit (or smaller) numbers as a set.
* The ObSet is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- H
* -- hHeap
* -- return
*/
POB_SET ObSet_New(_In_opt_ VMM_HANDLE H)
{
    POB_SET pObSet = Ob_AllocEx(H, OB_TAG_CORE_SET, LMEM_ZEROINIT, sizeof(OB_SET), (OB_CLEANUP_CB)_ObSet_ObCloseCallback, NULL);
    if(!pObSet) { return NULL; }
    InitializeSRWLock(&pObSet->LockSRW);
    pObSet->c = 1;     // item zero is reserved - hence the initialization of count to 1
    pObSet->cHashMax = 0x400;
    pObSet->cHashGrowThreshold = 0x300;
    pObSet->pTable0[0].pValues = pObSet->pStore00;
    return pObSet;
}

QWORD _ObSet_GetValueFromIndex(_In_ POB_SET pvs, _In_ DWORD iValue)
{
    WORD iDirectory = OB_SET_INDEX_DIRECTORY(iValue);
    WORD iTable = OB_SET_INDEX_TABLE(iValue);
    WORD iValueStore = OB_SET_INDEX_STORE(iValue);
    if(!iValue || (iValue >= pvs->c)) { return 0; }
    return pvs->fLargeMode ?
        pvs->pDirectory[OB_SET_INDEX_DIRECTORY(iValue)].pTable[iTable].pValues[iValueStore] :
        pvs->pTable0[iTable].pValues[iValueStore];
}

VOID _ObSet_SetValueFromIndex(_In_ POB_SET pvs, _In_ DWORD iValue, _In_ QWORD qwValue)
{
    WORD iDirectory = OB_SET_INDEX_DIRECTORY(iValue);
    WORD iTable = OB_SET_INDEX_TABLE(iValue);
    WORD iValueStore = OB_SET_INDEX_STORE(iValue);
    if(pvs->fLargeMode) {
        pvs->pDirectory[iDirectory].pTable[iTable].pValues[iValueStore] = qwValue;
    } else {
        pvs->pTable0[iTable].pValues[iValueStore] = qwValue;
    }
}

DWORD _ObSet_GetIndexFromHash(_In_ POB_SET pvs, _In_ DWORD iHash)
{
    return pvs->fLargeMode ? pvs->pHashMapLarge[iHash] : pvs->pHashMapSmall[iHash];
}

VOID _ObSet_SetHashIndex(_In_ POB_SET pvs, _In_ DWORD iHash, _In_ DWORD iValue)
{
    if(pvs->fLargeMode) {
        pvs->pHashMapLarge[iHash] = iValue;
    } else {
        pvs->pHashMapSmall[iHash] = (WORD)iValue;
    }
}

VOID _ObSet_InsertHash(_In_ POB_SET pvs, _In_ DWORD iValue)
{
    DWORD iHash;
    DWORD dwHashMask = pvs->cHashMax - 1;
    QWORD qwValueToHash = _ObSet_GetValueFromIndex(pvs, iValue);
    if(!qwValueToHash) { return; }
    iHash = OB_SET_HASH_FUNCTION(qwValueToHash) & dwHashMask;
    while(_ObSet_GetIndexFromHash(pvs, iHash)) {
        iHash = (iHash + 1) & dwHashMask;
    }
    _ObSet_SetHashIndex(pvs, iHash, iValue);
}

VOID _ObSet_RemoveHash(_In_ POB_SET pvs, _In_ DWORD iHash)
{
    DWORD dwHashMask = pvs->cHashMax - 1;
    DWORD iNextHash, iNextEntry, iNextHashPreferred;
    // clear existing hash entry
    _ObSet_SetHashIndex(pvs, iHash, 0);
    // re-hash any entries following
    iNextHash = iHash;
    while(TRUE) {
        iNextHash = (iNextHash + 1) & dwHashMask;
        iNextEntry = _ObSet_GetIndexFromHash(pvs, iNextHash);
        if(0 == iNextEntry) { return; }
        iNextHashPreferred = OB_SET_HASH_FUNCTION(_ObSet_GetValueFromIndex(pvs, iNextEntry)) & dwHashMask;
        if(iNextHash == iNextHashPreferred) { continue; }
        if(pvs->fLargeMode) {
            pvs->pHashMapLarge[iNextHash] = 0;
        } else {
            pvs->pHashMapSmall[iNextHash] = 0;
        }
        _ObSet_InsertHash(pvs, iNextEntry);
    }
}

_Success_(return)
BOOL _ObSet_GetIndexFromValue(_In_ POB_SET pvs, _In_ QWORD v, _Out_opt_ PDWORD pdwIndexValue, _Out_opt_ PDWORD pdwIndexHash)
{
    DWORD dwIndex;
    DWORD dwHashMask = pvs->cHashMax - 1;
    DWORD dwHash = OB_SET_HASH_FUNCTION(v) & dwHashMask;
    // scan hash table to find entry
    while(TRUE) {
        dwIndex = _ObSet_GetIndexFromHash(pvs, dwHash);
        if(0 == dwIndex) { return FALSE; }
        if(v == _ObSet_GetValueFromIndex(pvs, dwIndex)) { 
            if(pdwIndexValue) { *pdwIndexValue = dwIndex; }
            if(pdwIndexHash) { *pdwIndexHash = dwHash; }
            return TRUE;
        }
        dwHash = (dwHash + 1) & dwHashMask;
    }
}

BOOL _ObSet_Exists(_In_ POB_SET pvs, _In_ QWORD value)
{
    return _ObSet_GetIndexFromValue(pvs, value, NULL, NULL);
}

/*
* Check if a value already exists in the ObSet.
* -- pvs
* -- value
* -- return
*/
BOOL ObSet_Exists(_In_opt_ POB_SET pvs, _In_ QWORD value)
{
    OB_SET_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pvs, BOOL, FALSE, _ObSet_Exists(pvs, value))
}

/*
* Retrieve a value given a value index (which is less than the amount of items
* in the Set).
* NB! Correctness of the Get/GetNext functionality is _NOT- guaranteed if the
* ObSet_Remove function is called while iterating over the ObSet - items may
* be skipped or iterated over multiple times!
* -- pvs
* -- index
* -- return
*/
QWORD ObSet_Get(_In_opt_ POB_SET pvs, _In_ DWORD index)
{
    OB_SET_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pvs, QWORD, 0, _ObSet_GetValueFromIndex(pvs, index + 1))  // (+1 == account/adjust for index 0 (reserved))
}

QWORD _ObSet_GetNext(_In_ POB_SET pvs, _In_ QWORD value)
{
    DWORD iValue;
    if(value == 0) {
        return _ObSet_GetValueFromIndex(pvs, 1);   // (+1 == account/adjust for index 0 (reserved))
    }
    if(!_ObSet_GetIndexFromValue(pvs, value, &iValue, NULL)) { return 0; }
    return _ObSet_GetValueFromIndex(pvs, iValue + 1);
}

QWORD _ObSet_GetNextByIndex(_In_ POB_SET pvs, _Inout_ PDWORD pdwIndex)
{
    if(*pdwIndex == 0) {
        *pdwIndex = pvs->c - 1;
    } else {
        *pdwIndex = *pdwIndex - 1;
    }
    return _ObSet_GetValueFromIndex(pvs, *pdwIndex);
}

/*
* Retrieve the next value given a value. The start value and end value are the
* ZERO value (which is a special reserved non-valid value).
* NB! Correctness of the Get/GetNext functionality is _NOT_ guaranteed if the
* ObSet_Remove function is called while iterating over the ObSet - items may
* be skipped or iterated over multiple times!
* -- pvs
* -- value
* -- return
*/
QWORD ObSet_GetNext(_In_opt_ POB_SET pvs, _In_ QWORD value)
{
    OB_SET_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pvs, QWORD, 0, _ObSet_GetNext(pvs, value))
}

/*
* Retrieve the given an index. To start iterating, use index 0. When no more
* items are available, the function will return 0.
* Add/Remove rules:
*  - Added values are ok - but will not be iterated over.
*  - Removal of current value and already iterated values are ok.
*  - Removal of values not yet iterated is FORBIDDEN. It causes the iterator
*    fail by returning the same value multiple times or skipping values.
* -- pvs
* -- pdwIndex
* -- return
*/
QWORD ObSet_GetNextByIndex(_In_opt_ POB_SET pvs, _Inout_ PDWORD pdwIndex)
{
    OB_SET_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pvs, QWORD, 0, _ObSet_GetNextByIndex(pvs, pdwIndex))
}

POB_DATA _ObSet_GetAll(_In_ POB_SET pvs)
{
    DWORD iValue;
    POB_DATA pObData;
    if(!(pObData = Ob_AllocEx(pvs->ObHdr.H, OB_TAG_CORE_DATA, 0, sizeof(OB) + (pvs->c - 1) * sizeof(QWORD), NULL, NULL))) { return NULL; }
    for(iValue = pvs->c - 1; iValue; iValue--) {
        pObData->pqw[iValue - 1] = _ObSet_GetValueFromIndex(pvs, iValue);
    }
    return pObData;
}

/*
* Retrieve all values in the Set as a POB_DATA object containing the values
* in a QWORD table.
* -- CALLER DECREF: return
* -- pvs
* -- return
*/
POB_DATA ObSet_GetAll(_In_opt_ POB_SET pvs)
{
    OB_SET_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pvs, POB_DATA, NULL, _ObSet_GetAll(pvs))
}

BOOL _ObSet_Remove(_In_ POB_SET pvs, _In_ QWORD value)
{
    QWORD qwLastValue;
    DWORD iRemoveValue, iRemoveHash;
    DWORD iLastValue, iLastHash;
    DWORD dwHashMask = pvs->cHashMax - 1;
    if(value == 0) { return FALSE; }
    if(!_ObSet_GetIndexFromValue(pvs, value, &iRemoveValue, &iRemoveHash)) { return FALSE; }
    qwLastValue = _ObSet_GetValueFromIndex(pvs, pvs->c - 1);
    if(qwLastValue == 0) { return FALSE; }
    if(!_ObSet_GetIndexFromValue(pvs, qwLastValue, &iLastValue, &iLastHash)) { return FALSE; }
    _ObSet_SetValueFromIndex(pvs, iLastValue, 0);
    _ObSet_RemoveHash(pvs, iLastHash);
    pvs->c--;
    if(iLastValue != iRemoveValue) {    // overwrite value to remove with last value if required.
        _ObSet_RemoveHash(pvs, iRemoveHash);
        _ObSet_SetValueFromIndex(pvs, iRemoveValue, qwLastValue);
        _ObSet_InsertHash(pvs, iRemoveValue);
    }
    return TRUE;
}

/*
* Remove an existing value from the ObSet.
* NB! must not be called simultaneously while iterating with ObSet_Get/ObSet_GetNext.
* -- pvs
* -- value
* -- return = removal was successful (i.e. the value was found and removed).
*/
BOOL ObSet_Remove(_In_opt_ POB_SET pvs, _In_ QWORD value)
{
    OB_SET_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pvs, BOOL, FALSE, _ObSet_Remove(pvs, value))
}

/*
* Clear the ObSet by removing all values.
* NB! underlying allocated memory will remain unchanged.
* -- pvs
*/
VOID ObSet_Clear(_In_opt_ POB_SET pvs)
{
    if(!OB_SET_IS_VALID(pvs) || (pvs->c <= 1)) { return; }
    AcquireSRWLockExclusive(&pvs->LockSRW);
    if(pvs->c <= 1) {
        ReleaseSRWLockExclusive(&pvs->LockSRW);
        return;
    }
    if(pvs->fLargeMode) {
        ZeroMemory(pvs->pHashMapLarge, pvs->cHashMax * sizeof(DWORD));
    } else {
        ZeroMemory(pvs->pHashMapSmall, sizeof(pvs->pHashMapSmall));
    }
    pvs->c = 1;     // item zero is reserved - hence the initialization of count to 1
    ReleaseSRWLockExclusive(&pvs->LockSRW);
}

QWORD _ObSet_Pop(_In_ POB_SET pvs)
{
    QWORD qwLastValue;
    DWORD iLastValue, iLastHash;
    qwLastValue = _ObSet_GetValueFromIndex(pvs, pvs->c - 1);
    if(qwLastValue == 0) { return 0; }
    if(!_ObSet_GetIndexFromValue(pvs, qwLastValue, &iLastValue, &iLastHash)) { return 0; }
    _ObSet_SetValueFromIndex(pvs, iLastValue, 0);
    _ObSet_RemoveHash(pvs, iLastHash);
    pvs->c--;
    return qwLastValue;
}

/*
* Remove the "last" value in a way that is safe for concurrent iterations of
* values in the set.
* -- pvs
* -- return = success: value, fail: 0.
*
*/
QWORD ObSet_Pop(_In_opt_ POB_SET pvs)
{
    OB_SET_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pvs, QWORD, 0, _ObSet_Pop(pvs))
}

/*
* Grow the Table for hash lookups by a factor of *2.
* -- pvs
* -- return
*/
_Success_(return)
BOOL _ObSet_Grow(_In_ POB_SET pvs)
{
    DWORD iValue;
    PDWORD pdwNewAllocHashMap;
    if(!(pdwNewAllocHashMap = LocalAlloc(LMEM_ZEROINIT, 2 * sizeof(DWORD) * pvs->cHashMax))) { return FALSE; }
    if(!pvs->fLargeMode) {
        ZeroMemory(pvs->pDirectory, OB_SET_ENTRIES_DIRECTORY * sizeof(OB_SET_TABLE_DIRECTORY_ENTRY));
        pvs->pDirectory[0].pTable = pvs->pTable0;
        pvs->fLargeMode = TRUE;
    }
    pvs->cHashMax *= 2;
    pvs->cHashGrowThreshold *= 2;
    LocalFree(pvs->pHashMapLarge);
    pvs->pHashMapLarge = pdwNewAllocHashMap;
    for(iValue = 1; iValue < pvs->c; iValue++) {
        _ObSet_InsertHash(pvs, iValue);
    }
    return TRUE;
}

_Success_(return)
BOOL _ObSet_Push(_In_ POB_SET pvs, _In_ QWORD value)
{
    POB_SET_TABLE_ENTRY pTable = NULL;
    DWORD iValue = pvs->c;
    WORD iDirectory = OB_SET_INDEX_DIRECTORY(iValue);
    WORD iTable = OB_SET_INDEX_TABLE(iValue);
    WORD iValueStore = OB_SET_INDEX_STORE(iValue);
    if((value == 0) || _ObSet_Exists(pvs, value)) { return FALSE; }
    if(iValue == OB_SET_TABLE_MAX_CAPACITY) { return FALSE; }
    if(iValue == pvs->cHashGrowThreshold) {
        if(!_ObSet_Grow(pvs)) {
            return FALSE;
        }
    }
    if(iDirectory && !pvs->pDirectory[iDirectory].pTable) { // Ensure Table Exists
        pvs->pDirectory[iDirectory].pTable = LocalAlloc(LMEM_ZEROINIT, OB_SET_ENTRIES_TABLE * sizeof(OB_SET_TABLE_ENTRY));
        if(!pvs->pDirectory[iDirectory].pTable) { return FALSE; }
    }
    pTable = iDirectory ? pvs->pDirectory[iDirectory].pTable : pvs->pTable0;
    if(!pTable[iTable].pValues) {   // Ensure Store Exists
        pTable[iTable].pValues = LocalAlloc(0, OB_SET_ENTRIES_STORE * sizeof(OB_SET_TABLE_ENTRY));
        if(!pTable[iTable].pValues) { return FALSE; }
    }
    pvs->c++;
    _ObSet_SetValueFromIndex(pvs, iValue, value);
    _ObSet_InsertHash(pvs, iValue);
    return TRUE;
}

_Success_(return)
BOOL _ObSet_PushSet(_In_ POB_SET pvs, _In_opt_ POB_SET pvsSrc)
{
    DWORD iValue;
    if(pvsSrc) {
        AcquireSRWLockShared(&pvsSrc->LockSRW);
        for(iValue = pvsSrc->c - 1; iValue; iValue--) {
            QWORD qwValue = _ObSet_GetValueFromIndex(pvsSrc, iValue);
            _ObSet_Push(pvs, _ObSet_GetValueFromIndex(pvsSrc, iValue));
        }
        ReleaseSRWLockShared(&pvsSrc->LockSRW);
    }
    return TRUE;
}

_Success_(return)
BOOL _ObSet_PushData(_In_ POB_SET pvs, _In_opt_ POB_DATA pDataSrc)
{
    DWORD i, iMax;
    if(pDataSrc) {   
        for(i = 0, iMax = pDataSrc->ObHdr.cbData / sizeof(QWORD); i < iMax; i++) {
            _ObSet_Push(pvs, pDataSrc->pqw[i]);
        }
    }
    return TRUE;
}

/*
* Push / Insert a non-zero value into the ObSet.
* -- pvs
* -- value
* -- return = TRUE on insertion, FALSE otherwise - i.e. if value already
*             exists or if the max capacity of the set is reached.
*/
_Success_(return)
BOOL ObSet_Push(_In_opt_ POB_SET pvs, _In_ QWORD value)
{
    OB_SET_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pvs, BOOL, FALSE, _ObSet_Push(pvs, value))
}

/*
* Push/Merge/Insert all values from the ObSet pvsSrc into the ObSet pvs.
* The source set is kept intact.
* -- pvs
* -- pvsSrc
* -- return = TRUE on success, FALSE otherwise.
*/
_Success_(return)
BOOL ObSet_PushSet(_In_opt_ POB_SET pvs, _In_opt_ POB_SET pvsSrc)
{
    OB_SET_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pvs, BOOL, FALSE, _ObSet_PushSet(pvs, pvsSrc))
}

/*
* Push/Merge/Insert all QWORD values from the ObData pDataSrc into the ObSet pvs.
* The source data is kept intact.
* -- pvs
* -- pDataSrc
* -- return = TRUE on success, FALSE otherwise.
*/
_Success_(return)
BOOL ObSet_PushData(_In_opt_ POB_SET pvs, _In_opt_ POB_DATA pDataSrc)
{
    OB_SET_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pvs, BOOL, FALSE, _ObSet_PushData(pvs, pDataSrc))
}

/*
* Insert a value representing an address into the ObSet. If the length of the
* data read from the start of the address a traverses page boundries all the
* pages are inserted into the set.
* -- pvs
* -- a
* -- cb
*/
VOID ObSet_Push_PageAlign(_In_opt_ POB_SET pvs, _In_ QWORD a, _In_ DWORD cb)
{
    QWORD qwA;
    if(!OB_SET_IS_VALID(pvs)) { return; }
    qwA = a & ~0xfff;
    if(qwA == 0xfffffffffffff000) { return; }
    while(qwA < a + cb) {
        ObSet_Push(pvs, qwA);
        qwA += 0x1000;
    }
}

/*
* Retrieve the number of items in the given ObSet.
* -- pvs
* -- return
*/
DWORD ObSet_Size(_In_opt_ POB_SET pvs)
{
    OB_SET_CALL_SYNCHRONIZED_IMPLEMENTATION_READ(pvs, DWORD, 0, pvs->c - 1)
}
