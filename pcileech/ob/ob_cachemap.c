// ob_cachemap.c : implementation of object manager cached map functionality.
//
// The map (ObCacheMap) implements an efficient caching of objects stored in
// an internal hash map. The cached object are retrieved and cleared according
// to rules implemented by callback functions.
//
// If the max number of map entries are reached the least recently accessed
// entry will be removed if required to make room for a new entry.
//
// The map (ObCacheMap) is thread safe.
// The ObCacheMap is an object manager object and must be DECREF'ed when required.
//
// (c) Ulf Frisk, 2020-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "ob.h"

#define OB_CACHEMAP_IS_VALID(p)     (p && (p->ObHdr._magic2 == OB_HEADER_MAGIC) && (p->ObHdr._magic1 == OB_HEADER_MAGIC) && (p->ObHdr._tag == OB_TAG_CORE_CACHEMAP))

#define OB_CACHEMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pcm, RetTp, RetValFail, fn) { \
    if(!OB_CACHEMAP_IS_VALID(pcm)) { return RetValFail; }                                \
    RetTp retVal;                                                                        \
    AcquireSRWLockExclusive(&pcm->LockSRW);                                              \
    retVal = fn;                                                                         \
    ReleaseSRWLockExclusive(&pcm->LockSRW);                                              \
    return retVal;                                                                       \
}

typedef struct tdOB_CACHEMAPENTRY {
    struct tdOB_CACHEMAPENTRY *FLink;
    struct tdOB_CACHEMAPENTRY *BLink;
    PVOID pvObject;
    QWORD qwContext;
} OB_CACHEMAPENTRY, *POB_CACHEMAPENTRY;

typedef struct tdOB_CACHEMAP {
    OB ObHdr;
    SRWLOCK LockSRW;
    DWORD c;
    DWORD cMax;
    BOOL fObjectsOb;
    BOOL fObjectsLocalFree;
    POB_MAP pm;
    POB_CACHEMAPENTRY AgeListHead;
    OB_CACHEMAP_VALIDENTRY_PFN_CB pfnValidEntry;
} OB_CACHEMAP, *POB_CACHEMAP;

_Success_(return)
BOOL _ObCacheMap_Clear(_In_ POB_CACHEMAP pcm)
{
    POB_CACHEMAPENTRY pe, peNext;
    if(!(peNext = pcm->AgeListHead)) { return TRUE; }
    peNext->BLink->FLink = NULL;
    while((pe = peNext)) {
        peNext = pe->FLink;
        if(pcm->fObjectsOb) {
            Ob_DECREF(pe->pvObject);
        } else if(pcm->fObjectsLocalFree) {
            LocalFree(pe->pvObject);
        }
        LocalFree(pe);
    }
    ObMap_Clear(pcm->pm);
    pcm->AgeListHead = NULL;
    pcm->c = 0;
    return TRUE;
}

/*
* Clear the ObCacheMap by removing all objects and their keys.
* -- pcm
* -- return = clear was successful - always true.
*/
_Success_(return)
BOOL ObCacheMap_Clear(_In_opt_ POB_CACHEMAP pcm)
{
    OB_CACHEMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pcm, BOOL, TRUE, _ObCacheMap_Clear(pcm));
}

PVOID _ObCacheMap_RemoveByKey(_In_ POB_CACHEMAP pcm, _In_ QWORD qwKey, _In_ BOOL fNoReturn)
{
    PVOID pvRemovedObject;
    POB_CACHEMAPENTRY pe;
    if(!(pe = ObMap_RemoveByKey(pcm->pm, qwKey))) { return NULL; }
    pe->FLink->BLink = pe->BLink;
    pe->BLink->FLink = pe->FLink;
    pcm->c--;
    if(pcm->c == 0) {
        pcm->AgeListHead = NULL;
    } else if(pcm->AgeListHead == pe) {
        pcm->AgeListHead = pe->FLink;
    }
    pvRemovedObject = pe->pvObject;
    LocalFree(pe);
    if(fNoReturn && pvRemovedObject) {
        if(pcm->fObjectsOb) {
            Ob_DECREF(pvRemovedObject);
        } else if(pcm->fObjectsLocalFree) {
            LocalFree(pvRemovedObject);
        }
        pvRemovedObject = NULL;
    }
    return pvRemovedObject;
}

PVOID _ObCacheMap_GetByKey(_In_ POB_CACHEMAP pcm, _In_ QWORD qwKey)
{
    POB_CACHEMAPENTRY pe;
    if(!(pe = ObMap_GetByKey(pcm->pm, qwKey))) { return NULL; }
    if(pcm->pfnValidEntry && !pcm->pfnValidEntry(pcm->ObHdr.H, &pe->qwContext, qwKey, pe->pvObject)) {
        // invalid - remove object from map and return NULL
        _ObCacheMap_RemoveByKey(pcm, qwKey, TRUE);
        return NULL;
    }
    // valid - move to front of age list and return object
    if(pcm->AgeListHead != pe) {
        pe->FLink->BLink = pe->BLink;
        pe->BLink->FLink = pe->FLink;
        pe->BLink = pcm->AgeListHead->BLink;
        pe->FLink = pcm->AgeListHead;
        pcm->AgeListHead->BLink->FLink = pe;
        pcm->AgeListHead->BLink = pe;
        pcm->AgeListHead = pe;
    }
    if(pcm->fObjectsOb) { Ob_INCREF(pe->pvObject); }
    return pe->pvObject;
}

_Success_(return)
BOOL _ObCacheMap_Push(_In_ POB_CACHEMAP pcm, _In_ QWORD qwKey, _In_ PVOID pvObject, _In_ QWORD qwContextInitial)
{
    QWORD qwRemovedKey;
    POB_CACHEMAPENTRY pe;
    if(!qwKey || !pvObject) { return FALSE; }
    // 1: remove existing object with same key
    _ObCacheMap_RemoveByKey(pcm, qwKey, TRUE);
    // 2: remove least recently accessed object (if required)
    if(pcm->c >= pcm->cMax) {
        pe = pcm->AgeListHead->BLink;
        qwRemovedKey = ObMap_GetKey(pcm->pm, pe);
        _ObCacheMap_RemoveByKey(pcm, qwRemovedKey, TRUE);
    }
    // 3: add new object
    if(!(pe = LocalAlloc(0, sizeof(OB_CACHEMAPENTRY)))) { return FALSE; }
    if(pcm->fObjectsOb) { Ob_INCREF(pvObject); }
    pe->pvObject = pvObject;
    pe->qwContext = qwContextInitial;
    if(pcm->AgeListHead) {
        pe->BLink = pcm->AgeListHead->BLink;
        pe->FLink = pcm->AgeListHead;
        pcm->AgeListHead->BLink->FLink = pe;
        pcm->AgeListHead->BLink = pe;
    } else {
        pe->BLink = pe->FLink = pe;
    }
    ObMap_Push(pcm->pm, qwKey, pe);
    pcm->AgeListHead = pe;
    pcm->c++;
    return TRUE;
}

/*
* Retrieve a value given a key.
* CALLER DECREF(if OB): return
* -- pcm
* -- qwKey
* -- return
*/
PVOID ObCacheMap_GetByKey(_In_opt_ POB_CACHEMAP pcm, _In_ QWORD qwKey)
{
    OB_CACHEMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pcm, PVOID, NULL, _ObCacheMap_GetByKey(pcm, qwKey));
}

/*
* Remove an object from the ObCacheMap by using its key.
* NB! Object is removed and returned even if valid critera is not matched.
* CALLER DECREF(if OB): return
* -- pcm
* -- qwKey
* -- return = success: object, fail: NULL.
*/
PVOID ObCacheMap_RemoveByKey(_In_opt_ POB_CACHEMAP pcm, _In_ QWORD qwKey)
{
    OB_CACHEMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pcm, PVOID, NULL, _ObCacheMap_RemoveByKey(pcm, qwKey, FALSE));
}

/*
* Check if a key exists in the ObCacheMap.
* -- pcm
* -- qwKey/pvObject
* -- return
*/
BOOL ObCacheMap_ExistsKey(_In_opt_ POB_CACHEMAP pcm, _In_ QWORD qwKey)
{
    OB_CACHEMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pcm, DWORD, 0, ObMap_ExistsKey(pcm->pm, qwKey))
}

/*
* Retrieve the number of objects in the ObCacheMap.
* -- pcm
* -- return
*/
DWORD ObCacheMap_Size(_In_opt_ POB_CACHEMAP pcm)
{
    OB_CACHEMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pcm, DWORD, 0, pcm->c);
}

_Success_(return)
BOOL ObCacheMap_Push(_In_opt_ POB_CACHEMAP pcm, _In_ QWORD qwKey, _In_ PVOID pvObject, _In_ QWORD qwContextInitial)
{
    OB_CACHEMAP_CALL_SYNCHRONIZED_IMPLEMENTATION_WRITE(pcm, BOOL, FALSE, _ObCacheMap_Push(pcm, qwKey, pvObject, qwContextInitial))
}

/*
* Object Map object manager cleanup function to be called when reference
* count reaches zero.
* -- pObMap
*/
VOID _ObCacheMap_ObCloseCallback(_In_ POB_CACHEMAP pObCacheMap)
{
    _ObCacheMap_Clear(pObCacheMap);
    Ob_DECREF(pObCacheMap->pm);
}

/*
* Create a new cached map. A cached map (ObCacheMap) provides atomic map
* operations on cached objects.
* The ObCacheMap is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- H
* -- cMaxEntries = max entries in the cache, if more entries are added the
*       least recently accessed item will be removed from the cache map.
* -- pfnValidEntry = optional validation callback function.
* -- flags = defined by OB_CACHEMAP_FLAGS_*
* -- return
*/
POB_CACHEMAP ObCacheMap_New(_In_opt_ VMM_HANDLE H, _In_ DWORD cMaxEntries, _In_opt_ OB_CACHEMAP_VALIDENTRY_PFN_CB pfnValidEntry, _In_ QWORD flags)
{
    POB_CACHEMAP pObCacheMap;
    if(!cMaxEntries) { return NULL; }
    if((flags & OB_MAP_FLAGS_OBJECT_OB) && (flags & OB_MAP_FLAGS_OBJECT_LOCALFREE)) { return NULL; }
    pObCacheMap = Ob_AllocEx(H, OB_TAG_CORE_CACHEMAP, LMEM_ZEROINIT, sizeof(OB_CACHEMAP), (OB_CLEANUP_CB)_ObCacheMap_ObCloseCallback, NULL);
    if(!pObCacheMap) { return NULL; }
    InitializeSRWLock(&pObCacheMap->LockSRW);
    pObCacheMap->cMax = cMaxEntries;
    pObCacheMap->pfnValidEntry = pfnValidEntry;
    pObCacheMap->fObjectsOb = (flags & OB_CACHEMAP_FLAGS_OBJECT_OB) ? TRUE : FALSE;
    pObCacheMap->fObjectsLocalFree = (flags & OB_CACHEMAP_FLAGS_OBJECT_LOCALFREE) ? TRUE : FALSE;
    pObCacheMap->pm = ObMap_New(H, OB_MAP_FLAGS_OBJECT_VOID);
    if(!pObCacheMap->pm) {
        Ob_DECREF(pObCacheMap);
        return NULL;
    }
    return pObCacheMap;
}
