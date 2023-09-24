// ob_core.c : implementation of object manager core functionality.
//
// The object manager is a minimal non-threaded way of allocating objects with
// reference counts. When reference count reach zero the object is deallocated
// automatically.
//
// All Ob functions are thread-safe and performs only minimum locking.
//
// A thread calls Ob_Alloc to allocate an object of a specific length. The
// object initially have reference count 1. Reference counts may be increased
// by calling Ob_INCREF and decreased by calling Ob_DECREF. If the refcount
// reach one or zero in a call to Ob_DECREF optional callbacks may be made
// (specified at Ob_Alloc time). Callbacks may be useful for cleanup tasks
// - such as decreasing reference count of sub-objects contained in the object
// that is to be deallocated.
//
// (c) Ulf Frisk, 2018-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "ob.h"
#include <stdio.h>

#define obprintf_fn(format, ...)        printf("%s: "format, __func__, ##__VA_ARGS__);
#define OB_DEBUG_FOOTER_SIZE            0x20
#define OB_DEBUG_FOOTER_MAGIC           0x001122334455667788

/*
* Allocate a new object manager memory object.
* -- H = an optional handle to embed as OB.H in the header.
* -- tag = tag of the object to be allocated.
* -- uFlags = flags as given by LocalAlloc.
* -- uBytes = bytes of object (_including_ object headers).
* -- pfnRef_0 = optional callback for cleanup o be called before object is destroyed.
*               (if object has references that should be decremented before destruction).
* -- pfnRef_1 = optional callback for when object reach refcount = 1 (excl. initial).
* -- return = allocated object on success, with refcount = 1, - NULL on fail.
*/
PVOID Ob_AllocEx(_In_opt_ VMM_HANDLE H, _In_ DWORD tag, _In_ UINT uFlags, _In_ SIZE_T uBytes, _In_opt_ OB_CLEANUP_CB pfnRef_0, _In_opt_ OB_CLEANUP_CB pfnRef_1)
{
    POB pOb;
    if((uBytes > 0x40000000) || (uBytes < sizeof(OB))) { return NULL; }
    pOb = (POB)LocalAlloc(uFlags, uBytes + OB_DEBUG_FOOTER_SIZE);
    if(!pOb) { return NULL; }
    pOb->_magic1 = OB_HEADER_MAGIC;
    pOb->_magic2 = OB_HEADER_MAGIC;
    pOb->_count = 1;
    pOb->_tag = tag;
    pOb->_pfnRef_0 = pfnRef_0;
    pOb->_pfnRef_1 = pfnRef_1;
    pOb->H = H;
    pOb->cbData = (DWORD)uBytes - sizeof(OB);
#ifdef OB_DEBUG
    DWORD i, cb = sizeof(OB) + pOb->cbData;
    PBYTE pb = (PBYTE)pOb;
    for(i = 0; i < OB_DEBUG_FOOTER_SIZE; i += 8) {
        *(PQWORD)(pb + cb + i) = OB_DEBUG_FOOTER_MAGIC;
    }
#endif /* OB_DEBUG */
    return pOb;
}

/*
* Increase the reference count of a object manager object.
* -- pOb
* -- return
*/
PVOID Ob_XINCREF(_In_opt_ PVOID pObIn)
{
    POB pOb = (POB)pObIn;
    if(pOb) {
        if((pOb->_magic2 == OB_HEADER_MAGIC) && (pOb->_magic1 == OB_HEADER_MAGIC)) {
            InterlockedIncrement(&pOb->_count);
            return (POB)pOb;
        } else {
            obprintf_fn("ObCORE: CRITICAL: INCREF OF NON OBJECT MANAGER OBJECT!\n")
        }
    }
    return NULL;
}

/*
* Decrease the reference count of a object manager object. If the reference
* count reaches zero the object will be cleaned up.
* -- pObIn
* -- return = pObIn if pObIn is valid and refcount > 0 after decref.
*/
PVOID Ob_XDECREF(_In_opt_ PVOID pObIn)
{
    POB pOb = (POB)pObIn;
    DWORD c;
    if(pOb) {
        if((pOb->_magic2 == OB_HEADER_MAGIC) && (pOb->_magic1 == OB_HEADER_MAGIC)) {
            c = InterlockedDecrement(&pOb->_count);
#ifdef OB_DEBUG
            DWORD i, cb = sizeof(OB) + pOb->cbData;
            PBYTE pb = (PBYTE)pOb;
            for(i = 0; i < OB_DEBUG_FOOTER_SIZE; i += 8) {
                if(*(PQWORD)(pb + cb + i) != OB_DEBUG_FOOTER_MAGIC) {
                    obprintf_fn("ObCORE: CRITICAL: FOOTER OVERWRITTEN - MEMORY CORRUPTION? REFCNT: %i TAG: %04X\n", c, pOb->_tag)
                }
            }
#endif /* OB_DEBUG */
            if(c == 0) {
                if(pOb->_pfnRef_0) { pOb->_pfnRef_0(pOb); }
                pOb->_magic1 = 0;
                pOb->_magic2 = 0;
#ifdef OB_DEBUG_MEMZERO
                ZeroMemory(pOb, sizeof(OB) + pOb->cbData);
#endif /* OB_DEBUG_MEMZERO */
                LocalFree(pOb);
            } else if((c == 1) && pOb->_pfnRef_1) {
                pOb->_pfnRef_1(pOb);
                return pOb;
            } else {
                return pOb;
            }
        } else {
            obprintf_fn("ObCORE: CRITICAL: DECREF OF NON OBJECT MANAGER OBJECT!\n")
        }
    }
    return NULL;
}

/*
* Decrease the reference count of a object manager object.
* If the reference count reaches zero the object will be cleaned up.
* Also set the incoming pointer to NULL.
* -- ppOb
*/
VOID Ob_XDECREF_NULL(_In_opt_ PVOID *ppOb)
{
    POB pOb;
    if(ppOb) {
        pOb = (POB)*ppOb;
        *ppOb = NULL;
        Ob_DECREF(pOb);
    }
}

/*
* Checks if pObIn is a valid object manager object with the specified tag.
* -- pObIn
* -- tag
* -- return
*/
BOOL Ob_VALID_TAG(_In_ PVOID pObIn, _In_ DWORD tag)
{
    POB pOb = (POB)pObIn;
    return pOb && (pOb->_magic2 == OB_HEADER_MAGIC) && (pOb->_magic1 == OB_HEADER_MAGIC) && (pOb->_tag = tag);
}

/*
* Create a new object manager data object in which the ObHdr->cbData is equal
* to the number of bytes in the data buffer supplied to this function.
* May also be created with Ob_Alloc with size: sizeof(OB_HDR) + length of data.
* CALLER DECREF: return
* -- H
* -- pb
* -- cb
* -- return
*/
_Success_(return != NULL)
POB_DATA ObData_New(_In_opt_ VMM_HANDLE H, _In_ PBYTE pb, _In_ DWORD cb)
{
    POB_DATA pObData = NULL;
    if((pObData = Ob_AllocEx(H, OB_TAG_CORE_DATA, 0, sizeof(OB) + cb, NULL, NULL))) {
        memcpy(pObData->pb, pb, cb);
    }
    return pObData;
}
