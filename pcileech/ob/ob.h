// ob.h : definitions related to the object manager and object manager collections.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __OB_H__
#define __OB_H__

#ifdef _WIN32
#include <Windows.h>
typedef unsigned __int64                QWORD, *PQWORD;
#else
#include "../oscompatibility.h"
#endif /* _WIN32 */

// OB_DEBUG is not working (as currently coded) with arm32 due to alignment issues.
#if _WIN32 || _WIN64 || __i386__ || __amd64__ || __aarch64__
#define OB_DEBUG
//#define OB_DEBUG_MEMZERO
#endif /* _WIN32 || _WIN64 || __i386__ || __amd64__ || __aarch64__ */
#define OB_HEADER_MAGIC                 0x0c0efefe
typedef struct tdVMM_HANDLE             *VMM_HANDLE;

#define OB_TAG_CORE_CONTAINER           'ObCo'
#define OB_TAG_CORE_COMPRESSED          'ObCp'
#define OB_TAG_CORE_COUNTER             'ObCn'
#define OB_TAG_CORE_DATA                'ObDa'
#define OB_TAG_CORE_SET                 'ObSe'
#define OB_TAG_CORE_MAP                 'ObMa'
#define OB_TAG_CORE_MEMFILE             'ObMF'
#define OB_TAG_CORE_CACHEMAP            'ObMc'
#define OB_TAG_CORE_STRMAP              'ObMs'
#define OB_TAG_CORE_BYTEQUEUE           'ObBq'

// ----------------------------------------------------------------------------
// OBJECT MANAGER CORE FUNCTIONALITY BELOW:
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
// ----------------------------------------------------------------------------

typedef struct tdOB {
    // internal object manager functionality below: (= do not use unless absolutely necessary)
    DWORD _magic1;                          // magic value - OB_HEADER_MAGIC
    union {
        DWORD _tag;                         // tag - 4 chars, no null terminator
        CHAR _tagCh[4];
    };
    union {
        VOID(*_pfnRef_0)(_In_ PVOID pOb);   // callback - object specific cleanup before free
        QWORD _Filler1;
    };
    union {
        VOID(*_pfnRef_1)(_In_ PVOID pOb);   // callback - when object reach refcount 1 (not initial)
        QWORD _Filler2;
    };
    DWORD _Filler3[5];
    DWORD _count;                           // reference count
    // external object manager functionality below: (= ok to use)
    union { VMM_HANDLE H; QWORD _Filler4; };// vmm user handle (supplied at alloc)
    DWORD cbData;                           // data byte count (excl. OB header)
    DWORD _magic2;                          // magic value - OB_HEADER_MAGIC
} OB, *POB;

typedef VOID(*OB_CLEANUP_CB)(_In_ PVOID pOb);

/*
* Allocate a new object manager memory object.
* -- H = an optional handle to embed as OB.H in the header.
* -- tag = tag identifying the type of object.
* -- uFlags = flags as given by LocalAlloc.
* -- uBytes = bytes of object (_including_ object headers).
* -- pfnRef_0 = optional callback for cleanup o be called before object is destroyed.
*               (if object contains objects which references should be decremented
                 before destruction of this 'parent' object).
* -- pfnRef_1 = optional callback for when object reach refcount = 1 at DECREF.
* -- return = allocated object on success, with refcount = 1, - NULL on fail.
*/
PVOID Ob_AllocEx(_In_opt_ VMM_HANDLE H, _In_ DWORD tag, _In_ UINT uFlags, _In_ SIZE_T uBytes, _In_opt_ OB_CLEANUP_CB pfnRef_0, _In_opt_ OB_CLEANUP_CB pfnRef_1);

/*
* Allocate a new object manager memory object.
* -- tag = tag identifying the type of object.
* -- uFlags = flags as given by LocalAlloc.
* -- uBytes = bytes of object (_including_ object headers).
* -- pfnRef_0 = optional callback for cleanup o be called before object is destroyed.
*               (if object contains objects which references should be decremented
                 before destruction of this 'parent' object).
* -- pfnRef_1 = optional callback for when object reach refcount = 1 at DECREF.
* -- return = allocated object on success, with refcount = 1, - NULL on fail.
*/
__forceinline PVOID Ob_Alloc(_In_ DWORD tag, _In_ UINT uFlags, _In_ SIZE_T uBytes, _In_opt_ OB_CLEANUP_CB pfnRef_0, _In_opt_ OB_CLEANUP_CB pfnRef_1)
{
    return Ob_AllocEx(NULL, tag, uFlags, uBytes, pfnRef_0, pfnRef_1);
}

/*
* Increase the reference count of a object by one.
* -- pOb
* -- return
*/
PVOID Ob_XINCREF(_In_opt_ PVOID pOb);
#define Ob_INCREF(pOb)          (Ob_XINCREF((PVOID)pOb))

/*
* Decrease the reference count of an object manager object by one.
* NB! Do not use object after DECREF - other threads might have also DECREF'ed
* the object at same time making it to be free'd - making the memory invalid.
* -- pOb
* -- return = pObIn if pObIn is valid and refcount > 0 after decref.
*/
PVOID Ob_XDECREF(_In_opt_ PVOID pOb);
#define Ob_DECREF(pOb)          (Ob_XDECREF((PVOID)pOb))

/*
* Decrease the reference count of a object manager object.
* If the reference count reaches zero the object will be cleaned up.
* Also set the incoming pointer to NULL.
* -- ppOb
*/
VOID Ob_XDECREF_NULL(_In_opt_ PVOID *ppOb);
#define Ob_DECREF_NULL(pOb)     (Ob_XDECREF_NULL((PVOID*)pOb))

/*
* Checks if pObIn is a valid object manager object with the specified tag.
* -- pObIn
* -- tag
* -- return
*/
BOOL Ob_VALID_TAG(_In_ PVOID pObIn, _In_ DWORD tag);



// ----------------------------------------------------------------------------
// OBJECT MANAGER COMMON/GENERIC OBJECTS BELOW:
//
// ----------------------------------------------------------------------------

typedef struct tdOB_DATA {
    OB ObHdr;
    union {
        BYTE pb[0];
        CHAR sz[0];
        DWORD pdw[0];
        QWORD pqw[0];
    };
} OB_DATA, *POB_DATA;

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
POB_DATA ObData_New(_In_opt_ VMM_HANDLE H, _In_ PBYTE pb, _In_ DWORD cb);



// ----------------------------------------------------------------------------
// OBJECT CONTAINER FUNCTIONALITY BELOW:
//
// A container provides atomic access to a single Ob object. This is useful
// if a Ob object is to frequently be replaced by a new object in an atomic
// way. An example of this is the process list object containing the process
// information. The container holds a reference count to the object that is
// contained. The object container itself is an object manager object and
// must be DECREF'ed when required.
// ----------------------------------------------------------------------------

typedef struct tdOB_CONTAINER {
    OB ObHdr;
    SRWLOCK LockSRW;
    POB pOb;
} OB_CONTAINER, *POB_CONTAINER;

/*
* Create a new object container object without an initial contained object.
* An object container provides atomic access to its contained object in a
* multithreaded environment. The object container is in itself an object
* manager object and must be DECREF'ed by the caller when use is complete.
* CALLER DECREF: return
* -- return
*/
POB_CONTAINER ObContainer_New();

/*
* Retrieve an enclosed object from the given pObContainer.
* CALLER DECREF: return
* -- pObContainer
* -- return
*/
PVOID ObContainer_GetOb(_In_ POB_CONTAINER pObContainer);

/*
* Set or Replace an object in the object container.
* -- pObContainer
* -- pOb
*/
VOID ObContainer_SetOb(_In_ POB_CONTAINER pObContainer, _In_opt_ PVOID pOb);

/*
* Check if the object container is valid and contains an object.
* -- pObContainer
* -- return
*/
BOOL ObContainer_Exists(_In_opt_ POB_CONTAINER pObContainer);



// ----------------------------------------------------------------------------
// HASHED VALUE SET FUNCTIONALITY BELOW:
//
// The hashed value set (ObSet) provides thread safe efficient access to a set
// which is containing _NON_ZERO_ values (64-bit unsigned integers). The ObSet
// may hold a maximum capacity of 0x01000000 (~16M) entries - which are UNIQUE
// and _NON_ZERO_.
// The hashed value set (ObSet) guarantees order amongst values unless the
// function ObSet_Remove is called - in which order may change and on-going
// iterations of the set with ObSet_Get/ObSet_GetNext may fail.
// The ObSet is an object manager object and must be DECREF'ed when required.
// ----------------------------------------------------------------------------

typedef struct tdOB_SET *POB_SET;

/*
* Create a new hashed value set. A hashed value set (ObSet) provides atomic
* ways to store unique 64-bit (or smaller) numbers as a set.
* The ObSet is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- H
* -- return
*/
POB_SET ObSet_New(_In_opt_ VMM_HANDLE H);

/*
* Retrieve the number of items in the given ObSet.
* -- pvs
* -- return
*/
DWORD ObSet_Size(_In_opt_ POB_SET pvs);

/*
* Check if a value already exists in the ObSet.
* -- pvs
* -- value
* -- return
*/
BOOL ObSet_Exists(_In_opt_ POB_SET pvs, _In_ QWORD value);

/*
* Push / Insert a non-zero value into the ObSet.
* -- pvs
* -- value
* -- return = TRUE on insertion, FALSE otherwise - i.e. if value already
*             exists or if the max capacity of the set is reached.
*/
_Success_(return)
BOOL ObSet_Push(_In_opt_ POB_SET pvs, _In_ QWORD value);

/*
* Push/Merge/Insert all values from the ObSet pvsSrc into the ObSet pvs.
* The source set is kept intact.
* -- pvs
* -- pvsSrc
* -- return = TRUE on success, FALSE otherwise.
*/
_Success_(return)
BOOL ObSet_PushSet(_In_opt_ POB_SET pvs, _In_opt_ POB_SET pvsSrc);

/*
* Push/Merge/Insert all QWORD values from the ObData pDataSrc into the ObSet pvs.
* The source data is kept intact.
* -- pvs
* -- pDataSrc
* -- return = TRUE on success, FALSE otherwise.
*/
_Success_(return)
BOOL ObSet_PushData(_In_opt_ POB_SET pvs, _In_opt_ POB_DATA pDataSrc);

/*
* Insert a value representing an address into the ObSet. If the length of the
* data read from the start of the address a traverses page boundries all the
* pages are inserted into the set.
* -- pvs
* -- a
* -- cb
*/
VOID ObSet_Push_PageAlign(_In_opt_ POB_SET pvs, _In_ QWORD a, _In_ DWORD cb);

/*
* Remove an existing value from the ObSet.
* NB! must not be called simultaneously while iterating with ObSet_Get/ObSet_GetNext.
* -- pvs
* -- value
* -- return = removal was successful (i.e. the value was found and removed).
*/
BOOL ObSet_Remove(_In_opt_ POB_SET pvs, _In_ QWORD value);

/*
* Clear the ObSet by removing all values.
* NB! underlying allocated memory will remain unchanged.
* -- pvs
*/
VOID ObSet_Clear(_In_opt_ POB_SET pvs);

/*
* Remove the "last" value in a way that is safe for concurrent iterations of
* values in the set.
* -- pvs
* -- return = success: value, fail: 0.
*/
QWORD ObSet_Pop(_In_opt_ POB_SET pvs);

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
QWORD ObSet_GetNext(_In_opt_ POB_SET pvs, _In_ QWORD value);

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
QWORD ObSet_GetNextByIndex(_In_opt_ POB_SET pvs, _Inout_ PDWORD pdwIndex);

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
QWORD ObSet_Get(_In_opt_ POB_SET pvs, _In_ DWORD index);

/*
* Retrieve all values in the Set as a POB_DATA object containing the values
* in a QWORD table.
* -- CALLER DECREF: return
* -- pvs
* -- return
*/
POB_DATA ObSet_GetAll(_In_opt_ POB_SET pvs);



// ----------------------------------------------------------------------------
// MAP FUNCTIONALITY BELOW:
//
// The map is a key-value map that may, as an option, contain object manager
// objects in its value field. They key may be user-defined, generated by a
// function or absent. The ObMap may hold a maximum capacity of 0x02000000
// (~32M) entries which are UNIQUE and non-NULL.
//
// The map (ObMap) is thread safe and implement efficient access to the data
// via internal hashing functionality.
// The map (ObMap) guarantees order amongst values unless the ObMap_Remove*
// functions are called - in which order may change and on-going iterations
// of the set with ObMap_Get/ObMap_GetNext may fail.
// The ObMap is an object manager object and must be DECREF'ed when required.
// ----------------------------------------------------------------------------

typedef struct tdOB_MAP *POB_MAP;

#define OB_MAP_FLAGS_OBJECT_VOID        0x00
#define OB_MAP_FLAGS_OBJECT_OB          0x01
#define OB_MAP_FLAGS_OBJECT_LOCALFREE   0x02
#define OB_MAP_FLAGS_NOKEY              0x04

typedef struct tdOB_MAP_ENTRY {
    QWORD k;
    union { PVOID v; QWORD _Filler; };
} OB_MAP_ENTRY, *POB_MAP_ENTRY, **PPOB_MAP_ENTRY;

/*
* Create a new map. A map (ObMap) provides atomic map operations and ways
* to optionally map key values to values, pointers or object manager objects.
* The ObMap is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- H
* -- flags = defined by OB_MAP_FLAGS_*
* -- return
*/
POB_MAP ObMap_New(_In_opt_ VMM_HANDLE H, _In_ QWORD flags);

/*
* Retrieve the number of objects in the ObMap.
* -- pm
* -- return
*/
DWORD ObMap_Size(_In_opt_ POB_MAP pm);

/*
* Check if an object exists in the ObMap.
* -- pm
* -- qwKey/pvObject
* -- return
*/
BOOL ObMap_Exists(_In_opt_ POB_MAP pm, _In_ PVOID pvObject);

/*
* Check if a key exists in the ObMap.
* -- pm
* -- qwKey/pvObject
* -- return
*/
BOOL ObMap_ExistsKey(_In_opt_ POB_MAP pm, _In_ QWORD qwKey);

/*
* Push / Insert into the ObMap.
* If pvObject is OB the map performs Ob_INCREF on its own reference.
* -- pm
* -- qwKey
* -- pvObject
* -- return = TRUE on insertion, FALSE otherwise - i.e. if the key or object
*             already exists or if the max capacity of the map is reached.
*/
_Success_(return)
BOOL ObMap_Push(_In_opt_ POB_MAP pm, _In_ QWORD qwKey, _In_ PVOID pvObject);

/*
* Push / Insert into the ObMap by making a shallow copy of the object.
* NB! only valid for OB_MAP_FLAGS_OBJECT_LOCALFREE initialized maps.
* -- pm
* -- qwKey
* -- pvObject
* -- cbObject
* -- return = TRUE on insertion, FALSE otherwise - i.e. if the key or object
*             already exists or if the max capacity of the map is reached.
*/
_Success_(return)
BOOL ObMap_PushCopy(_In_opt_ POB_MAP pm, _In_ QWORD qwKey, _In_ PVOID pvObject, _In_ SIZE_T cbObject);

/*
* Push / Insert all objects in pmSrc to pmDst using the same key and value.
* NB! only valid for OB_MAP_FLAGS_OBJECT_OB and OB_MAP_FLAGS_OBJECT_VOID maps.
* -- pmDst
* -- pmSrc
* -- return = TRUE on success, FALSE otherwise.
*/
_Success_(return)
BOOL ObMap_PushAll(_In_opt_ POB_MAP pmDst, _In_ POB_MAP pmSrc);

/*
* Remove the "last" object.
* CALLER DECREF(if OB): return
* -- pm
* -- return = success: object, fail: NULL.
*/
_Success_(return != NULL)
PVOID ObMap_Pop(_In_opt_ POB_MAP pm);

/*
* Remove the "last" object and return it and its key.
* CALLER DECREF(if OB): return
* -- pm
* -- pKey
* -- return = success: object, fail: NULL.
*/
_Success_(return != NULL)
PVOID ObMap_PopWithKey(_In_opt_ POB_MAP pm, _Out_opt_ PQWORD pKey);

/*
* Remove an object from the ObMap.
* NB! must not be called simultaneously while iterating with ObMap_GetByIndex/ObMap_GetNext.
* CALLER DECREF(if OB): return
* -- pm
* -- value
* -- return = success: object, fail: NULL.
*/
PVOID ObMap_Remove(_In_opt_ POB_MAP pm, _In_ PVOID pvObject);

/*
* Remove an object from the ObMap by using its key.
* NB! must not be called simultaneously while iterating with ObMap_GetByIndex/ObMap_GetNext.
* CALLER DECREF(if OB): return
* -- pm
* -- qwKey
* -- return = success: object, fail: NULL.
*/
PVOID ObMap_RemoveByKey(_In_opt_ POB_MAP pm, _In_ QWORD qwKey);

/*
* Clear the ObMap by removing all objects and their keys.
* NB! underlying allocated memory will remain unchanged.
* -- pm
* -- return = clear was successful - always true.
*/
_Success_(return)
BOOL ObMap_Clear(_In_opt_ POB_MAP pm);

/*
* Peek the "last" object.
* CALLER DECREF(if OB): return
* -- pm
* -- return = success: object, fail: NULL.
*/
PVOID ObMap_Peek(_In_opt_ POB_MAP pm);

/*
* Peek the key of the "last" object.
* -- pm
* -- return = the key, otherwise 0.
*/
QWORD ObMap_PeekKey(_In_opt_ POB_MAP pm);

/*
* Retrieve the next object given an object. Start and end objects are NULL.
* NB! Correctness of the Get/GetNext functionality is _NOT_ guaranteed if the
* ObMap_Remove* functions are called while iterating over the ObMap - items may
* be skipped or iterated over multiple times!
* FUNCTION DECREF(if OB): pvObject
* CALLER DECREF(if OB): return
* -- pm
* -- pvObject
* -- return
*/
PVOID ObMap_GetNext(_In_opt_ POB_MAP pm, _In_opt_ PVOID pvObject);

/*
* Retrieve the next object given a key. To start iterating supply NULL in the
* pvObject parameter (this overrides qwKey). When no more objects are found
* NULL will be returned. This function may ideally be used when object maps
* may be refreshed between function calls. Key may be more stable than object.
* NB! Correctness of the Get/GetNext functionality is _NOT_ guaranteed if the
* ObMap_Remove* functions are called while iterating over the ObMap - items may
* be skipped or iterated over multiple times!
* FUNCTION DECREF(if OB): pvObject
* CALLER DECREF(if OB): return
* -- pm
* -- qwKey
* -- pvObject
* -- return
*/
PVOID ObMap_GetNextByKey(_In_opt_ POB_MAP pm, _In_ QWORD qwKey, _In_opt_ PVOID pvObject);

/*
* Retrieve the next object given a key in a map sorted by key. If the key isn't
* found the next object with a larger key will be returned. To start iterating
* supply zero (0) in the qwKey parameter. When no more objects are found NULL
* will be returned.
* NB! Correctness is only guarateed if the map is sorted by key ascending.
* FUNCTION DECREF(if OB): pvObject
* CALLER DECREF(if OB): return
* -- pm
* -- qwKey
* -- pvObject
* -- return
*/
PVOID ObMap_GetNextByKeySorted(_In_opt_ POB_MAP pm, _In_ QWORD qwKey, _In_opt_ PVOID pvObject);

/*
* Iterate over objects in reversed index order. To start iterating supply NULL
* in the pvObject parameter (this overrides pdwIndex). When no more objects
* are found NULL will be returned.
* Add/Remove rules:
*  - Added objects are ok - but will not be iterated over.
*  - Removal of current object and already iterated objects are ok.
*  - Removal of objects not yet iterated is FORBIDDEN. It causes the iterator
*    fail by returning the same object multiple times or skipping objects.
* FUNCTION DECREF(if OB): pvObject
* CALLER DECREF(if OB): return
* -- pm
* -- pdwIndex
* -- pvObject
* -- return
*/
PVOID ObMap_GetNextByIndex(_In_opt_ POB_MAP pm, _Inout_ PDWORD pdwIndex, _In_opt_ PVOID pvObject);

/*
* Retrieve a value given a key.
* CALLER DECREF(if OB): return
* -- pm
* -- qwKey
* -- return
*/
PVOID ObMap_GetByKey(_In_opt_ POB_MAP pm, _In_ QWORD qwKey);

/*
* Retrieve an object given an index (which is less than the amount of items
* in the ObMap).
* NB! Correctness of the Get/GetNext functionality is _NOT- guaranteed if the
* ObMap_Remove* functions are called while iterating over the ObSet - items
* may be skipped or iterated over multiple times!
* CALLER DECREF(if OB): return
* -- pm
* -- index
* -- return
*/
PVOID ObMap_GetByIndex(_In_opt_ POB_MAP pm, _In_ DWORD index);

/*
* Retrieve the key for an existing object in the ObMap.
* -- pm
* -- pvObject
* -- return
*/
_Success_(return != 0)
QWORD ObMap_GetKey(_In_opt_ POB_MAP pm, _In_ PVOID pvObject);

/*
* Callback function for ObMap_Filter which converts a ObMap to an arbitrary context.
*/
typedef VOID(*OB_MAP_FILTER_PFN_CB)(_In_opt_ PVOID ctx, _In_ QWORD k, _In_ PVOID v);

/*
* Callback function for ObMap_FilterSet which converts an ObMap to an ObSet.
*/
typedef VOID(*OB_MAP_FILTERSET_PFN_CB)(_In_opt_ PVOID ctx, _In_ POB_SET ps, _In_ QWORD k, _In_ PVOID v);

/*
* Callback function for ObMap_RemoveByFilter which removes objects from an ObMap.
*/
typedef BOOL(*OB_MAP_FILTER_REMOVE_PFN_CB)(_In_opt_ PVOID ctx, _In_ QWORD k, _In_ PVOID v);

/*
* Common filter function related to ObMap_FilterSet.
*/
VOID ObMap_FilterSet_FilterAllKey(_In_opt_ PVOID ctx, _In_ POB_SET ps, _In_ QWORD k, _In_ PVOID v);

/*
* Filter map objects into a generic context by using a user-supplied filter function.
* -- pm
* -- ctx = optional context to pass on to the filter function.
* -- pfnFilterCB = filter callback function. NULL = fail.
* -- return
*/
_Success_(return)
BOOL ObMap_Filter(_In_opt_ POB_MAP pm, _In_opt_ PVOID ctx, _In_opt_ OB_MAP_FILTER_PFN_CB pfnFilterCB);

/*
* Filter map objects into a POB_SET by using a user-supplied filter function.
* CALLER DECREF: return
* -- pm
* -- ctx = optional context to pass on to the filter function.
* -- pfnFilterSetCB = filter callback function. NULL = fail.
* -- return = POB_SET consisting of values gathered by the pfnFilter function.
*/
_Success_(return != NULL)
POB_SET ObMap_FilterSet(_In_opt_ POB_MAP pm, _In_opt_ PVOID ctx, _In_opt_ OB_MAP_FILTERSET_PFN_CB pfnFilterSetCB);

/*
* Remove map objects using a user-supplied filter function.
* -- pm
* -- ctx = optional context to pass on to the filter function.
* -- pfnFilterRemoveCB = decision making function: [pfnFilter(ctx,k,v)->TRUE(remove)|FALSE(keep)]
* -- return = number of entries removed.
*/
DWORD ObMap_RemoveByFilter(_In_opt_ POB_MAP pm, _In_opt_ PVOID ctx, _In_opt_ OB_MAP_FILTER_REMOVE_PFN_CB pfnFilterRemoveCB);

/*
* Sort compare callback function.
*/
typedef int(*OB_MAP_SORT_COMPARE_FUNCTION)(_In_ POB_MAP_ENTRY e1, _In_ POB_MAP_ENTRY e2);

/*
* Sort the ObMap entry index by a sort compare function.
* NB! The items sorted by the sort function are const OB_MAP_ENTRY* objects
*     which points to the underlying map object key/value.
* -- pm
* -- pfnSort = sort function callback. const void* == const OB_MAP_ENTRY*
* -- return
*/
_Success_(return)
BOOL ObMap_SortEntryIndex(_In_opt_ POB_MAP pm, _In_ OB_MAP_SORT_COMPARE_FUNCTION pfnSort);

/*
* Sort the ObMap entry index by key ascending.
* NB! The items sorted by the sort function are const OB_MAP_ENTRY* objects
*     which points to the underlying map object key/value.
* -- pm
* -- return
*/
_Success_(return)
BOOL ObMap_SortEntryIndexByKey(_In_opt_ POB_MAP pm);



// ----------------------------------------------------------------------------
// CACHE MAP FUNCTIONALITY BELOW:
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
// ----------------------------------------------------------------------------

typedef struct tdOB_CACHEMAP *POB_CACHEMAP;

#define OB_CACHEMAP_FLAGS_OBJECT_VOID        0x00
#define OB_CACHEMAP_FLAGS_OBJECT_OB          0x01
#define OB_CACHEMAP_FLAGS_OBJECT_LOCALFREE   0x02

/*
* Callback function for the pfnValidEntry in ObCacheMap_New()
* -- H
* -- qwContext
* -- qwKey
* -- pbObject
*/
typedef BOOL(*OB_CACHEMAP_VALIDENTRY_PFN_CB)(
    _In_opt_ VMM_HANDLE H,
    _Inout_ PQWORD qwContext,
    _In_ QWORD qwKey,
    _In_ PVOID pvObject
);

/*
* Create a new cached map. A cached map (ObCacheMap) provides atomic map
* operations on cached objects.
* The ObCacheMap is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- H
* -- cMaxEntries = max entries in the cache, if more entries are added the
*       least recently accessed item will be removed from the cache map.
* -- pfnValidEntry = validation callback function (if any).
* -- flags = defined by OB_CACHEMAP_FLAGS_*
* -- return
*/
POB_CACHEMAP ObCacheMap_New(
    _In_opt_ VMM_HANDLE H,
    _In_ DWORD cMaxEntries,
    _In_opt_ OB_CACHEMAP_VALIDENTRY_PFN_CB pfnValidEntry,
    _In_ QWORD flags
);

/*
* Clear the ObCacheMap by removing all objects and their keys.
* -- pcm
* -- return = clear was successful - always true.
*/
_Success_(return)
BOOL ObCacheMap_Clear(_In_opt_ POB_CACHEMAP pcm);

/*
* Check if a key exists in the ObCacheMap.
* -- pcm
* -- qwKey/pvObject
* -- return
*/
BOOL ObCacheMap_ExistsKey(_In_opt_ POB_CACHEMAP pcm, _In_ QWORD qwKey);

/*
* Push / Insert into the ObCacheMap. If an object with the same key already
* exists it's removed from the cache map before the new object is inserted.
* If pvObject is OB the map performs Ob_INCREF on its own reference.
* -- pcm
* -- qwKey
* -- pvObject
* -- qwContextInitial = initial context (passed on to pfnValidEntry callback).
* -- return = TRUE on insertion, FALSE otherwise - i.e. if the key or object
*             already exists or if the max capacity of the map is reached.
*/
_Success_(return)
BOOL ObCacheMap_Push(_In_opt_ POB_CACHEMAP pcm, _In_ QWORD qwKey, _In_ PVOID pvObject, _In_ QWORD qwContextInitial);

/*
* Retrieve the number of objects in the ObCacheMap.
* -- pcm
* -- return
*/
DWORD ObCacheMap_Size(_In_opt_ POB_CACHEMAP pcm);

/*
* Retrieve a value given a key.
* CALLER DECREF(if OB): return
* -- pcm
* -- qwKey
* -- return
*/
PVOID ObCacheMap_GetByKey(_In_opt_ POB_CACHEMAP pcm, _In_ QWORD qwKey);

/*
* Remove an object from the ObCacheMap by using its key.
* NB! Object is removed and returned even if valid critera is not matched.
* CALLER DECREF(if OB): return
* -- pcm
* -- qwKey
* -- return = success: object, fail: NULL.
*/
PVOID ObCacheMap_RemoveByKey(_In_opt_ POB_CACHEMAP pcm, _In_ QWORD qwKey);


// ----------------------------------------------------------------------------
// STRMAP FUNCTIONALITY BELOW:
// 
// The strmap is created and populated with strings (utf-8, ascii and wide-char)
// in an optimal way removing duplicates. Upon finalization the string map
// results in a multi-string and an update of string references will happen.
//
// References to the strings will only be valid after a successful call to
// FinalizeAlloc_DECREF_NULL() or FinalizeBuffer()
//
// The strmap is only meant to be an interim object to be used for creation
// of multi-string values and should not be kept as a long-lived object.
//
// The ObStrMap is an object manager object and must be DECREF'ed when required.
// ----------------------------------------------------------------------------

typedef struct tdOB_STRMAP *POB_STRMAP;

// Strings in OB_STRMAP are considered to be CASE SENSITIVE.
#define OB_STRMAP_FLAGS_CASE_SENSITIVE         0x00

// Strings in OB_STRMAP are considered to be CASE INSENSITIVE. The case is
// preserved for 1st unique entry added; subsequent entries will use 1st entry.
#define OB_STRMAP_FLAGS_CASE_INSENSITIVE       0x01

// Assign temporary string values to destinations at time of push.
// NB! values will become invalid after OB_STRMAP DECREF/FINALIZE!
#define OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY   0x02

// Assign offset in number of bytes to string pointers at finalize stage
// instead of pointers. Offset is counted from base of multi-string.
// incompatible with OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY option.
#define OB_STRMAP_FLAGS_STR_ASSIGN_OFFSET      0x04

// Read UNICODE OBJECT data from another process than SYSTEM (4).
// PID is specified in flags high 32-bits.
#define OB_STRMAP_FLAGS_WITH_PROCESS_PID       0x08

//
// STRMAP BELOW:
//

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- usz
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushU(_In_opt_ POB_STRMAP psm, _In_opt_ LPCSTR usz);

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- sz
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushA(_In_opt_ POB_STRMAP psm, _In_opt_ LPCSTR sz);

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- wsz
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushW(_In_opt_ POB_STRMAP psm, _In_opt_ LPCWSTR wsz);

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- usz
* -- puszDst
* -- pcbuDst
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushPtrUU(_In_opt_ POB_STRMAP psm, _In_opt_ LPCSTR usz, _Out_opt_ LPSTR *puszDst, _Out_opt_ PDWORD pcbuDst);

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- sz
* -- puszDst
* -- pcbuDst
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushPtrAU(_In_opt_ POB_STRMAP psm, _In_opt_ LPCSTR sz, _Out_opt_ LPSTR *puszDst, _Out_opt_ PDWORD pcbuDst);

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- wsz
* -- puszDst
* -- pcbuDst
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushPtrWU(_In_opt_ POB_STRMAP psm, _In_opt_ LPCWSTR wsz, _Out_opt_ LPSTR *puszDst, _Out_opt_ PDWORD pcbuDst);

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- usz
* -- pwszDst
* -- pcbwDst
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushPtrUW(_In_opt_ POB_STRMAP psm, _In_opt_ LPCSTR usz, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcbwDst);

/*
* Push / Insert into the ObStrMap.
* -- psm
* -- wsz
* -- pwszDst
* -- pcbwDst
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushPtrWW(_In_opt_ POB_STRMAP psm, _In_opt_ LPCWSTR wsz, _Out_opt_ LPWSTR *pwszDst, _Out_opt_ PDWORD pcbwDst);

/*
* Push / Insert into the ObStrMap. Result pointer is dependant on fWideChar flag.
* -- psm
* -- usz
* -- puszDst = ptr to utf-8 _OR_ wide string depending on fWideChar
* -- pcbuDst = # bytes required to hold *puszDst
* -- fWideChar
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushPtrUXUW(_In_opt_ POB_STRMAP psm, _In_opt_ LPCSTR usz, _Out_opt_ LPSTR *puszDst, _Out_opt_ PDWORD pcbuDst, BOOL fWideChar);

/*
* Push a UNICODE_OBJECT Pointer for delayed resolve at finalize stage.
* NB! Incompatible with: OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY create flag.
* -- psm
* -- f32 = 32-bit/64-bit unicode object.
* -- vaUnicodeObject
* -- puszDst
* -- pcbuDst
* -- return = TRUE on validation success (NB! no guarantee for final success).
*/
_Success_(return)
BOOL ObStrMap_Push_UnicodeObject(_In_opt_ POB_STRMAP psm, _In_ BOOL f32, _In_ QWORD vaUnicodeObject, _Out_opt_ LPSTR *puszDst, _Out_opt_ PDWORD pcbuDst);

/*
* Push a UNICODE_OBJECT Buffer for delayed resolve at finalize stage.
* NB! Incompatible with: OB_STRMAP_FLAGS_STR_ASSIGN_TEMPORARY create flag.
* -- psm
* -- cbUnicodeBuffer.
* -- vaUnicodeBuffer
* -- puszDst
* -- pcbuDst
* -- return = TRUE on validation success (NB! no guarantee for final success).
*/
_Success_(return)
BOOL ObStrMap_Push_UnicodeBuffer(_In_opt_ POB_STRMAP psm, _In_ WORD cbUnicodeBuffer, _In_ QWORD vaUnicodeBuffer, _Out_opt_ LPSTR *puszDst, _Out_opt_ PDWORD pcbuDst);

/*
* Push / Insert max 2048 char-bytes into ObStrMap using a snprintf_s syntax.
* All szFormat and all string-arguments are assumed to be utf-8 encoded.
* -- psm
* -- puszDst
* -- pcbuDst
* -- uszFormat
* -- ...
* -- return = TRUE on insertion, FALSE otherwise.
*/
_Success_(return)
BOOL ObStrMap_PushUU_snprintf_s(_In_opt_ POB_STRMAP psm, _Out_opt_ LPSTR *puszDst, _Out_opt_ PDWORD pcbuDst, _In_z_ _Printf_format_string_ char const *const uszFormat, ...);

/*
* Finalize the ObStrMap. Create and assign the MultiStr and assign each
* previously added string reference to a pointer location within the MultiStr.
* ---
* Also decrease the reference count of the object. If the reference count
* reaches zero the object will be cleaned up.
* Also set the incoming pointer to NULL.
* CALLER LOCALFREE: *ppbMultiStr
* -- ppObStrMap
* -- ppbMultiStr
* -- pcbMultiStr
* -- return
*/
_Success_(return)
BOOL ObStrMap_FinalizeAllocU_DECREF_NULL(_In_opt_ POB_STRMAP *ppObStrMap, _Out_ PBYTE *ppbMultiStr, _Out_ PDWORD pcbMultiStr);

/*
* Finalize the ObStrMap. Create and assign the MultiStr and assign each
* previously added string reference to a pointer location within the MultiStr.
* ---
* Also decrease the reference count of the object. If the reference count
* reaches zero the object will be cleaned up.
* Also set the incoming pointer to NULL.
* CALLER LOCALFREE: *ppbMultiStr
* -- ppObStrMap
* -- ppbMultiStr
* -- pcbMultiStr
* -- return
*/
_Success_(return)
BOOL ObStrMap_FinalizeAllocW_DECREF_NULL(_In_opt_ POB_STRMAP *ppObStrMap, _Out_ PBYTE *ppbMultiStr, _Out_ PDWORD pcbMultiStr);

/*
* Finalize the ObStrMap. Write the MultiStr into the supplied buffer and assign
* previously added string reference to a pointer location within the MultiStr.
* -- psm
* -- cbuMultiStr
* -- pbMultiStr = NULL for size query
* -- pcbMultiStr
* -- return
*/
_Success_(return)
BOOL ObStrMap_FinalizeBufferU(_In_opt_ POB_STRMAP psm, _In_ DWORD cbMultiStr, _Out_writes_bytes_opt_(cbMultiStr) PBYTE pbMultiStr, _Out_ PDWORD pcbMultiStr);

/*
* Finalize the ObStrMap. Write the MultiStr into the supplied buffer and assign
* previously added string reference to a pointer location within the MultiStr.
* -- psm
* -- cbMultiStr
* -- pbMultiStr = NULL for size query
* -- pcbMultiStr
* -- return
*/
_Success_(return)
BOOL ObStrMap_FinalizeBufferW(_In_opt_ POB_STRMAP psm, _In_ DWORD cbMultiStr, _Out_writes_bytes_opt_(cbMultiStr) PBYTE pbMultiStr, _Out_ PDWORD pcbMultiStr);

/*
* Finalize the ObStrMap as either UTF-8 or Wide. Write the MultiStr into the
* supplied buffer and assign previously added string reference to a pointer
* location within the MultiStr.
* -- psm
* -- cbMultiStr
* -- pbMultiStr = NULL for size query
* -- pcbMultiStr
* -- fWideChar
* -- return
*/
_Success_(return)
BOOL ObStrMap_FinalizeBufferXUW(_In_opt_ POB_STRMAP psm, _In_ DWORD cbMultiStr, _Out_writes_bytes_opt_(cbMultiStr) PBYTE pbMultiStr, _Out_ PDWORD pcbMultiStr, _In_ BOOL fWideChar);

/*
* Create a new strmap. A strmap (ObStrMap) provides an easy way to add new
* strings to a multi-string in an efficient way. The ObStrMap is not meant
* to be a long-term object - it's supposed to be finalized and possibly
* decommissioned by calling any of the ObStrMap_Finalize*() functions.
* The ObStrMap is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- H
* -- flags
* -- return
*/
_Success_(return != NULL)
POB_STRMAP ObStrMap_New(_In_opt_ VMM_HANDLE H, _In_ QWORD flags);



// ----------------------------------------------------------------------------
// COMPRESSED DATA OBJECT FUNCTIONALITY BELOW:
//
// The ObCompressed is an object manager object and must be DECREF'ed when required.
// ----------------------------------------------------------------------------

typedef struct tdOB_COMPRESSED *POB_COMPRESSED;

#define OB_COMPRESSED_CACHED_ENTRIES_MAX        0x40
#define OB_COMPRESSED_CACHED_ENTRIES_MAXSIZE    0x00100000

/*
* Create a new compressed buffer object from a byte buffer.
* It's strongly recommended to supply a global cache map to use.
* CALLER DECREF: return
* -- H
* -- pcmg = optional global (per VMM_HANDLE) cache map to use.
* -- pb
* -- cb
* -- return
*/
_Success_(return != NULL)
POB_COMPRESSED ObCompressed_NewFromByte(_In_opt_ VMM_HANDLE H, _In_opt_ POB_CACHEMAP pcmg, _In_reads_(cb) PBYTE pb, _In_ DWORD cb);

/*
* Create a new compressed buffer object from a zero terminated string.
* It's strongly recommended to supply a global cache map to use.
* CALLER DECREF: return
* -- H
* -- pcmg = optional global (per VMM_HANDLE) cache map to use.
* -- sz
* -- return
*/
_Success_(return != NULL)
POB_COMPRESSED ObCompress_NewFromStrA(_In_opt_ VMM_HANDLE H, _In_opt_ POB_CACHEMAP pcmg, _In_ LPCSTR sz);

/*
* Retrieve the uncompressed size of the compressed data object.
* -- pdc
* -- return
*/
DWORD ObCompress_Size(_In_opt_ POB_COMPRESSED pdc);

/*
* Retrieve uncompressed from a compressed data object.
* CALLER DECREF: return
* -- pdc
* -- return
*/
_Success_(return != NULL)
POB_DATA ObCompressed_GetData(_In_opt_ POB_COMPRESSED pdc);



// ----------------------------------------------------------------------------
// MEMORY BACKED FILE FUNCTIONALITY BELOW:
// 
// The memfile is a growing memory backed file that may be read and appended.
// The memfile will be automatically (de)compressed when it's required for
// optimal performance. This object is typically implementing a generated
// output file - such as some forensic JSON data output.
//
// The ObMemFile is an object manager object and must be DECREF'ed when required.
// ----------------------------------------------------------------------------

typedef struct tdOB_MEMFILE *POB_MEMFILE;

/*
* Create a new empty memory file.
* It's strongly recommended to supply a global cache map to use.
* CALLER DECREF: return
* -- H
* -- pcmg = optional global (per VMM_HANDLE) cache map to use.
* -- return
*/
_Success_(return != NULL)
POB_MEMFILE ObMemFile_New(_In_opt_ VMM_HANDLE H, _In_opt_ POB_CACHEMAP pcmg);

/*
* Retrieve byte count of the ObMemFile.
* -- pmf
* -- return
*/
QWORD ObMemFile_Size(_In_opt_ POB_MEMFILE pmf);

/*
* Append binary data to the ObMemFile.
* -- pmf
* -- pb
* -- cb
* -- return
*/
_Success_(return)
BOOL ObMemFile_Append(_In_opt_ POB_MEMFILE pmf, _In_reads_(cb) PBYTE pb, _In_ QWORD cb);

/*
* Append a string (ansi or utf-8) to the ObMemFile.
* -- pmf
* -- sz
* -- return
*/
_Success_(return)
BOOL ObMemFile_AppendString(_In_opt_ POB_MEMFILE pmf, _In_opt_z_ LPCSTR sz);

/*
* Append a string (ansi or utf-8) to the ObMemFile.
* -- H
* -- uszFormat
* -- ...
* -- return = the number of bytes appended (excluding terminating null).
*/
_Success_(return != 0)
SIZE_T ObMemFile_AppendStringEx(_In_opt_ POB_MEMFILE pmf, _In_z_ _Printf_format_string_ LPCSTR uszFormat, ...);

/*
* Append a string (ansi or utf-8) to the ObMemFile.
* -- H
* -- uszFormat
* -- arglist
* -- return = the number of bytes appended (excluding terminating null).
*/
_Success_(return != 0)
SIZE_T ObMemFile_AppendStringEx2(_In_opt_ POB_MEMFILE pmf, _In_z_ _Printf_format_string_ LPCSTR uszFormat, _In_ va_list arglist);

/*
* Read data 'as file' from the ObMemFile.
* -- pmf
* -- pb
* -- cb
* -- pcbRad
* -- cbOffset
* -- return
*/
_Success_(return == 0)
NTSTATUS ObMemFile_ReadFile(_In_opt_ POB_MEMFILE pmf, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);



// ----------------------------------------------------------------------------
// COUNTER FUNCTIONALITY BELOW
// 
// The counter is a auto-growing object that allows counting an unknown amount
// of objects. Counting operations are thread-safe and atomic.
// 
// When counting is completed the counted objects may be retrieved sorted.
//
// The ObCounter is an object manager object and must be DECREF'ed when required.
// ----------------------------------------------------------------------------

typedef struct tdOB_COUNTER *POB_COUNTER;

typedef struct tdOB_COUNTER_ENTRY {
    QWORD k;
    QWORD v;
} OB_COUNTER_ENTRY, *POB_COUNTER_ENTRY, **PPOB_COUNTER_ENTRY;

#define OB_COUNTER_FLAGS_SHOW_ZERO      0x01
#define OB_COUNTER_FLAGS_ALLOW_NEGATIVE 0x02

/*
* Create a new counter. A counter (ObCounter) provides atomic counting operations.
* The ObCounter is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- H
* -- flags = defined by OB_COUNTER_FLAGS_*
* -- return
*/
POB_COUNTER ObCounter_New(_In_opt_ VMM_HANDLE H, _In_ QWORD flags);

/*
* Clear the ObCounter by removing all counts and keys.
* NB! underlying allocated memory will remain unchanged.
* -- pm
* -- return = clear was successful - always true.
*/
_Success_(return)
BOOL ObCounter_Clear(_In_opt_ POB_COUNTER pc);

/*
* Retrieve the number of counted keys the ObCounter.
* -- pc
* -- return
*/
DWORD ObCounter_Size(_In_opt_ POB_COUNTER pc);

/*
* Retrieve the total count of the ObCounter.
* NB! The resulting count may overflow on large counts!
* -- pc
* -- return
*/
QWORD ObCounter_CountAll(_In_opt_ POB_COUNTER pc);

/*
* Check if the counted key exists in the ObCounter.
* -- pc
* -- k
* -- return
*/
BOOL ObCounter_Exists(_In_opt_ POB_COUNTER pc, _In_ QWORD k);

/*
* Get the count of a specific key.
* -- pc
* -- k
* -- return = the counted value after the action, zero on fail.
*/
QWORD ObCounter_Get(_In_opt_ POB_COUNTER pc, _In_ QWORD k);

/*
* Remove a specific key.
* -- pc
* -- k
* -- return = the count of the removed key, zero in fail.
*/
QWORD ObCounter_Del(_In_opt_ POB_COUNTER pc, _In_ QWORD k);

/*
* Set the count of a specific key.
* -- pc
* -- k
* -- v
* -- return = the counted value after the action, zero on fail.
*/
QWORD ObCounter_Set(_In_opt_ POB_COUNTER pc, _In_ QWORD k, _In_ QWORD v);

/*
* Add the count v of a specific key.
* -- pc
* -- k
* -- v
* -- return = the counted value after the action, zero on fail.
*/
QWORD ObCounter_Add(_In_opt_ POB_COUNTER pc, _In_ QWORD k, _In_ QWORD v);

/*
* Increment the count of a specific key with 1.
* -- pc
* -- k
* -- return = the counted value after the action, zero on fail.
*/
QWORD ObCounter_Inc(_In_opt_ POB_COUNTER pc, _In_ QWORD k);

/*
* Subtract the count v of a specific key.
* -- pc
* -- k
* -- v
* -- return = the counted value after the action, zero on fail.
*/
QWORD ObCounter_Sub(_In_opt_ POB_COUNTER pc, _In_ QWORD k, _In_ QWORD v);

/*
* Decrement the count of a specific key with 1.
* -- pc
* -- k
* -- return = the counted value after the action, zero on fail.
*/
QWORD ObCounter_Dec(_In_opt_ POB_COUNTER pc, _In_ QWORD k);

/*
* Retrieve all counts in an unsorted table.
* -- pc
* -- cEntries
* -- pEntries
* -- return
*/
_Success_(return)
BOOL ObCounter_GetAll(_In_opt_ POB_COUNTER pc, _In_ DWORD cEntries, _Out_writes_opt_(cEntries) POB_COUNTER_ENTRY pEntries);

/*
* Retrieve all counts in a sorted table.
* -- pc
* -- cEntries
* -- pEntries
* -- return
*/
_Success_(return)
BOOL ObCounter_GetAllSortedByKey(_In_opt_ POB_COUNTER pc, _In_ DWORD cEntries, _Out_writes_opt_(cEntries) POB_COUNTER_ENTRY pEntries);

/*
* Retrieve all counts in a sorted table.
* -- pc
* -- cEntries
* -- pEntries
* -- return
*/
_Success_(return)
BOOL ObCounter_GetAllSortedByCount(_In_opt_ POB_COUNTER pc, _In_ DWORD cEntries, _Out_writes_opt_(cEntries) POB_COUNTER_ENTRY pEntries);

/*
* Remove the "last" count.
* -- pc
* -- return = success: count, fail: 0.
*/
_Success_(return != 0)
QWORD ObCounter_Pop(_In_opt_ POB_COUNTER pc);

/*
* Remove the "last" count and return it and its key.
* -- pc
* -- pKey
* -- return = success: count, fail: 0.
*/
_Success_(return != 0)
QWORD ObCounter_PopWithKey(_In_opt_ POB_COUNTER pc, _Out_opt_ PQWORD pKey);



// ----------------------------------------------------------------------------
// BYTE QUEUE FUNCTIONALITY BELOW
//
// The byte queue contains a fixed number of bytes as buffer. The queue size
// is defined at queue creation and cannot be changed.
// Bytes in the form of packets [pb, cb, tag] is pushed on the queue as long
// as there is available space.
// Bytes may be popped from the queue. This will also free up space for more
// bytes to be pushed on the queue.
// The bytes queue is FIFO and will always pop the oldest bytes first.
// The ObByteQueue is an object manager object and must be DECREF'ed when required.
// ----------------------------------------------------------------------------

typedef struct tdOB_BYTEQUEUE *POB_BYTEQUEUE;

/*
* Retrieve the number of packets (not bytes) in the byte queue.
* -- pq
* -- return
*/
DWORD ObByteQueue_Size(_In_opt_ POB_BYTEQUEUE pq);

/*
* Peek data from the byte queue. The data is copied into the user-supplied buffer.
* If the buffer is insufficient the function will return FALSE and the required
* size will be returned in pcbRead.
* -- pq
* -- pqwTag
* -- cb
* -- pb
* -- pcbRead
* -- return = TRUE if there was data to peek, FALSE otherwise.
*/
_Success_(return)
BOOL ObByteQueue_Peek(_In_opt_ POB_BYTEQUEUE pq, _Out_opt_ QWORD * pqwTag, _In_ SIZE_T cb, _Out_ PBYTE pb, _Out_ SIZE_T * pcbRead);

/*
* Pop data from the byte queue. The data is copied into the user-supplied buffer.
* If the buffer is insufficient the function will return FALSE and the required
* size will be returned in pcbRead.
* -- pq
* -- pqwTag
* -- cb
* -- pb
* -- pcbRead
* -- return = TRUE if there was data to pop, FALSE otherwise.
*/
_Success_(return)
BOOL ObByteQueue_Pop(_In_opt_ POB_BYTEQUEUE pq, _Out_opt_ QWORD * pqwTag, _In_ SIZE_T cb, _Out_ PBYTE pb, _Out_ SIZE_T * pcbRead);

/*
* Push / Insert into the ObByteQueue. The data is copied into the queue.
* -- pq
* -- qwTag
* -- cb
* -- pb
* -- return = TRUE on insertion, FALSE otherwise - i.e. if the byte queue
*             is insufficient to hold the byte data.
*/
_Success_(return)
BOOL ObByteQueue_Push(_In_opt_ POB_BYTEQUEUE pq, _In_opt_ QWORD qwTag, _In_ SIZE_T cb, _In_reads_bytes_(cb) PBYTE pb);

/*
* Create a new byte queue. A byte queue (ObByteQueue) provides atomic queuing
* operations for pushing/popping bytes as packets on a FIFO queue.
* The ObByteQueue is an object manager object and must be DECREF'ed when required.
* CALLER DECREF: return
* -- H
* -- cbQueueSize = the queue size in bytes. Must be larger than 4096 bytes.
* -- return
*/
POB_BYTEQUEUE ObByteQueue_New(_In_opt_ VMM_HANDLE H, _In_ DWORD cbQueueSize);

#endif /* __OB_H__ */
