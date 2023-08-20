// vmmyara.h : External headers of the YARA API wrapper for MemProcFS.
//
// (c) Ulf Frisk, 2023
// Author: Ulf Frisk, pcileech@frizk.net
//
//
// VmmYara is a library that provides a YARA API wrapper for C/C++ projects
// and is used by MemProcFS to provide YARA scanning of memory dumps.
//
// For more information please consult the VmmYara information on Github:
// - README: https://github.com/ufrisk/vmmyara
//
// (c) Ulf Frisk, 2023
// Author: Ulf Frisk, pcileech@frizk.net
//
// Header Version: 4.3.1.4
//

#ifndef __VMMYARA_H__
#define __VMMYARA_H__
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

//-----------------------------------------------------------------------------
// OS COMPATIBILITY BELOW:
//-----------------------------------------------------------------------------

#ifdef _WIN32
#include <Windows.h>
#ifndef EXPORTED_FUNCTION
#define EXPORTED_FUNCTION
#endif /* EXPORTED_FUNCTION */
#endif /* _WIN32 */
#ifdef LINUX
#include <inttypes.h>
#include <stdlib.h>
#ifndef EXPORTED_FUNCTION
#define EXPORTED_FUNCTION                   __attribute__((visibility("default")))
#endif /* EXPORTED_FUNCTION */
typedef uint32_t                            BOOL;
typedef void                                VOID, *PVOID, *HANDLE;
typedef size_t                              SIZE_T;
typedef uint32_t                            DWORD, *PDWORD;
typedef uint8_t                             BYTE, *PBYTE;
typedef char                                CHAR, *LPSTR;
#define _In_
#define _In_reads_(x)
#define _In_reads_bytes_(x)
#define _Out_
#define _Success_(x)
#endif /* LINUX */

typedef int                                 VMMYARA_ERROR;          // corresponds exactly to YR_ERROR
typedef struct HANDLE                       *PVMMYARA_RULES;

// defines from yara error.h
#define VMMYARA_ERROR_SUCCESS                        0
#define VMMYARA_ERROR_INSUFFICIENT_MEMORY            1
#define VMMYARA_ERROR_COULD_NOT_ATTACH_TO_PROCESS    2
#define VMMYARA_ERROR_COULD_NOT_OPEN_FILE            3
#define VMMYARA_ERROR_COULD_NOT_MAP_FILE             4
#define VMMYARA_ERROR_INVALID_FILE                   6
#define VMMYARA_ERROR_CORRUPT_FILE                   7
#define VMMYARA_ERROR_UNSUPPORTED_FILE_VERSION       8
#define VMMYARA_ERROR_INVALID_REGULAR_EXPRESSION     9
#define VMMYARA_ERROR_INVALID_HEX_STRING             10
#define VMMYARA_ERROR_SYNTAX_ERROR                   11
#define VMMYARA_ERROR_LOOP_NESTING_LIMIT_EXCEEDED    12
#define VMMYARA_ERROR_DUPLICATED_LOOP_IDENTIFIER     13
#define VMMYARA_ERROR_DUPLICATED_IDENTIFIER          14
#define VMMYARA_ERROR_DUPLICATED_TAG_IDENTIFIER      15
#define VMMYARA_ERROR_DUPLICATED_META_IDENTIFIER     16
#define VMMYARA_ERROR_DUPLICATED_STRING_IDENTIFIER   17
#define VMMYARA_ERROR_UNREFERENCED_STRING            18
#define VMMYARA_ERROR_UNDEFINED_STRING               19
#define VMMYARA_ERROR_UNDEFINED_IDENTIFIER           20
#define VMMYARA_ERROR_MISPLACED_ANONYMOUS_STRING     21
#define VMMYARA_ERROR_INCLUDES_CIRCULAR_REFERENCE    22
#define VMMYARA_ERROR_INCLUDE_DEPTH_EXCEEDED         23
#define VMMYARA_ERROR_WRONG_TYPE                     24
#define VMMYARA_ERROR_EXEC_STACK_OVERFLOW            25
#define VMMYARA_ERROR_SCAN_TIMEOUT                   26
#define VMMYARA_ERROR_TOO_MANY_SCAN_THREADS          27
#define VMMYARA_ERROR_CALLBACK_ERROR                 28
#define VMMYARA_ERROR_INVALID_ARGUMENT               29
#define VMMYARA_ERROR_TOO_MANY_MATCHES               30
#define VMMYARA_ERROR_INTERNAL_FATAL_ERROR           31
#define VMMYARA_ERROR_NESTED_FOR_OF_LOOP             32
#define VMMYARA_ERROR_INVALID_FIELD_NAME             33
#define VMMYARA_ERROR_UNKNOWN_MODULE                 34
#define VMMYARA_ERROR_NOT_A_STRUCTURE                35
#define VMMYARA_ERROR_NOT_INDEXABLE                  36
#define VMMYARA_ERROR_NOT_A_FUNCTION                 37
#define VMMYARA_ERROR_INVALID_FORMAT                 38
#define VMMYARA_ERROR_TOO_MANY_ARGUMENTS             39
#define VMMYARA_ERROR_WRONG_ARGUMENTS                40
#define VMMYARA_ERROR_WRONG_RETURN_TYPE              41
#define VMMYARA_ERROR_DUPLICATED_STRUCTURE_MEMBER    42
#define VMMYARA_ERROR_EMPTY_STRING                   43
#define VMMYARA_ERROR_DIVISION_BY_ZERO               44
#define VMMYARA_ERROR_REGULAR_EXPRESSION_TOO_LARGE   45
#define VMMYARA_ERROR_TOO_MANY_RE_FIBERS             46
#define VMMYARA_ERROR_COULD_NOT_READ_PROCESS_MEMORY  47
#define VMMYARA_ERROR_INVALID_EXTERNAL_VARIABLE_TYPE 48
#define VMMYARA_ERROR_REGULAR_EXPRESSION_TOO_COMPLEX 49
#define VMMYARA_ERROR_INVALID_MODULE_NAME            50
#define VMMYARA_ERROR_TOO_MANY_STRINGS               51
#define VMMYARA_ERROR_INTEGER_OVERFLOW               52
#define VMMYARA_ERROR_CALLBACK_REQUIRED              53
#define VMMYARA_ERROR_INVALID_OPERAND                54
#define VMMYARA_ERROR_COULD_NOT_READ_FILE            55
#define VMMYARA_ERROR_DUPLICATED_EXTERNAL_VARIABLE   56
#define VMMYARA_ERROR_INVALID_MODULE_DATA            57
#define VMMYARA_ERROR_WRITING_FILE                   58
#define VMMYARA_ERROR_INVALID_MODIFIER               59
#define VMMYARA_ERROR_DUPLICATED_MODIFIER            60
#define VMMYARA_ERROR_BLOCK_NOT_READY                61
#define VMMYARA_ERROR_INVALID_PERCENTAGE             62
#define VMMYARA_ERROR_IDENTIFIER_MATCHES_WILDCARD    63
#define VMMYARA_ERROR_INVALID_VALUE                  64

// defines from yara scan.h
#define VMMYARA_SCAN_FLAGS_FAST_MODE                 1
#define VMMYARA_SCAN_FLAGS_PROCESS_MEMORY            2
#define VMMYARA_SCAN_FLAGS_NO_TRYCATCH               4
#define VMMYARA_SCAN_FLAGS_REPORT_RULES_MATCHING     8
#define VMMYARA_SCAN_FLAGS_REPORT_RULES_NOT_MATCHING 16



/*
* Load a compiled yara rule file.
* -- szCompiledFileRules = the file path of the compiled yara rule file to load.
* -- phVmmYaraRules = pointer to a PVMMYARA_RULES variable that will receive
*                    the handle to the loaded rule set on success.
* -- return = VMMYARA_ERROR_SUCCESS on success, otherwise a yara error.
*/
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_RulesLoadCompiled(
    _In_ LPSTR szCompiledFileRules,
    _Out_ PVMMYARA_RULES *phVmmYaraRules
);

/*
* Load one or multiple yara rules from either memory or source files.
* -- cszSourceCombinedRules = the number of source files/strings to load.
* -- pszSourceCombinedRules = array of source file paths/strings to load.
* -- phVmmYaraRules = pointer to a PVMMYARA_RULES variable that will receive the
*                    handle to the loaded rule set on success.
* -- return = VMMYARA_ERROR_SUCCESS on success, otherwise a yara error.
*/
EXPORTED_FUNCTION
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_RulesLoadSourceCombined(
    _In_ DWORD cszSourceCombinedRules,
    _In_reads_(cszSourceCombinedRules) LPSTR pszSourceCombinedRules[],
    _Out_ PVMMYARA_RULES *phVmmYaraRules
);

/*
* Load one or multiple yara rules from source files.
* -- cszSourceFileRules = the number of source files to load.
* -- pszSourceFileRules = array of source file paths to load.
* -- phVmmYaraRules = pointer to a PVMMYARA_RULES variable that will receive
*                    the handle to the loaded rule set on success.
* -- return = VMMYARA_ERROR_SUCCESS on success, otherwise a yara error.
*/
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_RulesLoadSourceFile(
    _In_ DWORD cszSourceFileRules,
    _In_reads_(cszSourceFileRules) LPSTR pszSourceFileRules[],
    _Out_ PVMMYARA_RULES *phVmmYaraRules
);

/*
* Load one or multiple yara rules from in-memory source strings.
* -- cSourceStringRules = the number of source strings to load.
* -- cszSourceStringRules = array of source strings to load.
* -- phVmmYaraRules = pointer to a PVMMYARA_RULES variable that will receive
*                    the handle to the loaded rule set on success.
* -- return = VMMYARA_ERROR_SUCCESS on success, otherwise a yara error.
*/
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_RulesLoadSourceString(
    _In_ DWORD cszSourceStringRules,
    _In_reads_(cszSourceStringRules) LPSTR pszSourceStringRules[],
    _Out_ PVMMYARA_RULES *phVmmYaraRules
);

/*
* Destroy a previously loaded rule set.
* -- hVmmYaraRules = the handle to the rule set to destroy.
* -- return = VMMYARA_ERROR_SUCCESS on success, otherwise a yara error.
*/
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_RulesDestroy(_In_ PVMMYARA_RULES hVmmYaraRules);

#define VMMYARA_RULE_MATCH_FLAG_MEMPROCFS   1
#define VMMYARA_RULE_MATCH_FLAG_SUPPRESS    2


// =========== START SHARED STRUCTS WITH <vmmdll.h/vmmyara.h> ===========
#ifndef VMMYARA_RULE_MATCH_DEFINED
#define VMMYARA_RULE_MATCH_DEFINED

#define VMMYARA_RULE_MATCH_VERSION          0xfedc0003
#define VMMYARA_RULE_MATCH_TAG_MAX          8
#define VMMYARA_RULE_MATCH_META_MAX         16
#define VMMYARA_RULE_MATCH_STRING_MAX       8
#define VMMYARA_RULE_MATCH_OFFSET_MAX       16

/*
* Struct with match information upon a match in VmmYara_RulesScanMemory().
*/
typedef struct tdVMMYARA_RULE_MATCH {
    DWORD dwVersion;                    // VMMYARA_RULE_MATCH_VERSION
    DWORD flags;
    LPSTR szRuleIdentifier;
    DWORD cTags;
    LPSTR szTags[VMMYARA_RULE_MATCH_TAG_MAX];
    DWORD cMeta;
    struct {
        LPSTR szIdentifier;
        LPSTR szString;
    } Meta[VMMYARA_RULE_MATCH_META_MAX];
    DWORD cStrings;
    struct {
        LPSTR szString;
        DWORD cMatch;
        SIZE_T cbMatchOffset[VMMYARA_RULE_MATCH_OFFSET_MAX];
    } Strings[VMMYARA_RULE_MATCH_STRING_MAX];
} VMMYARA_RULE_MATCH, *PVMMYARA_RULE_MATCH;

#endif /* VMMYARA_RULE_MATCH_DEFINED */

#ifndef VMMYARA_SCAN_MEMORY_CALLBACK_DEFINED
#define VMMYARA_SCAN_MEMORY_CALLBACK_DEFINED

/*
* Callback function to be called by VmmYara_RulesScanMemory() upon a match.
* -- pvContext = user context set in call to VmmYara_ScanMemory().
* -- pRuleMatch = pointer to match information.
* -- pbBuffer = the memory buffer that was scanned.
* -- cbBuffer = the size of the memory buffer that was scanned.
* -- return = return TRUE to continue scanning, FALSE to stop scanning.
*/
typedef BOOL(*VMMYARA_SCAN_MEMORY_CALLBACK)(
    _In_ PVOID pvContext,
    _In_ PVMMYARA_RULE_MATCH pRuleMatch,
    _In_reads_bytes_(cbBuffer) PBYTE pbBuffer,
    _In_ SIZE_T cbBuffer
);

#endif /* VMMYARA_SCAN_MEMORY_CALLBACK_DEFINED */
// =========== END SHARED STRUCTS WITH <vmmdll.h/vmmyara.h> ===========

/*
* Scan a memory buffer for matches against the specified rule set.
* Upon a match the callback function will be called with the match information.
* -- hVmmYaraRules = the handle to the rule set to scan against.
* -- pbBuffer = the memory buffer to scan.
* -- cbBuffer = the size of the memory buffer to scan.
* -- flags = flags according to yr_rules_scan_mem() to use.
* -- pfnCallback = the callback function to call upon a match.
* -- pvContext = context to pass to the callback function.
* -- timeout = timeout in seconds according to yr_rules_scan_mem().
* -- return = VMMYARA_ERROR_SUCCESS on success, otherwise a yara error.
*/
_Success_(return == VMMYARA_ERROR_SUCCESS)
VMMYARA_ERROR VmmYara_ScanMemory(
    _In_ PVMMYARA_RULES hVmmYaraRules,
    _In_reads_bytes_(cbBuffer) PBYTE pbBuffer,
    _In_ SIZE_T cbBuffer,
    _In_ int flags,
    _In_ VMMYARA_SCAN_MEMORY_CALLBACK pfnCallback,
    _In_ PVOID pvContext,
    _In_ int timeout
);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* __VMMYARA_H__ */
