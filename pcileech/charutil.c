// charutil.c : implementation of various character/string utility functions.
//
// (c) Ulf Frisk, 2021-2022
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "charutil.h"

#define CHARUTIL_CONVERT_MAXSIZE            0x40000000
#define CHARUTIL_ANSIFILENAME_ALLOW \
    "0000000000000000000000000000000011011111110111101111111111010100" \
    "1111111111111111111111111111011111111111111111111111111111110111"

/*
* Check whether a string is an ansi-string (only codepoints between 0-127).
* -- sz
* -- return
*/
BOOL CharUtil_IsAnsiA(_In_ LPCSTR sz)
{
    UCHAR c;
    DWORD i = 0;
    while(TRUE) {
        c = sz[i++];
        if(c == 0) { return TRUE; }
        if(c > 127) { return FALSE; }
    }
}

BOOL CharUtil_IsAnsiW(_In_ LPCWSTR wsz)
{
    USHORT c;
    DWORD i = 0;
    while(TRUE) {
        c = wsz[i++];
        if(c == 0) { return TRUE; }
        if(c > 127) { return FALSE; }
    }
}

/*
* Convert Ascii (0-255) or Wide (16-bit LE) string into a UTF-8 string.
* Function support sz/wsz == pbBuffer - sz/wsz will then become overwritten.
* CALLER LOCALFREE (if *pjsz != pbBuffer): *pjsz
* -- usz/sz/wsz = the string to convert.
* -- cch = -1 for null-terminated string; or max number of chars (excl. null).
* -- pbBuffer = optional buffer to place the result in.
* -- cbBuffer
* -- pusz = if set to null: function calculate length only and return TRUE.
            result utf-8 string, either as (*pjsz == pbBuffer) or LocalAlloc'ed
*           buffer that caller is responsible for free.
* -- pcbu = byte length (including terminating null) of utf-8 string.
* -- flags = CHARUTIL_FLAG_NONE, CHARUTIL_FLAG_ALLOC or CHARUTIL_FLAG_TRUNCATE
* -- return
*/
_Success_(return)
BOOL CharUtil_AtoU(_In_opt_ LPSTR sz, _In_ DWORD cch, _Maybenull_ _Writable_bytes_(cbBuffer) PBYTE pbBuffer, _In_ DWORD cbBuffer, _Out_opt_ LPSTR *pusz, _Out_opt_ PDWORD pcbu, _In_ DWORD flags)
{
    UCHAR c;
    LPSTR usz;
    DWORD i, j, cba = 0, cbu = 0;
    if(pcbu) { *pcbu = 0; }
    if(pusz) { *pusz = NULL; }
    if(!sz) { sz = ""; }
    if(cch > CHARUTIL_CONVERT_MAXSIZE) { cch = CHARUTIL_CONVERT_MAXSIZE; }
    // 1: ansi byte-length and if ansi-only
    if((flags & CHARUTIL_FLAG_TRUNCATE)) {
        if(!cbBuffer || (flags & CHARUTIL_FLAG_ALLOC)) { goto fail; }
        while((cba < cch) && (c = sz[cba])) {
            if(c > 0x7f) {
                if(cba + cbu + 1 + 1 >= cbBuffer) { break; }
                cbu++;
            } else {
                if(cba + cbu + 1 >= cbBuffer) { break; }
            }
            cba++;
        }
    } else {
        while((cba < cch) && (c = sz[cba])) {
            if(c > 0x7f) { cbu++; }
            cba++;
        }
    }
    cba++;
    cbu += cba;
    if(pcbu) { *pcbu = cbu; }
    // 2: return on length-request or alloc-fail
    if(!pusz) {
        if(!(flags & CHARUTIL_FLAG_STR_BUFONLY)) { return TRUE; }   // success: length request
        if(flags & CHARUTIL_FLAG_ALLOC) { return FALSE; }
    }                                              
    if(!(flags & CHARUTIL_FLAG_ALLOC) && (!pbBuffer || (cbBuffer < cbu))) { goto fail; } // fail: insufficient buffer space
    usz = (pbBuffer && (cbBuffer >= cbu)) ? pbBuffer : LocalAlloc(0, cbu);
    if(!usz) { goto fail; }                                              // fail: failed buffer space allocation
    // 3: populate with utf-8 string (backwards to support sz == pbBuffer case)
    i = cba - 2; j = cbu - 2;
    while(i < 0x7fffffff) {
        c = sz[i--];
        if(c > 0x7f) {
            usz[j--] = 0x80 | (c & 0x3f);
            usz[j--] = 0xc0 | ((c >> 6) & 0x1f);
        } else {
            usz[j--] = c;
        }
    }
    usz[cbu - 1] = 0;
    if(pusz) { *pusz = usz; }
    return TRUE;
fail:
    if(!(flags ^ CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR) && pbBuffer && cbBuffer) {
        if(pusz) { *pusz = (LPSTR)pbBuffer; }
        if(pcbu) { *pcbu = 1; }
        pbBuffer[0] = 0;
    }
    return FALSE;
}

_Success_(return)
BOOL CharUtil_UtoU(_In_opt_ LPSTR uszIn, _In_ DWORD cch, _Maybenull_ _Writable_bytes_(cbBuffer) PBYTE pbBuffer, _In_ DWORD cbBuffer, _Out_opt_ LPSTR *pusz, _Out_opt_ PDWORD pcbu, _In_ DWORD flags)
{
    // NB! function may look meaningless - but it provides some additional
    //     checking of the validity of the string and adheres to the flags.
    UCHAR c;
    LPSTR usz;
    DWORD n, cbu = 0;
    BOOL fTruncate = flags & CHARUTIL_FLAG_TRUNCATE;
    if(pcbu) { *pcbu = 0; }
    if(pusz) { *pusz = NULL; }
    if(!uszIn) { uszIn = ""; }
    if(cch > CHARUTIL_CONVERT_MAXSIZE) { cch = CHARUTIL_CONVERT_MAXSIZE; }
    // 1: utf-8 byte-length:
    if(fTruncate && (!cbBuffer || (flags & CHARUTIL_FLAG_ALLOC))) { goto fail; }
    while((cbu < cch) && (c = uszIn[cbu])) {
        if(c & 0x80) {
            // utf-8 char:
            n = 0;
            if((c & 0xe0) == 0xc0) { n = 2; }
            if((c & 0xf0) == 0xe0) { n = 3; }
            if((c & 0xf8) == 0xf0) { n = 4; }
            if(!n) { goto fail; }                                              // invalid char-encoding
            if(cbu + n > cch) { break; }
            if(fTruncate && (cbu + n >= cbBuffer)) { break; }
            if((n > 1) && ((uszIn[cbu + 1] & 0xc0) != 0x80)) { goto fail; }    // invalid char-encoding
            if((n > 2) && ((uszIn[cbu + 2] & 0xc0) != 0x80)) { goto fail; }    // invalid char-encoding
            if((n > 3) && ((uszIn[cbu + 3] & 0xc0) != 0x80)) { goto fail; }    // invalid char-encoding
            cbu += n;
        } else {
            if(fTruncate && (cbu + 1 >= cbBuffer)) { break; }
            cbu += 1;
        }
    }
    cbu++;
    if(pcbu) { *pcbu = cbu; }
    // 2: return on length-request or alloc-fail
    if(!pusz) {
        if(!(flags & CHARUTIL_FLAG_STR_BUFONLY)) { return TRUE; }   // success: length request
        if(flags & CHARUTIL_FLAG_ALLOC) { return FALSE; }
    }
    if(!(flags & CHARUTIL_FLAG_ALLOC) && (!pbBuffer || (cbBuffer < cbu))) { goto fail; } // fail: insufficient buffer space
    usz = (pbBuffer && (cbBuffer >= cbu)) ? pbBuffer : LocalAlloc(0, cbu);
    if(!usz) { goto fail; }                                                 // fail: failed buffer space allocation
    // 3: populate with utf-8 string
    if(usz != uszIn) {
        memcpy(usz, uszIn, cbu);
    }
    usz[cbu - 1] = 0;
    if(pusz) { *pusz = usz; }
    return TRUE;
fail:
    if(!(flags ^ CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR) && pbBuffer && cbBuffer) {
        if(pusz) { *pusz = (LPSTR)pbBuffer; }
        if(pcbu) { *pcbu = 1; }
        pbBuffer[0] = 0;
    }
    return FALSE;
}

_Success_(return)
BOOL CharUtil_WtoU(_In_opt_ LPWSTR wsz, _In_ DWORD cch, _Maybenull_ _Writable_bytes_(cbBuffer) PBYTE pbBuffer, _In_ DWORD cbBuffer, _Out_opt_ LPSTR *pusz, _Out_opt_ PDWORD pcbu, _In_ DWORD flags)
{
    USHORT c, cZERO = 0;
    LPSTR usz;
    PUSHORT pus;
    DWORD i, j, cbw = 0, cbu = 0, chSur;
    if(pcbu) { *pcbu = 0; }
    if(pusz) { *pusz = NULL; }
    pus = wsz ? (PUSHORT)wsz : &cZERO;
    if(cch > CHARUTIL_CONVERT_MAXSIZE) { cch = CHARUTIL_CONVERT_MAXSIZE; }
    // 1: ansi byte-length and if ansi-only
    if((flags & CHARUTIL_FLAG_TRUNCATE)) {
        if(!cbBuffer || (flags & CHARUTIL_FLAG_ALLOC)) { goto fail; }
        while((cbw < cch) && (c = pus[cbw])) {
            if(c > 0x7ff) {
                if(c >= 0xD800 && c <= 0xDFFF) {
                    // surrogate pair
                    if(cbw + cbu + 1 + 2 + 1 >= cbBuffer) { break; }
                    if(cbw + 1 >= cch) { break; }    // end of string
                    if(pus[cbw + 1] < 0xD800 || pus[cbw + 1] > 0xDFFF) { goto fail; }    // fail: invalid code point
                    cbu += 2;
                    cbw++;
                } else {
                    if(cbw + cbu + 1 + 2 >= cbBuffer) { break; }
                    cbu += 2;
                }
            } else if(c > 0x7f) {
                if(cbw + cbu + 1 + 1 >= cbBuffer) { break; }
                cbu++;
            } else {
                if(cbw + cbu + 1 >= cbBuffer) { break; }
            }
            cbw++;
        }
    } else {
        while((cbw < cch) && (c = pus[cbw])) {
            if(c > 0x7ff) {
                if(c >= 0xD800 && c <= 0xDFFF) {
                    // surrogate pair
                    if(cbw + 1 >= cch) { break; }    // end of string
                    if(pus[cbw + 1] < 0xD800 || pus[cbw + 1] > 0xDFFF) { goto fail; }    // fail: invalid code point
                    cbu += 2;
                    cbw++;
                } else {
                    cbu += 2;
                }
            } else if(c > 0x7f) {
                cbu++;
            }
            cbw++;
        }
    }
    cbw++;
    cbu += cbw;
    if(pcbu) { *pcbu = cbu; }
    // 2: return on length-request or alloc-fail
    if(!pusz) {
        if(!(flags & CHARUTIL_FLAG_STR_BUFONLY)) { return TRUE; }   // success: length request
        if(flags & CHARUTIL_FLAG_ALLOC) { return FALSE; }
    }
    if(!(flags & CHARUTIL_FLAG_ALLOC) && (!pbBuffer || (cbBuffer < cbu))) { goto fail; } // fail: insufficient buffer space
    usz = (pbBuffer && (cbBuffer >= cbu)) ? pbBuffer : LocalAlloc(0, cbu);
    if(!usz) { goto fail; }                                              // fail: failed buffer space allocation
    // 3: populate with utf-8 string
    i = cbw - 2; j = cbu - 2;
    while(i < 0x7fffffff) {
        c = pus[i--];
        if(c > 0x7ff) {
            if(c >= 0xD800 && c <= 0xDFFF) {
                // surrogate pair (previously validated in step 1)
                chSur = 0x10000 + (((pus[i--] - 0xD800) << 10) | ((c - 0xDC00) & 0x3ff));
                usz[j--] = 0x80 | (chSur & 0x3f);
                usz[j--] = 0x80 | ((chSur >> 6) & 0x3f);
                usz[j--] = 0x80 | ((chSur >> 12) & 0x3f);
                usz[j--] = 0xf0 | ((chSur >> 18) & 0x0f);
            } else {
                usz[j--] = 0x80 | (c & 0x3f);
                usz[j--] = 0x80 | ((c >> 6) & 0x3f);
                usz[j--] = 0xe0 | ((c >> 12) & 0x1f);
            }
        } else if(c > 0x7f) {
            usz[j--] = 0x80 | (c & 0x3f);
            usz[j--] = 0xc0 | ((c >> 6) & 0x3f);
        } else {
            usz[j--] = (CHAR)c;
        }
    }
    usz[cbu - 1] = 0;
    if(pusz) { *pusz = usz; }
    return TRUE;
fail:
    if(!(flags ^ CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR) && pbBuffer && cbBuffer) {
        if(pusz) { *pusz = (LPSTR)pbBuffer; }
        if(pcbu) { *pcbu = 1; }
        pbBuffer[0] = 0;
    }
    return FALSE;
}

/*
* Convert UTF-8 string into a Windows Wide-Char string.
* Function support usz == pbBuffer - usz will then become overwritten.
* CALLER LOCALFREE (if *pusz != pbBuffer): *pusz
* -- usz = the string to convert.
* -- cch = -1 for null-terminated string; or max number of chars (excl. null).
* -- pbBuffer = optional buffer to place the result in.
* -- cbBuffer
* -- pusz = if set to null: function calculate length only and return TRUE.
            result wide-string, either as (*pwsz == pbBuffer) or LocalAlloc'ed
*           buffer that caller is responsible for free.
* -- pcbu = byte length (including terminating null) of wide-char string.
* -- flags = CHARUTIL_FLAG_NONE, CHARUTIL_FLAG_ALLOC or CHARUTIL_FLAG_TRUNCATE
* -- return
*/
_Success_(return)
BOOL CharUtil_UtoW(_In_opt_ LPSTR usz, _In_ DWORD cch, _Maybenull_ _Writable_bytes_(cbBuffer) PBYTE pbBuffer, _In_ DWORD cbBuffer, _Out_opt_ LPWSTR *pwsz, _Out_opt_ PDWORD pcbw, _In_ DWORD flags)
{
    UCHAR c;
    LPWSTR wsz;
    DWORD i, j, n, cbu = 0, cbw = 0, ch;
    BOOL fTruncate = flags & CHARUTIL_FLAG_TRUNCATE;
    if(pcbw) { *pcbw = 0; }
    if(pwsz) { *pwsz = NULL; }
    if(!usz) { usz = ""; }
    if(cch > CHARUTIL_CONVERT_MAXSIZE) { cch = CHARUTIL_CONVERT_MAXSIZE; }
    // 1: utf-8 byte-length:
    cbBuffer = cbBuffer & ~1;       // multiple of 2-byte sizeof(WCHAR)
    if(fTruncate && (!cbBuffer || (flags & CHARUTIL_FLAG_ALLOC))) { goto fail; }
    while((cbu < cch) && (c = usz[cbu])) {
        if(c & 0x80) {
            // utf-8 char:
            n = 0;
            if((c & 0xe0) == 0xc0) { n = 2; }
            if((c & 0xf0) == 0xe0) { n = 3; }
            if((c & 0xf8) == 0xf0) { n = 4; }
            if(!n) { goto fail; }                                           // invalid char-encoding
            if(cbu + n > cch) { break; }
            if(fTruncate && (cbw + ((n == 4) ? 4 : 2) >= cbBuffer)) { break; }
            if((n > 1) && ((usz[cbu + 1] & 0xc0) != 0x80)) { goto fail; }   // invalid char-encoding
            if((n > 2) && ((usz[cbu + 2] & 0xc0) != 0x80)) { goto fail; }   // invalid char-encoding
            if((n > 3) && ((usz[cbu + 3] & 0xc0) != 0x80)) { goto fail; }   // invalid char-encoding
            cbw += (n == 4) ? 4 : 2;
            cbu += n;
        } else {
            if(fTruncate && (cbw + 2 >= cbBuffer)) { break; }
            cbw += 2;
            cbu += 1;
        }
    }
    cbu += 1;
    cbw += 2;
    if(pcbw) { *pcbw = cbw; }
    // 2: return on length-request or alloc-fail
    if(!pwsz) {
        if(!(flags & CHARUTIL_FLAG_STR_BUFONLY)) { return TRUE; }   // success: length request
        if(flags & CHARUTIL_FLAG_ALLOC) { return FALSE; }
    }
    if(!(flags & CHARUTIL_FLAG_ALLOC) && (!pbBuffer || (cbBuffer < cbw))) { goto fail; } // fail: insufficient buffer space
    wsz = (pbBuffer && (cbBuffer >= cbw)) ? pbBuffer : LocalAlloc(0, cbw);
    if(!wsz) { goto fail; }                                                 // fail: failed buffer space allocation
    // 3: Populate with wchar string. NB! algorithm works only on correctly
    //    formed UTF-8 - which has been verified in the count-step.
    i = cbu - 2; j = (cbw >> 1) - 1;
    wsz[j--] = 0;
    while(i < 0x7fffffff) {
        if(((c = usz[i--]) & 0xc0) == 0x80) {
            // 2-3-4 byte utf-8
            ch = c & 0x3f;
            if(((c = usz[i--]) & 0xc0) == 0x80) {
                // 3-4 byte utf-8
                ch += (c & 0x3f) << 6;
                if(((c = usz[i--]) & 0xc0) == 0x80) {
                    ch += (c & 0x3f) << 12;     // 4-byte utf-8
                    c = usz[i--];
                    ch += (c & 0x07) << 18;
                } else {
                    ch += (c & 0x0f) << 12;     // 3-byte utf-8
                }
            } else {
                ch += (c & 0x1f) << 6;          // 2-byte utf-8
            }
            if(ch >= 0x10000) {
                // surrogate pair:
                ch -= 0x10000;
                wsz[j--] = (ch & 0x3ff) + 0xdc00;
                wsz[j--] = (USHORT)((ch >> 10) + 0xd800);
            } else {
                wsz[j--] = (USHORT)ch;
            }
        } else {
            wsz[j--] = c;
        }
    }
    if(pwsz) { *pwsz = wsz; }
    return TRUE;
fail:
    if(!(flags ^ CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR) && pbBuffer && (cbBuffer > 1)) {
        if(pwsz) { *pwsz = (LPWSTR)pbBuffer; }
        if(pcbw) { *pcbw = 2; }
        pbBuffer[0] = 0;
    }
    return FALSE;
}

_Success_(return)
BOOL CharUtil_WtoW(_In_opt_ LPWSTR wsz, _In_ DWORD cch, _Maybenull_ _Writable_bytes_(cbBuffer) PBYTE pbBuffer, _In_ DWORD cbBuffer, _Out_opt_ LPWSTR *pwsz, _Out_opt_ PDWORD pcbw, _In_ DWORD flags)
{
    // NB!
    // This function is assumed to be rarely used. Due to this it's implemented
    // by calling CharUtil_WtoU and CharUtil_UtoW which is slightly ineffective.
    LPSTR usz;
    DWORD cbu;
    BYTE pbBufferInternal[MAX_PATH * 2];
    return
        CharUtil_WtoU(wsz, cch, pbBufferInternal, sizeof(pbBufferInternal), &usz, &cbu, CHARUTIL_FLAG_TRUNCATE) &&
        CharUtil_UtoW(usz, -1, pbBuffer, cbBuffer, pwsz, pcbw, flags);
}


VOID CharUtil_EscapeJSON2(_In_ CHAR ch, _Out_writes_(2) PCHAR chj)
{
    chj[0] = '\\';
    switch(ch) {
        case '"': chj[1] = '"'; break;
        case '\\': chj[1] = '\\'; break;
        case '\b': chj[1] = 'b'; break;
        case '\f': chj[1] = 'f'; break;
        case '\n': chj[1] = 'n'; break;
        case '\r': chj[1] = 'r'; break;
        case '\t': chj[1] = 't'; break;
    }
}

VOID CharUtil_EscapeJSON6(_In_ CHAR ch, _Out_writes_(6) PCHAR chj)
{
    CHAR chh;
    chj[0] = '\\';
    chj[1] = 'u';
    chj[2] = '0';
    chj[3] = '0';
    chh = (ch >> 4) & 0xf;
    chj[4] = (chh < 10) ? '0' + chh : 'a' - 10 + chh;
    chh = ch & 0xf;
    chj[5] = (chh < 10) ? '0' + chh : 'a' - 10 + chh;
}

/*
* Convert UTF-8, Ascii (0-255) or Wide (16-bit LE) string into a JSON string.
* Function support sz/usz/wsz == pbBuffer - sz/usz/wsz will then become overwritten.
* CALLER LOCALFREE (if *pjsz != pbBuffer): *pjsz
* -- sz/usz/wsz = the string to convert.
* -- cch = -1 for null-terminated string; or max number of chars (excl. null).
* -- pbBuffer = optional buffer to place the result in.
* -- cbBuffer
* -- pjsz = if set to null: function calculate length only and return TRUE.
            result utf-8 string, either as (*pjsz == pbBuffer) or LocalAlloc'ed
*           buffer that caller is responsible for free.
* -- pcbj = byte length (including terminating null) of utf-8 string.
* -- flags = CHARUTIL_FLAG_NONE, CHARUTIL_FLAG_ALLOC or CHARUTIL_FLAG_TRUNCATE
* -- return
*/
_Success_(return)
BOOL CharUtil_UtoJ(_In_opt_ LPSTR usz, _In_ DWORD cch, _Maybenull_ _Writable_bytes_(cbBuffer) PBYTE pbBuffer, _In_ DWORD cbBuffer, _Out_opt_ LPSTR *pjsz, _Out_opt_ PDWORD pcbj, _In_ DWORD flags)
{
    UCHAR c;
    LPSTR jsz;
    DWORD i, j, n, cba = 0, cbj = 0;
    if(pcbj) { *pcbj = 0; }
    if(pjsz) { *pjsz = NULL; }
    if(!usz) { usz = ""; }
    if(cch > CHARUTIL_CONVERT_MAXSIZE) { cch = CHARUTIL_CONVERT_MAXSIZE; }
    // 1: ansi byte-length and if ansi-only
    if((flags & CHARUTIL_FLAG_TRUNCATE)) {
        if(!cbBuffer || (flags & CHARUTIL_FLAG_ALLOC)) { goto fail; }
        while((cba < cch) && (c = usz[cba])) {
            if(c < 0x20 || c == '"' || c == '\\') {
                // JSON encode
                n = (c == '"' || c == '\\' || c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t') ? 1 : 5;
                if(cba + cbj + 1 + n >= cbBuffer) { break; }
                cbj += n;
            }
            cba++;
        }
    } else {
        while((cba < cch) && (c = usz[cba])) {
            if(c < 0x20 || c == '"' || c == '\\') {
                // JSON encode
                cbj += (c == '"' || c == '\\' || c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t') ? 1 : 5;
            }
            cba++;
        }
    }
    cba++;
    cbj += cba;
    if(pcbj) { *pcbj = cbj; }
    // 2: return on length-request or alloc-fail
    if(!pjsz) {
        if(!(flags & CHARUTIL_FLAG_STR_BUFONLY)) { return TRUE; }   // success: length request
        if(flags & CHARUTIL_FLAG_ALLOC) { return FALSE; }
    }
    if(!cbj) { goto fail; }
    if(!(flags & CHARUTIL_FLAG_ALLOC) && (!pbBuffer || (cbBuffer < cbj))) { goto fail; } // fail: insufficient buffer space
    jsz = (pbBuffer && (cbBuffer >= cbj)) ? pbBuffer : LocalAlloc(0, cbj);
    if(!jsz) { goto fail; }                                              // fail: failed buffer space allocation
    // 3: populate with utf-8 string (backwards to support sz == pbBuffer case)
    i = cba - 2; j = cbj - 2;
    while(i < 0x7fffffff) {
        c = usz[i--];
        if(c < 0x20 || c == '"' || c == '\\') {
            // JSON encode
            n = (c == '"' || c == '\\' || c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t') ? 1 : 5;
            if(n == 1) { CharUtil_EscapeJSON2(c, jsz + j - 1); }
            if(n == 5) { CharUtil_EscapeJSON6(c, jsz + j - 5); }
            j -= 1 + n;
        } else {
            jsz[j--] = c;
        }
    }
    jsz[cbj - 1] = 0;
    if(pjsz) { *pjsz = jsz; }
    return TRUE;
fail:
    if(!(flags ^ CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR) && pbBuffer && cbBuffer) {
        if(pjsz) { *pjsz = (LPSTR)pbBuffer; }
        if(pcbj) { *pcbj = 1; }
        pbBuffer[0] = 0;
    }
    return FALSE;
}

_Success_(return)
BOOL CharUtil_AtoJ(_In_opt_ LPSTR sz, _In_ DWORD cch, _Maybenull_ _Writable_bytes_(cbBuffer) PBYTE pbBuffer, _In_ DWORD cbBuffer, _Out_opt_ LPSTR *pjsz, _Out_opt_ PDWORD pcbj, _In_ DWORD flags)
{
    UCHAR c;
    LPSTR jsz;
    DWORD i, j, n, cba = 0, cbj = 0;
    if(pcbj) { *pcbj = 0; }
    if(pjsz) { *pjsz = NULL; }
    if(!sz) { sz = ""; }
    if(cch > CHARUTIL_CONVERT_MAXSIZE) { cch = CHARUTIL_CONVERT_MAXSIZE; }
    // 1: ansi byte-length and if ansi-only
    if((flags & CHARUTIL_FLAG_TRUNCATE)) {
        if(!cbBuffer || (flags & CHARUTIL_FLAG_ALLOC)) { goto fail; }
        while((cba < cch) && (c = sz[cba])) {
            if(c > 0x7f) {
                if(cba + cbj + 1 + 1 >= cbBuffer) { break; }
                cbj++;
            } else if(c < 0x20 || c == '"' || c == '\\') {
                // JSON encode
                n = (c == '"' || c == '\\' || c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t') ? 1 : 5;
                if(cba + cbj + 1 + n >= cbBuffer) { break; }
                cbj += n;
            } else {
                if(cba + cbj + 1 >= cbBuffer) { break; }
            }
            cba++;
        }
    } else {
        while((cba < cch) && (c = sz[cba])) {
            if(c > 0x7f) {
                cbj++;
            } else if(c < 0x20 || c == '"' || c == '\\') {
                // JSON encode
                cbj += (c == '"' || c == '\\' || c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t') ? 1 : 5;
            }
            cba++;
        }
    }
    cba++;
    cbj += cba;
    if(pcbj) { *pcbj = cbj; }
    // 2: return on length-request or alloc-fail
    if(!pjsz) {
        if(!(flags & CHARUTIL_FLAG_STR_BUFONLY)) { return TRUE; }   // success: length request
        if(flags & CHARUTIL_FLAG_ALLOC) { return FALSE; }
    }
    if(!cbj) { goto fail; }
    if(!(flags & CHARUTIL_FLAG_ALLOC) && (!pbBuffer || (cbBuffer < cbj))) { goto fail; } // fail: insufficient buffer space
    jsz = (pbBuffer && (cbBuffer >= cbj)) ? pbBuffer : LocalAlloc(0, cbj);
    if(!jsz) { goto fail; }                                              // fail: failed buffer space allocation
    // 3: populate with utf-8 string (backwards to support sz == pbBuffer case)
    i = cba - 2; j = cbj - 2;
    while(i < 0x7fffffff) {
        c = sz[i--];
        if(c > 0x7f) {
            jsz[j--] = 0x80 | (c & 0x3f);
            jsz[j--] = 0xc0 | ((c >> 6) & 0x1f);
        } else if(c < 0x20 || c == '"' || c == '\\') {
            // JSON encode
            n = (c == '"' || c == '\\' || c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t') ? 1 : 5;
            if(n == 1) { CharUtil_EscapeJSON2(c, jsz + j - 1); }
            if(n == 5) { CharUtil_EscapeJSON6(c, jsz + j - 5); }
            j -= 1 + n;
        } else {
            jsz[j--] = c;
        }
    }
    jsz[cbj - 1] = 0;
    if(pjsz) { *pjsz = jsz; }
    return TRUE;
fail:
    if(!(flags ^ CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR) && pbBuffer && cbBuffer) {
        if(pjsz) { *pjsz = (LPSTR)pbBuffer; }
        if(pcbj) { *pcbj = 1; }
        pbBuffer[0] = 0;
    }
    return FALSE;
}

_Success_(return)
BOOL CharUtil_WtoJ(_In_opt_ LPWSTR wsz, _In_ DWORD cch, _Maybenull_ _Writable_bytes_(cbBuffer) PBYTE pbBuffer, _In_ DWORD cbBuffer, _Out_opt_ LPSTR *pjsz, _Out_opt_ PDWORD pcbj, _In_ DWORD flags)
{
    USHORT c, cZERO = 0;
    LPSTR jsz;
    PUSHORT pus;
    DWORD i, j, n, cbw = 0, cbj = 0, chSur;
    if(pcbj) { *pcbj = 0; }
    if(pjsz) { *pjsz = NULL; }
    if(cch > CHARUTIL_CONVERT_MAXSIZE) { cch = CHARUTIL_CONVERT_MAXSIZE; }
    pus = wsz ? (PUSHORT)wsz : &cZERO;
    // 1: ansi byte-length and if ansi-only
    if((flags & CHARUTIL_FLAG_TRUNCATE)) {
        if(!cbBuffer || (flags & CHARUTIL_FLAG_ALLOC)) { goto fail; }
        while((cbw < cch) && (c = pus[cbw])) {
            if(c > 0x7ff) {
                if(c >= 0xD800 && c <= 0xDFFF) {
                    // surrogate pair
                    if(cbw + cbj + 1 + 2 + 1 >= cbBuffer) { break; }
                    if(cbw + 1 >= cch) { break; }    // end of string
                    if(pus[cbw + 1] < 0xD800 || pus[cbw + 1] > 0xDFFF) { goto fail; }    // fail: invalid code point
                    cbj += 2;
                    cbw++;
                } else {
                    if(cbw + cbj + 1 + 2 >= cbBuffer) { break; }
                    cbj += 2;
                }
            } else if(c > 0x7f) {
                if(cbw + cbj + 1 + 1 >= cbBuffer) { break; }
                cbj++;
            } else if(c < 0x20 || c == '"' || c == '\\') {
                // JSON encode
                n = (c == '"' || c == '\\' || c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t') ? 1 : 5;
                if(cbw + cbj + 1 + n >= cbBuffer) { break; }
                cbj += n;
            } else {
                if(cbw + cbj + 1 >= cbBuffer) { break; }
            }
            cbw++;
        }
    } else {
        while((cbw < cch) && (c = pus[cbw])) {
            if(c > 0x7ff) {
                if(c >= 0xD800 && c <= 0xDFFF) {
                    // surrogate pair
                    if(cbw + 1 >= cch) { break; }    // end of string
                    if(pus[cbw + 1] < 0xD800 || pus[cbw + 1] > 0xDFFF) { goto fail; }   // fail: invalid code point
                    cbj += 2;
                    cbw++;
                } else {
                    cbj += 2;
                }
            } else if(c > 0x7f) {
                cbj++;
            } else if(c < 0x20 || c == '"' || c == '\\') {
                // JSON encode
                cbj += (c == '"' || c == '\\' || c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t') ? 1 : 5;
            }
            cbw++;
        }
    }
    cbw++;
    cbj += cbw;
    if(pcbj) { *pcbj = cbj; }
    // 2: return on length-request or alloc-fail
    if(!pjsz) {
        if(!(flags & CHARUTIL_FLAG_STR_BUFONLY)) { return TRUE; }   // success: length request
        if(flags & CHARUTIL_FLAG_ALLOC) { return FALSE; }
    }
    if(!cbj) { goto fail; }
    if(!(flags & CHARUTIL_FLAG_ALLOC) && (!pbBuffer || (cbBuffer < cbj))) { goto fail; } // fail: insufficient buffer space
    jsz = (pbBuffer && (cbBuffer >= cbj)) ? pbBuffer : LocalAlloc(0, cbj);
    if(!jsz) { goto fail; }                                                 // fail: failed buffer space allocation
    // 3: populate with utf-8 string (backwards to support sz == pbBuffer case)
    i = cbw - 2; j = cbj - 2;
    while(i < 0x7fffffff) {
        c = pus[i--];
        if(c > 0x7ff) {
            if(c >= 0xD800 && c <= 0xDFFF) {
                // surrogate pair (previously validated in step 1)
                chSur = 0x10000 + (((pus[i--] - 0xD800) << 10) | ((c - 0xDC00) & 0x3ff));
                jsz[j--] = 0x80 | (chSur & 0x3f);
                jsz[j--] = 0x80 | ((chSur >> 6) & 0x3f);
                jsz[j--] = 0x80 | ((chSur >> 12) & 0x3f);
                jsz[j--] = 0xf0 | ((chSur >> 18) & 0x0f);
            } else {
                jsz[j--] = 0x80 | (c & 0x3f);
                jsz[j--] = 0x80 | ((c >> 6) & 0x3f);
                jsz[j--] = 0xe0 | ((c >> 12) & 0x1f);
            }
        } else if(c > 0x7f) {
            jsz[j--] = 0x80 | (c & 0x3f);
            jsz[j--] = 0xc0 | ((c >> 6) & 0x3f);
        } else if(c < 0x20 || c == '"' || c == '\\') {
            // JSON encode
            n = (c == '"' || c == '\\' || c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t') ? 1 : 5;
            if(n == 1) { CharUtil_EscapeJSON2((CHAR)c, jsz + j - 1); } 
            if(n == 5) { CharUtil_EscapeJSON6((CHAR)c, jsz + j - 5); }
            j -= 1 + n;
        } else {
            jsz[j--] = (CHAR)c;
        }
    }
    jsz[cbj - 1] = 0;
    if(pjsz) { *pjsz = jsz; }
    return TRUE;
fail:
    if(!(flags ^ CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR) && pbBuffer && cbBuffer) {
        if(pjsz) { *pjsz = (LPSTR)pbBuffer; }
        if(pcbj) { *pcbj = 1; }
        pbBuffer[0] = 0;
    }
    return FALSE;
}




/*
* Convert a string into a file name compatible string by replacing illegal
* characters with '_'. Also optionally add a suffix between 1-9 and fix
* upper-case letters. If insufficient space the result will be truncated.
* -- uszDst
* -- cbuDst
* -- uszSrc
* -- iSuffix
* -- fUpper
* -- return = number of bytes written (including terminating NULL).
*/
_Success_(return != 0)
DWORD CharUtil_FixFsNameU(_Out_writes_(cbuDst) LPSTR uszDst, _In_ DWORD cbuDst, _In_ LPCSTR uszSrc, _In_opt_ DWORD iSuffix, _In_ BOOL fUpper)
{
    UCHAR c;
    DWORD i = 0, nSuffix = 0;
    // 1: convert correct size utf-8
    if(iSuffix) {
        if(iSuffix < 100) { nSuffix = 3; }
        if(iSuffix < 10) { nSuffix = 2; }
    }
    if(cbuDst < 2 + nSuffix) {
        if(cbuDst) { uszDst[0] = 0; }
        return cbuDst ? 1 : 0;
    }
    CharUtil_UtoU((LPSTR)uszSrc, -1, (PBYTE)uszDst, cbuDst - nSuffix, NULL, NULL, CHARUTIL_FLAG_TRUNCATE | CHARUTIL_FLAG_STR_BUFONLY);
    // 2: replace bad/uppercase chars
    if(fUpper) {
        while((c = uszDst[i])) {
            if(c >= 'a' && c <= 'z') {
                c += 'A' - 'a';
            } else if(c < 128) {
                c = (CHARUTIL_ANSIFILENAME_ALLOW[c] == '0') ? '_' : c;
            }
            uszDst[i] = c;
            i++;
        }
    } else {
        while((c = uszDst[i])) {
            if(c < 128) {
                c = (CHARUTIL_ANSIFILENAME_ALLOW[c] == '0') ? '_' : c;
            }
            uszDst[i] = c;
            i++;
        }
    }
    // 3: append suffix (if required)
    if(nSuffix && (i + nSuffix + 1 < cbuDst)) {
        uszDst[i++] = '-';
        if(iSuffix >= 10) {
            uszDst[i++] = '0' + (CHAR)(iSuffix / 10);
        }
        uszDst[i++] = '0' + (CHAR)(iSuffix % 10);
        uszDst[i++] = 0;
    }
    if(i && (uszDst[i - 1] == '.')) { uszDst[i - 1] = '_'; }
    return (DWORD)(strlen(uszDst) + 1);
}

/*
* Convert a string into a file name compatible string by replacing illegal
* characters with '_'. Also optionally add a suffix between 1-9 and fix
* upper-case letters. One of [usz, sz, wsz] must be valid.
* -- uszOut
* -- cbuDst
* -- usz
* -- sz
* -- wsz
* -- cwsz
* -- cch = number of bytes/wchars in usz/sz/wsz or _TRUNCATE
* -- iSuffix
* -- fUpper
* -- return = number of bytes written (including terminating NULL).
*/
_Success_(return != 0)
DWORD CharUtil_FixFsName(_Out_writes_(cbuDst) LPSTR uszOut, _In_ DWORD cbuDst, _In_opt_ LPCSTR usz, _In_opt_ LPCSTR sz, _In_opt_ LPCWSTR wsz, _In_ DWORD cch, _In_opt_ DWORD iSuffix, _In_ BOOL fUpper)
{
    UCHAR c;
    DWORD i = 0;
    LPSTR uszTMP;
    uszOut[0] = 0;
    // 1: convert correct size utf-8
    if(cbuDst < 5) { return 0; }
    if(!sz && !usz && !wsz) { return 0; }
    if(sz && !CharUtil_AtoU((LPSTR)sz, cch, (PBYTE)uszOut, cbuDst - 4, &uszTMP, NULL, CHARUTIL_FLAG_TRUNCATE)) { return 0; }
    if(wsz && !CharUtil_WtoU((LPWSTR)wsz, cch, (PBYTE)uszOut, cbuDst - 4, &uszTMP, NULL, CHARUTIL_FLAG_TRUNCATE)) { return 0; }
    if(usz && !CharUtil_UtoU((LPSTR)usz, cch, (PBYTE)uszOut, cbuDst - 4, &uszTMP, NULL, CHARUTIL_FLAG_TRUNCATE)) { return 0; }
    // 2: replace bad/uppercase chars
    if(fUpper) {
        while((c = uszOut[i])) {
            if(c >= 'a' && c <= 'z') {
                c += 'A' - 'a';
            } else if(c < 128) {
                c = (CHARUTIL_ANSIFILENAME_ALLOW[c] == '0') ? '_' : c;
            }
            uszOut[i] = c;
            i++;
        }
    } else {
        while((c = uszOut[i])) {
            if(c < 128) {
                c = (CHARUTIL_ANSIFILENAME_ALLOW[c] == '0') ? '_' : c;
            }
            uszOut[i] = c;
            i++;
        }
    }
    // 3: append suffix (if required)
    if(iSuffix && (iSuffix < 100)) {
        uszOut[i++] = '-';
        if(iSuffix >= 10) {
            uszOut[i++] = '0' + (CHAR)(iSuffix / 10);
        }
        uszOut[i++] = '0' + (CHAR)(iSuffix % 10);
        uszOut[i++] = 0;
    }
    if(i && (uszOut[i - 1] == '.')) { uszOut[i - 1] = '_'; }
    return (DWORD)(strlen(uszOut) + 1);
}

/*
* Hash a string quickly using the ROT13 algorithm.
* -- sz/jsz/wsz = the string to hash
* -- fUpper
* -- return
*/
QWORD CharUtil_Hash64U(_In_opt_ LPCSTR usz, _In_ BOOL fUpper)
{
    CHAR c;
    QWORD i = 0, qwHash = 0;
    if(!usz) { return 0; }
    if(fUpper) {
        while(TRUE) {
            c = usz[i++];
            if(!c) { return qwHash; }
            if(c >= 'a' && c <= 'z') {
                c += 'A' - 'a';
            }
            qwHash = ((qwHash >> 13) | (qwHash << 51)) + c;
        }
    } else {
        while(TRUE) {
            c = usz[i++];
            if(!c) { return qwHash; }
            qwHash = ((qwHash >> 13) | (qwHash << 51)) + c;
        }
    }
}

QWORD CharUtil_Hash64A(_In_opt_ LPCSTR sz, _In_ BOOL fUpper)
{
    LPSTR usz;
    QWORD qwHash = 0;
    BYTE pbBuffer[MAX_PATH];
    if(!sz) { return 0; }
    if(CharUtil_IsAnsiA(sz)) {
        return CharUtil_Hash64U(sz, fUpper);
    }
    if(CharUtil_AtoU((LPSTR)sz, -1, pbBuffer, sizeof(pbBuffer), &usz, NULL, CHARUTIL_FLAG_ALLOC)) {
        qwHash = CharUtil_Hash64U(usz, fUpper);
        if(pbBuffer != (PBYTE)usz) { LocalFree(usz); }
    }
    return qwHash;
}

QWORD CharUtil_Hash64W(_In_opt_ LPCWSTR wsz, _In_ BOOL fUpper)
{
    CHAR c;
    LPSTR usz;
    QWORD i = 0, qwHash = 0;
    BYTE pbBuffer[MAX_PATH];
    PUSHORT pus = (PUSHORT)wsz;
    if(!wsz) { return 0; }
    if(CharUtil_IsAnsiW(wsz)) {
        while(TRUE) {
            c = (CHAR)pus[i++];
            if(!c) { return qwHash; }
            if(fUpper && c >= 'a' && c <= 'z') {
                c += 'A' - 'a';
            }
            qwHash = ((qwHash >> 13) | (qwHash << 51)) + c;
        }
    }
    if(CharUtil_WtoU((LPWSTR)wsz, -1, pbBuffer, sizeof(pbBuffer), &usz, NULL, CHARUTIL_FLAG_ALLOC)) {
        qwHash = CharUtil_Hash64U(usz, fUpper);
        if(pbBuffer != (PBYTE)usz) { LocalFree(usz); }
    }
    return qwHash;
}

DWORD CharUtil_Hash32U(_In_opt_ LPCSTR usz, _In_ BOOL fUpper)
{
    CHAR c;
    DWORD i = 0, dwHash = 0;
    if(!usz) { return 0; }
    if(fUpper) {
        while(TRUE) {
            c = usz[i++];
            if(!c) { return dwHash; }
            if(c >= 'a' && c <= 'z') {
                c += 'A' - 'a';
            }
            dwHash = ((dwHash >> 13) | (dwHash << 19)) + c;
        }
    } else {
        while(TRUE) {
            c = usz[i++];
            if(!c) { return dwHash; }
            dwHash = ((dwHash >> 13) | (dwHash << 19)) + c;
        }
    }
}

DWORD CharUtil_Hash32A(_In_opt_ LPCSTR sz, _In_ BOOL fUpper)
{
    LPSTR usz;
    DWORD dwHash = 0;
    BYTE pbBuffer[MAX_PATH];
    if(!sz) { return 0; }
    if(CharUtil_IsAnsiA(sz)) {
        return CharUtil_Hash32U(sz, fUpper);
    }
    if(CharUtil_AtoU((LPSTR)sz, -1, pbBuffer, sizeof(pbBuffer), &usz, NULL, CHARUTIL_FLAG_ALLOC)) {
        dwHash = CharUtil_Hash32U(usz, fUpper);
        if(pbBuffer != (PBYTE)usz) { LocalFree(usz); }
    }
    return dwHash;
}

DWORD CharUtil_Hash32W(_In_opt_ LPCWSTR wsz, _In_ BOOL fUpper)
{
    CHAR c;
    LPSTR usz;
    DWORD i = 0, dwHash = 0;
    BYTE pbBuffer[MAX_PATH];
    PUSHORT pus = (PUSHORT)wsz;
    if(!wsz) { return 0; }
    if(CharUtil_IsAnsiW(wsz)) {
        while(TRUE) {
            c = (CHAR)pus[i++];
            if(!c) { return dwHash; }
            if(fUpper && c >= 'a' && c <= 'z') {
                c += 'A' - 'a';
            }
            dwHash = ((dwHash >> 13) | (dwHash << 19)) + c;
        }
    }
    if(CharUtil_WtoU((LPWSTR)wsz, -1, pbBuffer, sizeof(pbBuffer), &usz, NULL, CHARUTIL_FLAG_ALLOC)) {
        dwHash = CharUtil_Hash32U(usz, fUpper);
        if(pbBuffer != (PBYTE)usz) { LocalFree(usz); }
    }
    return dwHash;
}




/*
* Internal hash function for HashNameFs* and HashPathFs* functions.
*/
DWORD CharUtil_Internal_HashFs(_In_ LPSTR usz)
{
    UCHAR c;
    DWORD i = 0, dwHash = 0;
    while((c = usz[i++])) {
        dwHash = ((dwHash >> 13) | (dwHash << 19)) + c;
    }
    return dwHash;
}

/*
* Hash a name string in a way that is supported by the file system.
* NB! this is not the same hash as the Windows registry uses.
* -- usz/sz/wsz
* -- iSuffix
* -- return
*/
DWORD CharUtil_HashNameFsU(_In_ LPCSTR usz, _In_opt_ DWORD iSuffix)
{
    CHAR uszFs[2*MAX_PATH];
    if(!CharUtil_FixFsName(uszFs, sizeof(uszFs), usz, NULL, NULL, -1, iSuffix, TRUE)) { return 0; }
    return CharUtil_Internal_HashFs(uszFs);
}

DWORD CharUtil_HashNameFsA(_In_ LPCSTR sz, _In_opt_ DWORD iSuffix)
{
    CHAR uszFs[2 * MAX_PATH];
    if(!CharUtil_FixFsName(uszFs, sizeof(uszFs), NULL, sz, NULL, -1, iSuffix, TRUE)) { return 0; }
    return CharUtil_Internal_HashFs(uszFs);
}

DWORD CharUtil_HashNameFsW(_In_ LPCWSTR wsz, _In_opt_ DWORD iSuffix)
{
    CHAR uszFs[2 * MAX_PATH];
    if(!CharUtil_FixFsName(uszFs, sizeof(uszFs), NULL, NULL, wsz, -1, iSuffix, TRUE)) { return 0; }
    return CharUtil_Internal_HashFs(uszFs);
}



/*
* Replace all characters in a string.
* -- sz
* -- chOld
* -- chNew
*/
VOID CharUtil_ReplaceAllA(_Inout_ LPSTR sz, _In_ CHAR chOld, _In_ CHAR chNew)
{
    CHAR c;
    DWORD i = 0;
    while((c = sz[i++])) {
        if(c == chOld) {
            sz[i - 1] = chNew;
        }
    }
}



/*
* Split the string usz into two at the last (back)slash which is removed.
* Ex: usz: XXX/YYY/ZZZ/AAA -> uszPath: XXX/YYY/ZZZ + return: AAA
* -- usz = utf-8 or ascii string.
* -- uszPath = buffer to receive result.
* -- cbuPath = byte length of uszPath buffer
* -- return
*/
LPSTR CharUtil_PathSplitLastEx(_In_ LPSTR usz, _Out_writes_(cbuPath) LPSTR uszPath, _In_ DWORD cbuPath)
{
    DWORD i, iSlash = -1;
    CHAR ch = -1;
    if(!cbuPath) { return NULL; }
    for(i = 0; ch && i < cbuPath; i++) {
        ch = usz[i];
        uszPath[i] = ch;
        if((ch == '\\') || (ch == '/')) {
            iSlash = i;
        }
    }
    uszPath[cbuPath - 1] = 0;
    if(iSlash == (DWORD)-1) { return NULL; }
    uszPath[iSlash] = 0;
    return uszPath + iSlash + 1;
}


/*
* Return the sub-string after the last (back)slash character in usz.
* If no (back)slash is found original string is returned. The returned data
* must not be free'd and is only valid as long as the usz parameter is valid.
* -- usz = utf-8 or ascii string.
* -- return
*/
LPSTR CharUtil_PathSplitLast(_In_ LPSTR usz)
{
    LPSTR uszResult = usz;
    UCHAR ch;
    DWORD i = 0;
    while(TRUE) {
        ch = usz[i++];
        if(ch == '\0') {
            return uszResult;
        }
        if(ch == '\\' || ch == '/') {
            uszResult = usz + i;
        }
    }
}

/*
* Return the sub-string after the first (back)slash character in usz.
* If no (back)slash is found original string is returned. The returned data
* must not be free'd and is only valid as long as the usz parameter is valid.
* -- usz = utf-8 or ascii string.
* -- return
*/
LPSTR CharUtil_PathSplitNext(_In_ LPSTR usz)
{
    CHAR ch;
    DWORD i = 0;
    while(TRUE) {
        ch = usz[i++];
        if(ch == '\0') {
            return usz + i - 1;
        }
        if((ch == '\\') || (ch == '/')) {
            return usz + i;
        }
    }
}

/*
* Split a "path" string into two at the first slash/backslash character.
* The 1st string is returned in the pusz1 caller-allocated buffer. The
* remainder is returned as return data (is a sub-string of wsz). If no
* 2nd string is found null-terminator character is returned (NB! not as NULL).
* -- usz = utf-8/ascii string to split.
* -- usz1 = buffer to receive result.
* -- cbu1 = byte length of usz1 buffer
* -- return = remainder of split string.
*/
LPSTR CharUtil_PathSplitFirst(_In_ LPSTR usz, _Out_writes_(cbu1) LPSTR usz1, _In_ DWORD cbu1)
{
    UCHAR c;
    DWORD i = 0;
    if(cbu1 < 3) {
        if(cbu1) { usz1[0] = 0; }
        return "";
    }
    while((c = usz[i]) && (c != '\\') && (c != '/') && (i < cbu1 - 2)) {
        usz1[i++] = c;
    }
    usz1[i] = 0;
    return usz[i] ? &usz[i + 1] : "";
}

/*
* Internal hash function for HashPathFs* functions.
*/
QWORD CharUtil_HashPathFs_Internal(_In_ LPCSTR uszPathFs)
{
    CHAR uszFirst[MAX_PATH];
    DWORD dwHashName;
    QWORD qwHashTotal = 0;
    while(uszPathFs[0]) {
        uszPathFs = CharUtil_PathSplitFirst((LPSTR)uszPathFs, uszFirst, _countof(uszFirst));
        dwHashName = CharUtil_HashNameFsU(uszFirst, 0);
        qwHashTotal = dwHashName + ((qwHashTotal >> 13) | (qwHashTotal << 51));
    }
    return qwHashTotal;
}

/*
* Hash a path string in a way that is supported by the file system.
* NB! this is not the same hash as the Windows registry uses.
* -- uszPath/szPath/wszPath
* -- iSuffix
* -- return
*/
QWORD CharUtil_HashPathFsU(_In_ LPCSTR uszPath)
{
    return CharUtil_HashPathFs_Internal(uszPath);
}

QWORD CharUtil_HashPathFsA(_In_ LPCSTR szPath)
{
    LPSTR uszPath;
    BYTE pbBuffer[2 * MAX_PATH];
    if(!CharUtil_AtoU((LPSTR)szPath, -1, pbBuffer, sizeof(pbBuffer), &uszPath, NULL, CHARUTIL_FLAG_TRUNCATE)) { return 0; }
    return CharUtil_HashPathFs_Internal(uszPath);
}

QWORD CharUtil_HashPathFsW(_In_ LPCWSTR wszPath)
{
    LPSTR uszPath;
    BYTE pbBuffer[2 * MAX_PATH];
    if(!CharUtil_WtoU((LPWSTR)wszPath, -1, pbBuffer, sizeof(pbBuffer), &uszPath, NULL, CHARUTIL_FLAG_TRUNCATE)) { return 0; }
    return CharUtil_HashPathFs_Internal(uszPath);
}

/*
* Checks if a string ends with a certain substring.
* -- usz
* -- uszEndsWith
* -- fCaseInsensitive
* -- return
*/
BOOL CharUtil_StrEndsWith(_In_opt_ LPSTR usz, _In_opt_ LPSTR uszEndsWith, _In_ BOOL fCaseInsensitive)
{
    SIZE_T cch, cchEndsWith;
    if(!usz || !uszEndsWith) { return FALSE; }
    cch = strlen(usz);
    cchEndsWith = strlen(uszEndsWith);
    if(cch < cchEndsWith) { return FALSE; }
    return fCaseInsensitive ?
        (0 == _stricmp(usz + cch - cchEndsWith, uszEndsWith)) :
        (0 == strcmp(usz + cch - cchEndsWith, uszEndsWith));
}

/*
* Compare a wide-char string to a utf-8 string.
* NB! only the first 2*MAX_PATH characters are compared.
* -- wsz1
* -- usz2
* -- return = 0 if equals, -1/1 otherwise.
*/
int CharUtil_CmpWU(_In_opt_ LPWSTR wsz1, _In_opt_ LPSTR usz2, _In_ BOOL fCaseInsensitive)
{
    LPSTR usz1;
    BYTE pbBuffer1[2 * MAX_PATH];
    if(!wsz1 && !usz2) { return 0; }
    if(!wsz1) { return -1; }
    if(!usz2) { return 1; }
    if(!CharUtil_WtoU(wsz1, -1, pbBuffer1, sizeof(pbBuffer1), &usz1, NULL, CHARUTIL_FLAG_TRUNCATE)) { return -1; }
    return fCaseInsensitive ? _stricmp(usz1, usz2) : strcmp(usz1, usz2);
}

/*
* Compare two wide-char strings.
* NB! only the first 2*MAX_PATH characters are compared.
* -- wsz1
* -- wsz2
* -- return = 0 if equals, -1/1 otherwise.
*/
int CharUtil_CmpWW(_In_opt_ LPWSTR wsz1, _In_opt_ LPWSTR wsz2, _In_ BOOL fCaseInsensitive)
{
    LPSTR usz1, usz2;
    BYTE pbBuffer1[2 * MAX_PATH], pbBuffer2[2 * MAX_PATH];
    if(!wsz1 && !wsz2) { return 0; }
    if(!wsz1) { return -1; }
    if(!wsz2) { return 1; }
    if(!CharUtil_WtoU(wsz1, -1, pbBuffer1, sizeof(pbBuffer1), &usz1, NULL, CHARUTIL_FLAG_TRUNCATE)) { return -1; }
    if(!CharUtil_WtoU(wsz2, -1, pbBuffer2, sizeof(pbBuffer2), &usz2, NULL, CHARUTIL_FLAG_TRUNCATE)) { return 1; }
    return fCaseInsensitive ? _stricmp(usz1, usz2) : strcmp(usz1, usz2);
}
