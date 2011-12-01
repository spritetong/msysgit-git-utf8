#ifndef __WIN32_XUTF8_H__
#define __WIN32_XUTF8_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Indicates UTF-8 is enabled. */
#define __XUTF8_ENABLED__

/******************************************************************************/

#ifdef __XUTF8_ENABLED__

#if (PATH_MAX < 2048)
#define _XUTF8_MAXPATH		2048
#else
#define _XUTF8_MAXPATH		PATH_MAX
#endif

#if (_XUTF8_MAXPATH/2 < 1024)
#define _XUTF8_MAXWPATH		1024
#else
#define _XUTF8_MAXWPATH	(_XUTF8_MAXPATH/2)
#endif

#define _XUTF8_DEFEVNNUM	512
#define _XUTF8_DEFEVNVAL	256
#define _XUTF8_CODEPAGE		CP_UTF8

extern wchar_t *_xutf8_a2w(unsigned codepage, const char *src, wchar_t *dst, int dst_len);

extern char *_xutf8_w2a(unsigned codepage, const wchar_t *src, char *dst, int dst_len);

extern wchar_t *_xutf8_a2w_alloc(unsigned codepage, const char *src);

extern char *_xutf8_w2a_alloc(unsigned codepage, const wchar_t *src);

/******************************************************************************/

WINBASEAPI HANDLE WINAPI xutf8_FindFirstFileA(LPCSTR,LPWIN32_FIND_DATAA);
#define FindFirstFileA xutf8_FindFirstFileA

WINBASEAPI BOOL WINAPI xutf8_FindNextFileA(HANDLE,LPWIN32_FIND_DATAA);
#define FindNextFileA xutf8_FindNextFileA

WINBASEAPI BOOL WINAPI xutf8_GetFileAttributesExA(LPCSTR,GET_FILEEX_INFO_LEVELS,PVOID);
#define GetFileAttributesExA xutf8_GetFileAttributesExA

WINBASEAPI DWORD WINAPI xutf8_GetFileAttributesA(LPCSTR);
#define GetFileAttributesA xutf8_GetFileAttributesA

WINBASEAPI BOOL WINAPI xutf8_SetFileAttributesA(LPCSTR,DWORD);
#define SetFileAttributesA xutf8_SetFileAttributesA

WINBASEAPI BOOL WINAPI xutf8_MoveFileExA(LPCSTR,LPCSTR,DWORD);
#define MoveFileExA xutf8_MoveFileExA

WINBASEAPI HANDLE WINAPI xutf8_CreateFileA(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
#define CreateFileA xutf8_CreateFileA

WINBASEAPI int WINAPI xutf8_CreateHardLinkA(LPCSTR,LPCSTR,LPSECURITY_ATTRIBUTES);
#define CreateHardLinkA xutf8_CreateHardLinkA

WINBASEAPI BOOL WINAPI xutf8_CreateProcessA(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,
	LPSECURITY_ATTRIBUTES,BOOL,DWORD,PVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
#define CreateProcessA xutf8_CreateProcessA

//GetUserName

/******************************************************************************/

int xutf8_unlink(const char *pathname);
#undef  unlink
#define unlink xutf8_unlink

int xutf8_rmdir(const char *pathname);
#undef  rmdir
#define rmdir xutf8_rmdir

int xutf8_mkdir(const char *path);
#undef  mkdir
#define mkdir xutf8_mkdir

int xutf8_open(const char *filename, int oflags, ...);
#undef  open
#define open xutf8_open

FILE *xutf8_fopen(const char *filename, const char *otype);
#undef  fopen
#define fopen xutf8_fopen

FILE *xutf8_freopen(const char *filename, const char *otype, FILE *stream);
#undef  freopen
#define freopen xutf8_freopen

char *xutf8_getcwd(char *pointer, int len);
#undef  getcwd
#define getcwd xutf8_getcwd

char *xutf8_getenv(const char *name);
#undef  getenv
#define getenv xutf8_getenv

int xutf8_rename(const char *pold, const char *pnew);
#undef  rename
#define rename xutf8_rename

#endif /* __XUTF8_ENABLED__ */

#ifdef __XUTF8_INIT__
#include "win32_xutf8.c"
#endif /* __XUTF8_INIT__ */

#ifdef __cplusplus
}
#endif

#endif /* __WIN32_XUTF8_H__ */
