#ifndef __WIN32_XUTF8_H__
#define __WIN32_XUTF8_H__

#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#ifdef __XUTF8_INIT__
#include <Windows.h>
#endif

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
#define _XUTF8_MAXWPATH		(_XUTF8_MAXPATH/2)
#endif

#ifndef _XUTF8_USE_WENV
#define _XUTF8_USE_WENV		TRUE
#endif
#define _XUTF8_DEFENVNUM	128
#define _XUTF8_DEFENVNAM	64
#define _XUTF8_DEFENVVAL	256
#define _XUTF8_EVNPOOLSIZE	(64*1024)
#define _XUTF8_CODEPAGE		CP_UTF8

extern wchar_t *_xutf8_a2w(unsigned codepage, const char *src, wchar_t *dst, int dst_len);

extern char *_xutf8_w2a(unsigned codepage, const wchar_t *src, char *dst, int dst_len);

extern wchar_t *_xutf8_a2w_alloc(unsigned codepage, const char *src,
								 wchar_t *buf, int bufsz);

extern char *_xutf8_w2a_alloc(unsigned codepage, const wchar_t *src,
							  char *buf, int bufsz);

/******************************************************************************/

#ifdef WINAPI

HANDLE WINAPI xutf8_FindFirstFileA(LPCSTR,LPWIN32_FIND_DATAA);

BOOL WINAPI xutf8_FindNextFileA(HANDLE,LPWIN32_FIND_DATAA);

BOOL WINAPI xutf8_GetFileAttributesExA(LPCSTR,GET_FILEEX_INFO_LEVELS,PVOID);

DWORD WINAPI xutf8_GetFileAttributesA(LPCSTR);

BOOL WINAPI xutf8_SetFileAttributesA(LPCSTR,DWORD);

BOOL WINAPI xutf8_MoveFileExA(LPCSTR,LPCSTR,DWORD);

HANDLE WINAPI xutf8_CreateFileA(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);

int WINAPI xutf8_CreateHardLinkA(LPCSTR,LPCSTR,LPSECURITY_ATTRIBUTES);

BOOL WINAPI xutf8_CreateProcessA(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,
	LPSECURITY_ATTRIBUTES,BOOL,DWORD,PVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);

DWORD WINAPI xutf8_GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize);

BOOL WINAPI xutf8_SetEnvironmentVariableA(LPCSTR lpName, LPCSTR lpValue);

BOOL WINAPI xutf8_SetEnvironmentVariableW(LPCWSTR lpName, LPCWSTR lpValue);

//GetUserName

#endif /* WINAPI */

/******************************************************************************/

int xutf8_unlink(const char *pathname);

int xutf8_rmdir(const char *pathname);

int xutf8_mkdir(const char *path);

int xutf8_open(const char *filename, int oflags, ...);

FILE *xutf8_fopen(const char *filename, const char *otype);

FILE *xutf8_freopen(const char *filename, const char *otype, FILE *stream);

char *xutf8_getcwd(char *pointer, int len);

int xutf8_rename(const char *pold, const char *pnew);

int xutf8_chmod(const char *filename, int pmode);

int xutf8_access(const char *filename, int pmode);

int xutf8_chdir(const char *path);

char *xutf8_mktemp(char *stemplate);

int xutf8_mktemp_s(char *stemplate, size_t size);

char **xutf8_environ(void);

char *xutf8_getenv(const char *name);

int xutf8_getenv_s(size_t *pReturnValue, char* buffer, size_t sizeInBytes,
				   const char *varname);

int xutf8_putenv(const char *envstring);

int xutf8_putenv_s(const char *name, const char *value);

int xutf8_wputenv(const wchar_t *envstring);

int xutf8_wputenv_s(const wchar_t *name, const wchar_t *value);

#ifdef __XUTF8_INIT__
#include "win32_xutf8.c"
#endif /* __XUTF8_INIT__ */

#ifdef WINAPI
#define FindFirstFileA			xutf8_FindFirstFileA
#define FindNextFileA			xutf8_FindNextFileA
#define GetFileAttributesExA	xutf8_GetFileAttributesExA
#define GetFileAttributesA		xutf8_GetFileAttributesA
#define SetFileAttributesA		xutf8_SetFileAttributesA
#define MoveFileExA				xutf8_MoveFileExA
#define CreateFileA				xutf8_CreateFileA
#define CreateHardLinkA			xutf8_CreateHardLinkA
#define CreateProcessA			xutf8_CreateProcessA
#define GetEnvironmentVariableA	xutf8_GetEnvironmentVariableA
#define SetEnvironmentVariableA	xutf8_SetEnvironmentVariableA
#define SetEnvironmentVariableW	xutf8_SetEnvironmentVariableW
#endif /* WINAPI */

#if defined(__XUTF8_INIT__) || !defined(__XUTF8_GITPRJ__)
	#undef  unlink
	#define unlink				xutf8_unlink
	#undef  rmdir
	#define rmdir				xutf8_rmdir
	#undef  mkdir
	#define mkdir				xutf8_mkdir
	#undef  open
	#define open				xutf8_open
	#undef  fopen
	#define fopen				xutf8_fopen
	#undef  freopen
	#define freopen				xutf8_freopen
	#undef  getcwd
	#define getcwd				xutf8_getcwd
	#undef  rename
	#define rename				xutf8_rename
	#undef  getenv
	#define getenv				xutf8_getenv
#endif /* defined(__XUTF8_INIT__) || !defined(__XUTF8_GITPRJ__) */

#undef  _unlink
#define _unlink					xutf8_unlink
#undef  _rmdir
#define _rmdir					xutf8_rmdir
#undef  _mkdir
#define _mkdir					xutf8_mkdir
#undef  _open
#define _open					xutf8_open
//#undef  _fopen
//#define _fopen				xutf8_fopen
//#undef  _freopen
//#define _freopen				xutf8_freopen
#undef  _getcwd
#define _getcwd					xutf8_getcwd
//#undef  _rename
//#define _rename				xutf8_rename
//#undef  _getenv
//#define _getenv				xutf8_getenv
#undef  chmod
#define chmod					xutf8_chmod
#undef  _chmod
#define _chmod					xutf8_chmod
#undef  access
#define access					xutf8_access
#undef  _access
#define _access					xutf8_access
#undef  chdir
#define chdir					xutf8_chdir
#undef  _chdir
#define _chdir					xutf8_chdir
#undef  mktemp
#define mktemp					xutf8_mktemp
#undef  _mktemp
#define _mktemp					xutf8_mktemp
#undef  _mktemp_s
#define _mktemp_s				xutf8_mktemp_s
#undef  environ
#define environ					xutf8_environ()
#undef  _environ
#define _environ				xutf8_environ()
#undef  getenv_s
#define getenv_s				xutf8_getenv_s
#undef  putenv
#define putenv					xutf8_putenv
#undef  _putenv
#define _putenv					xutf8_putenv
#undef  _putenv_s
#define _putenv_s				xutf8_putenv_s
#undef  _wputenv
#define _wputenv				xutf8_wputenv
#undef  _wputenv_s
#define _wputenv_s				xutf8_wputenv_s

#endif /* __XUTF8_ENABLED__ */

#ifdef __cplusplus
}
#endif

#endif /* __WIN32_XUTF8_H__ */
