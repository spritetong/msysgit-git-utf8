#ifndef __XUTF8_INIT__
#include "win32.h"
#include "win32_xutf8.h"
#endif

#ifdef __XUTF8_ENABLED__

#define _xutf82w(src, dst)	_xutf8_a2w(_XUTF8_CODEPAGE, src, dst, ARRAY_SIZE(dst))
#define _xw2utf8(src, dst)	_xutf8_w2a(_XUTF8_CODEPAGE, src, dst, ARRAY_SIZE(dst))

wchar_t *_xutf8_a2w(unsigned codepage, const char *src, wchar_t *dst, int dst_len)
{
	int len;

	if (!dst || dst_len <= 0)
		return NULL;

	if (src)
	{
		len = MultiByteToWideChar(codepage, 0, src, -1, dst, dst_len - 1);
		if (len >= 0)
		{
			dst[len] = '\0';
			return dst;
		}
	}
	dst[0] = '\0';
	return NULL;
}

char *_xutf8_w2a(unsigned codepage, const wchar_t *src, char *dst, int dst_len)
{
	int len;

	if (!dst || dst_len <= 0)
		return NULL;

	if (src)
	{
		len = WideCharToMultiByte(codepage, 0, src, -1, dst, dst_len - 1, NULL, NULL);
		if (len >= 0)
		{
			dst[len] = '\0';
			return dst;
		}
	}
	dst[0] = '\0';
	return NULL;
}

wchar_t *_xutf8_a2w_alloc(unsigned codepage, const char *src)
{
	wchar_t *dst = NULL;
	int len;

	if (src)
	{
		len = MultiByteToWideChar(codepage, 0, src, -1, NULL, 0);
		if (len > 0)
		{
			dst = (wchar_t *)xmalloc((len + 1) * sizeof(wchar_t));
			if (dst)
			{
				len = MultiByteToWideChar(codepage, 0, src, -1, dst, len);
				dst[len] = '\0';
			}
		}
	}
	return dst;
}

char *_xutf8_w2a_alloc(unsigned codepage, const wchar_t *src)
{
	char *dst = NULL;
	int len;

	if (src)
	{
		len = WideCharToMultiByte(codepage, 0, src, -1, NULL, 0, NULL, NULL);
		if (len > 0)
		{
			dst = (char *)xmalloc((len + 1) * sizeof(char));
			if (dst)
			{
				len = WideCharToMultiByte(codepage, 0, src, -1, dst, len, NULL, NULL);
				dst[len] = '\0';
			}
		}
	}
	return dst;
}

/******************************************************************************/

typedef struct _xutf8_env_struct
{
	char **env;
	int avail;
	int capacity;
} xutf8_env_t;

typedef struct _xutf8_wenv_struct
{
	wchar_t **env;
	int avail;
	int capacity;
} xutf8_wenv_t;

static xutf8_env_t _xutf8_environ;

static char **_xutf8_evn_lookup(char **env, const char *name)
{
	char *entry;
	const char *pname;
	char centry, cname;

	if (env == NULL || name == NULL)
		return NULL;

	while ((entry = *env++) != NULL)
	{
		pname = name;
		do
		{
			centry = *entry++;
			cname  = *pname++;
			if (cname == '\0')
			{
				if (centry == '=')
					return env - 1;
				break;
			}
			if (centry >= 'A' && centry <= 'Z')
				centry += 'a' - 'A';
			if (cname >= 'A' && cname <= 'Z')
				cname += 'a' - 'A';
		} while (centry == cname);
	}
	return NULL;
}

static char **_xutf8_env_add(xutf8_env_t *env, const char *name, const char *value)
{
	char **entry, *p;
	if (env->avail == env->capacity)
		return NULL;
	if ((p = (char *)xmalloc(strlen(name) + strlen(value) + 2)) == NULL)
		return NULL;
	sprintf(p, "%s=%s", name, value);
	entry = env->env + env->avail++;
	entry[0] = p;
	entry[1] = NULL;
	return entry;
}

static char **_xutf8_env_setenv(xutf8_env_t *env, const char *name, const char *value)
{
	char **entry, *p;

	if (env == NULL || env->env == NULL || name == NULL)
		return NULL;

	/* Lookup entry that matches the name. */
	if ((entry = _xutf8_evn_lookup(env->env, name)) == NULL)
	{
		if (value == NULL || value[0] == '\0')
			return NULL;
		return _xutf8_env_add(env, name, value);
	}

	if (value == NULL || value[0] == '\0')
	{
do_remove:
		/* Remove entry. */
		while ((*entry = *(entry + 1)) != NULL)
			entry++;
		env->avail--;
		return NULL;
	}

	/* Get value from the entry. */
	if ((p = strchr(*entry, '=')) == NULL)
	{
		/* Remove bad entry. */
		goto do_remove;
	}
	p++;

	/* If old value is identical to the new value, do nothing. */
	if (strcmp(p, value) == 0)
		return entry;

	if (strlen(p) >= strlen(value))
	{
		/* Set value. */
		strcpy(p, value);
	}
	else
	{
		/* Enlarge entry. */
		if ((p = (char *)xrealloc(*entry, strlen(name) + strlen(value) + 2)) == NULL)
			return NULL;
		sprintf(p, "%s=%s", name, value);
		*entry = p;
	}
	return entry;
}

static char *_xutf8_getenv(xutf8_env_t *env, const char *name)
{
	wchar_t valbuf[_XUTF8_DEFEVNVAL], *wval;
	char *ret = NULL, *val = (char *)valbuf, **entry;
	int cnt;

	if (env == NULL || env->env == NULL || name == NULL)
		return NULL;

	/* Get the unicode environment value. */
	_xutf82w(name, valbuf);
	if ((wval = _wgetenv(valbuf)) == NULL)
		return NULL;

	/* Convert unicode to UTF-8. */
	cnt = WideCharToMultiByte(_XUTF8_CODEPAGE, 0, wval, -1, val, sizeof(valbuf) - 1, NULL, NULL);
	if (cnt <= 0)
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			return NULL;
		if ((val = _xutf8_w2a_alloc(_XUTF8_CODEPAGE, wval)) == NULL)
			return NULL;
	}
	else
		val[cnt] = '\0';

	/* Update the relative variable in the environment control block. */
	if ((entry = _xutf8_env_setenv(env, name, val)) != NULL)
		ret = strchr(*entry, '=') + 1;

	if (val != (char *)valbuf)
		free(val);
	return ret;
}

int _xutf8_putenv(xutf8_env_t *env, const char *envstring)
{
	wchar_t valbuf[_XUTF8_DEFEVNVAL];
	wchar_t *wenvstr = valbuf;
	char *val = (char *)valbuf, *p;
	char **entry;
	int ret;

	if (envstring == NULL)
		return -1;
	if ((p = (char *)strchr(envstring, '=')) == NULL || p == envstring)
		return -1;

	/* At first, call system _wsetenv(). */
	ret = MultiByteToWideChar(_XUTF8_CODEPAGE, 0, envstring, -1, valbuf, ARRAY_SIZE(valbuf) - 1);
	if (ret <= 0)
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			return -1;
		if ((wenvstr = _xutf8_a2w_alloc(_XUTF8_CODEPAGE, envstring)) == NULL)
			return -1;
	}
	else
		wenvstr[ret] = '\0';
	ret = _wputenv(wenvstr);
	if (wenvstr != valbuf)
		free(wenvstr);
	if (ret != 0)
		return ret;

	/* Then, put the environment variable into the UTF-8 environment control block. */
	if (strlen(envstring) >= sizeof(valbuf))
	{
		if ((val = xstrdup(envstring)) == NULL)
			return -1;
	}
	else
		strcpy(val, envstring);
	p = val + (p - envstring);
	*p++ = '\0';
	if ((entry = _xutf8_env_setenv(env, val, p)) == NULL && *p != '\0')
		ret = -1;
	if (val != (char *)valbuf)
		free(val);

	return ret;
}

static char **_xutf8_clonewenv(xutf8_env_t *dst, wchar_t **src)
{
	char **dst_entry;
	wchar_t **src_entry;
	int count, cap;
	
	if (dst == NULL)
		return NULL;

	if (dst->env)
	{
		/* Free all old variables. */
		dst_entry = dst->env;
		while (*dst_entry)
			free(*dst_entry++);
		dst->env[0] = NULL;
		dst->avail = 0;
	}

	if (src == NULL)
	{
		/* Free the environment control block. */
		if (dst->env)
		{
			free(dst->env);
			dst->env = NULL;
			dst->capacity = 0;
		}
		return NULL;
	}

	/* Get the number of variables. */
	src_entry = src;
	count = 0;
	while (*src_entry++)
		count++;

	if (dst->capacity < count)
	{
		cap = count + count / 2;
		if (cap < _XUTF8_DEFEVNNUM)
			cap = _XUTF8_DEFEVNNUM;
		dst_entry = (char **)xmalloc((cap + 1) * sizeof(void *));
		if (dst_entry == NULL)
			return dst->env;
		dst_entry[0] = NULL;
		if (dst->env)
			free(dst->env);
		dst->env = dst_entry;
		dst->capacity = cap;
	}

	/* Clone environment data block. */
	src_entry = src;
	dst_entry = dst->env;
	while (count-- && *src_entry)
	{
		if ((*dst_entry = _xutf8_w2a_alloc(_XUTF8_CODEPAGE, *src_entry++)) == NULL)
			break;
		dst->avail++;
		dst_entry++;
	}
	*dst_entry = NULL;

	return dst->env;
}

/******************************************************************************/

static inline void xutf8_FindDataW2Utf8(LPWIN32_FIND_DATAW wfdata, LPWIN32_FIND_DATAA afdata)
{
	afdata->dwFileAttributes = wfdata->dwFileAttributes;
	afdata->ftCreationTime   = wfdata->ftCreationTime;
	afdata->ftLastAccessTime = wfdata->ftLastAccessTime;
	afdata->ftLastWriteTime  = wfdata->ftLastWriteTime;
	afdata->nFileSizeHigh    = wfdata->nFileSizeHigh;
	afdata->nFileSizeLow     = wfdata->nFileSizeLow;
#ifdef _WIN32_WCE
    afdata->dwOID            = wfdata->dwOID;
#else
	afdata->dwReserved0      = wfdata->dwReserved0;
	afdata->dwReserved1      = wfdata->dwReserved1;
#endif
	_xutf8_w2a(_XUTF8_CODEPAGE, wfdata->cFileName,
		afdata->cFileName, ARRAY_SIZE(afdata->cFileName));
#ifndef _WIN32_WCE
	_xutf8_w2a(_XUTF8_CODEPAGE, wfdata->cAlternateFileName,
		afdata->cAlternateFileName, ARRAY_SIZE(afdata->cAlternateFileName));
#endif
}

HANDLE WINAPI xutf8_FindFirstFileA(LPCSTR lpFileName,
								   LPWIN32_FIND_DATAA lpFindFileData)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	WIN32_FIND_DATAW wfdata;
	HANDLE ret;
	ret = FindFirstFileW(_xutf82w(lpFileName, wstr1),
						 lpFindFileData ? &wfdata : NULL);
	if (ret != INVALID_HANDLE_VALUE)
		xutf8_FindDataW2Utf8(&wfdata, lpFindFileData);
	return ret;
}

BOOL WINAPI xutf8_FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
{
	WIN32_FIND_DATAW wfdata;
	BOOL ret;
	ret = FindNextFileW(hFindFile, (lpFindFileData ? &wfdata : NULL));
	if (ret)
		xutf8_FindDataW2Utf8(&wfdata, lpFindFileData);
	return ret;
}

BOOL WINAPI xutf8_GetFileAttributesExA(LPCSTR lpFileName,
									   GET_FILEEX_INFO_LEVELS fInfoLevelId,
									   PVOID lpFileInformation)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return GetFileAttributesExW(_xutf82w(lpFileName, wstr1), fInfoLevelId, lpFileInformation);
}

DWORD WINAPI xutf8_GetFileAttributesA(LPCSTR lpFileName)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return GetFileAttributesW(_xutf82w(lpFileName, wstr1));
}

BOOL WINAPI xutf8_SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return SetFileAttributesW(_xutf82w(lpFileName, wstr1), dwFileAttributes);
}

BOOL WINAPI xutf8_MoveFileExA(LPCSTR lpExistingFileName,
							  LPCSTR lpNewFileName,
							  DWORD dwFlags)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	wchar_t wstr2[_XUTF8_MAXWPATH];
	return MoveFileExW(_xutf82w(lpExistingFileName, wstr1),
		_xutf82w(lpNewFileName, wstr2), dwFlags);
}

#if (_WIN32_WINNT >= 0x0500)
int WINAPI xutf8_CreateHardLinkA(LPCSTR filename, LPCSTR existingFilename,
								 LPSECURITY_ATTRIBUTES securityAttributes)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	wchar_t wstr2[_XUTF8_MAXWPATH];
	return CreateHardLinkW(_xutf82w(filename, wstr1),
		_xutf82w(existingFilename, wstr2), securityAttributes);
}
#endif

HANDLE WINAPI xutf8_CreateFileA(
	LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return CreateFileW(_xutf82w(lpFileName, wstr1),
			  dwDesiredAccess,
			  dwShareMode,
			  lpSecurityAttributes,
			  dwCreationDisposition,
			  dwFlagsAndAttributes,
			  hTemplateFile);
}

BOOL WINAPI xutf8_CreateProcessA(
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	PVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation)
{
	STARTUPINFOW si;
	STARTUPINFOA *sa = lpStartupInfo;
	BOOL ret;
	wchar_t *lpwszDesktop, *lpwszTitle, *lpwszAppName, *lpwszCmdLine, *lpwszCurDir, *lpwEnviron;
	char *p;
	int cnt;

	if (sa == NULL)
		return FALSE;

	lpwszDesktop = _xutf8_a2w_alloc(_XUTF8_CODEPAGE, sa->lpDesktop);
	lpwszTitle   = _xutf8_a2w_alloc(_XUTF8_CODEPAGE, sa->lpTitle);
	lpwszAppName = _xutf8_a2w_alloc(_XUTF8_CODEPAGE, lpApplicationName);
	lpwszCmdLine = _xutf8_a2w_alloc(_XUTF8_CODEPAGE, lpCommandLine);
	lpwszCurDir  = _xutf8_a2w_alloc(_XUTF8_CODEPAGE, lpCurrentDirectory);

	/* Convert environment block. */
	lpwEnviron   = NULL;
	if (lpEnvironment && !(dwCreationFlags & CREATE_UNICODE_ENVIRONMENT))
	{
		p = (char *)lpEnvironment;
		while (1)
		{
			if (*p++ == '\0')
				if (*p++ == '\0')
					break;
		}
		cnt = MultiByteToWideChar(_XUTF8_CODEPAGE, 0,
				(char *)lpEnvironment, p - (char *)lpEnvironment, NULL, 0) + 1;
		if (cnt > 0)
		{
			if ((lpwEnviron = (wchar_t *)xmalloc(cnt * sizeof(wchar_t))) != NULL)
			{
				cnt = MultiByteToWideChar(_XUTF8_CODEPAGE, 0,
						(char *)lpEnvironment, p - (char *)lpEnvironment, lpwEnviron, cnt);
				if (cnt > 0)
				{
					dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
				}
				else
				{
					free(lpwEnviron);
					lpwEnviron = NULL;
				}
			}
		}
	}
	if (lpwEnviron == NULL)
		lpwEnviron = (wchar_t *)lpEnvironment;

	/* Convert startupinfo. */
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.lpDesktop = lpwszDesktop;
	si.lpTitle = lpwszTitle;
	si.dwX = sa->dwX;
	si.dwY = sa->dwY;
	si.dwXSize = sa->dwXSize;
	si.dwYSize = sa->dwYSize;
	si.dwXCountChars = sa->dwXCountChars;
	si.dwYCountChars = sa->dwYCountChars;
	si.dwFillAttribute = sa->dwFillAttribute;
	si.dwFlags = sa->dwFlags;
	si.wShowWindow = sa->wShowWindow;
	si.hStdInput = sa->hStdInput;
	si.hStdOutput = sa->hStdOutput;
	si.hStdError = sa->hStdError;

	ret = CreateProcessW(
		lpwszAppName,
		lpwszCmdLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpwEnviron,
		lpwszCurDir,
		&si,
		lpProcessInformation);

	free(lpwszDesktop);
	free(lpwszTitle);
	free(lpwszAppName);
	free(lpwszCmdLine);
	free(lpwszCurDir);
	if (lpwEnviron != (wchar_t *)lpEnvironment)
		free(lpwEnviron);
	return ret;
}

/******************************************************************************/

int xutf8_unlink(const char *pathname)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return _wunlink(_xutf82w(pathname, wstr1));
}

int xutf8_rmdir(const char *pathname)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return _wrmdir(_xutf82w(pathname, wstr1));
}

int xutf8_mkdir(const char *path)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return _wmkdir(_xutf82w(path, wstr1));
}

int xutf8_open(const char *filename, int oflags, ...)
{
	va_list args;
	unsigned mode;
	wchar_t wstr1[_XUTF8_MAXWPATH];

	va_start(args, oflags);
	mode = va_arg(args, int);
	va_end(args);

	return _wopen(_xutf82w(filename, wstr1), oflags, mode);
}

FILE *xutf8_fopen(const char *filename, const char *otype)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	wchar_t wstr2[20];
	return _wfopen(_xutf82w(filename, wstr1), _xutf82w(otype, wstr2));
}

FILE *xutf8_freopen(const char *filename, const char *otype, FILE *stream)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	wchar_t wstr2[20];
	return _wfreopen(_xutf82w(filename, wstr1), _xutf82w(otype, wstr2), stream);
}

char *xutf8_getcwd(char *pointer, int len)
{
	wchar_t *ret;
	wchar_t wstr1[_XUTF8_MAXWPATH];
	ret = _wgetcwd(wstr1, ARRAY_SIZE(wstr1));
	if (!ret)
		return NULL;
	return _xutf8_w2a(_XUTF8_CODEPAGE, ret, pointer, len);
}

char *xutf8_getenv(const char *name)
{
	return _xutf8_getenv(&_xutf8_environ, name);
}

int xutf8_rename(const char *pold, const char *pnew)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	wchar_t wstr2[_XUTF8_MAXWPATH];
	return _wrename(_xutf82w(pold, wstr1), _xutf82w(pnew, wstr2));
}

/******************************************************************************/

#include <shellapi.h>
static void xutf8_startup(int argc, char **argv)
{
	wchar_t wpgm[_XUTF8_MAXWPATH];
	wchar_t **wargv;
	int n, i;

	wargv = CommandLineToArgvW(GetCommandLineW(), &n);
	if (wargv == NULL)
		return;
	/* Copy executable name to argv[0] */
	wpgm[0] = '\0';
	GetModuleFileNameW(NULL, wpgm, ARRAY_SIZE(wpgm));
	if (wpgm[0])
		argv[0] = _xutf8_w2a_alloc(_XUTF8_CODEPAGE, wpgm);
	/* Copy arguments. */
	if (n > argc)
		n = argc;
	for (i = 1; i < n; i++)
		argv[i] = _xutf8_w2a_alloc(_XUTF8_CODEPAGE, wargv[i]);
	for (; i < argc; i++)
		argv[i] = xstrdup("");
	LocalFree(wargv);

	/* Create an UTF-8 environment block. */
	_wgetenv(L"PATH");
	_xutf8_clonewenv(&_xutf8_environ, _wenviron);
}

int mingw_putenv(const char *envstring)
{
	return _xutf8_putenv(&_xutf8_environ, envstring);
}

char **mingw_environ(void)
{
	return _xutf8_environ.env;
}

int mingw_chmod(const char *filename, int pmode)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return _wchmod(_xutf82w(filename, wstr1), pmode);
}

int mingw_access(const char *filename, int pmode)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return _waccess(_xutf82w(filename, wstr1), pmode);
}

int mingw_chdir(const char *path)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return _wchdir(_xutf82w(path, wstr1));
}

int mkstemp(char *template)
{
	wchar_t *filename;
	wchar_t wstr1[_XUTF8_MAXWPATH];
	filename = _wmktemp(_xutf82w(template, wstr1));
	if (filename == NULL)
		return -1;
	return _wopen(filename, O_RDWR | O_CREAT, 0600);
}
#define mkstemp _mkstemp_dummy

#else /* !__XUTF8_ENABLED__ */

#define xutf8_startup(argc, argv)	(void)0

int mingw_putenv(const char *envstring)
{
	return _putenv(envstring);
}

char **mingw_environ(void)
{
	return _environ;
}

int mingw_chmod(const char *filename, int pmode)
{
	return _chmod(filename,pmode);
}

int mingw_access(const char *filename, int pmode)
{
	return _access(filename,pmode);
}

int mingw_chdir(const char *path)
{
	return _chdir(path);
}

#endif /* __XUTF8_ENABLED__ */

