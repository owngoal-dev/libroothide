#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <libgen.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/param.h>

#include "common.h"

EXPORT
const char* __roothideinit_JBRAND=NULL;
EXPORT
const char* __roothideinit_JBROOT=NULL;

#define BOOTSTRAP_LIBRARY_PATH     "/usr/lib/roothideinit.dylib"

int bootstrap()
{
    struct dl_info di={0};
    assert(dladdr((void*)bootstrap, &di) != 0);

    char* librealpath = strdup(di.dli_fname);

    assert(strlen(librealpath) >= (sizeof(BOOTSTRAP_LIBRARY_PATH)-1));

    char* plib = librealpath + strlen(librealpath) - (sizeof(BOOTSTRAP_LIBRARY_PATH)-1);
    assert(strcmp(plib, BOOTSTRAP_LIBRARY_PATH) == 0);

    *plib = '\0';
    const char* jbroot = librealpath;
    
    char bname[PATH_MAX];
    basename_r(jbroot, bname);

    assert(is_jbroot_name(bname));

    uint64_t randvalue = resolve_jbrand_value(bname);
    assert(randvalue != 0);

    char jbrand[32]={0};
    snprintf(jbrand, sizeof(jbrand), "%016llX", randvalue);

    char jbroot_standardized[PATH_MAX]={0};
    snprintf(jbroot_standardized, sizeof(jbroot_standardized), "%s/%s%s", JB_ROOT_PARENT, JB_ROOT_PREFIX, jbrand);

    __roothideinit_JBRAND = strdup(jbrand);
    __roothideinit_JBROOT = strdup(jbroot_standardized);

    free(librealpath);
    return 0;
}

static void init_locale_path(void)
{
    int olderr = errno;
    char* resolved = NULL;
    if(issetugid() || !__roothideinit_JBROOT)
        goto out;

    const char* path = getenv("PATH_LOCALE");
    if(!path) {
        path = "/usr/share/locale";
    } else {
        const char* defaults[] = {"/usr/share/locale", "/usr/local/share/locale"};
        int translate = 0;
        for(size_t i=0; i<sizeof(defaults)/sizeof(defaults[0]); i++) {
            size_t length = strlen(defaults[i]);
            if(strncmp(path, defaults[i], length) == 0 &&
               (path[length] == '\0' || path[length] == '/')) {
                translate = 1;
                break;
            }
        }
        if(!translate)
            goto out;
    }

    size_t root_length = strlen(__roothideinit_JBROOT);
    size_t path_length = strlen(path);
    /* Apple libc reserves two slashes, ENCODING_LEN (31), CATEGORY_LEN (11). */
    size_t max_length = PATH_MAX - 44;
    if(root_length >= max_length || path_length >= max_length - root_length)
        goto out;

    resolved = malloc(root_length + path_length + 1);
    if(!resolved)
        goto out;
    memcpy(resolved, __roothideinit_JBROOT, root_length);
    memcpy(resolved + root_length, path, path_length + 1);
    setenv("PATH_LOCALE", resolved, 1);
out:
    free(resolved);
    errno = olderr;
}

static void __attribute__((__constructor__)) _roothide_init()
{
    assert(bootstrap() == 0);
    /* Supply the native directory before libc caches PATH_LOCALE on first use. */
    init_locale_path();
}
