#ifndef VROOT_SHM_NAME_H
#define VROOT_SHM_NAME_H

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

/* XNU PSHMNAMLEN counts bytes before the terminating NUL. */
#define VROOT_SHM_NAME_MAX 31

/*
 * Shared-memory names are kernel namespace keys, not filesystem paths. Keep
 * Darwin's exact name bytes (including any slashes), but isolate each jbrand.
 * A domain-separated 168-bit SHA-256 prefix fits in the native 31-byte limit;
 * as with any finite digest namespace, collisions are not impossible.
 */
static int vroot_shm_name(const char *name, uint64_t root,
                          char mapped[VROOT_SHM_NAME_MAX + 1])
{
    if (name == NULL) {
        errno = EFAULT;
        return -1;
    }

    size_t length = strnlen(name, VROOT_SHM_NAME_MAX + 1);
    if (length == 0) {
        errno = EINVAL;
        return -1;
    }
    if (length > VROOT_SHM_NAME_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }

    static const unsigned char domain[] = "roothide.shm.v1";
    unsigned char input[sizeof(domain) + sizeof(root) + VROOT_SHM_NAME_MAX];
    memcpy(input, domain, sizeof(domain));
    for (size_t i = 0; i < sizeof(root); ++i)
        input[sizeof(domain) + i] = (unsigned char)(root >> (56 - i * 8));
    memcpy(input + sizeof(domain) + sizeof(root), name, length);

    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(input, (CC_LONG)(sizeof(domain) + sizeof(root) + length), digest);

    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    memcpy(mapped, "/rh", 3);
    for (size_t i = 0, out = 3; i < 21; i += 3, out += 4) {
        uint32_t bits = ((uint32_t)digest[i] << 16) |
                        ((uint32_t)digest[i + 1] << 8) | digest[i + 2];
        mapped[out] = alphabet[(bits >> 18) & 63];
        mapped[out + 1] = alphabet[(bits >> 12) & 63];
        mapped[out + 2] = alphabet[(bits >> 6) & 63];
        mapped[out + 3] = alphabet[bits & 63];
    }
    mapped[VROOT_SHM_NAME_MAX] = '\0';
    return 0;
}

#endif
