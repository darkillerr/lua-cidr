#ifndef _CIDR_H_
#define _CIDR_H_

#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>

/* ngx code definiton */
#define  NGX_OK          0
#define  NGX_ERROR      -1
#define  NGX_DONE       -4
/* end of ngx code definiton */

#define ngx_memzero(buf, n)       (void) memset(buf, 0, n)
#define ngx_memset(buf, c, n)     (void) memset(buf, c, n)
#define ngx_inline      inline

#define NGX_HAVE_INET6  1
#ifndef INADDR_NONE  /* Solaris */
#define INADDR_NONE  ((unsigned int) -1)
#endif

// atoi only used to calculate the subnet mask here, it should not greater than 128, so use INT_MAX.
#define NGX_MAX_INT_T_VALUE  2147483647

typedef intptr_t        ngx_int_t;
typedef uintptr_t       ngx_uint_t;

typedef struct {
    size_t      len;
    u_char     *data;
} ngx_str_t;

/* ipv4/ipv6 cidr definition */
typedef struct {
    in_addr_t                 addr;
    in_addr_t                 mask;
} ngx_in_cidr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr           addr;
    struct in6_addr           mask;
} ngx_in6_cidr_t;

#endif

typedef struct {
    ngx_uint_t                family;
    union {
        ngx_in_cidr_t         in;
#if (NGX_HAVE_INET6)
        ngx_in6_cidr_t        in6;
#endif
    } u;
} ngx_cidr_t;
/* end of ipv4/ipv6 cidr definition */

/* some aux function definition */
static ngx_inline u_char *
ngx_strlchr(u_char *p, u_char *last, u_char c)
{
    while (p < last) {

        if (*p == c) {
            return p;
        }

        p++;
    }

    return NULL;
}

ngx_int_t ngx_atoi(u_char *line, size_t n);
/* end of some aux function definition */

in_addr_t ngx_inet_addr(u_char *text, size_t len);
#if (NGX_HAVE_INET6)
ngx_int_t ngx_inet6_addr(u_char *p, size_t len, u_char *addr);
#endif
ngx_int_t ngx_ptocidr(ngx_str_t *text, ngx_cidr_t *cidr);

int is_cidr_contains_ip(const char *cidr_str, const char *ip_str);

#endif
