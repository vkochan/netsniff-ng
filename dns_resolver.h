#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

typedef void (* dns_resolve_cb_t) (const struct hostent *he, void *ctx);

extern int dns_resolver_init(void);
extern void dns_resolver_uninit(void);

extern int hostname_by_addr_async(int af, void *addr, dns_resolve_cb_t cb, void *ctx);

#endif /* DNS_RESOLVER_H */
