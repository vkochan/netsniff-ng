/*
 * netsniff-ng - the packet sniffing beast
 * Subject to the GPL, version 2.
 */

#define _LGPL_SOURCE

#include <urcu.h>
#include <netdb.h>
#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>

#include "list.h"
#include "locking.h"
#include "built_in.h"
#include "xmalloc.h"
#include "dns_resolver.h"

static volatile bool is_uninitializing = false;
static bool is_initialized = false;
static pthread_t resolver_tid;

struct dns_request {
	struct list_head entry;

	int af;
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} sock_addr;

	dns_resolve_cb_t cb;
	void *ctx;
};

static struct {
	struct spinlock lock;
	struct list_head head;
} request_list;

static void *resolver_thread(void *null __maybe_unused)
{
	rcu_register_thread();

	while (!is_uninitializing) {
		struct hostent *he = NULL;
		struct dns_request *req;
		int af;

		spinlock_lock(&request_list.lock);

		if (list_empty(&request_list.head)) {
			spinlock_unlock(&request_list.lock);
			usleep(100000);
			continue;
		}

		req = list_first_entry(&request_list.head, struct dns_request, entry);
		list_del(&req->entry);

		spinlock_unlock(&request_list.lock);

		af = req->af;
		if (af == AF_INET) {
			struct sockaddr_in *sa4 = &req->sock_addr.v4;

			he = gethostbyaddr(&sa4->sin_addr, sizeof(sa4->sin_addr), af);
		} else if (af == AF_INET6) {
			struct sockaddr_in6 *sa6 = &req->sock_addr.v6;

			he = gethostbyaddr(&sa6->sin6_addr, sizeof(sa6->sin6_addr), af);
		} else {
			bug();
		}

		if (he)
			req->cb(he, req->ctx);

		xfree(req);
	};

	rcu_unregister_thread();
	pthread_exit(NULL);
}

int hostname_by_addr_async(int af, void *addr, dns_resolve_cb_t cb, void *ctx)
{
	struct dns_request *req;

	if (!is_initialized)
		bug();

	req = xzmalloc(sizeof(*req));
	req->af  = af;
	req->cb  = cb;
	req->ctx = ctx;

	if (af == AF_INET) {
		req->sock_addr.v4 = *(struct sockaddr_in *)addr;
	} else if (af == AF_INET6) {
		memcpy(&req->sock_addr.v6, addr, sizeof(struct sockaddr_in6));
	} else {
		bug();
	}

	spinlock_lock(&request_list.lock);
	list_add_tail(&req->entry, &request_list.head);
	spinlock_unlock(&request_list.lock);

	return 0;
}

int dns_resolver_init(void)
{
	int ret;

	if (is_initialized)
		bug();

	INIT_LIST_HEAD(&request_list.head);
	spinlock_init(&request_list.lock);

	ret = pthread_create(&resolver_tid, NULL, resolver_thread, NULL);
	if (ret < 0) {
		fprintf(stderr, "Cannot create resolver thread!\n");
		return ret;
	}

	is_initialized = true;
	return 0;
}

void dns_resolver_uninit(void)
{
	struct dns_request *req, *tmp;

	if (!is_initialized)
		return;

	is_uninitializing = true;

	pthread_join(resolver_tid, NULL);
	spinlock_destroy(&request_list.lock);

	list_for_each_entry_safe(req, tmp, &request_list.head, entry)
		xfree(req);

	is_uninitializing = false;
}
