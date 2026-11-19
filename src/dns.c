#include "qwfwd.h"

#include <ares.h>
#include <stdatomic.h>

#define MAX_DNS_REQUESTS MAX_PRX_DNS_REQUESTS
#define DNS_PENDING (-1)

typedef struct
{
	// Only the main thread accesses callback and arg.
	// Release/acquire on status makes address visible to the main thread.
	net_dns_callback_t callback;
	void *arg;
	atomic_int status;
	struct in_addr address;
} dns_request_t;

static ares_channel_t *dns_channel;
static dns_request_t dns_requests[MAX_DNS_REQUESTS];

void NET_DNS_Init(void)
{
	struct ares_options options = {0};
	int status = ares_library_init(ARES_LIB_INIT_ALL);

	if (status != ARES_SUCCESS)
		Sys_Error("c-ares initialization failed: %s", ares_strerror(status));

	options.evsys = ARES_EVSYS_DEFAULT;
	status = ares_init_options(&dns_channel, &options, ARES_OPT_EVENT_THREAD);
	if (status != ARES_SUCCESS)
	{
		ares_library_cleanup();
		Sys_Error("c-ares channel initialization failed: %s", ares_strerror(status));
	}
}

static void NET_DNS_Reply(void *arg, int status, int timeouts, struct ares_addrinfo *result)
{
	dns_request_t *request = arg;

	if (status == ARES_SUCCESS)
	{
		if (result && result->nodes && result->nodes->ai_family == AF_INET)
			request->address = ((struct sockaddr_in *)result->nodes->ai_addr)->sin_addr;
		else
			status = ARES_ENODATA;
	}
	ares_freeaddrinfo(result);

	// Publish the address after this callback has finished using the slot.
	atomic_store_explicit(&request->status, status, memory_order_release);
}

qbool NET_DNS_Resolve(const char *host, net_dns_callback_t callback, void *arg)
{
	struct ares_addrinfo_hints hints = {0};
	int i;

	if (!dns_channel)
		return false;

	for (i = 0; i < MAX_DNS_REQUESTS; i++)
	{
		dns_request_t *request = &dns_requests[i];
		if (request->callback)
			continue;

		request->callback = callback;
		request->arg = arg;
		atomic_store_explicit(&request->status, DNS_PENDING, memory_order_relaxed);
		hints.ai_family = AF_INET;
		hints.ai_flags = ARES_AI_NOSORT;
		ares_getaddrinfo(dns_channel, host, NULL, &hints, NET_DNS_Reply, request);
		return true;
	}

	return false;
}

void NET_DNS_Frame(void)
{
	int i;

	for (i = 0; i < MAX_DNS_REQUESTS; i++)
	{
		dns_request_t *request = &dns_requests[i];
		net_dns_callback_t callback = request->callback;
		int status;
		struct in_addr address;

		if (!callback)
			continue;
		status = atomic_load_explicit(&request->status, memory_order_acquire);
		if (status == DNS_PENDING)
			continue;

		if (status == ARES_SUCCESS)
			address = request->address;
		request->callback = NULL;
		callback(status == ARES_SUCCESS ? &address : NULL, request->arg);
	}
}

void NET_DNS_Shutdown(void)
{
	ares_channel_t *channel = dns_channel;

	dns_channel = NULL;
	ares_destroy(channel);
	NET_DNS_Frame(); // Deliver cancellation so callers can free their pending requests.
	ares_library_cleanup();
}
