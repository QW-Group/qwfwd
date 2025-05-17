#include "qwfwd.h"

#define WHITELIST_MAX_ADDRS 4096

static int whitelist_count;
static unsigned int whitelist[WHITELIST_MAX_ADDRS];

static void Cmd_Whitelist_f (void);
static void Cmd_WhitelistAdd_f (void);
static void Cmd_WhitelistRemove_f (void);

void Whitelist_Init(void)
{
	whitelist_count = 0;

	Cmd_AddCommand("whitelist", Cmd_Whitelist_f);
	Cmd_AddCommand("whitelistadd", Cmd_WhitelistAdd_f);
	Cmd_AddCommand("whitelistremove", Cmd_WhitelistRemove_f);
}

qbool SV_IsWhitelisted(struct sockaddr_in *addr)
{
	int i;

	if (!whitelist_count)
	{
		return true;
	}

	for (i = 0; i < whitelist_count; i++)
	{
		if (addr->sin_addr.s_addr == whitelist[i])
		{
			Sys_DPrintf("connection from %s allowed: address found in whitelist\n",
				inet_ntoa(addr->sin_addr));
			return true;
		}
	}

	Sys_DPrintf("connection from %s dropped: address NOT in whitelist\n",
		inet_ntoa(addr->sin_addr));
	return false;
}

static void Cmd_Whitelist_f(void)
{
	struct in_addr addr;
	int i;

	Sys_Printf("whitelist: %d addresses\n", whitelist_count);

	for (i = 0; i < whitelist_count; i++)
	{
		addr.s_addr = whitelist[i];
		Sys_Printf("%s\n", inet_ntoa(addr));
	}
}

static void Cmd_WhitelistAdd_f(void)
{
	char *ip_str;
	int ip;
	int i;

	if (Cmd_Argc() != 2)
	{
		Sys_Printf("usage: whitelistadd <ip>\n");
		return;
	}

	if (whitelist_count >= WHITELIST_MAX_ADDRS)
	{
		Sys_Printf("error: whitelist is full\n");
		return;
	}

	ip_str = Cmd_Argv(1);

	ip = inet_addr(ip_str);
	if (ip == INADDR_NONE)
	{
		Sys_Printf("error: invalid IP address %s\n", ip_str);
		return;
	}

	for (i = 0; i < whitelist_count; i++)
	{
		if (ip == whitelist[i])
		{
			Sys_Printf("error: %s has already been added to the whitelist\n", ip_str);
			return;
		}
	}

	whitelist[whitelist_count++] = ip;
}


static void Cmd_WhitelistRemove_f(void)
{
	char *ip_str;
	int ip;
	int i;
	int j;

	if (Cmd_Argc() != 2)
	{
		Sys_Printf("usage: whitelistremove <ip>\n");
		return;
	}

	ip_str = Cmd_Argv(1);

	ip = inet_addr(ip_str);
	if (ip == INADDR_NONE)
	{
		Sys_Printf("error: invalid IP address %s\n", ip_str);
		return;
	}

	for (i = 0; i < whitelist_count; i++)
	{
		if (whitelist[i] == ip)
		{
			for (j = i; j < whitelist_count - 1; j++)
			{
				whitelist[j] = whitelist[j + 1];
			}

			whitelist_count--;
			Sys_Printf("%s removed from whitelist\n", ip_str);
			return;
		}
	}

	Sys_Printf("error: %s not found in whitelist\n", ip_str);
}
