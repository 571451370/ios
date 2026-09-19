//go:build ios

// 仅 iOS：改写本进程 Mach-O 的 connect/sendto 等到本机 127.0.0.1。
// 隧道本身走 Go syscall，不会进这些挂钩。

#include "hook_ios.h"
#include "fishhook.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef int (*fn_connect)(int, const struct sockaddr *, socklen_t);
typedef int (*fn_getpeername)(int, struct sockaddr *, socklen_t *);
typedef int (*fn_getsockname)(int, struct sockaddr *, socklen_t *);
typedef int (*fn_close)(int);
typedef ssize_t (*fn_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
typedef ssize_t (*fn_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef ssize_t (*fn_sendmsg)(int, const struct msghdr *, int);
typedef ssize_t (*fn_recvmsg)(int, struct msghdr *, int);

static int hook_connect_impl(int fd, const struct sockaddr *addr, socklen_t len);
static int hook_getpeername_impl(int fd, struct sockaddr *addr, socklen_t *len);
static int hook_close_impl(int fd);
static ssize_t hook_sendto_impl(int fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t alen);
static ssize_t hook_recvfrom_impl(int fd, void *buf, size_t n, int flags, struct sockaddr *addr, socklen_t *alen);
static ssize_t hook_sendmsg_impl(int fd, const struct msghdr *msg, int flags);
static ssize_t hook_recvmsg_impl(int fd, struct msghdr *msg, int flags);

static fn_connect orig_connect;
static fn_getpeername orig_getpeername;
static fn_getsockname orig_getsockname;
static fn_close orig_close;
static fn_sendto orig_sendto;
static fn_recvfrom orig_recvfrom;
static fn_sendmsg orig_sendmsg;
static fn_recvmsg orig_recvmsg;

static int g_tcp_port;
static int g_udp_port;
static int g_installed;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static __thread int g_in_hook;

static int skip_img(const char *name) {
	if (!name || !name[0]) {
		return 0;
	}
	if (strstr(name, "Protect.framework") || strstr(name, "libprotect") ||
	    strstr(name, "/usr/lib/") || strstr(name, "/System/") ||
	    strstr(name, "libswift")) {
		return 1;
	}
	return 0;
}

static void resolve_orig(void) {
	if (!orig_connect) orig_connect = (fn_connect)dlsym(RTLD_NEXT, "connect");
	if (!orig_getpeername) orig_getpeername = (fn_getpeername)dlsym(RTLD_NEXT, "getpeername");
	if (!orig_getsockname) orig_getsockname = (fn_getsockname)dlsym(RTLD_NEXT, "getsockname");
	if (!orig_close) orig_close = (fn_close)dlsym(RTLD_NEXT, "close");
	if (!orig_sendto) orig_sendto = (fn_sendto)dlsym(RTLD_NEXT, "sendto");
	if (!orig_recvfrom) orig_recvfrom = (fn_recvfrom)dlsym(RTLD_NEXT, "recvfrom");
	if (!orig_sendmsg) orig_sendmsg = (fn_sendmsg)dlsym(RTLD_NEXT, "sendmsg");
	if (!orig_recvmsg) orig_recvmsg = (fn_recvmsg)dlsym(RTLD_NEXT, "recvmsg");
}

static int parse_v4(const struct sockaddr *addr, socklen_t len, char *ip, size_t iplen, int *port) {
	if (!addr || len < sizeof(struct sockaddr_in) || addr->sa_family != AF_INET) {
		return 0;
	}
	const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
	if (!inet_ntop(AF_INET, &in->sin_addr, ip, (socklen_t)iplen)) {
		return 0;
	}
	*port = ntohs(in->sin_port);
	return 1;
}

static int local_port_of(int fd) {
	struct sockaddr_in a;
	socklen_t l = sizeof(a);
	if (!orig_getsockname) {
		return -1;
	}
	if (orig_getsockname(fd, (struct sockaddr *)&a, &l) != 0 || a.sin_family != AF_INET) {
		return -1;
	}
	return ntohs(a.sin_port);
}

static int bind_ephemeral(int fd) {
	int lp = local_port_of(fd);
	if (lp > 0) {
		return lp;
	}
	struct sockaddr_in a;
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	a.sin_port = 0;
	if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 && errno != EINVAL) {
		return -1;
	}
	return local_port_of(fd);
}

static int hook_connect_impl(int fd, const struct sockaddr *addr, socklen_t len) {
	if (g_in_hook || !orig_connect) {
		return orig_connect ? orig_connect(fd, addr, len) : -1;
	}
	char ip[64];
	int port = 0;
	if (!parse_v4(addr, len, ip, sizeof(ip), &port)) {
		return orig_connect(fd, addr, len);
	}
	g_in_hook = 1;
	int stype = SOCK_STREAM;
	socklen_t sl = sizeof(stype);
	getsockopt(fd, SOL_SOCKET, SO_TYPE, &stype, &sl);
	int udp = (stype == SOCK_DGRAM);
	int hit = udp ? goInterceptUDP(ip, port) : goInterceptTCP(ip, port);
	if (!hit) {
		g_in_hook = 0;
		return orig_connect(fd, addr, len);
	}
	int lp = bind_ephemeral(fd);
	if (lp > 0) {
		if (udp) {
			goRegisterUDP(lp, ip, port);
		} else {
			goRegisterTCP(lp, ip, port);
		}
	}
	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	dst.sin_port = htons((uint16_t)(udp ? g_udp_port : g_tcp_port));
	int rc = orig_connect(fd, (struct sockaddr *)&dst, sizeof(dst));
	g_in_hook = 0;
	return rc;
}

static int hook_getpeername_impl(int fd, struct sockaddr *addr, socklen_t *len) {
	int rc = orig_getpeername ? orig_getpeername(fd, addr, len) : -1;
	if (rc != 0 || !addr || !len || *len < sizeof(struct sockaddr_in)) {
		return rc;
	}
	struct sockaddr_in *in = (struct sockaddr_in *)addr;
	if (in->sin_family != AF_INET || ntohl(in->sin_addr.s_addr) != INADDR_LOOPBACK) {
		return rc;
	}
	uint16_t peer = ntohs(in->sin_port);
	int lp = local_port_of(fd);
	char ip[64];
	int port = 0;
	int found = 0;
	if (lp > 0 && peer == (uint16_t)g_tcp_port) {
		found = goLookupTCP(lp, ip, (int)sizeof(ip), &port);
	} else if (lp > 0 && peer == (uint16_t)g_udp_port) {
		found = goLookupUDP(lp, ip, (int)sizeof(ip), &port);
	}
	if (found == 1) {
		inet_pton(AF_INET, ip, &in->sin_addr);
		in->sin_port = htons((uint16_t)port);
	}
	return rc;
}

static int hook_close_impl(int fd) {
	if (!orig_close) {
		return -1;
	}
	int lp = local_port_of(fd);
	if (lp > 0) {
		goUnregisterPort(lp);
	}
	return orig_close(fd);
}

static ssize_t hook_sendto_impl(int fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t alen) {
	if (g_in_hook || !orig_sendto) {
		return orig_sendto ? orig_sendto(fd, buf, n, flags, addr, alen) : -1;
	}
	char ip[64];
	int port = 0;
	if (!parse_v4(addr, alen, ip, sizeof(ip), &port) || !goInterceptUDP(ip, port)) {
		return orig_sendto(fd, buf, n, flags, addr, alen);
	}
	g_in_hook = 1;
	uint8_t hdr[10];
	hdr[0] = 'G';
	hdr[1] = 'S';
	hdr[2] = 'U';
	hdr[3] = '1';
	struct in_addr ia;
	inet_pton(AF_INET, ip, &ia);
	memcpy(hdr + 4, &ia, 4);
	uint16_t p = htons((uint16_t)port);
	memcpy(hdr + 8, &p, 2);
	size_t total = 10 + n;
	uint8_t *tmp = (uint8_t *)malloc(total);
	if (!tmp) {
		g_in_hook = 0;
		errno = ENOMEM;
		return -1;
	}
	memcpy(tmp, hdr, 10);
	if (n && buf) memcpy(tmp + 10, buf, n);
	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	dst.sin_port = htons((uint16_t)g_udp_port);
	ssize_t rc = orig_sendto(fd, tmp, total, flags, (struct sockaddr *)&dst, sizeof(dst));
	free(tmp);
	g_in_hook = 0;
	if (rc < 10) {
		return rc;
	}
	return rc - 10;
}

static int rewrite_from_hdr(uint8_t *buf, ssize_t n, struct sockaddr *addr, socklen_t *alen) {
	if (n < 10 || buf[0] != 'G' || buf[1] != 'S' || buf[2] != 'U' || buf[3] != '1') {
		return 0;
	}
	if (addr && alen && *alen >= (socklen_t)sizeof(struct sockaddr_in)) {
		struct sockaddr_in *in = (struct sockaddr_in *)addr;
		memset(in, 0, sizeof(*in));
		in->sin_family = AF_INET;
		memcpy(&in->sin_addr, buf + 4, 4);
		uint16_t p;
		memcpy(&p, buf + 8, 2);
		in->sin_port = p;
		*alen = sizeof(*in);
	}
	return 1;
}

static ssize_t hook_recvfrom_impl(int fd, void *buf, size_t n, int flags, struct sockaddr *addr, socklen_t *alen) {
	if (!orig_recvfrom) {
		return -1;
	}
	if (!buf || n < 10) {
		return orig_recvfrom(fd, buf, n, flags, addr, alen);
	}
	ssize_t rc = orig_recvfrom(fd, buf, n, flags, addr, alen);
	if (rc < 10) {
		return rc;
	}
	uint8_t *p = (uint8_t *)buf;
	if (!rewrite_from_hdr(p, rc, addr, alen)) {
		return rc;
	}
	memmove(p, p + 10, (size_t)rc - 10);
	return rc - 10;
}

static ssize_t hook_sendmsg_impl(int fd, const struct msghdr *msg, int flags) {
	if (!orig_sendmsg) {
		return -1;
	}
	if (!msg || !msg->msg_name) {
		return orig_sendmsg(fd, msg, flags);
	}
	size_t n = 0;
	for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++) {
		n += msg->msg_iov[i].iov_len;
	}
	uint8_t *flat = (uint8_t *)malloc(n ? n : 1);
	if (!flat) {
		errno = ENOMEM;
		return -1;
	}
	size_t off = 0;
	for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++) {
		memcpy(flat + off, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
		off += msg->msg_iov[i].iov_len;
	}
	ssize_t rc = hook_sendto_impl(fd, flat, n, flags, (const struct sockaddr *)msg->msg_name, msg->msg_namelen);
	free(flat);
	return rc;
}

static ssize_t hook_recvmsg_impl(int fd, struct msghdr *msg, int flags) {
	if (!orig_recvmsg || !msg || !msg->msg_iov || msg->msg_iovlen < 1) {
		return orig_recvmsg ? orig_recvmsg(fd, msg, flags) : -1;
	}
	return hook_recvfrom_impl(fd, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len, flags,
				  (struct sockaddr *)msg->msg_name, msg->msg_name ? &msg->msg_namelen : NULL);
}

static struct rebinding g_binds[] = {
	{"connect", (void *)hook_connect_impl, (void **)&orig_connect},
	{"getpeername", (void *)hook_getpeername_impl, (void **)&orig_getpeername},
	{"close", (void *)hook_close_impl, (void **)&orig_close},
	{"sendto", (void *)hook_sendto_impl, (void **)&orig_sendto},
	{"recvfrom", (void *)hook_recvfrom_impl, (void **)&orig_recvfrom},
	{"sendmsg", (void *)hook_sendmsg_impl, (void **)&orig_sendmsg},
	{"recvmsg", (void *)hook_recvmsg_impl, (void **)&orig_recvmsg},
};

static void rebind_one(const struct mach_header *mh, intptr_t slide) {
	const char *name = NULL;
	uint32_t n = _dyld_image_count();
	for (uint32_t i = 0; i < n; i++) {
		if (_dyld_get_image_header(i) == mh) {
			name = _dyld_get_image_name(i);
			break;
		}
	}
	if (skip_img(name)) {
		return;
	}
	protect_rebind_symbols_image((void *)mh, slide, g_binds, sizeof(g_binds) / sizeof(g_binds[0]));
}

static void on_image(const struct mach_header *mh, intptr_t slide) {
	if (!g_installed) {
		return;
	}
	rebind_one(mh, slide);
}

int protect_hook_install(int tcp_port, int udp_port) {
	pthread_mutex_lock(&g_mu);
	g_tcp_port = tcp_port;
	g_udp_port = udp_port;
	resolve_orig();
	if (!orig_connect || !orig_sendto) {
		pthread_mutex_unlock(&g_mu);
		return -1;
	}
	g_installed = 1;
	static int registered;
	if (!registered) {
		registered = 1;
		_dyld_register_func_for_add_image(on_image);
	} else {
		uint32_t n = _dyld_image_count();
		for (uint32_t i = 0; i < n; i++) {
			rebind_one(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
		}
	}
	pthread_mutex_unlock(&g_mu);
	return 0;
}

void protect_hook_rescan(void) {
	if (!g_installed) {
		return;
	}
	pthread_mutex_lock(&g_mu);
	uint32_t n = _dyld_image_count();
	for (uint32_t i = 0; i < n; i++) {
		rebind_one(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
	}
	pthread_mutex_unlock(&g_mu);
}

void protect_hook_uninstall(void) {
	pthread_mutex_lock(&g_mu);
	g_installed = 0;
	struct rebinding back[] = {
		{"connect", (void *)orig_connect, NULL},
		{"getpeername", (void *)orig_getpeername, NULL},
		{"close", (void *)orig_close, NULL},
		{"sendto", (void *)orig_sendto, NULL},
		{"recvfrom", (void *)orig_recvfrom, NULL},
		{"sendmsg", (void *)orig_sendmsg, NULL},
		{"recvmsg", (void *)orig_recvmsg, NULL},
	};
	uint32_t n = _dyld_image_count();
	for (uint32_t i = 0; i < n; i++) {
		const char *name = _dyld_get_image_name(i);
		if (skip_img(name)) {
			continue;
		}
		protect_rebind_symbols_image((void *)_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i),
					     back, sizeof(back) / sizeof(back[0]));
	}
	pthread_mutex_unlock(&g_mu);
}
