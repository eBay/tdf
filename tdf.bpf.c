#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <string.h>
#include "tdf.h"

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65535);
	__type(key, u64);
	__type(value, struct tdf_skb_ckie);
} tdf_skb_cookies SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 2);
        __type(key, u32);
        __type(value, u32);
} tdf_conf_map SEC(".maps");

const volatile uid_t dns_uid = 0;
const volatile u32 dns_fwd_ip = 0;
const volatile u32 tdf_excluded_ips[MAX_EXCLUDED_IPS] = {0};

static inline int tdf_mangle_udp_egress(struct bpf_sock_addr *ctx) {
	if (!dns_uid || !dns_fwd_ip || dns_fwd_ip <= 0) {
		return 1;
	}

	struct bpf_sock_tuple bst = {};
	struct bpf_sock *sk;

	memset(&bst.ipv4.saddr, 0, sizeof(bst.ipv4.saddr));
	memset(&bst.ipv4.sport, 0, sizeof(bst.ipv4.sport));

	bst.ipv4.daddr = ctx->user_ip4;
	bst.ipv4.dport = ctx->user_port;

        if (ctx->type != SOCK_STREAM && ctx->type != SOCK_DGRAM)
                return 1;
        else if (ctx->type == SOCK_STREAM)
                sk = bpf_sk_lookup_tcp(ctx, &bst, sizeof(bst.ipv4),
				BPF_F_CURRENT_NETNS, 0);
        else
                sk = bpf_sk_lookup_udp(ctx, &bst, sizeof(bst.ipv4),
				BPF_F_CURRENT_NETNS, 0);

	if (sk) {
		bpf_sk_release(sk);
		return 1;
	}

	if (tdf_excluded_ips[0]) {
		int ei = 0;
		do {
			if (ctx->user_ip4 == tdf_excluded_ips[ei]) {
				return 1;
			}
		} while (++ei < MAX_EXCLUDED_IPS && tdf_excluded_ips[ei]);
	}

	u64 uid = bpf_get_current_uid_gid() & 0xffffffff;

	if (uid==dns_uid) {
		return 1;
	}

	u32 conf_idx = 0;
	u32 *dns_listening, *ipvs_exclusion_ip;

	dns_listening = bpf_map_lookup_elem(&tdf_conf_map, &conf_idx);

	if (dns_listening && !*dns_listening) {
		return 1;
	}

	conf_idx = 1;
	ipvs_exclusion_ip = bpf_map_lookup_elem(&tdf_conf_map, &conf_idx);

	if (ipvs_exclusion_ip && *ipvs_exclusion_ip == ctx->user_ip4) {
		return 1;
	}

	u64 ckie = bpf_get_socket_cookie(ctx);
	struct tdf_skb_ckie skb_ckie;
	__builtin_memset(&skb_ckie, 0, sizeof(struct tdf_skb_ckie));
	__builtin_memset(skb_ckie.ip, 0, sizeof(u32) * 3);
	skb_ckie.ip[3] = ctx->user_ip4;
	skb_ckie.port = ctx->user_port;
	if (bpf_map_update_elem(&tdf_skb_cookies, &ckie, &skb_ckie, BPF_ANY)) {
		return 1;
	}
	ctx->user_port = bpf_htons(53);
	if (dns_fwd_ip) {
		ctx->user_ip4 = dns_fwd_ip;
	}
	return 1;
}

SEC("cgroup/sendmsg4")
int tdf_sendmsg(struct bpf_sock_addr *ctx) {
	if (ctx->type != SOCK_DGRAM || bpf_htons(ctx->user_port) != 53) {
		return 1;
	}
	return tdf_mangle_udp_egress(ctx);
}

SEC("cgroup/recvmsg4")
int tdf_recvmsg(struct bpf_sock_addr *ctx) {
	if (ctx->type != SOCK_DGRAM) {
		return 1;
	}

	u64 ckie = bpf_get_socket_cookie(ctx);
	struct tdf_skb_ckie *skb_ckie_found = (struct tdf_skb_ckie *)
		bpf_map_lookup_elem(&tdf_skb_cookies, &ckie);
	if (skb_ckie_found) {
		ctx->user_port = skb_ckie_found->port;
		ctx->user_ip4 = skb_ckie_found->ip[3];
	}
	return 1;
}

SEC("cgroup/connect4")
int tdf_connect(struct bpf_sock_addr *ctx) {
	if (ctx->protocol != IPPROTO_UDP || bpf_htons(ctx->user_port) != 53) {
		return 1;
	}

	return tdf_mangle_udp_egress(ctx);
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 1;
