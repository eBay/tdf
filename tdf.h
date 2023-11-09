#ifndef __TDF_H
#define __TDF_H

#ifndef BPF_F_CURRENT_NETNS
#define BPF_F_CURRENT_NETNS (-1L)
#endif

struct tdf_skb_ckie {
	__u32 ip[4];
	__u32 pid;
	__u16 port;
	__u16 flags;
};

#define MAX_EXCLUDED_IPS 10

#ifndef u32
typedef __u32 u32;
#endif

#ifndef printk
#define printk(fmt, ...)                                                       \
    ({                                                                         \
        char ____fmt[] = fmt "\n\n";                                     \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);             \
    })
#endif

/*struct bpf_elf_map SEC("maps") tdf_skb_cookies = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .size_key = sizeof(__u64),
    .size_value = sizeof(struct tdf_skb_ckie),
    .max_elem = 65535,
    .flags = BPF_F_NO_COMMON_LRU,
};*/

#endif
