#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <pwd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tdf.h"
#include "tdf.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#include <libipvs.h>
#include <netinet/in.h>

static volatile sig_atomic_t exiting = 0;
static int ipvs_inited = 0;

static struct tdf_opts {
	struct hostent *fwd_dns;
	char *cgroup;
	u32 excluded_ips[MAX_EXCLUDED_IPS];
	u32 excluded_ips_count;
	u32 ipvs_exclusion_ip;
} tdf_opts = {
	.cgroup = NULL,
	.fwd_dns = NULL,
	.excluded_ips = {0},
	.excluded_ips_count = 0,
	.ipvs_exclusion_ip = 0,
};

static struct timespec start_time;

const char *argp_program_version = "tdf 0.1";
const char *argp_program_bug_address =
	"https://github.com/ebay/tdf";
const char argp_program_doc[] =
"Proxy DNS queries transparently\n"
"\n"
"USAGE: tdf\n"
"\n"
"EXAMPLES:\n"
"   ./tdf -s 192.168.1.1	# transparently forward queries to 192.168.1.1\n";

static const struct argp_option opts[] = {
	{ NULL, 's', "", 0, "IP address"},
	{ NULL, 'c', "", 0, "cgroup path"},
	{ NULL, 'e', "", 0, "Exclude IP from being forwarded, multiple -e flags can be set for multiple IP's"},
	{ NULL, 'i', "", 0, "Exclude service destination in ipvs behind the specified service IP from being forwarded (port 53)"},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
		case 'h':
			argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
			break;
		case 's':
			tdf_opts.fwd_dns = gethostbyname(arg);
			break;
		case 'c':
			tdf_opts.cgroup = arg;
			break;
		case 'i':
			struct in_addr n;
			if (inet_pton(AF_INET, arg, &n)) {
				tdf_opts.ipvs_exclusion_ip = n.s_addr;
			} else {
				printf("Failed to parse IP %s for ipvsadm: %s\n", arg, strerror(errno));
				return ARGP_ERR_UNKNOWN;
			}
			break;
		case 'e':
			if (tdf_opts.excluded_ips_count >= (MAX_EXCLUDED_IPS)) {
				fprintf(stderr, "Reached IP exclusion limit, skipping %s from being excluded\n", arg);
				break;
			}
			struct sockaddr_in sa;
			if (!inet_pton(AF_INET, arg, &(sa.sin_addr))) {
				fprintf(stderr, "Failed to describe address %s: %s\n", arg, strerror(errno));
				return ARGP_ERR_UNKNOWN;
			}
			tdf_opts.excluded_ips[tdf_opts.excluded_ips_count++] = sa.sin_addr.s_addr;
			fprintf(stderr, "DNS traffic to IP %s will be excluded\n", arg);
			break;
		case ARGP_KEY_END:
			if (!tdf_opts.fwd_dns) {
				fprintf(stderr, "FATAL: failed to get forward server, did you set it with -s?\n");
				argp_usage(state);
			}
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

u32 fetch_service_dest_ip_ipvs(int service_ip) {
	if (!ipvs_inited) {
		if (ipvs_init()) {
			fprintf(stderr, "%s\n", ipvs_strerror(errno));
			exiting = 1;
			return 0;
		}
		ipvs_inited = 1;
	}

	u32 dest_ip = 0;
	union nf_inet_addr dest_svc;
	ipvs_service_entry_t *s_e;

	dest_svc.ip = service_ip;

	if (!(s_e = ipvs_get_service(0, AF_INET, IPPROTO_TCP,
				dest_svc, htons(53)))) {
		fprintf(stderr, "%s\n", ipvs_strerror(errno));
		return 0;
	}

	struct ip_vs_get_dests *d = ipvs_get_dests(s_e);
	for (int c = 0; c < d->num_dests; c++) {
		ipvs_dest_entry_t *p = &d->entrytable[c];
		dest_ip = p->addr.in.s_addr;
		break;
	}

	free(d);
	free(s_e);
	return dest_ip;
}

static void sig_int(int signo)
{
	exiting = 1;
}

/*static struct bpf_link *attach_tdf_to_netns(struct bpf_program *prog)
{
        struct bpf_link *link;
        int net_fd;

        net_fd = open("/proc/self/ns/net", O_RDONLY);
        if (net_fd < 0) {
                fprintf(stderr, "failed to open /proc/self/ns/net");
                return NULL;
        }

        link = bpf_program__attach_netns(prog, net_fd);
        if (!link) {
                fprintf(stderr, "failed to attach program '%s' to netns",
                        bpf_program__name(prog));
                link = NULL;
        }

        close(net_fd);
        return link;
}*/

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	struct tdf_bpf *obj = NULL;
	int err, cg_fd = 0, sock_fd = 0, dns_listening = -1, conf_dns_listen_idx = 0,
		conf_map = 0, previous_dns_state = -1, conf_ipvs_ip_idx = 1;
	u32 previous_ipvs_ip = 0, current_ipvs_ip = 0;
	struct bpf_link *send_link = NULL, *recv_link = NULL, *conn_link;
	struct sockaddr_in serv_addr;
	struct in_addr dns_fwd_in;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!tdf_opts.cgroup) {
		fprintf(stderr, "WARN: cgroup2 fs not specified.\n");
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = tdf_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	memset(&dns_fwd_in, 0, sizeof(dns_fwd_in));
	if (!inet_aton(tdf_opts.fwd_dns->h_name, &dns_fwd_in)) {
		fprintf(stderr, "inet_aton failed on %s\n", tdf_opts.fwd_dns->h_name);
		goto cleanup;
	}

	struct passwd *pdns_pswd = getpwnam("pdns");

	if (pdns_pswd && pdns_pswd->pw_uid < 1) {
		fprintf(stderr, "Failed to find the pdns user - is pdns-recursor installed properly to run as non-root?\n");
		err = -EINVAL;
		goto cleanup;
	}

	obj->rodata->dns_uid = pdns_pswd->pw_uid;
	obj->rodata->dns_fwd_ip = dns_fwd_in.s_addr;
	for (int ei=0; ei < tdf_opts.excluded_ips_count; ei++) {
	  obj->rodata->tdf_excluded_ips[ei] = tdf_opts.excluded_ips[ei];
	}

	err = tdf_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

        /*attach_tdf_to_netns(obj->progs.tdf_sendmsg4);*/

	if (tdf_opts.cgroup) {
		cg_fd = open(tdf_opts.cgroup, O_DIRECTORY | O_RDONLY);
		if (cg_fd < 0) {
			printf("Failed to open cgroup path: '%s'\n", strerror(errno));
			goto cleanup;
		}
		/* todo: optimize this section out, bpf_object__for_each_program
		 * and bpf_program__section_name */
		send_link = bpf_program__attach_cgroup(obj->progs.tdf_sendmsg, cg_fd);
		if (libbpf_get_error(send_link)) {
			printf("ERROR: bpf_program__attach_cgroup (send) failed\n");
			send_link = NULL;
			goto cleanup;
		}
		recv_link = bpf_program__attach_cgroup(obj->progs.tdf_recvmsg, cg_fd);
		if (libbpf_get_error(recv_link)) {
			printf("ERROR: bpf_program__attach_cgroup (recv) failed\n");
			recv_link = NULL;
			goto cleanup;
		}
		conn_link = bpf_program__attach_cgroup(obj->progs.tdf_connect, cg_fd);
		if (libbpf_get_error(conn_link)) {
			printf("ERROR: bpf_program__attach_cgroup (conn) failed\n");
			recv_link = NULL;
			goto cleanup;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &start_time);

	conf_map = bpf_map__fd(obj->maps.tdf_conf_map);

	/* leaving for now - BPF_SK_SKB_STREAM_VERDICT does not support fully udp
	 * until >=jammy */
	/*int _map_fd = bpf_create_map(BPF_MAP_TYPE_SOCKMAP, sizeof(int), sizeof(int), 2, 0);
	err = bpf_prog_attach(obj->progs.tdf_lookup, _map_fd, BPF_SK_SKB_STREAM_VERDICT, 0);*/

	err = tdf_bpf__attach(obj);

	if (err) {
		fprintf(stderr, "failed to attach BPF program\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	struct timeval to;
	to.tv_sec = 1;
	to.tv_usec = 0;

	while (!exiting) {
		if (tdf_opts.ipvs_exclusion_ip != 0) {
			current_ipvs_ip = fetch_service_dest_ip_ipvs(tdf_opts.ipvs_exclusion_ip);
			if (current_ipvs_ip && current_ipvs_ip!=previous_ipvs_ip) {
				struct in_addr t;
				char p_ip_a[60], c_ip_a[60];

				t.s_addr = current_ipvs_ip;
				snprintf(c_ip_a, sizeof(c_ip_a), "%s", inet_ntoa(t));

				if (previous_ipvs_ip) {
					t.s_addr = previous_ipvs_ip;
					snprintf(p_ip_a, sizeof(p_ip_a), "%s", inet_ntoa(t));
					fprintf(stderr, "updating ipvs pod IP, new: %s old: %s\n", c_ip_a, p_ip_a);
				} else {
					fprintf(stderr, "setting ipvs pod IP %s\n", c_ip_a);
				}

				if (bpf_map_update_elem(conf_map, &conf_ipvs_ip_idx, &current_ipvs_ip, BPF_ANY)) {
					fprintf(stderr, "failed to update conf with IPVS exlusion IP\n");
				} else {
					previous_ipvs_ip = current_ipvs_ip;
				}
			}
		}
		sock_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (sock_fd < 0) {
			fprintf(stderr, "failed to open socket, %s\n", strerror(errno));
		}

		memset(&serv_addr, 0, sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		memmove(&serv_addr.sin_addr.s_addr, tdf_opts.fwd_dns->h_addr, tdf_opts.fwd_dns->h_length);
		serv_addr.sin_port = htons(53);

		setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));
		setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof(to));

		if (connect(sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
			dns_listening = 0L;
		} else {
			dns_listening = 1L;
		}
		if (dns_listening!=previous_dns_state &&
			bpf_map_update_elem(conf_map, &conf_dns_listen_idx, &dns_listening, BPF_ANY)) {
			fprintf(stderr, "failed to update conf with dns server status\n");
		}
		if (dns_listening!=previous_dns_state) {
			fprintf(stderr, "dns_listening previous: %s, current: %s\n", previous_dns_state > 0 ? "up" : "down", dns_listening ? "up" : "down");
		}
		previous_dns_state = dns_listening;
		if (sock_fd) {
			close(sock_fd);
		}
		err = dns_listening << 2;
		usleep(50000);
	}

	if (exiting) {
		dns_listening = 0L;
		bpf_map_update_elem(conf_map, &conf_dns_listen_idx, &dns_listening, BPF_ANY);
		/* allow any remaining DNS responses to finish routing before cleaning up */
		usleep(2000000);
	}
cleanup:
	if (cg_fd) {
		close(cg_fd);
	}
	if (send_link) {
		bpf_link__detach(send_link);
	}
	if (recv_link) {
		bpf_link__detach(recv_link);
	}
	if (sock_fd) {
		close(sock_fd);
	}
	if (obj) {
		tdf_bpf__destroy(obj);
	}
	if (ipvs_inited) {
		ipvs_close();
	}
	cleanup_core_btf(&open_opts);

	return err;
}
