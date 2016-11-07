/*
 * hostapd / IEEE 802.11F-2003 Inter-Access Point Protocol (IAPP)
 * Copyright (c) 2002-2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * Note: IEEE 802.11F-2003 was a experimental use specification. It has expired
 * and IEEE has withdrawn it. In other words, it is likely better to look at
 * using some other mechanism for AP-to-AP communication than extending the
 * implementation here.
 */

/* TODO:
 * Level 1: no administrative or security support
 *	(e.g., static BSSID to IP address mapping in each AP)
 * Level 2: support for dynamic mapping of BSSID to IP address
 * Level 3: support for encryption and authentication of IAPP messages
 * - add support for MOVE-notify and MOVE-response (this requires support for
 *   finding out IP address for previous AP using RADIUS)
 * - add support for Send- and ACK-Security-Block to speedup IEEE 802.1X during
 *   reassociation to another AP
 * - implement counters etc. for IAPP MIB
 * - verify endianness of fields in IAPP messages; are they big-endian as
 *   used here?
 * - RADIUS connection for AP registration and BSSID to IP address mapping
 * - TCP connection for IAPP MOVE, CACHE
 * - broadcast ESP for IAPP ADD-notify
 * - ESP for IAPP MOVE messages
 * - security block sending/processing
 * - IEEE 802.11 context transfer
 */

#include "utils/includes.h"
#include <net/if.h>
#include <sys/ioctl.h>
#ifdef USE_KERNEL_HEADERS
#include <linux/if_packet.h>
#else /* USE_KERNEL_HEADERS */
#include <netpacket/packet.h>
#endif /* USE_KERNEL_HEADERS */
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "hostapd.h"
#include "ap_config.h"
#include "ieee802_11.h"
#include "sta_info.h"
#include "iapp.h"
#include "connect_log.h"


#define IAPP_MULTICAST "224.0.1.178"
#define IAPP_UDP_PORT 3517
#define IAPP_TCP_PORT 3517

struct iapp_hdr {
	u8 version;
	u8 command;
	be16 identifier;
	be16 length;
	/* followed by length-6 octets of data */
} __attribute__ ((packed));

#define IAPP_VERSION 0

enum IAPP_COMMAND {
	IAPP_CMD_ADD_notify = 0,
	IAPP_CMD_MOVE_notify = 1,
	IAPP_CMD_MOVE_response = 2,
	IAPP_CMD_Send_Security_Block = 3,
	IAPP_CMD_ACK_Security_Block = 4,
	IAPP_CMD_CACHE_notify = 5,
	IAPP_CMD_CACHE_response = 6,
};


/* ADD-notify - multicast UDP on the local LAN */
struct iapp_add_notify {
	u8 addr_len; /* ETH_ALEN */
	u8 reserved;
	u8 mac_addr[ETH_ALEN];
	be16 seq_num;
} __attribute__ ((packed));


/* Layer 2 Update frame (802.2 Type 1 LLC XID Update response) */
struct iapp_layer2_update {
	u8 da[ETH_ALEN]; /* broadcast */
	u8 sa[ETH_ALEN]; /* STA addr */
	be16 len; /* 6 */
	u8 dsap; /* null DSAP address */
	u8 ssap; /* null SSAP address, CR=Response */
	u8 control;
	u8 xid_info[3];
} __attribute__ ((packed));


/* MOVE-notify - unicast TCP */
struct iapp_move_notify {
	u8 addr_len; /* ETH_ALEN */
	u8 reserved;
	u8 mac_addr[ETH_ALEN];
	u16 seq_num;
	u16 ctx_block_len;
	/* followed by ctx_block_len bytes */
} __attribute__ ((packed));


/* MOVE-response - unicast TCP */
struct iapp_move_response {
	u8 addr_len; /* ETH_ALEN */
	u8 status;
	u8 mac_addr[ETH_ALEN];
	u16 seq_num;
	u16 ctx_block_len;
	/* followed by ctx_block_len bytes */
} __attribute__ ((packed));

enum {
	IAPP_MOVE_SUCCESSFUL = 0,
	IAPP_MOVE_DENIED = 1,
	IAPP_MOVE_STALE_MOVE = 2,
};


/* CACHE-notify */
struct iapp_cache_notify {
	u8 addr_len; /* ETH_ALEN */
	u8 reserved;
	u8 mac_addr[ETH_ALEN];
	u16 seq_num;
	u8 current_ap[ETH_ALEN];
	u16 ctx_block_len;
	/* ctx_block_len bytes of context block followed by 16-bit context
	 * timeout */
} __attribute__ ((packed));


/* CACHE-response - unicast TCP */
struct iapp_cache_response {
	u8 addr_len; /* ETH_ALEN */
	u8 status;
	u8 mac_addr[ETH_ALEN];
	u16 seq_num;
} __attribute__ ((packed));

enum {
	IAPP_CACHE_SUCCESSFUL = 0,
	IAPP_CACHE_STALE_CACHE = 1,
};


/* Send-Security-Block - unicast TCP */
struct iapp_send_security_block {
	u8 iv[8];
	u16 sec_block_len;
	/* followed by sec_block_len bytes of security block */
} __attribute__ ((packed));


/* ACK-Security-Block - unicast TCP */
struct iapp_ack_security_block {
	u8 iv[8];
	u8 new_ap_ack_authenticator[48];
} __attribute__ ((packed));


struct iapp_data {
	struct hostapd_data *hapd;
	u16 identifier; /* next IAPP identifier */
	struct in_addr own, multicast;
	int ifindex;  /* index of the iapp interface */
	int udp_sock;
	int packet_sock;
	int nl_sock;
	Boolean ready;  /* indicates iapp is fully initialized and ready */
};

static void iapp_initialize(struct iapp_data *iapp);
static void iapp_cleanup(struct iapp_data *iapp);

static void iapp_send_add(struct iapp_data *iapp, u8 *mac_addr, u16 seq_num)
{
	char buf[128];
	struct iapp_hdr *hdr;
	struct iapp_add_notify *add;
	struct sockaddr_in addr;

	/* Send IAPP ADD-notify to remove possible association from other APs
	 */

	hdr = (struct iapp_hdr *) buf;
	hdr->version = IAPP_VERSION;
	hdr->command = IAPP_CMD_ADD_notify;
	hdr->identifier = host_to_be16(iapp->identifier++);
	hdr->length = host_to_be16(sizeof(*hdr) + sizeof(*add));

	add = (struct iapp_add_notify *) (hdr + 1);
	add->addr_len = ETH_ALEN;
	add->reserved = 0;
	os_memcpy(add->mac_addr, mac_addr, ETH_ALEN);

	add->seq_num = host_to_be16(seq_num);
	
	os_memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = iapp->multicast.s_addr;
	addr.sin_port = htons(IAPP_UDP_PORT);
	if (sendto(iapp->udp_sock, buf, (char *) (add + 1) - buf, 0,
		   (struct sockaddr *) &addr, sizeof(addr)) < 0)
		wpa_printf(MSG_INFO, "sendto[IAPP-ADD]: %s", strerror(errno));
}


static void iapp_send_layer2_update(struct iapp_data *iapp, u8 *addr)
{
	struct iapp_layer2_update msg;

	/* Send Level 2 Update Frame to update forwarding tables in layer 2
	 * bridge devices */

	/* 802.2 Type 1 Logical Link Control (LLC) Exchange Identifier (XID)
	 * Update response frame; IEEE Std 802.2-1998, 5.4.1.2.1 */

	os_memset(msg.da, 0xff, ETH_ALEN);
	os_memcpy(msg.sa, addr, ETH_ALEN);
	msg.len = host_to_be16(6);
	msg.dsap = 0; /* NULL DSAP address */
	msg.ssap = 0x01; /* NULL SSAP address, CR Bit: Response */
	msg.control = 0xaf; /* XID response lsb.1111F101.
			     * F=0 (no poll command; unsolicited frame) */
	msg.xid_info[0] = 0x81; /* XID format identifier */
	msg.xid_info[1] = 1; /* LLC types/classes: Type 1 LLC */
	msg.xid_info[2] = 1 << 1; /* XID sender's receive window size (RW)
				   * FIX: what is correct RW with 802.11? */

	if (send(iapp->packet_sock, &msg, sizeof(msg), 0) < 0)
		wpa_printf(MSG_INFO, "send[L2 Update]: %s", strerror(errno));
}


/**
 * iapp_new_station - IAPP processing for a new STA
 * @iapp: IAPP data
 * @sta: The associated station
 */
void iapp_new_station(struct iapp_data *iapp, struct sta_info *sta)
{
	u16 seq = 0; /* TODO */

	if (iapp == NULL || !iapp->ready)
		return;

	/* IAPP-ADD.request(MAC Address, Sequence Number, Timeout) */
	hostapd_logger(iapp->hapd, sta->addr, HOSTAPD_MODULE_IAPP,
		       HOSTAPD_LEVEL_DEBUG, "IAPP-ADD.request(seq=%d)", seq);
	iapp_send_layer2_update(iapp, sta->addr);
	iapp_send_add(iapp, sta->addr, seq);

	/* TODO: If this was reassociation:
	 * IAPP-MOVE.request(MAC Address, Sequence Number, Old AP,
	 *                   Context Block, Timeout)
	 * TODO: Send IAPP-MOVE to the old AP; Map Old AP BSSID to
	 * IP address */
}


static void iapp_process_add_notify(struct iapp_data *iapp,
				    struct sockaddr_in *from,
				    struct iapp_hdr *hdr, int len)
{
	struct iapp_add_notify *add = (struct iapp_add_notify *) (hdr + 1);
	struct sta_info *sta;

	if (len != sizeof(*add)) {
		wpa_printf(MSG_INFO, "Invalid IAPP-ADD packet length %d (expected %lu)",
			   len, (unsigned long) sizeof(*add));
		return;
	}

	sta = ap_get_sta(iapp->hapd, add->mac_addr);

	/* IAPP-ADD.indication(MAC Address, Sequence Number) */
	hostapd_logger(iapp->hapd, add->mac_addr, HOSTAPD_MODULE_IAPP,
		       HOSTAPD_LEVEL_INFO,
		       "Received IAPP ADD-notify (seq# %d) from %s:%d%s",
		       be_to_host16(add->seq_num),
		       inet_ntoa(from->sin_addr), ntohs(from->sin_port),
		       sta ? "" : " (STA not found)");

	if (!sta)
		return;

	/* TODO: could use seq_num to try to determine whether last association
	 * to this AP is newer than the one advertised in IAPP-ADD. Although,
	 * this is not really a reliable verification. */

	hostapd_logger(iapp->hapd, add->mac_addr, HOSTAPD_MODULE_IAPP,
		       HOSTAPD_LEVEL_DEBUG,
		       "Removing STA due to IAPP ADD-notify");

	connect_log_event(iapp->hapd, sta->addr, CONNECTION_EVENT_DISCONNECT,
			  1, REASON_DISCONNECT_IAPP_NOTIFY, sta, 0,
			  INVALID_SIGNAL, INVALID_STEERING_REASON, NULL,
			  NULL, NULL);
	ap_sta_disconnect(iapp->hapd, sta, NULL, 0);
}


/**
 * iapp_receive_udp - Process IAPP UDP frames
 * @sock: File descriptor for the socket
 * @eloop_ctx: IAPP data (struct iapp_data *)
 * @sock_ctx: Not used
 */
static void iapp_receive_udp(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct iapp_data *iapp = eloop_ctx;
	int len, hlen;
	unsigned char buf[128];
	struct sockaddr_in from;
	socklen_t fromlen;
	struct iapp_hdr *hdr;

	/* Handle incoming IAPP frames (over UDP/IP) */

	fromlen = sizeof(from);
	len = recvfrom(iapp->udp_sock, buf, sizeof(buf), 0,
		       (struct sockaddr *) &from, &fromlen);
	if (len < 0) {
		wpa_printf(MSG_INFO, "iapp_receive_udp - recvfrom: %s",
			   strerror(errno));
		return;
	}

	if (from.sin_addr.s_addr == iapp->own.s_addr)
		return; /* ignore own IAPP messages */

	hostapd_logger(iapp->hapd, NULL, HOSTAPD_MODULE_IAPP,
		       HOSTAPD_LEVEL_DEBUG,
		       "Received %d byte IAPP frame from %s%s\n",
		       len, inet_ntoa(from.sin_addr),
		       len < (int) sizeof(*hdr) ? " (too short)" : "");

	if (len < (int) sizeof(*hdr))
		return;

	hdr = (struct iapp_hdr *) buf;
	hlen = be_to_host16(hdr->length);
	hostapd_logger(iapp->hapd, NULL, HOSTAPD_MODULE_IAPP,
		       HOSTAPD_LEVEL_DEBUG,
		       "RX: version=%d command=%d id=%d len=%d\n",
		       hdr->version, hdr->command,
		       be_to_host16(hdr->identifier), hlen);
	if (hdr->version != IAPP_VERSION) {
		wpa_printf(MSG_INFO, "Dropping IAPP frame with unknown version %d",
			   hdr->version);
		return;
	}
	if (hlen > len) {
		wpa_printf(MSG_INFO, "Underflow IAPP frame (hlen=%d len=%d)",
			   hlen, len);
		return;
	}
	if (hlen < len) {
		wpa_printf(MSG_INFO, "Ignoring %d extra bytes from IAPP frame",
			   len - hlen);
		len = hlen;
	}

	switch (hdr->command) {
	case IAPP_CMD_ADD_notify:
		iapp_process_add_notify(iapp, &from, hdr, len - sizeof(*hdr));
		break;
	case IAPP_CMD_MOVE_notify:
		/* TODO: MOVE is using TCP; so move this to TCP handler once it
		 * is implemented.. */
		/* IAPP-MOVE.indication(MAC Address, New BSSID,
		 * Sequence Number, AP Address, Context Block) */
		/* TODO: process */
		break;
	default:
		wpa_printf(MSG_INFO, "Unknown IAPP command %d", hdr->command);
		break;
	}
}

static void iapp_reinitialize(struct iapp_data *iapp, Boolean if_up)
{
	struct ip_mreqn mreq;

	if (iapp == NULL)
		return;

	if (iapp->ready) {
		if (iapp->udp_sock >= 0) {
			os_memset(&mreq, 0, sizeof(mreq));
			mreq.imr_multiaddr = iapp->multicast;
			mreq.imr_address.s_addr = INADDR_ANY;
			mreq.imr_ifindex = 0;
			if (setsockopt(iapp->udp_sock, SOL_IP, IP_DROP_MEMBERSHIP,
				       &mreq, sizeof(mreq)) < 0) {
				wpa_printf(MSG_INFO,
					"iapp_reinitialize - setsockopt[UDP,IP_DEL_MEMBERSHIP]: %s",
					strerror(errno));
			}
			eloop_unregister_read_sock(iapp->udp_sock);
		}
		if (iapp->packet_sock >= 0) {
			close(iapp->packet_sock);
			iapp->packet_sock = -1;
		}
		iapp->ready = FALSE;
	}

	if (if_up) {
		iapp_initialize(iapp);
	}
}

static void iapp_receive_nl_msg(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct iapp_data *iapp = eloop_ctx;
	char buffer[1024];
	int len;
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;

	len = recv(iapp->nl_sock, buffer, sizeof(buffer), 0);
	if (len < 0) {
		wpa_printf(MSG_DEBUG, "iapp_receive_nl_msg - recv error: %s",
			   strerror(errno));
		return;
	}
	for (nlh = (struct nlmsghdr *)buffer;
	     NLMSG_OK(nlh, len) && nlh->nlmsg_type != NLMSG_DONE;
	     nlh = NLMSG_NEXT(nlh, len)) {
		Boolean if_up;

		if (nlh->nlmsg_type == RTM_NEWADDR) {
			if_up = TRUE;
			wpa_printf(MSG_INFO, "iapp_receive_nl_msg: RTM_NEWADDR ");
		} else if (nlh->nlmsg_type == RTM_DELADDR) {
			if_up = FALSE;
			wpa_printf(MSG_INFO, "iapp_receive_nl_msg: RTM_DELADDR ");
		} else {
			continue;
		}

		ifa = (struct ifaddrmsg *) NLMSG_DATA (nlh);
		if (ifa->ifa_index == iapp->ifindex) {
			iapp_reinitialize(iapp, if_up);
		}
	}
}

static Boolean iapp_monitor_ip_address(struct iapp_data *iapp)
{
	struct sockaddr_nl addr;
	int nlsock,len;

	if ((iapp->nl_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1) {
		wpa_printf(MSG_INFO, "iapp_monitor_ip_address - routing socket failure %s",
		strerror(errno));
		return FALSE;
	}

	memset (&addr,0,sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_IPV4_IFADDR;

	if (bind(iapp->nl_sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		wpa_printf(MSG_INFO, "iapp_monitor_ip_address - bind failure %s",
		strerror(errno));
		return FALSE;
	}

	if (eloop_register_read_sock(iapp->nl_sock, iapp_receive_nl_msg,
		iapp, NULL)) {
		wpa_printf(MSG_INFO, "Could not register read socket for nl message");
		return FALSE;
	}

	hostapd_logger(iapp->hapd, NULL, HOSTAPD_MODULE_IAPP,
		HOSTAPD_LEVEL_INFO,
		"iapp_monitor_ip_address - monitor ip address");
	return TRUE;
}

struct iapp_data * iapp_init(struct hostapd_data *hapd, const char *iface)
{
	struct ifreq ifr;
	struct iapp_data *iapp;

	iapp = os_zalloc(sizeof(*iapp));
	if (iapp == NULL)
		return NULL;
	iapp->hapd = hapd;
	iapp->udp_sock = iapp->packet_sock = iapp->nl_sock =  -1;

	/* TODO:
	 * open socket for sending and receiving IAPP frames over TCP
	 */

	iapp->udp_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (iapp->udp_sock < 0) {
		wpa_printf(MSG_INFO, "iapp_init - socket[PF_INET,SOCK_DGRAM]: %s",
			   strerror(errno));
		iapp_deinit(iapp);
		return NULL;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
	if (ioctl(iapp->udp_sock, SIOCGIFINDEX, &ifr) != 0) {
		wpa_printf(MSG_INFO, "iapp_init - ioctl(SIOCGIFINDEX): %s",
			   strerror(errno));
		iapp_deinit(iapp);
		return NULL;
	}
	iapp->ifindex = ifr.ifr_ifindex;

	if (setsockopt(iapp->udp_sock, SOL_SOCKET, SO_BINDTODEVICE, iface,
		       strlen(iface)) < 0) {
		wpa_printf(MSG_INFO, "iapp_init - setsockopt[UDP,SO_BINDTODEVICE]: %s",
			   strerror(errno));
		iapp_deinit(iapp);
		return NULL;
	}

	if (!iapp_monitor_ip_address(iapp)) {
		hostapd_logger(iapp->hapd, NULL, HOSTAPD_MODULE_IAPP,
			       HOSTAPD_LEVEL_INFO,
			       "iapp_init - failed to monitor ip change");
		iapp_deinit(iapp);
		return NULL;
	}

	iapp_initialize(iapp);

	wpa_printf(MSG_INFO, "IEEE 802.11F (IAPP) using interface %s", iface);

	/* TODO: For levels 2 and 3: send RADIUS Initiate-Request, receive
	 * RADIUS Initiate-Accept or Initiate-Reject. IAPP port should actually
	 * be openned only after receiving Initiate-Accept. If Initiate-Reject
	 * is received, IAPP is not started. */
	return iapp;
}

void iapp_deinit(struct iapp_data *iapp)
{
	iapp_cleanup(iapp);
	os_free(iapp);
}

/*
 * second part of initialization.
 * initializes data socket and joins iapp multicast group.
 * if no IP addreess is assigned to the interface then defers
 * initialization until ip address is assigned.
 *
 */
static void iapp_initialize(struct iapp_data *iapp)
{
	struct ifreq ifr;
	struct sockaddr_ll addr;
	int ifindex;
	struct sockaddr_in *paddr, uaddr;
	struct ip_mreqn mreq;
 	int reuse_port=1;
	char iface[IFNAMSIZ];

	ifindex = iapp->ifindex;
	os_memset(&ifr, 0, sizeof(ifr));
	if_indextoname(ifindex,iface);

	os_strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));

	if (ioctl(iapp->udp_sock, SIOCGIFADDR, &ifr) != 0) {
		wpa_printf(MSG_INFO, "iapp_initialize - ioctl(SIOCGIFADDR): %s",
			   strerror(errno));
		return;
	}
	paddr = (struct sockaddr_in *) &ifr.ifr_addr;
	if (paddr->sin_family != AF_INET) {
		wpa_printf(MSG_INFO, "iapp_initialize - Invalid address family %i (SIOCGIFADDR)",
			   paddr->sin_family);
		iapp_cleanup(iapp);
		return;
	}
	iapp->own.s_addr = paddr->sin_addr.s_addr;

	if (ioctl(iapp->udp_sock, SIOCGIFBRDADDR, &ifr) != 0) {
		wpa_printf(MSG_INFO, "iapp_initialize - ioctl(SIOCGIFBRDADDR): %s",
			   strerror(errno));
		iapp_cleanup(iapp);
		return;
	}
	paddr = (struct sockaddr_in *) &ifr.ifr_addr;
	if (paddr->sin_family != AF_INET) {
		wpa_printf(MSG_INFO, "iapp_initialize - Invalid address family %i (SIOCGIFBRDADDR)",
			   paddr->sin_family);
		iapp_cleanup(iapp);
		return;
	}
	if (setsockopt(iapp->udp_sock, SOL_SOCKET, SO_REUSEPORT, &reuse_port,
		sizeof(reuse_port)) < 0) {
		wpa_printf(MSG_INFO, "iapp_initialize - setsockopt[UDP,SO_REUSEPORT]: %s",
			strerror(errno));
		iapp_cleanup(iapp);
		return;
	}
	inet_aton(IAPP_MULTICAST, &iapp->multicast);

	os_memset(&uaddr, 0, sizeof(uaddr));
	uaddr.sin_family = AF_INET;
	uaddr.sin_port = htons(IAPP_UDP_PORT);
	if (bind(iapp->udp_sock, (struct sockaddr *) &uaddr,
		 sizeof(uaddr)) < 0) {
		wpa_printf(MSG_INFO, "iapp_initialize - bind[UDP]: %s",
			   strerror(errno));
		iapp_cleanup(iapp);
		return;
	}

	os_memset(&mreq, 0, sizeof(mreq));
	mreq.imr_multiaddr = iapp->multicast;
	mreq.imr_address.s_addr = INADDR_ANY;
	mreq.imr_ifindex = ifindex;
	if (setsockopt(iapp->udp_sock, SOL_IP, IP_ADD_MEMBERSHIP, &mreq,
		       sizeof(mreq)) < 0) {
		wpa_printf(MSG_INFO, "iapp_initialize - setsockopt[UDP,IP_ADD_MEMBERSHIP]: %s",
			   strerror(errno));
		iapp_cleanup(iapp);
		return;
	}

	iapp->packet_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (iapp->packet_sock < 0) {
		wpa_printf(MSG_INFO, "iapp_initialize - socket[PF_PACKET,SOCK_RAW]: %s",
			   strerror(errno));
		iapp_cleanup(iapp);
		return;
	}

	os_memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifindex;
	if (bind(iapp->packet_sock, (struct sockaddr *) &addr,
		 sizeof(addr)) < 0) {
		wpa_printf(MSG_INFO, "iapp_initialize - bind[PACKET]: %s",
			   strerror(errno));
		iapp_cleanup(iapp);
		return;
	}

	if (eloop_register_read_sock(iapp->udp_sock, iapp_receive_udp,
				     iapp, NULL)) {
		wpa_printf(MSG_INFO, "iapp_initialize - Could not register read socket for IAPP");
		iapp_cleanup(iapp);
		return;
	}

	iapp->ready = TRUE;

	hostapd_logger(iapp->hapd, NULL, HOSTAPD_MODULE_IAPP,
		       HOSTAPD_LEVEL_INFO,
		       "iapp_initialize - finished initialization");
}

static void iapp_cleanup(struct iapp_data *iapp)
{
	struct ip_mreqn mreq;

	if (iapp == NULL)
		return;

	if (iapp->udp_sock >= 0) {
		os_memset(&mreq, 0, sizeof(mreq));
		mreq.imr_multiaddr = iapp->multicast;
		mreq.imr_address.s_addr = INADDR_ANY;
		mreq.imr_ifindex = 0;
		if (setsockopt(iapp->udp_sock, SOL_IP, IP_DROP_MEMBERSHIP,
			       &mreq, sizeof(mreq)) < 0) {
			wpa_printf(MSG_INFO,
				   "iapp_cleanup - setsockopt[UDP,IP_DEL_MEMBERSHIP]: %s",
				   strerror(errno));
		}

		eloop_unregister_read_sock(iapp->udp_sock);
		close(iapp->udp_sock);
		iapp->udp_sock = -1;
	}
	if (iapp->packet_sock >= 0) {
		close(iapp->packet_sock);
		iapp->packet_sock = -1;
	}
	if (iapp->nl_sock >= 0) {
		eloop_unregister_read_sock(iapp->nl_sock);
		close(iapp->nl_sock);
		iapp->nl_sock = -1;
	}
}

