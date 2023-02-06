#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_arp.h>

#include <base.h>

uint32_t local_ip = 0xa010002;
char local_mac[] = {0xde,0xad,0xbe,0xef,0x5e,0xb1};

static int eth_out(struct rte_mbuf *pkt_buf, uint16_t h_proto,
			struct rte_ether_addr *dst_haddr, uint16_t iplen)
{
	/* fill the ethernet header */
	struct rte_ether_hdr *hdr = rte_pktmbuf_mtod(pkt_buf, struct rte_ether_hdr *);

	hdr->dst_addr = *dst_haddr;
	//rte_eth_macaddr_get(0, &hdr->src_addr);
	memcpy(&hdr->src_addr, local_mac, 6);
	hdr->ether_type = rte_cpu_to_be_16(h_proto);

	/* Print the packet */
	// pkt_dump(pkt_buf);

	/* enqueue the packet */
  pkt_buf->data_len = iplen + sizeof(struct rte_ether_hdr);
  pkt_buf->pkt_len = pkt_buf->data_len;
	dpdk_out(pkt_buf);

  return 0;
}

static void arp_reply(struct rte_mbuf *pkt, struct rte_arp_hdr *arph)
{
	arph->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

	/* fill arp body */
	arph->arp_data.arp_tip = arph->arp_data.arp_sip;
	arph->arp_data.arp_sip = rte_cpu_to_be_32(local_ip);

	arph->arp_data.arp_tha = arph->arp_data.arp_sha;
  memcpy(&arph->arp_data.arp_sha, local_mac, 6);
	//rte_eth_macaddr_get(0, &arph->arp_data.arp_sha);

  eth_out(pkt, RTE_ETHER_TYPE_ARP, &arph->arp_data.arp_tha,
      sizeof(struct rte_arp_hdr));
}

static void arp_in(struct rte_mbuf *pkt)
{
	struct rte_arp_hdr *arph = rte_pktmbuf_mtod_offset(
		pkt, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

	/* process only arp for this address */
	if (rte_be_to_cpu_32(arph->arp_data.arp_tip) != local_ip)
		goto OUT;

	switch (rte_be_to_cpu_16(arph->arp_opcode)) {
	case RTE_ARP_OP_REQUEST:
		arp_reply(pkt, arph);
		break;
	default:
		fprintf(stderr, "apr: Received unknown ARP op");
		goto OUT;
	}

	return;

OUT:
	rte_pktmbuf_free(pkt);
	return;
}

void eth_in(struct rte_mbuf *pkt_buf)
{
	unsigned char *payload = rte_pktmbuf_mtod(pkt_buf, unsigned char *);
	struct rte_ether_hdr *hdr = (struct rte_ether_hdr *)payload;

	if (hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
		arp_in(pkt_buf);
	} else {
		//printf("Unknown ether type: %" PRIu16 "\n",
		//	   rte_be_to_cpu_16(hdr->ether_type));
		rte_pktmbuf_free(pkt_buf);
	}
}
