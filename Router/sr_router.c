/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

 

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */


/*
*  If the given router instance has IP address addr as one of its interface's addresses, return that interface's name.
*  Return NULL otherwise.
*/
char* sr_contains_ip(struct sr_instance* sr, uint32_t addr){

  struct sr_if* curr_if = sr->if_list;
  while (curr_if != NULL) {
    if (curr_if->ip == addr){
      return curr_if->name;
    }
    curr_if = curr_if->next;
  }
  return NULL;
}

/*
*  Create an ARP reply packet for the given destination address on behalf of the given reply address.
*/
uint8_t* sr_create_arp_reply(uint8_t* sender_eth, uint32_t sender_ip, uint8_t* dest_eth, uint32_t dest_ip){

  /*Create the packet buffer and create structs for the ethernet header and arp header for easy packet creation*/
  uint8_t* buf = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  sr_ethernet_hdr_t* ether_packet = (sr_ethernet_hdr_t *)(buf);
  sr_arp_hdr_t* arp_packet = (sr_arp_hdr_t *)(buf+sizeof(sr_ethernet_hdr_t));
  
  memcpy((void *) ether_packet->ether_dhost, (void *) dest_eth, ETHER_ADDR_LEN);
  memcpy((void *) ether_packet->ether_shost, (void *) sender_eth, ETHER_ADDR_LEN);
  ether_packet->ether_type = ethertype_arp;
  
  arp_packet->ar_hrd = arp_hrd_ethernet;
  arp_packet->ar_pro = ethertype_ip;
  arp_packet->ar_hln = ETHER_ADDR_LEN;
  arp_packet->ar_pln = 4; /*Hard coded but couldn't think of a better option*/
  arp_packet->ar_op = arp_op_reply;
  memcpy((void *)arp_packet->ar_sha, (void *)sender_eth, ETHER_ADDR_LEN);
  arp_packet->ar_sip = sender_ip;
  memcpy((void *)arp_packet->ar_tha, (void *)dest_eth, ETHER_ADDR_LEN);
  arp_packet->ar_tip = dest_ip;
  
  return buf;
  
}



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  /*it is ARP...*/
  if (ethertype(packet)== ethertype_arp ){
    /*First lets extract the ARP packet*/
    printf("Recevied packet and we think it is ARP\n");
    printf("Ether header:\n"); 
    print_hdr_eth(packet); /*for debugging */
    sr_arp_hdr_t *arp_packet = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    printf("ARP header:\n");
    print_hdr_arp((uint8_t *)arp_packet); /* debugging */
  
    /*If it is a broadcast ARP request and we have the IP, send a reply. Otherwise ignore.*/
    if (arp_packet->ar_op == arp_op_request && (strcmp((char *)arp_packet->ar_tha, "0xffffffffffff") == 0 )) {
      /*Have to go through all the interfaces and see if the requested IP matches any of them*/
      char if_name[sr_IFACE_NAMELEN];
      strncpy(if_name, sr_contains_ip(sr, arp_packet->ar_tip), sr_IFACE_NAMELEN);
      if (if_name != NULL) {
        /*Generate and send ARP reply*/
        struct sr_if* found_if = sr_get_interface(sr, if_name);
        uint8_t *arp_reply = sr_create_arp_reply(found_if->addr, found_if->ip, arp_packet->ar_sha, arp_packet->ar_sip);
        printf("We sending off this ARP reply:\n");
        print_hdr_arp(arp_reply);
        sr_send_packet(sr, arp_reply, sizeof(arp_reply), interface);  /*Send off the packet*/
      }
    } else if (arp_packet->ar_op == arp_op_reply) {
      /*If it is an ARP reply, cache only if the target IP is one of our interfaces*/
      char if_name[sr_IFACE_NAMELEN];
      strncpy(if_name, sr_contains_ip(sr, arp_packet->ar_tip), sr_IFACE_NAMELEN);
      if (if_name != NULL) {
          /*Cache the ARP*/
          sr_arpcache_insert(&sr->cache, arp_packet->ar_sha, arp_packet->ar_sip);
      }
    }

  }else if (ethertype(packet)== ethertype_ip ){/*it is ip...*/
    /*Check if packet is ICMP echo.  If it is echo for us need to create and send reply.*/
    sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    printf("We think the packet is IP. Packet header: \n");
    print_hdr_eth(packet);
    printf("IP header:\n");
    print_hdr_ip((uint8_t *)ip_packet);
    
    /*If it is echo not for us, need to forward to destination*/
    
    /*If this packet is for us :)*/
    if (sr_contains_ip(sr, ip_packet->ip_dst)){

      /*we need to modify icmp unreachable function into echo reply*/
      if (ip_packet->ip_p == 1){/* number for icmp*/
        send_echo_reply(ip_packet->ip_src,packet, sr);
      }else{
      /*If packet is TCP/UDP need to reply with host unreachable*/
        send_host_unreachable(ip_packet->ip_src, packet, sr);
      }
    }else { /*If packet is ICMP not meant for us, need to forward it.*/
      ip_packet->ip_ttl--;
      /*if the time to live is 0... we send an icmp*/
      if (ip_packet->ip_ttl ==0){
        send_times_up(ip_packet->ip_src,packet, sr);
      }
      int size = 32+20+8+28;
      printf("We think packet is not for us. Forwarding:\n");
      print_hdr_ip(packet);
      sr_send_packet(sr, packet, size, sr->if_list->name);
      }
    }
}/* end sr_ForwardPacket */

