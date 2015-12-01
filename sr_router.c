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
uint8_t* sr_create_arp_reply(unsigned char* sender_eth, uint32_t sender_ip, unsigned char* dest_eth, uint32_t dest_ip){
  //Create the packet buffer and create structs for the ethernet header and arp header for easy packet creation
  uint8_t* buf = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  sr_ethernet_hdr_t* ether_packet = (sr_ethernet_hdr_t *)(buf);
  sr_arp_hdr_t* arp_packet = (sr_arp_hdr_t *)(buf+sizeof(sr_ethernet_hdr_t);
  
  ether_packet->ether_dhost = dest_eth;
  ether_packet->ether_shost = sender_eth;
  ether_packet->ether_type = ethertype_arp;
  
  arp_packet->ar_hdr = arp_hdr_ethernet;
  arp_packet->ar_pro = ethertype_ip;
  arp_packet->ar_hln = ETHER_ADDR_LEN;
  arp_packet->ar_pln = 4; //Hard coded but couldn't think of a better option
  arp_packet->ar_op = arp_op_reply;
  arp_packet->ar_sha = sender_eth;
  arp_packet->ar_sip = sender_ip;
  arp_packet->ar_tha = dest_eth;
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
  //it is ARP...
  if (sr_ethertype(packet)== ethertype_arp ){
    //First lets extract the ARP packet
    sr_arp_hdr_t *arp_packet = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  
    //If it is a broadcast ARP request and we have the IP, send a reply. Otherwise ignore.
    if (arp_packet->ar_op == sr_arp_opcode.arp_op_request && arp_packet->ar_tha == "ffffffffffff") {
      //Have to go through all the interfaces and see if the requested IP matches any of them
      char if_name[sr_IFACE_NAMELEN];
      strncpy(if_name, sr_contains_ip(sr, arp_packet->ar_ip), sr_IFACE_NAMELEN);
      if (if_name) {
        //Generate and send ARP reply
        struct sr_if* found_if = sr_get_interface(sr, if_name);
        uint8_t *arp_reply = sr_create_arp_reply(found_if->addr, found_if->ip, arp_packet->ar_sha, arp_packet->ar_sip);
        sr_send_packet(sr, arp_reply, sizeof(erp_reply), interface);  //Send off the packet
      }
    } else if (arp_packet->ar_op == arp_op_reply) {
      //If it is an ARP reply, cache only if the target IP is one of our interfaces
      char if_name[sr_IFACE_NAMELEN];
      strncpy(if_name, sr_contains_ip(sr, arp_packet->ar_ip), sr_IFACE_NAMELEN);
      if (if_name) {
          //Cache the ARP
          sr_arpcache_insert(sr->cache, arp_packet->ar_sha, arp_packet->ar_sip);
      }
    }

  }else if (sr_ethertype(packet)== ethertype_ip ){//it is ip...
    //Check if packet is ICMP echo.  If it is echo for us need to create and send reply.

    
    //If it is echo not for us, need to forward to destination
    extrac_ip_hdr(ip_hdr);// suppose to be the ip header we extract from packet... finish this later
    //If packet is ICMP not meant for us, need to forward it.
    if (sr_contains_ip(sr ,ip_hdr)){

      //we need to modify icmp unreachable function into echo reply
      if (ip_hdr->ip_p == 1){// number for icmp

      
      send_echo_reply(uint8_t source_addr, sr_packet *packet, struct sr_instance *sr);
      }else{
      //If packet is TCP/UDP need to reply with host unreachable
      send_host_unreachable(uint8_t source_addr, sr_packet *packet, struct sr_instance *sr);//filll in later
      }
    }else { //not for us... forward it
      forward_packet(sr,ip_hdr);
    }

  }

}/* end sr_ForwardPacket */

