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
*  If the given router instance has IP address addr as one of its interface's addresses, return that interface's ethernet address.
*  Return NULL otherwise.
*/
unsigned char* sr_contains_ip(struct sr_instance* sr, uint32_t addr){

  struct sr_if* curr_if = sr->if_list;
  while (curr_if != NULL) {
    if (curr_if->ip == addr){
      return curr_if->addr;
    }
    curr_if = curr_if->next;
  }
  return NULL;
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
    if (arp_packet->ar_op == 1 && arp_packet->ar_tha == "ffffffffffff") {
      //Have to go through all the interfaces and see if the requested IP matches any of them
      unsigned char if_addr[ETHER_ADDR_LEN];
      strncpy(if_addr, sr_contains_ip(sr, arp_packet->ar_ip), ETHER_ADDR_LEN);
      if (if_addr) {
        //Generate and send ARP reply
        uint8_t *arp_reply = sr_create_arp_reply();
      }
    }
    
    
    //If it is an ARP reply, cache only if the target IP is one of our interfaces

  }else if (sr_ethertype(packet)== ethertype_ip ){//it is ip...
    //Check if packet is ICMP echo.  If it is echo for us need to create and send reply.
    //If it is echo not for us, need to forward to destination
    
    //If packet is ICMP not meant for us, need to forward it.
    
    //If packet is TCP/UDP need to reply with host unreachable

  }

}/* end sr_ForwardPacket */

