#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"


//all icmp type obtained from http://www.nthelp.com/icmp.html
#define ICMP_DESTINATION_UNREACHABLE 3
#define ICMP_TIME_EXCEED 11

/*Dynamic array implimentation from http://stackoverflow.com/questions/3536153/c-dynamically-growing-array
*/

void initArray(Array *a, size_t initialSize) {
  a->array = (uint8_t *)malloc(initialSize * sizeof(uint8_t));
  a->used = 0;
  a->size = initialSize;
}

void insertArray(Array *a, uint8_t element) {
  if (a->used == a->size) {
    a->size *= 2;
    a->array = (uint8_t *)realloc(a->array, a->size * sizeof(uint8_t));
  }
  a->array[a->used++] = element;
}

void freeArray(Array *a) {
  free(a->array);
  a->array = NULL;
  a->used = a->size = 0;
}

/*
  Check to see if the given Array a contains element. Return true if it does, and false if not
*/
bool array_contains(Array a, uint8_t element){
  int i;
  for (i = 0; i < a.used; i++){
    if (a.array[i] == element){
      return true;
    }
  }
  return false;
}

/*
  Handle the given arpreq.  Re-send the request if need be and alert packet sources waiting on the req if the request is bad.
  Return 0 if the arpreq has been handled or return 1 if the arpreq needs to be destroyed
*/
int handle_arpreq(struct sr_instance *sr, struct sr_arpreq *arp_req){
  //if it tried 5 times... destination is unreachable
  if (arp_req->times_sent >5){
    //Go through each packet and for each unique source, send ICMP to say host unreachable
    notify_sources_badreq(arp_req);


  }else{
    //look at the routing table and see if there's a match
    if (rtable_look_up(sr, arp_req)==1){
        // incrememnt times_sent
        arp_req->times_sent++;
        //Broadcast ARP request
        boardcast_arpreq(arp_req);
    }else{
        notify_sources_badreq(arp_req);

    }

  }
  return 1;
}

/* Look through the routing table and see if there is any prefix matched */
int rtable_look_up(struct sr_instance *sr, struct sr_arpreq *arp_req)={
    struct sr_rt* curl;
    struct sr_rt* matched;
    int longest = 0;
    cur = sr->routing_table;
    while (cur){
        if ((cur->dest.s_addr & cur->mask.s_addr) == (arp_req.ip & cur->mask.s_addr)){
            return 1;

            }
            cur = cur->next;
        }
    return 0;

    }

/*
  Return the source address of the given ethernet packet
*/
uint8_t get_ether_source(struct sr_packet *packet){
  
  uint8_t *frame = packet->buf;
  //First 6 bytes of frame = dest, second 6 bytes = source
  uint8_t *source = (uint8_t *)malloc(sizeof(uint8_t));
  int i;
  for (i = 6; i < 12; i++){
    source[i] = frame[i];
  }
  return &source;
}


/*
  Go through each unique source of the packets waiting on arp_req
  and send a ICMP host unreachable message.
*/
void notify_sources_badreq(struct sr_instance *sr, struct sr_arpreq *arp_req){
  //For each packet waiting on arp_req, determine unique sources and send them a ICMP.  Have to read packet to find source
  //Go through each packet and for each unique source, send TCMP to say host unreachable
    struct sr_packet *packet = arp_req->packets;
    Array sources;
    initArray(&a, 1);
    while (packet){
        uint8_t source[ETHER_ADDR_LEN] = get_ether_source(packet);
        //Check to make sure we haven't sent to this source yet
        if (!array_contains(sources, source)){
          send_host_runreachable(source, packet);
          insertArray(&sources, source);
        }
        free(&source);
        packet = packet->next;
    }
    freeArray(&sources);
}

/*  Extract and return the ip address from the IP header encapsulated by the given ethernet packet.  */
uint32_t get_ip_addr(sr_packet *packet){
  //We know that the ethernet header is 32 bytes long, and the source address in the IP header is at the 12th octet
  uint32_t address;
  address = (uint32_t)(packet->buf[32+12*8]);
  return address;

}

/*
  Send a host unreachable ICMP to the given source address
*/
void send_host_unreachable(uint8_t source_addr, sr_packet *packet, struct sr_instance *sr){
  /* Trying to work on this - Dylan */
  
  //Allocate a buffer to hold the packet
  uint8_t *buf = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  
  //Create and send the host unreachable ICMP TO source, telling them that dest was unreachable
  //First have to create the ICMP packet
  sr_icmp_t3_hdr_t *icmp_packet = (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
  icmp_packet->icmp_type = 3;
  icmp_packet->icmp_code = 1;
  icmp_packet->icmp_sum = 0;
  icmp_packet->icmp_sum = cksum((const void *)(icmp_packet.icmp_type + icmp_packet.icmp_code), 2);
  //Have to craft data.  Data will be the original packet header plus the first 8 bytes of the packet content.
  memcpy(icmp_packet->data, packet->buf, ICMP_DATA_SIZE);
  
  //Now have to form the ip packet to encase the icmp content
  sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
  ip_packet->ip_p = 1;
  ip_packet->ip_tos;			/* type of service */
  ip_packet->ip_len;			/* total length */
  ip_packet->ip_id;			/* identification */
  ip_packet->ip_off;			/* fragment offset field */
  ip_packet->ip_ttl;			/* time to live */
  ip_packet->ip_p = 1;			/* protocol */
  ip_packet->ip_sum;			/* checksum */
  ip_packet->ip_src = sr->if_list[0]->ip;  //Assign the packet source to one of the router's interfaces
  ip_packet->ip_dst = get_ip_addr(packet);	//set the packet destination to the original source IP
  
  //Now make an ethernet frame to wrap the IP packet with the ICMP packet
  sr_ethernet_hdr_t *ether_packet = (sr_ethernet_hdr_t *)(buf);
  ether_packet->ether_dhost = source_addr;  //Set ethernet destination
  ether_packet->ether_shost = sr->if_list[0]->addr;  //Set ethernet source
  ether_packet->ether_type = sr_ethertype.ethertype_ip;
  
  //Now send off the packet
  int size = 32+20+8+28; //Size of the packet. Ether header = 32, ip header = 20, ICMP header = 8, ICMP data = 28.
  sr_send_packet(sr, buf, size, sr->if_list);
  

}


/* prepare arp into ethernet frame and send it */
int boardcast_arpreq(struct sr_instance *sr, struct sr_arpreq *arp_req){
    struct sr_if *o_interface;
    //first package the arp package header first...
    o_interface = sr_get_interface(sr, arp_req->packets->iface);
    struct sr_arp_hdr arp_hdr;
<<<<<<< HEAD
    int *arp_package;
    int *e_pack;
    arp_hdr.ar_hrd = sr_arp_hrd_fmt hfmt = arp_hrd_ethernet;             /* format of hardware address   */
    arp_hdr.ar_pro = 0X800;            //from http://www.networksorcery.com/enp/protocol/arp.htm#Protocol%20address%20length
    arp_hdr.ar_hln = ETHER_ADDR_LEN = 8; //from http://www.networksorcery.com/enp/protocol/arp.htm#Protocol%20address%20length
    arp_hdr.ar_pln = 8;             //from http://www.networksorcery.com/enp/protocol/arp.htm#Protocol%20address%20length
    sr_arp_opcode code = arp_op_request;
    arp_hdr.ar_op = code;              /* ARP opcode (command)         */
    memcpy(arp_hdr.ar_sha, o_interface->addr, ETHER_ADDR_LEN); /* sender hardware address      */
    arp_hdr.ar_sip = o_interface.ip;             /* sender IP address            */
    arp_hdr.ar_tip = arp_req.ip;                 /* target IP address            */
    //copy everything into the arp_header
    arp_package = malloc(sizeof(sr_arp_hdr_t));
    memcpy(arp_package, &apr_hdr, sizeof(sr_arp_hdr_t));
    //then package the ethernet header along with the arp header...
    e_pack = eth_hdr_package(uint8_t  ether_dhost, sr, o_interface->addr, arp_package, sizeof(struct sr_arp_hdr));

    //send it out
    sr_send_packet(sr, e_pack, sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr), o_interface);



/* build the ethernet frame to be broadcast */
int eth_hdr_package(uint8_t  ether_dhost, uint8_t  ether_shost, uint16_t ether_type, int *content, int len){
    int *output;
    int total_length;
    struct sr_ethernet_hdr e_hdr;
    //first step is to create a ethernet header...
    memcpy(e_hdr.ether_dhost,ether_dhost,ETHER_ADDR_LEN); /* destination ethernet address */
    memcpy(e_hdr.ether_shost,ether_shost,ETHER_ADDR_LEN); /* source ethernet address */
    e_hdr.ether_type = ether_type;
    //calculate the length of the entire thing...
    total_length = sizeof(sr_ethernet_hdr_t) + len;
    //put everything together
    output = malloc(total_length);
    //put the ethernet header in the front
    memcpy(output, &e_hdr, sizeof(sr_ethernet_hdr_t));
    memcpy(output + sizeof(sr_ethernet_hdr_t), content,len);
    return output;
    
}
/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
        //Have to: go through each arprequest in the queue
      //for each one: "handle" the arp request
        //Handle: if arpreq time == current time => req just made, don't touch
        //        else (time diff >= 1) : 
          //if # times requested >= 5: need to drop request -> go through each packet for request, and tell the source that host unreachable.  Then destroy arpreq *(careful not to lose next requests on queue!)*
          //else(req not brand new but <5 re-sends) : send arprequest again, update time last send and sent count

    struct sr_arpreq *sweepreq;
    struct sr_arpreq *prevreq = sr->cache->requests;
    struct sr_nextreq *nextreq;
    //There are no requests!
    if (prevreq == NULL){
      return;
    }
    
    sweepreq = prevreq;
    //There are still request left
    while (sweepreq != NULL){
        if (handle_arpreq(sweepreq) == 1){
          //request has been sent too many times. Destroy without losing the request queue. Have to point the previous req to the next req
          if (prevreq == sweepreq){
            //Handle the case of the first request
            sr->cache->requests = sweepreq->next;
            sweepreq = sweepreq->next;
            nextreq = sweepreg->next;
            sr_arpreq_destroy(prevreq);
            prevreq = sweepreq;
          } else {
            nextreq = sweepreq->next;
            prevreq->next = nextreq;
            sr_arpreq_destroy(sweepreq);
            sweepreq = nextreq;
          }
        } else {
          //No deletion to be made. Just update previous and current request
          prevreq = sweepreq;
          sweepreq = sweepreq->next;
        }
}


/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

