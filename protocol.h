//
// Created by Eric White on 11/10/17.
//

#ifndef COMPNETWORKS_WRAPPERS_H
#define COMPNETWORKS_WRAPPERS_H

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <stdbool.h>
#include <unistd.h>

// define server port
#define SERVER_PORT 6667
// define client post
#define CLIENT_PORT 8889
// define server buffer size
// for receiving packets
#define BUFFER_SIZE 5280

// the packet start and end id byte
// to be repeated twice
#define PACKET_ID 0xFF

//Packet types
#define MAX_TIMEOUTS 3
#define EXIT_FAILURE 1
#define DATA 1
#define ACK 2
#define REJECT 3
#define ACC_PER 8
#define NOT_PAID 9
#define NOT_EXISTS 10
#define ACC_OK 11

// Reject sub codes
#define OUT_OF_SEQ 4
#define LEN_MISMATCH 5
#define END_MISS 6
#define DUP_PACK 7

// Define packet lengths
#define ACK_LEN 8
#define REJECT_LEN 10
#define ACC_LEN 14
#define RES_BUFF_LEN 14
#define MAX_PAYLOAD_LEN 255
#define MAX_DATA_LEN MAX_PAYLOAD_LEN+9

// Subscriber type
typedef unsigned int sub_no_type;



struct res_packet {
    int status;
    int type;
    unsigned char client_id;
    unsigned char segment;
    int reject_code;
    char err_msg[MAX_PAYLOAD_LEN];
    int err_len;

};

struct data_packet {
    int type;
    int client_id;
    int segment;
    int len;
    char payload[255];
    int reject_code;
    char err_msg[100];
};

struct device_id {
    int tech;
    sub_no_type subscriber_no;
};

struct acc_packet {
    struct res_packet res_pack;
    struct device_id dev_id;

};

struct send_packet {
    int sockfd;
    int type;
    struct sockaddr_in address;
    unsigned char client_id;
    unsigned char segment;
};


// functions appear in same order here and int protocol.c

/* ------------------------------------NETWORKING CONFIG AND SETUP------------------------------------ */


// socket setup functions

//open a socket and return the file descriptor
int setup_socket(int port, int family, int type, int proto, struct sockaddr_in *address);
//create n address structure from a string ip address
struct sockaddr_in construct_address(char *ip, int port, int family);
//set the timeout on a socket
int set_timeout(int sockfd, int sec, int usec);


// send packets

// send a data packet to the server. wait_for_res will have the function get and return a response
// from the server or timeout trying
struct res_packet send_data_packet(struct send_packet send_pack, void *payload,
                                   unsigned char length, bool wait_for_res);

// send an access request to the server. waits for a response or timeout trying
struct acc_packet send_acc_req(struct send_packet pack, int tech, unsigned int sub_no);

// send a data payload and wait for a response; used by other functions;
struct res_packet send_wait_for_res(struct send_packet pack, void *payload, int length,
                                    void *res_buffer, int buf_len);

// send a data payload without a response; used by server and other functions
int send_data_packet_no_res(struct send_packet pack, void *payload, unsigned char length);

//used directly by the sever to send ack packets
int send_ack(struct send_packet send_pack);

//used directly by the sever to send reject packets
int send_reject(struct send_packet send_pack, int reject_code);

//wrapper around sendto; adds error checking and easier args
int Sendto(int socket, void *packet, size_t length, int flags, struct sockaddr_in dest_addr);

//wrapper around sendto; adds error checking and easier args
int Recvfrom(int socket, void *buffer, size_t length, int flags, struct sockaddr_in *address);



/* ------------------------------------PACKET PARSING FUNCTIONS------------------------------------ */


// extract info from data packet char array (buffer) and check for errors in packet.
// if segment checking is not needed set exp_seg to -1; else will compare to the
// data packets segment value. Returns to data by reference; returns int status code
// that will be less then 0 if the check failed
int parse_data_packet(void *buffer, struct data_packet *data, int exp_seg);

//parse the common header from the server response; checks start id and sets type
//and client_id in res_packet return value
struct res_packet parse_response(void *res_buffer);

// receives an error message sent and puts message in the res_packet structure
// called if the first response type is REJECT
int recv_error_msg(int sockfd, struct res_packet *res_pack);

// get reject sub code and packet segment and put it into the proper res_packet fields
int parse_reject_res(void *response, struct res_packet *res_pack);

// get the response from an ACC_PER sent data and fill in the proper acc_packet fields;
int parse_acc_res(void *response, struct acc_packet *acc_pack, int expected_seg);

// get segment from ack_res


// check the packet id; use by parsing functions to check the start and end id
int check_packet_id(void *buffer);

// convert a 2 byte type array into the corresponding int id defined above
int get_type(unsigned char *type_array);

// covert 2 byte code array into its corresponding int id defined above
int get_reject_code(unsigned char *code_array);

// parse the segment from all response packets besides reject packets
// the reject packets annoyingly have the segment number in a different location
int get_segment(void *response);

// Get the 1 byte and 4 byte tech and subscriber numbers from a data packet
// payload. used with ACC requests and responses
struct device_id get_id_from_payload(char *payload, int length);



/* ------------------------------------PACKET CONSTRUCTION FUNCTIONS------------------------------------ */


// make a data packet; used in functions sending data packets
int make_data_pack(unsigned char *packet, unsigned char client_id, int type,
                   unsigned char segment, void *payload, unsigned long length);

// set the packet id; used to set start and end id in functions
void set_packet_id(unsigned char *packet);

// used to set the appropriate type in type_array (by reference)
// given one of the type int ids defined above
int set_type(int type, unsigned char *type_array);

// used to set the appropriate type in code_array (by reference)
// given one of the reject codes ids defined above
int set_reject_code(int type, unsigned char *code_array);

// construct the payload for an access request or response packet given
// tech and subscriber numbers
void construct_id_payload(char *payload, char tech, sub_no_type sub_no);

//set the packet header common to all packets, start id, client id, and type
int set_packet_header(unsigned char *packet, unsigned char client_id, int type);


/* ------------------------------------PRINTING FUNCTIONS------------------------------------ */


// convert a sockaddr_in object to a address:port string
void get_address(struct sockaddr_in address, char *str_addr);

// print a dashed newline used to separate packets in
// server and client output
void print_dashnl();

// convert a type id defined above to get a string for printing
char * strtype(int type);

// use a reject code defined above to get a string for printing
char *strreject_code(int code);

// print an array of bytes in hexadecimal values;
// used to print out packets and payloads
void print_array(void *array, int len, int max);

// print the data  in a res_packet structure
void print_data_res(struct res_packet res_pack);


/* ------------------------------------HELPER FUNCTIONS------------------------------------ */

// copy and array from source to destination over len.
void copy_array(void *source, void *dest, int len);

// opens the database file and searches line by line
// for the subscriber and tech number. Returns the
// corresponding id type for response (EX: ACC_OK)
int search_database(int tech, int sub_no);


#endif //COMPNETWORKS_WRAPPERS_H
