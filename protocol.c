//
// Created by Eric White on 11/11/17.
//

#include "protocol.h"


/* ------------------------------------NETWORKING CONFIG AND SETUP------------------------------------ */

// set up

int setup_socket(int port, int family, int type, int proto, struct sockaddr_in *address) {
    int sock, status;
    // open socket and get socket file descriptor; check for errors
    sock = socket(family, type, proto);
    if (sock < 0) {
        printf("failed to create socket: %s \n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    //fill in the address
    bzero(address, sizeof(*address));
    address->sin_family = family;
    // let the kernel pick the ip interface
    address->sin_addr.s_addr = htonl(INADDR_ANY);
    address->sin_port = htons(port);
    // bind the socket the the address
    status = bind(sock, (struct sockaddr *) address, sizeof(*address));
    if (status == -1) {
        printf("failed to bind socket to address: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    return sock;
}


struct sockaddr_in construct_address(char *ip, int port, int family) {
    struct sockaddr_in address;
    // zero out randomness is structure
    bzero(&address, sizeof(address));
    // set family
    address.sin_family = family;
    //set ip
    address.sin_addr.s_addr = inet_addr(ip);
    // set port
    address.sin_port = htons(port);
    return address;
}


int set_timeout(int sockfd, int sec, int usec) {
    struct timeval timeout;
    timeout.tv_sec = sec;
    timeout.tv_usec = usec;
    // set the timeout option for recvfrom
    int status = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (status < 0) printf("Error setting recvfrom timeout: %s\n", strerror(errno));
    return status;
}


// send packets

struct res_packet send_data_packet(struct send_packet send_pack, void *payload,
                                   unsigned char length, bool wait_for_res){
    int status;
    struct res_packet res_pack;
    bzero(&res_pack, sizeof(res_pack));

    if ( !wait_for_res )
        // use function that just sends the data; res_pack returned with status only
        res_pack.status = send_data_packet_no_res(send_pack, payload, length);
    else {
        unsigned char res_buffer[RES_BUFF_LEN];
        // get and parse a response to the sent message; retries on timeout
        res_pack = send_wait_for_res(send_pack, payload, length, res_buffer, RES_BUFF_LEN);
        if (res_pack.status >= 0) {
            switch (res_pack.type) {
                case REJECT:
                    //get the error message sent
                    res_pack.status = recv_error_msg(send_pack.sockfd, &res_pack);
                    if ( res_pack.status < 0) return res_pack;
                    //get the reject code and segment from the initial response
                    res_pack.status = parse_reject_res(res_buffer, &res_pack);
                    if ( res_pack.status < 0 ) return res_pack;
                    break;
                default:
                    res_pack.segment = get_segment(res_buffer);
                    if ( res_pack.segment < 0 ){
                        res_pack.status = res_pack.segment;
                        return res_pack;
                    }
            }
        }
    }
    return res_pack;
}


struct acc_packet send_acc_req(struct send_packet pack, int tech, unsigned int sub_no){
    struct acc_packet acc_pack;
    bzero(&acc_pack, sizeof(acc_pack));
    // tech int needs to fit in a single, unsigned char
    if ( tech > 255 ){
        printf("tech %d is too large\n", tech);
        acc_pack.res_pack.status = -1;
        return acc_pack;
    }

    struct data_packet data_pack;
    bzero(&data_pack, sizeof(data_pack));
    int payload_len = 5;
    char payload[payload_len];
    unsigned char res_buff[ACC_LEN];

    construct_id_payload(payload, (char)tech, sub_no);

    // send a access request and wait for a response.
    acc_pack.res_pack = send_wait_for_res(pack, payload, payload_len, res_buff, ACC_LEN);
    if ( acc_pack.res_pack.type == REJECT ) {
        // received an error; get the next message
        acc_pack.res_pack.status = recv_error_msg(pack.sockfd, &acc_pack.res_pack);
        if ( acc_pack.res_pack.status < 0) return acc_pack;
        acc_pack.res_pack.status = parse_reject_res(res_buff, &acc_pack.res_pack);
    }
    else
        // if no error, parse the acc packet (either REJECT of a type ACC response)
        // not checking expected segment numbers from the server.
        acc_pack.res_pack.status = parse_acc_res(res_buff, &acc_pack, -1);
    return acc_pack;
}


struct res_packet send_wait_for_res(struct send_packet pack, void *payload, int length,
                                    void *res_buffer, int buf_len){
    struct res_packet res_pack;
    bzero(&res_pack, sizeof(res_pack));
    int packet_len = length + 9;
    int packet_pos;
    unsigned char packet[packet_len];
    bool resend = false;
    int status;
    int num_timeout = 0;

    // construct a data packet as defined in protocol
    status = make_data_pack(packet, pack.client_id, pack.type, pack.segment, payload, length);
    do {
        status = Sendto(pack.sockfd, packet, packet_len * sizeof(*packet), 0, pack.address);
        if (status < 0) {
            res_pack.status = status;
            res_pack.type = -1;
            return res_pack;
        }
        // attempt to receive response; retry sending packet until a response
        // is received or exit process if max retries reached
        status = Recvfrom(pack.sockfd, res_buffer, buf_len, 0, 0);
        if ( status < 0 ){
            num_timeout++;
            if ( num_timeout >= MAX_TIMEOUTS ) {
                printf("Server does not respond: Max number of timeouts reached (%d); "
                               "Failed to send packet.\n", MAX_TIMEOUTS);
                exit(EXIT_FAILURE);
            }
            resend = true;
            printf("Timeout waiting for server ack; resending packet\n");
        } else resend = false;
    } while(resend);
    res_pack = parse_response(res_buffer);
    return res_pack;
}


int send_data_packet_no_res(struct send_packet pack, void *payload, unsigned char length){
    // construct and send a data packet; don't wait for a response.
    int packet_len = length + 9;
    int packet_pos, status;
    unsigned char packet[packet_len];
    packet_pos =  make_data_pack(packet, pack.client_id, pack.type, pack.segment, payload, length);
    status = Sendto(pack.sockfd, packet, packet_len, 0, pack.address);
    if ( status < 0 ) return status;
    return 0;
}


int send_ack(struct send_packet send_pack) {
    unsigned char pack[ACK_LEN];
    int pack_pos = set_packet_header(pack, send_pack.client_id, ACK);
    *(pack + pack_pos) = send_pack.segment;
    pack_pos++;
    set_packet_id(pack + pack_pos);
    int num_bytes = Sendto(send_pack.sockfd, pack, ACK_LEN, 0, send_pack.address);
    return num_bytes;
}


int send_reject(struct send_packet send_pack, int reject_code) {
    unsigned char pack[REJECT_LEN];

    int pack_pos = set_packet_header(pack, send_pack.client_id, REJECT);
    int code_exists = set_reject_code(reject_code, pack+pack_pos);
    pack_pos += 2;

    if (code_exists == -1) {
        printf("Reject code %d is not a valid code\n", reject_code);
        return -1;
    }
    *(pack+pack_pos) = send_pack.segment;
    pack_pos++;
    set_packet_id(pack+pack_pos);
    int num_bytes = Sendto(send_pack.sockfd, pack, REJECT_LEN, 0, send_pack.address);
    return num_bytes;
}


int Sendto(int socket, void *packet, size_t length, int flags, struct sockaddr_in dest_addr) {
    // easier to use sendto wrapper with error checking
    int status = sendto(socket, packet, length, flags, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
    if (status == -1)
        printf("failed to sent packet: %s\n", strerror(errno));
    return status;
}


int Recvfrom(int socket, void *buffer, size_t length, int flags, struct sockaddr_in *address) {
    // easier to use recvfrom with error checking
    socklen_t len = sizeof(address);
    int bytes_recv = recvfrom(socket, buffer, length, flags, (struct sockaddr *) address, &len);
    if (bytes_recv < 0)
        printf("failed to receive packet: %s\n", strerror(errno));
    return bytes_recv;

}



/* ------------------------------------PACKET PARSING FUNCTIONS------------------------------------ */


int parse_data_packet(void *buffer, struct data_packet *data, int exp_seg) {
    unsigned char *tmp_buf = (unsigned char *) buffer;
    int idx;

    // get the data packets info from where it should be
    // according to the protocol
    data->client_id = *(tmp_buf + 2);
    data->type = get_type(tmp_buf + 3);
    data->segment = *(tmp_buf + 5);
    data->len = *(tmp_buf + 6);
    data->reject_code = 0;
    tmp_buf = tmp_buf + 7;

    // loop through to get the data payload
    for (idx = 0; idx < data->len; idx++) {
        // if the end of packet id it reached before the loop has quit, then payload length error
        if (*(tmp_buf + idx) == PACKET_ID && *(tmp_buf + idx + 1) == PACKET_ID) {
            sprintf(data->err_msg, "Payload length error; Length specified: %d, received: %d\n", data->len, idx);
            data->reject_code = LEN_MISMATCH;
            return -1;
        }
        data->payload[idx] = *(tmp_buf + idx);
    }
    // if the end of packet id is not at the end of the packet, end of packet id error
    if (*(tmp_buf + idx) != PACKET_ID || *(tmp_buf + idx + 1) != PACKET_ID) {
        sprintf(data->err_msg, "payload longer then specified or packet has no end id. "
                "Received end blocks {%x, %x}\n", *(tmp_buf + idx), *(tmp_buf + idx + 1));
        data->reject_code = END_MISS;
        return -1;
    }
    // if the expected segment was not entered as -1, check the packets segment compared to the expected
    if (exp_seg != -1 && exp_seg != data->segment) {
        if (data->segment < exp_seg) {
            data->reject_code = DUP_PACK;
            sprintf(data->err_msg, "Duplicate Packet: received segment: %d  expected: %d\n", data->segment, exp_seg);
            return -1;
        } else if (data->segment > exp_seg) {
            sprintf(data->err_msg, "Out of sequence: received segment: %d  expected: %d\n", data->segment, exp_seg);
            data->reject_code = OUT_OF_SEQ;
            return -1;
        }
    }
    data->reject_code = -1;
    return 0;
}


struct res_packet parse_response(void *res_buffer) {
    unsigned char *char_buff = (unsigned char *) res_buffer;
    struct res_packet res_pack;
    bzero(&res_pack, sizeof(res_pack));
    // check start id
    res_pack.status = check_packet_id(char_buff);
    //get basic packet header info; used to dicover
    // packet type and futher parse the packer
    res_pack.client_id = *(char_buff + 2);
    res_pack.type = get_type((char_buff + 3));
    return res_pack;
}


int recv_error_msg(int sockfd, struct res_packet *res_pack){
    // if a reject response was received, get the corresponding
    // error message sent by the server
    unsigned char buffer[MAX_DATA_LEN];
    struct data_packet data_pack;
    bzero(&data_pack, sizeof(data_pack));
    // only attempt the get the message once
    if ( Recvfrom(sockfd, buffer, MAX_DATA_LEN, 0, 0) < 0 )
        return -1;
    parse_data_packet(buffer, &data_pack, -1);
    if ( strncpy(res_pack->err_msg, data_pack.payload, data_pack.len) < 0 )
        return -1;
    res_pack->err_len = data_pack.len;
    return 0;
}


int parse_reject_res(void *response, struct res_packet *res_pack){
    unsigned char *res = (unsigned char *)response;
    if ( check_packet_id(res) < 0 )
        return -1;
    res += 5;
    res_pack->reject_code = get_reject_code(res);
    res += 2;
    res_pack->segment = (int)*res;
    res++;
    return check_packet_id(res);
}


int parse_acc_res(void *response, struct acc_packet *acc_pack, int expected_seg){
    unsigned char *res = (unsigned char *)response;
    // parse a response for an access request
    struct data_packet data_pack;
    bzero(&data_pack, sizeof(data_pack));

    // access packets are the same format a data packets; can use the same function
    if ( parse_data_packet(res, &data_pack, expected_seg) < 0 ) return -1;

    acc_pack->res_pack.reject_code = data_pack.reject_code;
    strcpy(acc_pack->res_pack.err_msg, data_pack.err_msg);

    // get segment, tech, and subscriber number from response
    acc_pack->res_pack.segment = data_pack.segment;
    acc_pack->dev_id = get_id_from_payload(data_pack.payload, data_pack.len);
    return 0;
}


int check_packet_id(void *buffer) {
    // check the buffer's next two bytes make a packet id {0xFF, 0xFF}
    unsigned char *tmp_buf = (unsigned char *) buffer;
    if (*(tmp_buf) != PACKET_ID || *(tmp_buf + 1) != PACKET_ID) {
        printf("Buffer does not start with packet id\n");
        return -1;
    }
    return 0;
}


int get_type(unsigned char *type_array) {
    switch (type_array[0]) {
        case 0xFF:
            switch (type_array[1]) {
                case 0xF1:
                    return DATA;
                case 0xF2:
                    return ACK;
                case 0xF3:
                    return REJECT;
                case 0xF8:
                    return ACC_PER;
                case 0xF9:
                    return NOT_PAID;
                case 0xFA:
                    return NOT_EXISTS;
                case 0xFB:
                    return ACC_OK;
                default:
                    return -1;
            }
        default:
            return -1;
    }
}


int get_reject_code(unsigned char *code_array) {
    switch (code_array[0]) {
        case 0xFF:
            switch (code_array[1]) {
                case 0xF4:
                    return OUT_OF_SEQ;
                case 0xF5:
                    return LEN_MISMATCH;
                case 0xF6:
                    return END_MISS;
                case 0xF7:
                    return DUP_PACK;
                default:
                    return -1;
            }
        default:
            return -1;
    }
}


int get_segment(void *response){
    // get the segment from all packets but the reject packets
    // where the segment number is annoyingly in a different place
    unsigned char *res = (unsigned char *)response;
    if ( check_packet_id(res) < 0 ) return -1;
    res += 5;
    return (int)*res;
}


struct device_id get_id_from_payload(char *payload, int length) {
    struct device_id id;
    // need AT LEAST one byte for tech and one for subscriber number
    if (length < 2) {
        id.tech = -1;
        id.subscriber_no = -1;
    } else {
        unsigned char sub_no[length - 1];
        id.tech = (int) payload[0];
        id.subscriber_no = *((sub_no_type *) (payload + 1));
    }
    return id;
}



/* ------------------------------------PACKET CONSTRUCTION FUNCTIONS------------------------------------ */


int make_data_pack(unsigned char *packet, unsigned char client_id, int type, unsigned char segment,
                   void *payload, unsigned long length) {
    // make sure the payload does not exceed the maximum number of bytes
    if ( length > MAX_DATA_LEN ) {
        printf("Payload length (%lu) is too lagre; max value 255\n", length);
        return -1;
    }
    // run through packet byte array and set bytes according to protocol
    int packet_location = set_packet_header(packet, client_id, type);
    *(packet + packet_location) = (segment);
    packet_location++;
    *(packet + packet_location) = length;
    packet_location++;
    copy_array(packet + packet_location, payload, length);
    packet_location += length;
    set_packet_id(packet + packet_location);
    return packet_location;
}


void set_packet_id(unsigned char *packet) {
    // set a packet id in the first two bytes of the pointer
    packet[0] = PACKET_ID;
    packet[1] = PACKET_ID;
}


int set_type(int type, unsigned char *type_array) {
    switch (type) {
        case DATA:
            type_array[0] = 0xFF;
            type_array[1] = 0xF1;
            break;
        case ACK:
            type_array[0] = 0xFF;
            type_array[1] = 0xF2;
            break;
        case REJECT:
            type_array[0] = 0xFF;
            type_array[1] = 0xF3;
            break;
        case ACC_PER:
            type_array[0] = 0xFF;
            type_array[1] = 0xF8;
            break;
        case NOT_PAID:
            type_array[0] = 0xFF;
            type_array[1] = 0xF9;
            break;
        case NOT_EXISTS:
            type_array[0] = 0xFF;
            type_array[1] = 0xFA;
            break;
        case ACC_OK:
            type_array[0] = 0xFF;
            type_array[1] = 0xFB;
            break;
        default :
            return -1;
    }
    return 0;
}


int set_reject_code(int type, unsigned char *code_array) {
    switch (type) {
        case OUT_OF_SEQ:
            code_array[0] = 0xFF;
            code_array[1] = 0xF4;
            break;
        case LEN_MISMATCH:
            code_array[0] = 0xFF;
            code_array[1] = 0xF5;
            break;
        case END_MISS:
            code_array[0] = 0xFF;
            code_array[1] = 0xF6;
            break;
        case DUP_PACK:
            code_array[0] = 0xFF;
            code_array[1] = 0xF7;
            break;
        default:
            return -1;
    }
    return 0;
}


void construct_id_payload(char *payload, char tech, sub_no_type sub_no) {
    // construct a payload for an access request or response
    char *sub_char = (char *) &sub_no;
    payload[0] = tech;
    for (int i = 1; i < sizeof(sub_no) + 1; ++i)
        payload[i] = sub_char[i - 1];
}


int set_packet_header(unsigned char *packet, unsigned char client_id, int type) {
    // set field all packets have in common
    unsigned char type_id[2], packet_id[2];
    int status = set_type(type, type_id);
    if (status == -1) {
        printf("type %d not found\n", type);
        return -1;
    }
    set_packet_id(packet);
    *(packet + 2) = client_id;
    copy_array(packet + 3, type_id, 2);
    return 5;
}


/* ------------------------------------PRINTING FUNCTIONS------------------------------------ */


void get_address(struct sockaddr_in address, char *str_addr) {
    char addr[20];
    int status, port;
    // converts the address into a string an places the IP address into addr
    inet_ntop(address.sin_family, &(address.sin_addr), addr, sizeof(addr));
    port = ntohs(address.sin_port);
    // return (by reference) address:port string
    sprintf(str_addr, "%s:%d", addr, port);
}


void print_dashnl() {
    // standardise number of dashes used to print out packets
    printf("------------------------------------------------------------\n");
}


char *strtype(int type){
    switch (type) {
        case ACK:
            return "ACK";
        case REJECT:
            return "REJECT";
        case DATA:
            return "DATA";
        case ACC_PER:
            return "ACC_PER";
        case NOT_PAID:
            return "NOT_PAID";
        case NOT_EXISTS:
            return "NOT_EXISTS";
        case ACC_OK:
            return "ACC_OK";
        default:
            return "UNKNOWN";
    }
}


char *strreject_code(int code){
    switch(code) {
        case OUT_OF_SEQ:
            return "Out of Sequence";
        case LEN_MISMATCH:
            return "Length Mismatch";
        case END_MISS:
            return "End of Packet Missing";
        case DUP_PACK:
            return "Duplicate Packet";
        default:
            return "Unknown";
    }
}


void print_array(void *array, int len, int max) {
    // print an array; if the length is greater then max,
    // print the head and tail of the array up to max bytes
    unsigned char *tmp_array = (unsigned char *) array;
    int itr = max;
    if (max < len) itr = itr / 2;
    else itr = len;
    for (int i = 0; i < itr; i++) {
        printf("%x ", tmp_array[i]);
    }
    if (max < len) {
        printf("... [%d] ...", len - max);
        for (int i = len - itr; i < len; i++)
            printf("%x ", tmp_array[i]);
    }
    printf("\n");
}


void print_data_res(struct res_packet res_pack){
    // print the important data in the res packet structure
    printf("%s ", strtype(res_pack.type));

    switch(res_pack.type){
        case REJECT:
            printf("%s", strreject_code(res_pack.reject_code));
            break;
    }
    printf("\tclient_id: %d  segment: %d  status: %d\n", res_pack.client_id,
           res_pack.segment, res_pack.status);

    if (res_pack.type == REJECT)
        printf("Error Message: %s\n", res_pack.err_msg);
}


/* ------------------------------------HELPER FUNCTIONS------------------------------------ */


void copy_array(void *source, void *dest, int len) {
    char *tmp_source = (char *) source;
    char *tmp_dest = (char *) dest;
    // copy array from sourse to dest iteratively
    for (int i = 0; i < len; i++)
        *(tmp_source + i) = *(tmp_dest + i);
}


int search_database(int tech, int sub_no){
    FILE *fp = fopen("Verification_Database.txt", "r");
    unsigned int read_sub_no;
    int read_tech;
    int read_paid;
    while(!feof (fp)) {
        // read all three numbers from the db file
        fscanf(fp, "%d", &read_sub_no);
        fscanf(fp, "%d", &read_tech);
        fscanf(fp, "%d", &read_paid);
        if (read_sub_no == sub_no && read_tech == tech) {
            if (read_paid)
                return ACC_OK;
            else
                return NOT_PAID;
        }
    }
    return NOT_EXISTS;
}
