
#include "protocol.h"

void print_packet(struct send_packet send_pack, struct res_packet res_pack);

int main(int argc, char *argv[]) {

    srand(time(NULL));


    int sock;
    struct sockaddr_in client_addr, server_addr;
    char *server_ip = "127.0.0.1";

    // set up socket with timeout at 3 seconds
    sock = setup_socket(CLIENT_PORT, AF_INET, SOCK_DGRAM, IPPROTO_UDP, &client_addr);
    set_timeout(sock, 3, 0);
    server_addr = construct_address(server_ip, SERVER_PORT, AF_INET);

    // create a random payload
    int num_bytes;

    //set up required response variables

    struct res_packet res_pack;
    bzero(&res_pack, sizeof(res_pack));

    // set up the packet sending structure
    struct send_packet send_pack;
    send_pack.sockfd = sock;
    send_pack.segment = 0;
    send_pack.client_id = 1;
    send_pack.address = server_addr;
    send_pack.type = DATA;

    /* Send 5 corret packets */
    printf("\nSENDING 5 CORRECT PACKETS\n");
    for (int i=0; i<5; i++) {
        // construct a random payload
        num_bytes = rand() % 255;
        char payload[num_bytes];
        for (int i = 0; i < num_bytes; i++) {
            payload[i] = rand();
        }
        //send the data to the sever
        res_pack = send_data_packet(send_pack, payload, num_bytes, true);
        //print the response packet data
        print_packet(send_pack, res_pack);
        //increment the segment number
        send_pack.segment++;
    }

    /* Send 4 Incorrect Packets */
    printf("\nSENDING 4 INCORRECT PACKETS\n");

    //create random payload
    num_bytes = 5;
    char payload[num_bytes];
    for (int i = 0; i < num_bytes; i++) {
        payload[i] = rand();
    }


    //test out of sequence, use old payload
    send_pack.segment++;
    res_pack = send_data_packet(send_pack, payload, num_bytes, true);
    print_packet(send_pack, res_pack);
    //correct the segment number for next packet
    send_pack.segment--;

    //test payload length mismatch
    //the 0xFFFF payload will be interpreted as an end of packet id
    char end_id[] = {0xFF, 0xFF};
    res_pack = send_data_packet(send_pack, end_id, 2, true);
    print_packet(send_pack, res_pack);
    send_pack.segment++;

    //test end of packet missing
    //this takes some work because all functions automatically
    //place an end of packet id
    unsigned char packet[] = {0Xff, 0xff, 0x01, 0xff, 0xf1, 0x06, 0x03, 0xab, 0xdc, 0x13, 0xff, 0xfe};
    // send all but last two bytes of the packet
    Sendto(send_pack.sockfd, packet, 12, 0, send_pack.address);
    //Get the response
    char buffer[MAX_DATA_LEN];
    Recvfrom(send_pack.sockfd, buffer, MAX_DATA_LEN, 0, 0);
    res_pack = parse_response(buffer);
    if ( res_pack.status >= 0 && res_pack.type == REJECT){
        if ( parse_reject_res(buffer, &res_pack) >= 0){
            if ( recv_error_msg(send_pack.sockfd, &res_pack) >= 0)
                print_packet(send_pack, res_pack);
            else printf("failed to get error message\n");
        } else printf("failed to parse reject response\n");
    } else printf("failed to parse response\n");

    //test duplicate packet
    send_pack.segment -= 2;
    res_pack = send_data_packet(send_pack, payload, num_bytes, true);
    print_packet(send_pack, res_pack);
    send_pack.segment+=3;


    /* Send 5 ACC Requests */
    printf("\nSENDING 5 ACC_PER REQUESTS\n");
    struct acc_packet acc_pack;
    bzero(&acc_pack, sizeof(acc_pack));

    sub_no_type n[] = {4085546805u,4085546805u, 4086668821u, 4086808821, 2086668821u};
    int tech_nums[] = {4, 3, 3, 2, 2};
    send_pack.type = ACC_PER;

    for (int send_ack=0; send_ack<5; send_ack++) {
        acc_pack = send_acc_req(send_pack, tech_nums[send_ack], n[send_ack]);

        print_dashnl();
        printf("(SENT) %s\n", strtype(send_pack.type));
        print_data_res(acc_pack.res_pack);
        printf("Tech: %d  SubNo: %u\n", acc_pack.dev_id.tech, acc_pack.dev_id.subscriber_no);
        print_dashnl();
        if ( send_ack < 3 )
            send_pack.segment++;
    }
    send_pack.segment++;

    /* TEST TIMEOUT */
    //if server receives "no ack" c string, it will not send a response
    char *no_ack = "no ack";
    send_pack.type = DATA;
    res_pack = send_data_packet(send_pack, no_ack, strlen(no_ack), true);
    print_packet(send_pack, res_pack);
    close(sock);
}


void print_packet(struct send_packet send_pack, struct res_packet res_pack){
    print_dashnl();
    printf("(SENT) %s\tclient_id: %d  segment: %d\n", strtype(send_pack.type),
           send_pack.client_id, send_pack.segment);
    print_data_res(res_pack);
    print_dashnl();
}