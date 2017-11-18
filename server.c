
#include "protocol.h"

int main(int argc, char *argv[]) {

    struct data_packet data;
    bzero(&data, sizeof(data));

    struct send_packet send_pack;
    bzero(&send_pack, sizeof(send_pack));

    struct device_id dev_id;
    bzero(&dev_id, sizeof(dev_id));

    int sockfd;
    int status;
    int msg_size;
    int packet_size;
    int exp_seg = 0;

    unsigned char buffer[BUFFER_SIZE];
    char str_addr[20];
    struct sockaddr_in client_addr, server_addr;

    sockfd = setup_socket(SERVER_PORT, AF_INET, SOCK_DGRAM, IPPROTO_UDP, &server_addr);
    socklen_t len = sizeof(client_addr);
    bzero(buffer, BUFFER_SIZE);

    send_pack.sockfd = sockfd;

    while (msg_size >= 0) {
        msg_size = Recvfrom(sockfd, buffer, BUFFER_SIZE, 0, &client_addr);
        if (msg_size < 0) {
            printf("failed to receive packet from client: %s\n", strerror(errno));
        }

        get_address(client_addr, str_addr);
        status = parse_data_packet(buffer, &data, exp_seg);

        send_pack.client_id = data.client_id;
        send_pack.address = client_addr;
        send_pack.segment = data.segment;

        if (data.segment == exp_seg)
            exp_seg++;

        if ( strncmp(data.payload, "no ack", data.len) == 0){
            printf("No ack requested\n");
            continue;
        }

        //handle reject
        if ( data.reject_code > 0 ){
            send_pack.type = REJECT;
            if ( send_reject(send_pack, data.reject_code) < 0 ) {
                printf("Failed to send reject packet to client\n");
            }
            if ( send_data_packet_no_res(send_pack, data.err_msg, strlen(data.err_msg)) ) {
                printf("Failed to send Error packet");
            }
        }
        else {
            switch (data.type) {
                case DATA:
                    send_pack.type = ACK;
                    if (send_ack(send_pack) < 0)
                        printf("Failed to send ACK");
                    break;
                case ACC_PER:
                    dev_id = get_id_from_payload(data.payload, data.len);
                    send_pack.type = search_database(dev_id.tech, dev_id.subscriber_no);
                    if (send_data_packet_no_res(send_pack, data.payload, data.len))
                        printf("Failed to respond to ACC request");
            }
        }
        /* Print the packet details */
        print_dashnl();
        printf("Address: %s  client_id: %d  segment: %d  expected_seq: %d  length: %d\n",
               str_addr, data.client_id, data.segment, exp_seg, data.len);
        printf("Received Packet: ");
        print_array(buffer, data.len + 9, 20);
        printf("%s  ", strtype(send_pack.type));
        if( data.type == ACC_PER )
            printf("Tech: %d  Sub_No: %u\n", dev_id.tech, dev_id.subscriber_no);
        if ( data.reject_code > 0 )
            printf("Error msg: %s", data.err_msg);
        printf("\n");
        print_dashnl();


    }
    close(sockfd);
}
