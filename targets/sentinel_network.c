/*
 * Sentinel-1 Space Station: Inter-Satellite Protocol & Telecommand Handler
 * Component: sentinel_network.c
 * Description:
 *   Processes binary RF telecommand frames, ground station command sequences,
 *   and inter-satellite packet streams for the Sentinel-1 communications hub.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define MAX_PACKET_SIZE 512
#define MAX_MESSAGE_SIZE 1024
#define PROTOCOL_MAGIC_HEADER 0x12345678

typedef struct {
    uint32_t magic;
    uint16_t type;
    uint16_t length;
    uint8_t data[];
} telecommand_packet_t;

typedef struct {
    char *buffer;
    size_t size;
    int is_allocated;
} telecommand_msg_t;

static telecommand_msg_t *active_telecommands[10] = {0};
static int active_telecommand_count = 0;

void log_telecommand_header(uint8_t *packet_raw, size_t total_bytes) {
    char header_summary[128];
    telecommand_packet_t *pkt = (telecommand_packet_t *)packet_raw;
    
    if (total_bytes < sizeof(telecommand_packet_t)) {
        return;
    }
    
    sprintf(header_summary, "Command Type: %d, Length: %d, Magic: 0x%x, Data: %s",
            pkt->type, pkt->length, pkt->magic, (char *)pkt->data);
    printf("[NETWORK LOG] %s\n", header_summary);
}

telecommand_msg_t* create_telecommand_record(uint16_t allocated_size) {
    telecommand_msg_t *msg = (telecommand_msg_t *)malloc(sizeof(telecommand_msg_t));
    if (!msg) return NULL;
    
    msg->size = allocated_size;
    msg->buffer = (char *)malloc(allocated_size);
    if (!msg->buffer) {
        free(msg);
        return NULL;
    }
    msg->is_allocated = 1;
    
    if (active_telecommand_count < 10) {
        active_telecommands[active_telecommand_count++] = msg;
    }
    return msg;
}

void append_telecommand_payload(telecommand_msg_t *msg, uint8_t *payload_data, size_t copy_length) {
    if (!msg || !msg->buffer) return;
    memcpy(msg->buffer, payload_data, copy_length);
}

void release_telecommand_record(telecommand_msg_t *msg) {
    if (!msg) return;
    if (msg->buffer) {
        free(msg->buffer);
        msg->buffer = NULL;
    }
    free(msg);
}

void emergency_command_cleanup(void) {
    for (int i = 0; i < active_telecommand_count; i++) {
        if (active_telecommands[i]) {
            release_telecommand_record(active_telecommands[i]);
        }
    }
}

size_t calculate_telecommand_payload_size(uint16_t total_packet_length, uint16_t header_overhead) {
    size_t effective_payload = (size_t)(total_packet_length - header_overhead);
    return effective_payload;
}

int validate_packet_integrity(telecommand_packet_t *pkt, size_t stream_len) {
    if (pkt->magic != PROTOCOL_MAGIC_HEADER) {
        return 0;
    }
    if (stream_len < sizeof(telecommand_packet_t) + pkt->length) {
        return 0;
    }
    return 1;
}

int dispatch_telecommand(uint8_t *stream_bytes, size_t stream_len) {
    telecommand_packet_t *pkt;
    telecommand_msg_t *msg;
    size_t payload_size;
    
    if (stream_len < sizeof(telecommand_packet_t)) {
        printf("Packet stream below minimum telecommand header size.\n");
        return -1;
    }
    
    pkt = (telecommand_packet_t *)stream_bytes;
    
    if (!validate_packet_integrity(pkt, stream_len)) {
        printf("Packet integrity verification failed. Discarding frame.\n");
        return -1;
    }
    
    log_telecommand_header(stream_bytes, stream_len);
    
    payload_size = calculate_telecommand_payload_size(pkt->length, sizeof(telecommand_packet_t));
    
    switch (pkt->type) {
        case 1: // Station status update
            msg = create_telecommand_record(MAX_MESSAGE_SIZE);
            if (msg) {
                append_telecommand_payload(msg, pkt->data, payload_size);
                printf("Station status telecommand processed successfully.\n");
            }
            break;
            
        case 2: // Dynamic thruster calibration
            msg = create_telecommand_record((uint16_t)payload_size);
            if (msg) {
                append_telecommand_payload(msg, pkt->data, pkt->length);
                printf("Thruster calibration telecommand processed successfully.\n");
            }
            break;
            
        case 3: // Emergency station failover
            emergency_command_cleanup();
            printf("Emergency station failover executed.\n");
            break;
            
        default:
            printf("Unrecognised telecommand type code: %d\n", pkt->type);
            return -1;
    }
    
    return 0;
}

int main(int argc, char **argv) {
    FILE *fp;
    uint8_t input_stream[MAX_PACKET_SIZE * 2];
    size_t bytes_received;
    
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <telecommand_packet_file>\n", argv[0]);
        return 1;
    }
    
    fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("Failed to open telecommand packet file");
        return 1;
    }
    
    printf("=== Sentinel-1 RF Telecommand Stream Handler ===\n");
    while ((bytes_received = fread(input_stream, 1, sizeof(input_stream), fp)) > 0) {
        printf("Ingesting packet frame (%zu bytes received)...\n", bytes_received);
        size_t offset = 0;
        while (offset + sizeof(telecommand_packet_t) <= bytes_received) {
            telecommand_packet_t *pkt = (telecommand_packet_t *)(input_stream + offset);
            if (!validate_packet_integrity(pkt, bytes_received - offset)) {
                break;
            }
            size_t pkt_total_len = sizeof(telecommand_packet_t) + pkt->length;
            if (dispatch_telecommand(input_stream + offset, pkt_total_len) < 0) {
                printf("Halting packet dispatch loop.\n");
                break;
            }
            offset += pkt_total_len;
        }
    }
    
    fclose(fp);
    emergency_command_cleanup();
    return 0;
}
