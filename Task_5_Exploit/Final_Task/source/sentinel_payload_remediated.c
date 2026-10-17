/*
 * Sentinel-1 Space Station: Scientific Payload & Imaging Frame Parser (REMEDIATED)
 * Component: sentinel_payload.c
 * Description:
 *   Securely patched version neutralizing Format String (CWE-134), Stack Buffer
 *   Overflow (CWE-121), Heap Buffer Overflow (CWE-122), Use-After-Free (CWE-416),
 *   and Integer Overflow (CWE-190).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#define MAX_LABEL_LEN 64
#define MAX_FRAME_CAPACITY 1024

typedef struct {
    char *data;
    size_t size;
    int is_valid;
    char sensor_type[32];
} payload_frame_t;

static payload_frame_t *global_frame = NULL;

/*
 * FIX (CWE-121 Stack Buffer Overflow):
 * Enforce strict bounds check using strncpy with explicit null termination.
 */
void process_frame_label(const char *label) {
    char local_label[MAX_LABEL_LEN];
    strncpy(local_label, label, sizeof(local_label) - 1);
    local_label[sizeof(local_label) - 1] = '\0';
    printf("Processing observation frame label: %s\n", local_label);
}

/*
 * FIX (CWE-134 Format String Vulnerability):
 * Use explicit "%s" format specifier to prevent user input from being evaluated as a format string.
 */
void log_payload_error(const char *error_description) {
    fprintf(stderr, "[PAYLOAD ERROR] %s\n", error_description);
}

/*
 * FIX (CWE-190 Integer Overflow):
 * Check for arithmetic overflow during multi-dimensional size computation.
 */
size_t calculate_frame_dimension_size(unsigned int width, unsigned int height, unsigned int depth) {
    if (width == 0 || height == 0 || depth == 0) {
        return 0;
    }
    uint64_t step1 = (uint64_t)width * (uint64_t)height;
    if (width != 0 && step1 / width != height) {
        return 0; // Multiplication overflow
    }
    uint64_t total = step1 * (uint64_t)depth;
    if (depth != 0 && total / depth != step1) {
        return 0; // Multiplication overflow
    }
    if (total > MAX_FRAME_CAPACITY) {
        return 0; // Exceeds subsystem memory capacity
    }
    return (size_t)total;
}

/*
 * FIX (CWE-416 Use-After-Free):
 * Zero out pointers immediately upon freeing to prevent dangling pointer access.
 */
void cleanup_active_frame(void) {
    if (global_frame) {
        if (global_frame->data) {
            free(global_frame->data);
            global_frame->data = NULL;
        }
        free(global_frame);
        global_frame = NULL;
        printf("Active observation frame released from cache.\n");
    }
}

void inspect_cached_frame(void) {
    if (global_frame) {
        printf("Cached frame buffer size: %zu bytes\n", global_frame->size);
        if (global_frame->data) {
            printf("Cached frame leading byte: 0x%02x\n", (unsigned char)global_frame->data[0]);
        }
    } else {
        printf("No active frame currently cached.\n");
    }
}

/*
 * FIX (CWE-122 Heap Buffer Overflow):
 * Enforce strict bounds check ensuring incoming data never exceeds MAX_FRAME_CAPACITY.
 */
void process_payload_data(const char *input_bytes, size_t input_size) {
    if (input_size > MAX_FRAME_CAPACITY) {
        log_payload_error("Incoming payload size exceeds maximum frame capacity buffer");
        return;
    }

    if (!global_frame) {
        global_frame = (payload_frame_t *)malloc(sizeof(payload_frame_t));
        if (!global_frame) {
            log_payload_error("Allocation failed for payload frame descriptor");
            return;
        }
        global_frame->size = MAX_FRAME_CAPACITY;
        global_frame->data = (char *)malloc(global_frame->size);
        if (!global_frame->data) {
            free(global_frame);
            global_frame = NULL;
            log_payload_error("Allocation failed for frame payload data");
            return;
        }
        global_frame->is_valid = 1;
        strncpy(global_frame->sensor_type, "SPECTRAL_RADAR", sizeof(global_frame->sensor_type) - 1);
        global_frame->sensor_type[sizeof(global_frame->sensor_type) - 1] = '\0';
    }
    
    memcpy(global_frame->data, input_bytes, input_size);
    printf("Transferred %zu bytes into observation buffer.\n", input_size);
}

int parse_payload_file(FILE *fp) {
    char header_line[256];
    char label_buffer[MAX_LABEL_LEN];
    unsigned int width, height, depth;
    
    if (!fgets(header_line, sizeof(header_line), fp)) {
        log_payload_error("Empty payload stream or unreadable header");
        return -1;
    }
    
    // Scan with explicit width limitation (%63s) matching MAX_LABEL_LEN - 1
    if (sscanf(header_line, "PAYLOAD_FRAME %u %u %u %63s", &width, &height, &depth, label_buffer) != 4) {
        log_payload_error("Malformed header line: expected PAYLOAD_FRAME <w> <h> <d> <label>");
        return -1;
    }
    
    process_frame_label(label_buffer);
    
    size_t expected_data_size = calculate_frame_dimension_size(width, height, depth);
    if (expected_data_size == 0) {
        log_payload_error("Invalid payload dimensions or size exceeds frame capacity");
        return -1;
    }
    
    printf("Payload frame dimensions: %u x %u x %u (%zu bytes required)\n", width, height, depth, expected_data_size);
    
    char *stream_data = (char *)malloc(expected_data_size + 1);
    if (!stream_data) {
        log_payload_error("Memory allocation failed for incoming stream buffer");
        return -1;
    }
    
    size_t actual_bytes = fread(stream_data, 1, expected_data_size, fp);
    printf("Read %zu bytes from payload observation stream.\n", actual_bytes);
    
    process_payload_data(stream_data, actual_bytes);
    
    free(stream_data);
    
    // Check for optional frame inspection trigger
    if (width == 1337) {
        cleanup_active_frame();
        inspect_cached_frame();
    }
    
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <payload_binary_file>\n", argv[0]);
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("Failed to open scientific payload file");
        return 1;
    }
    
    printf("=== Sentinel-1 Scientific Payload Ingestion Subsystem ===\n");
    int result = parse_payload_file(fp);
    
    fclose(fp);
    cleanup_active_frame();
    
    return (result == 0) ? 0 : 1;
}
