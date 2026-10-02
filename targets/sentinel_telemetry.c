/*
 * Sentinel-1 Space Station: Subsystem Telemetry & Configuration Parser
 * Component: sentinel_telemetry.c
 * Description:
 *   Parses telemetry stream configuration directives, sensor calibration profiles,
 *   and environmental monitoring setpoints for the Sentinel-1 communications hub.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#define MAX_LINE_LENGTH 256
#define MAX_KEY_LENGTH 64
#define MAX_VALUE_LENGTH 128
#define MAX_TELEMETRY_ENTRIES 100

typedef struct {
    char key[MAX_KEY_LENGTH];
    char value[MAX_VALUE_LENGTH];
    int value_type; // 0=string, 1=integer, 2=floating_point
    int is_initialised;
} telemetry_entry_t;

typedef struct {
    telemetry_entry_t entries[MAX_TELEMETRY_ENTRIES];
    int entry_count;
    char *dynamic_stream_buffer;
    size_t stream_buffer_size;
} station_telemetry_t;

static station_telemetry_t *global_telemetry = NULL;

void log_telemetry_event(const char *event_message) {
    FILE *logfile = fopen("/tmp/sentinel_telemetry.log", "a");
    if (logfile) {
        fprintf(logfile, "%s\n", event_message);
        fclose(logfile);
    }
    printf("[TELEMETRY LOG] ");
    printf(event_message);
    printf("\n");
}

size_t calculate_stream_buffer_size(int num_channels, int sample_rate) {
    size_t channel_overhead = num_channels * sizeof(telemetry_entry_t);
    size_t stream_bandwidth = num_channels * sample_rate;
    size_t total_allocation = channel_overhead + stream_bandwidth;
    return total_allocation;
}

char* allocate_auxiliary_buffer(size_t buffer_size) {
    char *buffer = (char *)malloc(buffer_size);
    if (!buffer) {
        log_telemetry_event("Memory allocation failure in auxiliary buffer");
        return NULL;
    }
    memset(buffer, 0, buffer_size);
    return buffer;
}

void process_telemetry_directive(char *key, char *value) {
    char formatted_key[MAX_KEY_LENGTH];
    char formatted_value[MAX_VALUE_LENGTH];
    char status_output[64];
    
    strncpy(formatted_key, key, sizeof(formatted_key) - 1);
    formatted_key[sizeof(formatted_key) - 1] = '\0';
    strncpy(formatted_value, value, sizeof(formatted_value) - 1);
    formatted_value[sizeof(formatted_value) - 1] = '\0';
    
    for (int i = 0; formatted_key[i]; i++) {
        formatted_key[i] = (char)tolower((unsigned char)formatted_key[i]);
    }
    
    if (strcmp(formatted_key, "log_event") == 0) {
        log_telemetry_event(formatted_value);
    } else if (strcmp(formatted_key, "stream_multiplier") == 0) {
        int multiplier = atoi(formatted_value);
        size_t required_size = calculate_stream_buffer_size(global_telemetry->entry_count, multiplier);
        
        if (required_size > 0) {
            if (global_telemetry->dynamic_stream_buffer) {
                free(global_telemetry->dynamic_stream_buffer);
            }
            global_telemetry->dynamic_stream_buffer = (char *)malloc(required_size);
            global_telemetry->stream_buffer_size = required_size;
            printf("Stream buffer resized to %zu bytes.\n", required_size);
        }
    } else if (strcmp(formatted_key, "aux_buffer_request") == 0) {
        size_t req_size = (size_t)atoi(formatted_value);
        char *aux = allocate_auxiliary_buffer(req_size);
        if (aux) {
            printf("Auxiliary stream memory reserved: %zu bytes.\n", req_size);
        }
    }
    
    sprintf(status_output, "Directive parsed: %s=%s", formatted_key, formatted_value);
    printf("%s\n", status_output);
}

void process_sensor_calibration(const char *key, const char *value) {
    int sensor_id;
    float calibration_factor;
    char calibration_log[64];
    
    if (strstr(key, "sensor_id_") == key) {
        if (sscanf(value, "%d", &sensor_id) != 1) {
            printf("Sensor calibration reading failed; using default channel.\n");
        }
        snprintf(calibration_log, sizeof(calibration_log), "CAL_ID_%s=%d", key, sensor_id);
        log_telemetry_event(calibration_log);
    } else if (strstr(key, "cal_factor_") == key) {
        if (sscanf(value, "%f", &calibration_factor) != 1) {
            printf("Calibration factor reading failed; using default factor.\n");
        }
        snprintf(calibration_log, sizeof(calibration_log), "CAL_FACTOR_%s=%f", key, calibration_factor);
        log_telemetry_event(calibration_log);
    }
}

int parse_telemetry_line(char *line) {
    char *key;
    char *value;
    char *delimiter;
    
    if (line[0] == '#' || line[0] == '\n' || line[0] == '\r' || line[0] == '\0') {
        return 0;
    }
    
    delimiter = strchr(line, '=');
    if (!delimiter) {
        char err_msg[512];
        sprintf(err_msg, "Invalid telemetry line syntax (missing '=' delimiter): %s", line);
        log_telemetry_event(err_msg);
        return -1;
    }
    
    *delimiter = '\0';
    key = line;
    value = delimiter + 1;
    
    // Trim trailing newline
    size_t val_len = strlen(value);
    while (val_len > 0 && (value[val_len - 1] == '\n' || value[val_len - 1] == '\r')) {
        value[--val_len] = '\0';
    }
    
    if (global_telemetry->entry_count < MAX_TELEMETRY_ENTRIES) {
        telemetry_entry_t *entry = &global_telemetry->entries[global_telemetry->entry_count];
        strncpy(entry->key, key, MAX_KEY_LENGTH - 1);
        entry->key[MAX_KEY_LENGTH - 1] = '\0';
        strncpy(entry->value, value, MAX_VALUE_LENGTH - 1);
        entry->value[MAX_VALUE_LENGTH - 1] = '\0';
        entry->is_initialised = 1;
        global_telemetry->entry_count++;
    }
    
    process_telemetry_directive(key, value);
    process_sensor_calibration(key, value);
    
    return 0;
}

int parse_telemetry_stream(FILE *fp) {
    char line_buffer[MAX_LINE_LENGTH];
    int parsed_lines = 0;
    
    printf("Initialising telemetry stream parser...\n");
    while (fgets(line_buffer, sizeof(line_buffer), fp) != NULL) {
        if (parse_telemetry_line(line_buffer) == 0) {
            parsed_lines++;
        }
    }
    return parsed_lines;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <telemetry_config_file>\n", argv[0]);
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        perror("Failed to open telemetry configuration file");
        return 1;
    }
    
    global_telemetry = (station_telemetry_t *)malloc(sizeof(station_telemetry_t));
    if (!global_telemetry) {
        fclose(fp);
        return 1;
    }
    memset(global_telemetry, 0, sizeof(station_telemetry_t));
    
    printf("=== Sentinel-1 Orbital Telemetry Processor ===\n");
    int count = parse_telemetry_stream(fp);
    printf("Telemetry parsing complete. Processed entries: %d\n", count);
    
    fclose(fp);
    if (global_telemetry->dynamic_stream_buffer) {
        free(global_telemetry->dynamic_stream_buffer);
    }
    free(global_telemetry);
    return 0;
}

