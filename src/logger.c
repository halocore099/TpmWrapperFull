#include "logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static log_level_t g_log_level = LOG_LEVEL_INFO;

// Check if we should suppress wolfTPM debug output
static int g_suppress_wolftpm_debug = 1;

void logger_set_level(log_level_t level) {
    g_log_level = level;
}

log_level_t logger_get_level(void) {
    return g_log_level;
}

static void log_message(log_level_t level, const char* prefix, const char* format, va_list args) {
    if (level < g_log_level) {
        return;
    }
    
    FILE* output = (level >= LOG_LEVEL_ERROR) ? stderr : stdout;
    fprintf(output, "%s", prefix);
    vfprintf(output, format, args);
    fprintf(output, "\n");
}

void log_debug(const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_message(LOG_LEVEL_DEBUG, "[DEBUG] ", format, args);
    va_end(args);
}

void log_info(const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_message(LOG_LEVEL_INFO, "", format, args);
    va_end(args);
}

void log_warn(const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_message(LOG_LEVEL_WARN, "[WARN] ", format, args);
    va_end(args);
}

void log_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_message(LOG_LEVEL_ERROR, "[ERROR] ", format, args);
    va_end(args);
}

// Function to suppress wolfTPM debug output
// This can be called to reduce verbosity
void logger_suppress_wolftpm_debug(int suppress) {
    g_suppress_wolftpm_debug = suppress;
}

