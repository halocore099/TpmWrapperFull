#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

// Log levels
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_WARN = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_NONE = 4
} log_level_t;

/**
 * Set the minimum log level
 * @param level Minimum log level to display
 */
void logger_set_level(log_level_t level);

/**
 * Get the current log level
 * @return Current log level
 */
log_level_t logger_get_level(void);

/**
 * Log a debug message
 */
void log_debug(const char* format, ...);

/**
 * Log an info message
 */
void log_info(const char* format, ...);

/**
 * Log a warning message
 */
void log_warn(const char* format, ...);

/**
 * Log an error message
 */
void log_error(const char* format, ...);

#ifdef __cplusplus
}
#endif

#endif // LOGGER_H

