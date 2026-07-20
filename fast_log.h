#ifndef FAST_LOG_H
#define FAST_LOG_H

#define LOG_RING_SIZE (1 << 20) // 1 MB ring buffer
#define LOG_RING_MASK (LOG_RING_SIZE - 1)
#define LOG_FLUSH_CHUNK 65536 // flush up to 64 KB at a time

typedef enum
{
    LOG_DEBUG,
    LOG_VERBOSE,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_NONE
} log_level_t;

void log_init(const char *filename, log_level_t log_level);
void log_close(void);
void log_set_level(log_level_t level);

void log_write(const char *data, int len);                    // Write to ring buffer.
void log_printf(log_level_t log_level, const char *fmt, ...); // printf-style logging into ring
void log_flush(void);                                         // Drain from ring buffer to disk

#endif /* FAST_LOG_H */