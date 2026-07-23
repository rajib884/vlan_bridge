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

// GUI/memory sink: when enabled, log_flush() no longer writes to disk; instead
// the caller pulls pending bytes with log_drain() (e.g. into a text control).
// All ring operations become thread-safe, so a worker thread can log while the
// UI thread drains. If the ring fills before a drain, the oldest bytes are
// dropped rather than corrupting the buffer.
void log_set_memory_sink(int enabled);
int  log_drain(char *dst, int max_len);   // returns bytes copied (0 if none)

#endif /* FAST_LOG_H */