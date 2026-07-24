#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <windows.h>

#include "fast_log.h"

typedef struct
{
    char buf[LOG_RING_SIZE];
    int write_pos; // next byte to write
    int read_pos;  // next byte to flush
    HANDLE file;
    log_level_t min_level;
    int memory_mode;        // 1 = log_flush() is a no-op; drain via log_drain()
    CRITICAL_SECTION cs;
    int cs_init;
} Logger;

static Logger g_log;

static inline void log_lock(void)   { if (g_log.cs_init) EnterCriticalSection(&g_log.cs); }
static inline void log_unlock(void) { if (g_log.cs_init) LeaveCriticalSection(&g_log.cs); }

void log_init(const char *filename, log_level_t log_level)
{
    g_log.write_pos = 0;
    g_log.read_pos = 0;
    g_log.min_level = log_level;
    g_log.memory_mode = 0;
    if (!g_log.cs_init)
    {
        InitializeCriticalSection(&g_log.cs);
        g_log.cs_init = 1;
    }
    if (filename != NULL)
    {
        g_log.file = CreateFileA( filename, GENERIC_WRITE,
            FILE_SHARE_READ, // allow other processes to read log live
            NULL, OPEN_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, // hint to prefetcher
            NULL);
    }
    else
    {
        g_log.file = GetStdHandle(STD_OUTPUT_HANDLE);
    }
    if (g_log.file == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "Failed to open log file: %lu\n", GetLastError());
        exit(1);
    }
    // Append: seek to end
    SetFilePointer(g_log.file, 0, NULL, FILE_END);
}

// Flush everything remaining before exit
void log_close(void)
{
    log_flush();
    if (!g_log.memory_mode)
        CloseHandle(g_log.file);
}

void log_set_level(log_level_t level)
{
    g_log.min_level = level;
}

void log_set_memory_sink(int enabled)
{
    g_log.memory_mode = enabled ? 1 : 0;
}

// How many bytes are pending (not yet flushed/drained)
static inline int log_pending(void)
{
    return (g_log.write_pos - g_log.read_pos) & LOG_RING_MASK;
}

// Write to ring buffer. If there's no room, flush (file mode) or drop the
// oldest pending bytes (memory mode) to make room.
void log_write(const char *data, int len)
{
    log_lock();

    // If message won't fit, make room.
    if (len > LOG_RING_SIZE - log_pending() - 1)
    {
        if (g_log.memory_mode)
        {
            // Drop oldest: advance read_pos so the new data fits.
            int need = len - (LOG_RING_SIZE - log_pending() - 1);
            g_log.read_pos = (g_log.read_pos + need) & LOG_RING_MASK;
        }
        else
        {
            log_unlock();
            log_flush();
            log_lock();
        }
    }

    // If message is larger than the entire ring, write directly (file mode only).
    if (len >= LOG_RING_SIZE)
    {
        if (!g_log.memory_mode)
        {
            DWORD written;
            WriteFile(g_log.file, data, len, &written, NULL);
        }
        log_unlock();
        return;
    }

    // Copy into ring, wrapping around if needed
    int space_to_end = LOG_RING_SIZE - g_log.write_pos;
    if (len <= space_to_end)
    {
        memcpy(g_log.buf + g_log.write_pos, data, len);
    }
    else
    {
        memcpy(g_log.buf + g_log.write_pos, data, space_to_end);
        memcpy(g_log.buf, data + space_to_end, len - space_to_end);
    }
    g_log.write_pos = (g_log.write_pos + len) & LOG_RING_MASK;

    log_unlock();
}

// printf-style logging: formats into a stack buffer, then into ring
void log_printf(log_level_t log_level, const char *fmt, ...)
{
    if (g_log.min_level > log_level)
        return;
    char tmp[2048];
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    /* vsnprintf returns the length it WOULD have written; clamp so a truncated
     * message never makes log_write read past tmp. */
    if (len >= (int)sizeof(tmp))
        len = (int)sizeof(tmp) - 1;
    if (len > 0)
        log_write(tmp, len);
    return;
}

// Drain pending bytes from ring buffer to disk in one or two WriteFile calls.
// In memory mode this is a no-op (the GUI pulls bytes with log_drain instead).
void log_flush(void)
{
    if (g_log.memory_mode)
        return;

    log_lock();
    int pending = log_pending();
    if (pending == 0) { log_unlock(); return; }

    DWORD written;
    int to_end = LOG_RING_SIZE - g_log.read_pos;

    if (pending <= to_end) {
        WriteFile(g_log.file, g_log.buf + g_log.read_pos, pending, &written, NULL);
    } else {
        WriteFile(g_log.file, g_log.buf + g_log.read_pos, to_end,          &written, NULL);
        WriteFile(g_log.file, g_log.buf,                  pending - to_end, &written, NULL);
    }

    g_log.read_pos = (g_log.read_pos + pending) & LOG_RING_MASK;
    log_unlock();
}

// Copy up to max_len pending bytes into dst (no NUL added), advancing read_pos.
// Returns the number of bytes copied. Safe to call from a different thread than
// the one calling log_printf.
int log_drain(char *dst, int max_len)
{
    if (max_len <= 0) return 0;

    log_lock();
    int pending = log_pending();
    int n = pending < max_len ? pending : max_len;
    if (n <= 0) { log_unlock(); return 0; }

    int to_end = LOG_RING_SIZE - g_log.read_pos;
    if (n <= to_end) {
        memcpy(dst, g_log.buf + g_log.read_pos, n);
    } else {
        memcpy(dst, g_log.buf + g_log.read_pos, to_end);
        memcpy(dst + to_end, g_log.buf, n - to_end);
    }
    g_log.read_pos = (g_log.read_pos + n) & LOG_RING_MASK;
    log_unlock();
    return n;
}
