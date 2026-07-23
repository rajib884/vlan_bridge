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
} Logger;

static Logger g_log;

void log_init(const char *filename, log_level_t log_level)
{
    g_log.write_pos = 0;
    g_log.read_pos = 0;
    g_log.min_level = log_level;
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
    CloseHandle(g_log.file);
}

void log_set_level(log_level_t level)
{
    g_log.min_level = level;
}

// How many bytes are pending (not yet flushed)
static inline int log_pending(void)
{
    return (g_log.write_pos - g_log.read_pos) & LOG_RING_MASK;
}

// Write to ring buffer. If there's no room, flush first.
void log_write(const char *data, int len)
{
    // If message won't fit, flush to make room
    if (len > LOG_RING_SIZE - log_pending() - 1)
        log_flush();

    // If message is larger than the entire ring, write directly
    if (len >= LOG_RING_SIZE)
    {
        DWORD written;
        WriteFile(g_log.file, data, len, &written, NULL);
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

// Drain pending bytes from ring buffer to disk in one or two WriteFile calls
void log_flush(void)
{
    int pending = log_pending();
    if (pending == 0) return;

    DWORD written;
    int to_end = LOG_RING_SIZE - g_log.read_pos;

    if (pending <= to_end) {
        // Contiguous chunk
        WriteFile(g_log.file, g_log.buf + g_log.read_pos, pending, &written, NULL);
    } else {
        // Two chunks: tail of buffer, then wrap-around head
        WriteFile(g_log.file, g_log.buf + g_log.read_pos, to_end,          &written, NULL);
        WriteFile(g_log.file, g_log.buf,                  pending - to_end, &written, NULL);
    }

    g_log.read_pos = (g_log.read_pos + pending) & LOG_RING_MASK;
}

#if 0
// ---------------------------------------------------------------
// Usage example — drop-in for your TFTP session logging
// ---------------------------------------------------------------

// Call this AFTER sending the reply, not before.
// The log is batched in RAM and flushed in big chunks.
void log_session(int i)
{
    // Replace with your actual session fields
    unsigned session_id  = 42;
    int      in_use      = 1;   // TFTP_RECEIVING
    int      ftp         = 0;
    unsigned client_ip   = 0x0100007f; // 127.0.0.1
    unsigned client_port = 1234;
    short    vlan_id     = 10;
    unsigned server_port = 69;

    char ip_str[16];
    // inet_ntoa equivalent, avoiding the static buffer issue
    unsigned char *b = (unsigned char *)&client_ip;
    snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);

    log_printf("\nSession ID: %3u [%s]%s\n  %s:%u [VLAN:%d]\n  Session Server Port: %u\n",
        i,
        (in_use == 1) ? "WRQ" : "RRQ",
        ftp ? "[FTP]" : "",
        ip_str,
        client_port,
        vlan_id,
        server_port
    );

    // Flush strategy options (pick one):
    //   A) Flush here every call      — lowest latency, more WriteFile calls
    //   B) Flush every N sessions     — good balance
    //   C) Flush in your select/recv  — flush while waiting for next packet (best)
    //   D) Flush only on ring-full    — maximum batching, highest throughput

    // Option C is recommended: call log_flush() right before your blocking recv,
    // so the disk write happens while you're waiting for network anyway.
}

#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#include <windows.h>
#include <stdio.h>

int main(void)
{
    log_init("log.log");

    SYSTEMTIME st_start, st_end;
    FILETIME ft_start, ft_end;

    GetLocalTime(&st_start);

    for (int i = 0; i < 10000; i++) {
        log_session(i);
    }
        log_flush();

    GetLocalTime(&st_end);

    // Convert SYSTEMTIME to FILETIME
    SystemTimeToFileTime(&st_start, &ft_start);
    SystemTimeToFileTime(&st_end, &ft_end);

    // Convert FILETIME to 64-bit integers
    ULARGE_INTEGER t1, t2;
    t1.LowPart  = ft_start.dwLowDateTime;
    t1.HighPart = ft_start.dwHighDateTime;

    t2.LowPart  = ft_end.dwLowDateTime;
    t2.HighPart = ft_end.dwHighDateTime;

    // Difference in 100-nanosecond intervals
    ULONGLONG diff = t2.QuadPart - t1.QuadPart;

    // Convert to milliseconds
    double diff_ms = diff / 10000.0;

    printf("Elapsed time: %.3f ms\n", diff_ms);

    log_close();
    return 0;
}
#endif
