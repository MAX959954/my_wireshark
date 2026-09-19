#pragma once
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <queue>
#include <vector>

/*
One captured frame, fully copied off the kernel's ring buffer (see
raw_socket.c) so it can safely outlive the poll() cycle that produced it
and cross over to a different thread.
*/
struct CapturedFrame {
    std::vector<uint8_t> data;
    uint32_t ts_seconds = 0;
    uint32_t ts_microseconds = 0;
};

/*
A bounded, mutex-protected producer/consumer queue sitting between the
capture thread (which only needs to copy each frame off the kernel's ring
buffer and hand it off - see raw_socket.c's TPACKET_V3 comment) and the
parse/print thread (which does the actual work: decoding headers,
verifying checksums, formatting and writing a summary line). Splitting
these across two threads means a slow consumer (a scrollback-heavy
terminal, output piped into something slow) no longer makes the capture
thread miss frames between poll() calls - the classic failure mode of a
sniffer built as one single-threaded "recv -> parse -> print" loop.

Bounded rather than unbounded: an unbounded queue in front of a consumer
slower than the producer just moves the traffic-burst problem from
"dropped packets" to "unbounded memory growth" instead of solving it.
Once full, push() blocks the capture thread - deliberately applying
backpressure to the producer rather than growing memory without limit or
silently dropping frames ourselves. (The kernel's own ring buffer, and
its tp_drops counter, remain the last line of defense against genuine
sustained overload - this queue only smooths out short bursts.)
*/
class PacketQueue {
   public:
    explicit PacketQueue(std::size_t max_size = 4096) : max_size_(max_size) {}

    // Copies 'length' bytes starting at 'data' into a new CapturedFrame and
    // enqueues it, blocking while the queue is full. A no-op once close()
    // has been called (the capture thread's own loop should have already
    // stopped calling this by then, but a call landing right at shutdown
    // must not deadlock).
    void push(const uint8_t* data, uint32_t length, uint32_t ts_seconds, uint32_t ts_microseconds);

    // Blocks while the queue is empty and still open. Returns false once
    // the queue has been closed AND drained - the consumer's signal to
    // stop; otherwise fills '*out' and returns true.
    bool pop(CapturedFrame* out);

    // Wakes up any thread blocked in push()/pop() and makes every future
    // pop() on an empty queue return false immediately instead of
    // blocking. The capture thread calls this exactly once, after its
    // capture loop has returned for good.
    void close();

   private:
    std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    std::queue<CapturedFrame> queue_;
    std::size_t max_size_;
    bool closed_ = false;
};
