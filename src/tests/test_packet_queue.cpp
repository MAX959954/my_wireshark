#include "test_util.h"
#include "cpp/packet_queue.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>

namespace {

void pop_returns_frames_in_fifo_order() {
    PacketQueue q;
    const uint8_t a[] = {1, 2, 3};
    const uint8_t b[] = {4, 5};
    q.push(a, sizeof(a), 100, 1);
    q.push(b, sizeof(b), 200, 2);

    CapturedFrame f1, f2;
    TEST_ASSERT(q.pop(&f1) == true);
    TEST_ASSERT(f1.data.size() == 3);
    TEST_ASSERT(std::memcmp(f1.data.data(), a, 3) == 0);
    TEST_ASSERT(f1.ts_seconds == 100);
    TEST_ASSERT(f1.ts_microseconds == 1);

    TEST_ASSERT(q.pop(&f2) == true);
    TEST_ASSERT(f2.data.size() == 2);
    TEST_ASSERT(std::memcmp(f2.data.data(), b, 2) == 0);
}

void pop_drains_remaining_frames_after_close_then_returns_false() {
    PacketQueue q;
    const uint8_t a[] = {9};
    q.push(a, sizeof(a), 0, 0);
    q.close();

    CapturedFrame f;
    TEST_ASSERT(q.pop(&f) == true);   // still drains what was queued before close()
    TEST_ASSERT(q.pop(&f) == false);  // now empty and closed
}

void pop_on_an_empty_closed_queue_returns_false_immediately(void) {
    PacketQueue q;
    q.close();
    CapturedFrame f;
    TEST_ASSERT(q.pop(&f) == false);
}

// A consumer blocked in pop() on an empty, still-open queue must wake up
// once a producer pushes a frame - the actual producer/consumer handoff
// main.cpp relies on. Uses a real second thread, not just single-threaded
// push-then-pop, so it also exercises the condition_variable wakeup path.
void pop_blocks_until_a_concurrent_push_arrives() {
    PacketQueue q;
    std::atomic<bool> popped{false};

    std::thread consumer([&] {
        CapturedFrame f;
        if (q.pop(&f) && f.data.size() == 1 && f.data[0] == 0x42) {
            popped = true;
        }
    });

    // Give the consumer a real chance to actually block in pop() first -
    // this doesn't prove it did, but a flake here would mean the test
    // passes trivially (push-before-pop), not that it silently fails.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    TEST_ASSERT(popped.load() == false);

    const uint8_t data[] = {0x42};
    q.push(data, sizeof(data), 0, 0);
    consumer.join();

    TEST_ASSERT(popped.load() == true);
}

// push() must block once the queue is full, and unblock as soon as the
// consumer makes room - the backpressure packet_queue.h's header comment
// promises.
void push_blocks_when_full_and_unblocks_once_a_slot_frees_up() {
    PacketQueue q(/*max_size=*/1);
    const uint8_t first[] = {1};
    const uint8_t second[] = {2};
    q.push(first, sizeof(first), 0, 0);  // fills the single slot

    std::atomic<bool> second_pushed{false};
    std::thread producer([&] {
        q.push(second, sizeof(second), 0, 0);  // must block until popped below
        second_pushed = true;
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    TEST_ASSERT(second_pushed.load() == false);

    CapturedFrame f;
    TEST_ASSERT(q.pop(&f) == true);  // frees the slot
    producer.join();

    TEST_ASSERT(second_pushed.load() == true);
}

}  // namespace

int main(void) {
    TEST_RUN(pop_returns_frames_in_fifo_order);
    TEST_RUN(pop_drains_remaining_frames_after_close_then_returns_false);
    TEST_RUN(pop_on_an_empty_closed_queue_returns_false_immediately);
    TEST_RUN(pop_blocks_until_a_concurrent_push_arrives);
    TEST_RUN(push_blocks_when_full_and_unblocks_once_a_slot_frees_up);
    TEST_MAIN_END();
}
