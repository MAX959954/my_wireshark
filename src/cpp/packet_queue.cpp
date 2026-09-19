#include "packet_queue.h"

void PacketQueue::push(const uint8_t* data, uint32_t length, uint32_t ts_seconds,
                       uint32_t ts_microseconds) {
    CapturedFrame frame;
    frame.data.assign(data, data + length);
    frame.ts_seconds = ts_seconds;
    frame.ts_microseconds = ts_microseconds;

    std::unique_lock<std::mutex> lock(mutex_);
    not_full_.wait(lock, [&] { return queue_.size() < max_size_ || closed_; });
    if (closed_) {
        return;
    }
    queue_.push(std::move(frame));
    lock.unlock();
    not_empty_.notify_one();
}

bool PacketQueue::pop(CapturedFrame* out) {
    std::unique_lock<std::mutex> lock(mutex_);
    not_empty_.wait(lock, [&] { return !queue_.empty() || closed_; });
    if (queue_.empty()) {
        return false;  // closed and drained
    }
    *out = std::move(queue_.front());
    queue_.pop();
    lock.unlock();
    not_full_.notify_one();
    return true;
}

void PacketQueue::close() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
    }
    not_empty_.notify_all();
    not_full_.notify_all();
}
