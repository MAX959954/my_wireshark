#include "c/capture.h"

#include <cstdint>
#include <iostream> 

namespace {
	void on_packet(const uint8_t* /*packet*/, uint32_t length, 
		uint32_t ts_seconds, uint32_t ts_microseconds, void* user_data) {
		auto* count = static_cast<uint64_t*> (user_data);
		++(*count);
		std :: cout << "[#" << *count << "] len=" << length << " bytes"
			<< "  ts=" << ts_seconds << "." << ts_microseconds << "\n";
	}
}

int main() {
	capture_device_t devices[CAPTURE_MAX_DEVICES];
	int device_count = capture_list_device(devices, CAPTURE_MAX_DEVICES);

	if (device_count <= 0) {
		std::cerr << "No capture devices found. Is Npcap installed, and is "
			"this process running as Administrator?\n";
		return 1;
	}

	std::cout << "Available interfaces : \n";
	for (int i = 0; i < device_count; i++) {
		std::cout << "  [" << i << "] " << devices[i].name << " - "
			<< devices[i].description << "\n";
	}

	std::cout << "Select interface index : ";
	int choice = -1;
	std::cin >> choice;

	if (choice < 0 || choice >= device_count) {
		std::cerr << "Invalid choice";
		return 1;
	}

	std::cout << "Capturing on " << devices[choice].name << " (Ctrl+C to stop)...\n";
	uint64_t packet_count = 0;
	if (capture_run(devices[choice].name, on_packet, &packet_count) != 0) {
		std::cerr << "Capturing failed\n";
		return 1;
	}
}
