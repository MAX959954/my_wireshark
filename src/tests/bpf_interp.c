#include "bpf_interp.h"

#include <string.h>

static int load_u(const uint8_t* pkt, uint32_t pkt_len, uint32_t off, int width, uint32_t* out) {
    if (off + (uint32_t)width > pkt_len) {
        return -1; /* out-of-bounds access: kernel aborts the program, packet is rejected */
    }
    uint32_t v = 0;
    for (int i = 0; i < width; i++) {
        v = (v << 8) | pkt[off + i];
    }
    *out = v;
    return 0;
}

uint32_t bpf_interp_run(const struct sock_fprog* prog, const uint8_t* pkt, uint32_t pkt_len) {
    if (prog == NULL || prog->filter == NULL || prog->len == 0) {
        return 0xFFFFu; /* an empty program is capfilter_compile's "accept everything" */
    }

    uint32_t a = 0, x = 0;
    unsigned int pc = 0;
    unsigned int steps = 0;

    while (pc < prog->len) {
        if (++steps > 10000) {
            return 0; /* guard against unexpectedly looping bytecode in a test */
        }
        const struct sock_filter* f = &prog->filter[pc];
        uint16_t cls = BPF_CLASS(f->code);

        if (cls == BPF_LD || cls == BPF_LDX) {
            int width = (BPF_SIZE(f->code) == BPF_W) ? 4 : (BPF_SIZE(f->code) == BPF_H) ? 2 : 1;
            uint16_t mode = BPF_MODE(f->code);
            uint32_t off;
            uint32_t v;

            if (mode == BPF_ABS) {
                off = f->k;
            } else if (mode == BPF_IND) {
                off = f->k + x;
            } else if (mode == BPF_MSH) {
                /* only meaningful as LDX|B|MSH: X = (pkt[k] & 0x0f) * 4 */
                if (load_u(pkt, pkt_len, f->k, 1, &v) != 0) {
                    return 0;
                }
                x = (v & 0x0f) * 4;
                pc++;
                continue;
            } else {
                return 0; /* opcode our codegen never emits */
            }

            if (load_u(pkt, pkt_len, off, width, &v) != 0) {
                return 0;
            }
            if (cls == BPF_LD) {
                a = v;
            } else {
                x = v;
            }
            pc++;
            continue;
        }

        if (cls == BPF_ALU) {
            if (BPF_OP(f->code) == BPF_AND) {
                a &= f->k; /* only BPF_K source is generated */
            }
            pc++;
            continue;
        }

        if (cls == BPF_JMP) {
            int taken;
            if (BPF_OP(f->code) == BPF_JEQ) {
                taken = (a == f->k);
            } else {
                return 0; /* opcode our codegen never emits */
            }
            pc += 1 + (taken ? f->jt : f->jf);
            continue;
        }

        if (cls == BPF_RET) {
            return f->k;
        }

        return 0; /* opcode our codegen never emits */
    }

    return 0; /* fell off the end without a RET -- shouldn't happen for our codegen */
}
