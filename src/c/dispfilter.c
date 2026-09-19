#include "dispfilter.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DF_MAX_TOKENS 256
#define DF_MAX_NODES 256

/* ============================== Lexer ================================ */

typedef enum {
    TOK_END,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_AND,
    TOK_OR,
    TOK_NOT,
    TOK_EQ,
    TOK_NE,
    TOK_FIELD,
    TOK_NUMBER,
    TOK_IPV4,
    TOK_IPV6,
    TOK_MAC,
} token_type_t;

typedef enum {
    FIELD_ETH_SRC,
    FIELD_ETH_DST,
    FIELD_ETH_ADDR,
    FIELD_IP_SRC,
    FIELD_IP_DST,
    FIELD_IP_ADDR,
    FIELD_IPV6_SRC,
    FIELD_IPV6_DST,
    FIELD_IPV6_ADDR,
    FIELD_TCP_SRCPORT,
    FIELD_TCP_DSTPORT,
    FIELD_TCP_PORT,
    FIELD_UDP_SRCPORT,
    FIELD_UDP_DSTPORT,
    FIELD_UDP_PORT,
} df_field_t;

typedef struct {
    token_type_t type;
    df_field_t field; /* TOK_FIELD */
    uint32_t num;     /* TOK_NUMBER */
    uint8_t ipv4[4];  /* TOK_IPV4 */
    uint8_t ipv6[16]; /* TOK_IPV6 */
    uint8_t mac[6];   /* TOK_MAC */
} token_t;

typedef struct {
    token_t toks[DF_MAX_TOKENS];
    int n_toks;
    int pos;

    char* err;
    int err_len;
    int failed;
} df_ctx_t;

static void df_fail(df_ctx_t* c, const char* msg) {
    if (c->failed) {
        return;
    }
    c->failed = 1;
    if (c->err != NULL && c->err_len > 0) {
        snprintf(c->err, (size_t)c->err_len, "%s", msg);
    }
}

static void df_failf(df_ctx_t* c, const char* fmt, const char* arg) {
    if (c->failed) {
        return;
    }
    c->failed = 1;
    if (c->err != NULL && c->err_len > 0) {
        snprintf(c->err, (size_t)c->err_len, fmt, arg);
    }
}

static const struct {
    const char* word;
    token_type_t type;
    df_field_t field;
} KEYWORDS[] = {
    {"and", TOK_AND, 0},
    {"or", TOK_OR, 0},
    {"not", TOK_NOT, 0},
    {"eth.src", TOK_FIELD, FIELD_ETH_SRC},
    {"eth.dst", TOK_FIELD, FIELD_ETH_DST},
    {"eth.addr", TOK_FIELD, FIELD_ETH_ADDR},
    {"ip.src", TOK_FIELD, FIELD_IP_SRC},
    {"ip.dst", TOK_FIELD, FIELD_IP_DST},
    {"ip.addr", TOK_FIELD, FIELD_IP_ADDR},
    {"ipv6.src", TOK_FIELD, FIELD_IPV6_SRC},
    {"ipv6.dst", TOK_FIELD, FIELD_IPV6_DST},
    {"ipv6.addr", TOK_FIELD, FIELD_IPV6_ADDR},
    {"tcp.srcport", TOK_FIELD, FIELD_TCP_SRCPORT},
    {"tcp.dstport", TOK_FIELD, FIELD_TCP_DSTPORT},
    {"tcp.port", TOK_FIELD, FIELD_TCP_PORT},
    {"udp.srcport", TOK_FIELD, FIELD_UDP_SRCPORT},
    {"udp.dstport", TOK_FIELD, FIELD_UDP_DSTPORT},
    {"udp.port", TOK_FIELD, FIELD_UDP_PORT},
};
#define N_KEYWORDS (int)(sizeof(KEYWORDS) / sizeof(KEYWORDS[0]))

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Parses "d.d.d.d" from word[0..len). Each octet must be 0..255. Returns 0/-1. */
static int parse_ipv4_word(const char* word, int len, uint8_t out[4]) {
    int octet = 0;
    long value = -1;
    int digits = 0;

    for (int i = 0; i <= len; i++) {
        char ch = (i < len) ? word[i] : '.'; /* a virtual trailing dot simplifies the loop */
        if (ch == '.') {
            if (digits == 0 || value > 255 || octet > 3) {
                return -1;
            }
            out[octet++] = (uint8_t)value;
            value = -1;
            digits = 0;
        } else if (ch >= '0' && ch <= '9') {
            value = (value < 0 ? 0 : value) * 10 + (ch - '0');
            digits++;
            if (value > 255) {
                return -1;
            }
        } else {
            return -1;
        }
    }
    return (octet == 4) ? 0 : -1;
}

/* "xx:xx:xx:xx:xx:xx" - always exactly 17 characters, two hex digits per
   octet, no "::" shorthand (unlike IPv6, MAC addresses don't have one). */
static int parse_mac_word(const char* word, int len, uint8_t out[6]) {
    if (len != 17) {
        return -1;
    }
    for (int g = 0; g < 6; g++) {
        int base = g * 3;
        int hi = hex_nibble(word[base]);
        int lo = hex_nibble(word[base + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[g] = (uint8_t)((hi << 4) | lo);
        if (g < 5 && word[base + 2] != ':') {
            return -1;
        }
    }
    return 0;
}

/* Splits s[0..len) on single colons into up to 'max_groups' 1-4 hex-digit
   hextets. Used on each side of an IPv6 literal's "::" (if any) - or the
   whole literal, if it has none. An empty side (len==0) is valid and
   contributes zero groups (that's what "::1" and "fe80::" rely on). */
static int parse_hextet_list(const char* s, int len, uint16_t* out, int* out_n, int max_groups) {
    *out_n = 0;
    if (len == 0) {
        return 0;
    }
    int i = 0;
    while (i < len) {
        int start = i;
        while (i < len && s[i] != ':') {
            i++;
        }
        int glen = i - start;
        if (glen == 0 || glen > 4) {
            return -1;
        }
        uint16_t val = 0;
        for (int j = 0; j < glen; j++) {
            int nib = hex_nibble(s[start + j]);
            if (nib < 0) {
                return -1;
            }
            val = (uint16_t)((val << 4) | (uint16_t)nib);
        }
        if (*out_n >= max_groups) {
            return -1;
        }
        out[(*out_n)++] = val;
        if (i < len) {
            i++; /* skip the single ':' between groups */
            if (i >= len) {
                return -1; /* trailing lone ':' with nothing after it */
            }
        }
    }
    return 0;
}

/* Parses a (possibly "::"-compressed) IPv6 literal, RFC 4291 SS2.2 style. */
static int parse_ipv6_word(const char* word, int len, uint8_t out[16]) {
    const char* dbl = NULL;
    for (int i = 0; i + 1 < len; i++) {
        if (word[i] == ':' && word[i + 1] == ':') {
            dbl = word + i;
            break;
        }
    }

    uint16_t left[8];
    int n_left = 0;
    uint16_t right[8];
    int n_right = 0;

    int left_len = dbl ? (int)(dbl - word) : len;
    if (parse_hextet_list(word, left_len, left, &n_left, 8) != 0) {
        return -1;
    }

    if (dbl != NULL) {
        const char* right_part = dbl + 2;
        int right_len = len - (int)(right_part - word);
        if (parse_hextet_list(right_part, right_len, right, &n_right, 8) != 0) {
            return -1;
        }
    }

    int total = n_left + n_right;
    if (dbl != NULL) {
        if (total > 7) {
            return -1; /* "::" must stand in for at least one zero group */
        }
    } else if (total != 8) {
        return -1;
    }

    int n_zero = 8 - total;
    int idx = 0;
    for (int i = 0; i < n_left; i++) {
        out[idx * 2] = (uint8_t)(left[i] >> 8);
        out[idx * 2 + 1] = (uint8_t)(left[i] & 0xFF);
        idx++;
    }
    for (int i = 0; i < n_zero; i++) {
        out[idx * 2] = 0;
        out[idx * 2 + 1] = 0;
        idx++;
    }
    for (int i = 0; i < n_right; i++) {
        out[idx * 2] = (uint8_t)(right[i] >> 8);
        out[idx * 2 + 1] = (uint8_t)(right[i] & 0xFF);
        idx++;
    }
    return 0;
}

static void df_lex(df_ctx_t* c, const char* expr) {
    int i = 0;
    while (expr[i] != '\0') {
        char ch = expr[i];
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') {
            i++;
            continue;
        }
        if (c->n_toks >= DF_MAX_TOKENS) {
            df_fail(c, "filter expression has too many tokens");
            return;
        }

        token_t* tok = &c->toks[c->n_toks];
        memset(tok, 0, sizeof(*tok));

        if (ch == '(') {
            tok->type = TOK_LPAREN;
            i++;
            c->n_toks++;
            continue;
        }
        if (ch == ')') {
            tok->type = TOK_RPAREN;
            i++;
            c->n_toks++;
            continue;
        }
        if (ch == '&' && expr[i + 1] == '&') {
            tok->type = TOK_AND;
            i += 2;
            c->n_toks++;
            continue;
        }
        if (ch == '|' && expr[i + 1] == '|') {
            tok->type = TOK_OR;
            i += 2;
            c->n_toks++;
            continue;
        }
        if (ch == '=' && expr[i + 1] == '=') {
            tok->type = TOK_EQ;
            i += 2;
            c->n_toks++;
            continue;
        }
        if (ch == '!' && expr[i + 1] == '=') {
            tok->type = TOK_NE;
            i += 2;
            c->n_toks++;
            continue;
        }
        if (ch == '!') {
            tok->type = TOK_NOT;
            i++;
            c->n_toks++;
            continue;
        }

        if (isalnum((unsigned char)ch) || ch == '_' || ch == '.' || ch == ':') {
            int start = i;
            while (expr[i] != '\0' && (isalnum((unsigned char)expr[i]) || expr[i] == '_' ||
                                       expr[i] == '.' || expr[i] == ':')) {
                i++;
            }
            int len = i - start;
            const char* word = expr + start;

            int has_colon = 0;
            for (int j = 0; j < len; j++) {
                if (word[j] == ':') {
                    has_colon = 1;
                    break;
                }
            }

            if (has_colon) {
                uint8_t mac[6];
                uint8_t ipv6[16];
                if (parse_mac_word(word, len, mac) == 0) {
                    tok->type = TOK_MAC;
                    memcpy(tok->mac, mac, 6);
                } else if (parse_ipv6_word(word, len, ipv6) == 0) {
                    tok->type = TOK_IPV6;
                    memcpy(tok->ipv6, ipv6, 16);
                } else {
                    df_fail(c, "invalid MAC or IPv6 literal");
                    return;
                }
                c->n_toks++;
                continue;
            }

            if (word[0] >= '0' && word[0] <= '9') {
                uint8_t addr[4];
                if (parse_ipv4_word(word, len, addr) == 0) {
                    tok->type = TOK_IPV4;
                    memcpy(tok->ipv4, addr, 4);
                } else {
                    int all_digits = 1;
                    for (int j = 0; j < len; j++) {
                        if (word[j] < '0' || word[j] > '9') {
                            all_digits = 0;
                            break;
                        }
                    }
                    if (!all_digits) {
                        df_fail(c, "invalid number or IPv4 address");
                        return;
                    }
                    unsigned long v = strtoul(word, NULL, 10);
                    if (v > 0xFFFFFFFFu) {
                        df_fail(c, "number out of range");
                        return;
                    }
                    tok->type = TOK_NUMBER;
                    tok->num = (uint32_t)v;
                }
                c->n_toks++;
                continue;
            }

            /* Starts with a letter: a field name or 'and'/'or'/'not'. */
            int matched = 0;
            for (int k = 0; k < N_KEYWORDS; k++) {
                size_t klen = strlen(KEYWORDS[k].word);
                if ((int)klen == len && strncmp(word, KEYWORDS[k].word, klen) == 0) {
                    tok->type = KEYWORDS[k].type;
                    tok->field = KEYWORDS[k].field;
                    matched = 1;
                    break;
                }
            }
            if (!matched) {
                char buf[64];
                int blen = len < (int)sizeof(buf) - 1 ? len : (int)sizeof(buf) - 1;
                memcpy(buf, word, (size_t)blen);
                buf[blen] = '\0';
                df_failf(c, "unknown field or keyword '%s'", buf);
                return;
            }
            c->n_toks++;
            continue;
        }

        df_fail(c, "unexpected character in filter expression");
        return;
    }

    c->toks[c->n_toks].type = TOK_END;
    c->n_toks++;
}

/* ============================== AST ================================== */

typedef enum {
    N_AND,
    N_OR,
    N_NOT,
    N_CMP,
} df_node_kind_t;

typedef enum {
    CMP_EQ,
    CMP_NE,
} df_cmp_t;

struct df_node {
    df_node_kind_t kind;
    struct df_node* left;
    struct df_node* right;

    /* N_CMP only: */
    df_field_t field;
    df_cmp_t cmp;
    union {
        uint16_t port;
        uint8_t ipv4[4];
        uint8_t ipv6[16];
        uint8_t mac[6];
    } value;
};

typedef struct df_node df_node_t;

/* The AST *is* the runtime representation here (there's no separate
   codegen pass like capfilter.c's BPF backend), so nodes live in the
   dispfilter_t itself and must survive past dispfilter_compile() -
   hence a heap-allocated array rather than a stack-scoped one. */
struct dispfilter {
    df_node_t* nodes;
    int node_count;
    df_node_t* root; /* NULL means "match everything" */
};

typedef struct {
    df_node_t* pool;
    int count;
    int cap;
} node_arena_t;

static df_node_t* mk_node(df_ctx_t* c, node_arena_t* a, df_node_kind_t kind) {
    if (c->failed) {
        return NULL;
    }
    if (a->count >= a->cap) {
        df_fail(c, "filter expression is too complex");
        return NULL;
    }
    df_node_t* n = &a->pool[a->count++];
    memset(n, 0, sizeof(*n));
    n->kind = kind;
    return n;
}

/* ============================= Parser ================================= */

typedef struct {
    df_ctx_t* c;
    node_arena_t* arena;
} parser_t;

static token_t* p_peek(parser_t* p) {
    return &p->c->toks[p->c->pos];
}
static token_t* p_advance(parser_t* p) {
    token_t* t = p_peek(p);
    if (t->type != TOK_END)
        p->c->pos++;
    return t;
}

static df_node_t* parse_expr(parser_t* p);

static df_node_t* parse_primitive(parser_t* p) {
    df_ctx_t* c = p->c;

    token_t* field_tok = p_advance(p);
    if (field_tok->type != TOK_FIELD) {
        df_fail(c, "expected a field name (e.g. tcp.port, ip.src)");
        return NULL;
    }
    df_field_t field = field_tok->field;

    token_t* op_tok = p_advance(p);
    df_cmp_t cmp;
    if (op_tok->type == TOK_EQ) {
        cmp = CMP_EQ;
    } else if (op_tok->type == TOK_NE) {
        cmp = CMP_NE;
    } else {
        df_fail(c, "expected '==' or '!=' after field name");
        return NULL;
    }

    token_t* val_tok = p_advance(p);

    df_node_t* n = mk_node(c, p->arena, N_CMP);
    if (n == NULL) {
        return NULL;
    }
    n->field = field;
    n->cmp = cmp;

    switch (field) {
        case FIELD_ETH_SRC:
        case FIELD_ETH_DST:
        case FIELD_ETH_ADDR:
            if (val_tok->type != TOK_MAC) {
                df_fail(c, "expected a MAC address (aa:bb:cc:dd:ee:ff)");
                return NULL;
            }
            memcpy(n->value.mac, val_tok->mac, 6);
            break;

        case FIELD_IP_SRC:
        case FIELD_IP_DST:
        case FIELD_IP_ADDR:
            if (val_tok->type != TOK_IPV4) {
                df_fail(c, "expected an IPv4 address");
                return NULL;
            }
            memcpy(n->value.ipv4, val_tok->ipv4, 4);
            break;

        case FIELD_IPV6_SRC:
        case FIELD_IPV6_DST:
        case FIELD_IPV6_ADDR:
            if (val_tok->type != TOK_IPV6) {
                df_fail(c, "expected an IPv6 address");
                return NULL;
            }
            memcpy(n->value.ipv6, val_tok->ipv6, 16);
            break;

        case FIELD_TCP_SRCPORT:
        case FIELD_TCP_DSTPORT:
        case FIELD_TCP_PORT:
        case FIELD_UDP_SRCPORT:
        case FIELD_UDP_DSTPORT:
        case FIELD_UDP_PORT:
            if (val_tok->type != TOK_NUMBER || val_tok->num > 65535u) {
                df_fail(c, "expected a port number (0-65535)");
                return NULL;
            }
            n->value.port = (uint16_t)val_tok->num;
            break;
    }

    return n;
}

static df_node_t* parse_not(parser_t* p) {
    if (p_peek(p)->type == TOK_NOT) {
        p_advance(p);
        df_node_t* operand = parse_not(p);
        df_node_t* n = mk_node(p->c, p->arena, N_NOT);
        if (n == NULL)
            return NULL;
        n->left = operand;
        return n;
    }
    if (p_peek(p)->type == TOK_LPAREN) {
        p_advance(p);
        df_node_t* inner = parse_expr(p);
        if (p_advance(p)->type != TOK_RPAREN) {
            df_fail(p->c, "expected ')'");
            return NULL;
        }
        return inner;
    }
    return parse_primitive(p);
}

static df_node_t* parse_and(parser_t* p) {
    df_node_t* left = parse_not(p);
    while (p_peek(p)->type == TOK_AND) {
        p_advance(p);
        df_node_t* right = parse_not(p);
        df_node_t* n = mk_node(p->c, p->arena, N_AND);
        if (n == NULL)
            return NULL;
        n->left = left;
        n->right = right;
        left = n;
    }
    return left;
}

static df_node_t* parse_expr(parser_t* p) {
    df_node_t* left = parse_and(p);
    while (p_peek(p)->type == TOK_OR) {
        p_advance(p);
        df_node_t* right = parse_and(p);
        df_node_t* n = mk_node(p->c, p->arena, N_OR);
        if (n == NULL)
            return NULL;
        n->left = left;
        n->right = right;
        left = n;
    }
    return left;
}

/* ============================= Evaluator =============================== */

static int bytes_eq(const uint8_t* a, const uint8_t* b, size_t n) {
    return memcmp(a, b, n) == 0;
}

static int eval_cmp(const df_node_t* n, const dispfilter_fields_t* f) {
    int eq;
    switch (n->field) {
        case FIELD_ETH_SRC:
            eq = bytes_eq(f->eth_src, n->value.mac, 6);
            break;
        case FIELD_ETH_DST:
            eq = bytes_eq(f->eth_dst, n->value.mac, 6);
            break;
        case FIELD_ETH_ADDR:
            eq = bytes_eq(f->eth_src, n->value.mac, 6) || bytes_eq(f->eth_dst, n->value.mac, 6);
            break;

        case FIELD_IP_SRC:
            eq = f->has_ip && bytes_eq(f->ip_src, n->value.ipv4, 4);
            break;
        case FIELD_IP_DST:
            eq = f->has_ip && bytes_eq(f->ip_dst, n->value.ipv4, 4);
            break;
        case FIELD_IP_ADDR:
            eq = f->has_ip &&
                 (bytes_eq(f->ip_src, n->value.ipv4, 4) || bytes_eq(f->ip_dst, n->value.ipv4, 4));
            break;

        case FIELD_IPV6_SRC:
            eq = f->has_ipv6 && bytes_eq(f->ipv6_src, n->value.ipv6, 16);
            break;
        case FIELD_IPV6_DST:
            eq = f->has_ipv6 && bytes_eq(f->ipv6_dst, n->value.ipv6, 16);
            break;
        case FIELD_IPV6_ADDR:
            eq = f->has_ipv6 && (bytes_eq(f->ipv6_src, n->value.ipv6, 16) ||
                                 bytes_eq(f->ipv6_dst, n->value.ipv6, 16));
            break;

        case FIELD_TCP_SRCPORT:
            eq = f->has_tcp && f->tcp_src_port == n->value.port;
            break;
        case FIELD_TCP_DSTPORT:
            eq = f->has_tcp && f->tcp_dst_port == n->value.port;
            break;
        case FIELD_TCP_PORT:
            eq = f->has_tcp &&
                 (f->tcp_src_port == n->value.port || f->tcp_dst_port == n->value.port);
            break;

        case FIELD_UDP_SRCPORT:
            eq = f->has_udp && f->udp_src_port == n->value.port;
            break;
        case FIELD_UDP_DSTPORT:
            eq = f->has_udp && f->udp_dst_port == n->value.port;
            break;
        case FIELD_UDP_PORT:
            eq = f->has_udp &&
                 (f->udp_src_port == n->value.port || f->udp_dst_port == n->value.port);
            break;

        default:
            eq = 0;
            break;
    }
    return n->cmp == CMP_EQ ? eq : !eq;
}

static int eval_node(const df_node_t* n, const dispfilter_fields_t* f) {
    switch (n->kind) {
        case N_AND:
            return eval_node(n->left, f) && eval_node(n->right, f);
        case N_OR:
            return eval_node(n->left, f) || eval_node(n->right, f);
        case N_NOT:
            return !eval_node(n->left, f);
        case N_CMP:
            return eval_cmp(n, f);
    }
    return 0;
}

/* ============================= Public API ============================== */

dispfilter_t* dispfilter_compile(const char* expr, char* err, int err_len) {
    dispfilter_t* filter = malloc(sizeof(dispfilter_t));
    if (filter == NULL) {
        if (err != NULL && err_len > 0) {
            snprintf(err, (size_t)err_len, "out of memory compiling filter");
        }
        return NULL;
    }
    filter->nodes = malloc(sizeof(df_node_t) * DF_MAX_NODES);
    if (filter->nodes == NULL) {
        free(filter);
        if (err != NULL && err_len > 0) {
            snprintf(err, (size_t)err_len, "out of memory compiling filter");
        }
        return NULL;
    }
    filter->node_count = 0;
    filter->root = NULL;

    if (expr == NULL || expr[0] == '\0') {
        return filter; /* root == NULL -> "match everything" */
    }

    df_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.err = err;
    ctx.err_len = err_len;

    df_lex(&ctx, expr);
    if (ctx.failed) {
        dispfilter_free(filter);
        return NULL;
    }

    node_arena_t arena;
    arena.pool = filter->nodes;
    arena.count = 0;
    arena.cap = DF_MAX_NODES;
    parser_t parser = {&ctx, &arena};

    df_node_t* root = parse_expr(&parser);
    if (!ctx.failed && p_peek(&parser)->type != TOK_END) {
        df_fail(&ctx, "unexpected trailing tokens in filter expression");
    }
    if (ctx.failed) {
        dispfilter_free(filter);
        return NULL;
    }

    filter->root = root;
    filter->node_count = arena.count;
    return filter;
}

void dispfilter_free(dispfilter_t* filter) {
    if (filter == NULL) {
        return;
    }
    free(filter->nodes);
    free(filter);
}

int dispfilter_matches(const dispfilter_t* filter, const dispfilter_fields_t* fields) {
    if (filter == NULL || filter->root == NULL) {
        return 1;
    }
    return eval_node(filter->root, fields);
}
