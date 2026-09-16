#include "capfilter.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CF_MAX_TOKENS 256 /* максимум токенов в одном выражении */
#define CF_MAX_NODES  256 /* максимум узлов AST (включая синтетические, см. ниже) */
#define CF_MAX_INSNS  1024 /* максимум инструкций в итоговом байт-коде */

/* Смещения полей относительно начала Ethernet-кадра (см. eth_parser.h /
   ip_parser.h) — фильтр работает на сыром кадре, поэтому дублирует эти
   константы, а не подключает парсеры (они разные слои: один готовит
   входные данные для программы, другой — программу для ядра). */
#define OFF_ETHERTYPE   12
#define OFF_IP_IHL_BYTE 14 /* первый байт IP-заголовка: version(4)|ihl(4) */
#define OFF_IP_PROTO    23 /* 14 + 9: позиция протокола фиксирована независимо от IHL */
#define OFF_IP_SRC      26 /* 14 + 12 */
#define OFF_IP_DST      30 /* 14 + 16 */

#define ETHERTYPE_IPV4 0x0800u
#define ETHERTYPE_IPV6 0x86DDu
#define ETHERTYPE_ARP  0x0806u

#define IPPROTO_ICMP_ 1u
#define IPPROTO_TCP_  6u
#define IPPROTO_UDP_  17u

/* ============================== Lexer ================================ */

typedef enum {
    TOK_END,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_SLASH,
    TOK_AND,
    TOK_OR,
    TOK_NOT,
    TOK_SRC,
    TOK_DST,
    TOK_HOST,
    TOK_PORT,
    TOK_NET,
    TOK_PROTO_TCP,
    TOK_PROTO_UDP,
    TOK_PROTO_ICMP,
    TOK_PROTO_IP,
    TOK_PROTO_IP6,
    TOK_PROTO_ARP,
    TOK_NUMBER,
    TOK_IPV4,
} token_type_t;

typedef struct {
    token_type_t type;
    uint32_t num;      /* TOK_NUMBER */
    uint8_t addr[4];   /* TOK_IPV4 */
} token_t;

typedef struct {
    token_t toks[CF_MAX_TOKENS];
    int n_toks;
    int pos;

    char* err;
    int err_len;
    int failed; /* 1 после первой ошибки — все стадии молча сдаются */
} cf_ctx_t;

static void cf_fail(cf_ctx_t* c, const char* msg) {
    if (c->failed) {
        return; /* первая ошибка важнее — не затираем её более поздней */
    }
    c->failed = 1;
    if (c->err != NULL && c->err_len > 0) {
        snprintf(c->err, (size_t)c->err_len, "%s", msg);
    }
}

static void cf_failf(cf_ctx_t* c, const char* fmt, const char* arg) {
    if (c->failed) {
        return;
    }
    c->failed = 1;
    if (c->err != NULL && c->err_len > 0) {
        snprintf(c->err, (size_t)c->err_len, fmt, arg);
    }
}

/* keyword table для лексера — линейный поиск, таблица короткая */
static const struct { const char* word; token_type_t type; } KEYWORDS[] = {
    { "and", TOK_AND }, { "or", TOK_OR }, { "not", TOK_NOT },
    { "src", TOK_SRC }, { "dst", TOK_DST },
    { "host", TOK_HOST }, { "port", TOK_PORT }, { "net", TOK_NET },
    { "tcp", TOK_PROTO_TCP }, { "udp", TOK_PROTO_UDP }, { "icmp", TOK_PROTO_ICMP },
    { "ip", TOK_PROTO_IP }, { "ip6", TOK_PROTO_IP6 }, { "arp", TOK_PROTO_ARP },
};
#define N_KEYWORDS (int)(sizeof(KEYWORDS) / sizeof(KEYWORDS[0]))

/* Парсит "d.d.d.d" из word[0..len). Каждый октет 0..255. Возвращает 0/-1. */
static int parse_ipv4_word(const char* word, int len, uint8_t out[4]) {
    int octet = 0;
    long value = -1;
    int digits = 0;

    for (int i = 0; i <= len; i++) {
        char ch = (i < len) ? word[i] : '.'; /* виртуальная точка в конце упрощает цикл */
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
                return -1; /* короткое замыкание — не ждать конца слова */
            }
        } else {
            return -1;
        }
    }
    return (octet == 4) ? 0 : -1;
}

static void cf_lex(cf_ctx_t* c, const char* expr) {
    int i = 0;
    while (expr[i] != '\0') {
        char ch = expr[i];
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') {
            i++;
            continue;
        }
        if (c->n_toks >= CF_MAX_TOKENS) {
            cf_fail(c, "filter expression has too many tokens");
            return;
        }

        token_t* tok = &c->toks[c->n_toks];

        if (ch == '(') { tok->type = TOK_LPAREN; i++; c->n_toks++; continue; }
        if (ch == ')') { tok->type = TOK_RPAREN; i++; c->n_toks++; continue; }
        if (ch == '/') { tok->type = TOK_SLASH; i++; c->n_toks++; continue; }
        if (ch == '!') { tok->type = TOK_NOT; i++; c->n_toks++; continue; }
        if (ch == '&' && expr[i + 1] == '&') { tok->type = TOK_AND; i += 2; c->n_toks++; continue; }
        if (ch == '|' && expr[i + 1] == '|') { tok->type = TOK_OR; i += 2; c->n_toks++; continue; }

        if ((ch >= '0' && ch <= '9')) {
            int start = i;
            while ((expr[i] >= '0' && expr[i] <= '9') || expr[i] == '.') {
                i++;
            }
            int len = i - start;
            uint8_t addr[4];
            if (parse_ipv4_word(expr + start, len, addr) == 0) {
                tok->type = TOK_IPV4;
                memcpy(tok->addr, addr, 4);
            } else {
                /* pure number? re-scan without dots allowed */
                int all_digits = 1;
                for (int j = start; j < i; j++) {
                    if (expr[j] == '.') { all_digits = 0; break; }
                }
                if (!all_digits) {
                    cf_fail(c, "invalid IPv4 address");
                    return;
                }
                unsigned long v = strtoul(expr + start, NULL, 10);
                if (v > 0xFFFFFFFFu) {
                    cf_fail(c, "number out of range");
                    return;
                }
                tok->type = TOK_NUMBER;
                tok->num = (uint32_t)v;
            }
            c->n_toks++;
            continue;
        }

        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
            int start = i;
            while ((expr[i] >= 'a' && expr[i] <= 'z') || (expr[i] >= 'A' && expr[i] <= 'Z')
                || (expr[i] >= '0' && expr[i] <= '9') || expr[i] == '_') {
                i++;
            }
            int len = i - start;
            int matched = 0;
            for (int k = 0; k < N_KEYWORDS; k++) {
                size_t klen = strlen(KEYWORDS[k].word);
                if ((int)klen == len && strncmp(expr + start, KEYWORDS[k].word, klen) == 0) {
                    tok->type = KEYWORDS[k].type;
                    matched = 1;
                    break;
                }
            }
            if (!matched) {
                char word[64];
                int wlen = len < (int)sizeof(word) - 1 ? len : (int)sizeof(word) - 1;
                memcpy(word, expr + start, (size_t)wlen);
                word[wlen] = '\0';
                cf_failf(c, "unknown keyword '%s'", word);
                return;
            }
            c->n_toks++;
            continue;
        }

        cf_fail(c, "unexpected character in filter expression");
        return;
    }

    c->toks[c->n_toks].type = TOK_END;
    c->n_toks++;
}

/* ============================== AST ================================== */

typedef enum {
    N_AND, N_OR, N_NOT,
    N_ETHERTYPE, /* offset 12, 16-bit compare */
    N_IPPROTO,   /* offset 23, 8-bit compare (только имеет смысл под ethertype==IPv4) */
    N_HOST,      /* offset 26/30, 32-bit compare */
    N_PORT,      /* MSH+IND load, 16-bit compare */
    N_NET,       /* offset 26/30, masked 32-bit compare */
} node_kind_t;

typedef enum { DIR_SRC, DIR_DST } dir_t;

typedef struct node {
    node_kind_t kind;
    struct node* left;
    struct node* right;
    uint32_t k;        /* ethertype / ip proto / port number */
    dir_t dir;          /* HOST / PORT / NET */
    uint8_t addr[4];     /* HOST / NET */
    uint8_t prefix_len;   /* NET, 0..32 */
} node_t;

typedef struct {
    node_t pool[CF_MAX_NODES];
    int count;
} node_arena_t;

static node_t* mk_node(cf_ctx_t* c, node_arena_t* arena, node_kind_t kind) {
    if (c->failed) {
        return NULL;
    }
    if (arena->count >= CF_MAX_NODES) {
        cf_fail(c, "filter expression is too complex");
        return NULL;
    }
    node_t* n = &arena->pool[arena->count++];
    memset(n, 0, sizeof(*n));
    n->kind = kind;
    return n;
}

static node_t* mk_and(cf_ctx_t* c, node_arena_t* a, node_t* l, node_t* r) {
    node_t* n = mk_node(c, a, N_AND);
    if (n == NULL) return NULL;
    n->left = l; n->right = r;
    return n;
}

static node_t* mk_or(cf_ctx_t* c, node_arena_t* a, node_t* l, node_t* r) {
    node_t* n = mk_node(c, a, N_OR);
    if (n == NULL) return NULL;
    n->left = l; n->right = r;
    return n;
}

static node_t* mk_ethertype(cf_ctx_t* c, node_arena_t* a, uint32_t ethertype) {
    node_t* n = mk_node(c, a, N_ETHERTYPE);
    if (n == NULL) return NULL;
    n->k = ethertype;
    return n;
}

static node_t* mk_ipproto(cf_ctx_t* c, node_arena_t* a, uint32_t proto) {
    node_t* n = mk_node(c, a, N_IPPROTO);
    if (n == NULL) return NULL;
    n->k = proto;
    return n;
}

static node_t* mk_host(cf_ctx_t* c, node_arena_t* a, dir_t dir, const uint8_t addr[4]) {
    node_t* n = mk_node(c, a, N_HOST);
    if (n == NULL) return NULL;
    n->dir = dir;
    memcpy(n->addr, addr, 4);
    return n;
}

static node_t* mk_port(cf_ctx_t* c, node_arena_t* a, dir_t dir, uint32_t port) {
    node_t* n = mk_node(c, a, N_PORT);
    if (n == NULL) return NULL;
    n->dir = dir;
    n->k = port;
    return n;
}

static node_t* mk_net(cf_ctx_t* c, node_arena_t* a, dir_t dir, const uint8_t addr[4], uint8_t prefix_len) {
    node_t* n = mk_node(c, a, N_NET);
    if (n == NULL) return NULL;
    n->dir = dir;
    memcpy(n->addr, addr, 4);
    n->prefix_len = prefix_len;
    return n;
}

/* "tcp"/"udp"/"icmp" require IPv4 first (ip_proto byte only means something
   under an IPv4 header) — matches how this project's own parsers dispatch
   L4 only from IPv4 (see ip_parser.c / tcp_udp_parser.h), so the filter's
   idea of "tcp" and the analyzer's idea of "tcp" stay in sync. */
static node_t* mk_l4_proto(cf_ctx_t* c, node_arena_t* a, uint32_t ip_proto) {
    return mk_and(c, a, mk_ethertype(c, a, ETHERTYPE_IPV4), mk_ipproto(c, a, ip_proto));
}

/* ============================= Parser ================================= */

typedef struct {
    cf_ctx_t* c;
    node_arena_t* arena;
} parser_t;

static token_t* p_peek(parser_t* p) { return &p->c->toks[p->c->pos]; }
static token_t* p_advance(parser_t* p) { token_t* t = p_peek(p); if (t->type != TOK_END) p->c->pos++; return t; }

static node_t* parse_expr(parser_t* p);

/* [ 'src' | 'dst' ] 'host' A.B.C.D | [ 'src' | 'dst' ] 'port' N
   | [ 'src' | 'dst' ] 'net' A.B.C.D '/' N | proto-keyword */
static node_t* parse_primitive(parser_t* p) {
    cf_ctx_t* c = p->c;
    node_arena_t* a = p->arena;

    int has_dir = 0;
    dir_t dir = DIR_SRC;
    if (p_peek(p)->type == TOK_SRC) { has_dir = 1; dir = DIR_SRC; p_advance(p); }
    else if (p_peek(p)->type == TOK_DST) { has_dir = 1; dir = DIR_DST; p_advance(p); }

    token_t* t = p_peek(p);

    if (has_dir) {
        if (t->type != TOK_HOST && t->type != TOK_PORT && t->type != TOK_NET) {
            cf_fail(c, "expected 'host', 'port' or 'net' after 'src'/'dst'");
            return NULL;
        }
    }

    switch (t->type) {
    case TOK_PROTO_TCP:  p_advance(p); return mk_l4_proto(c, a, IPPROTO_TCP_);
    case TOK_PROTO_UDP:  p_advance(p); return mk_l4_proto(c, a, IPPROTO_UDP_);
    case TOK_PROTO_ICMP: p_advance(p); return mk_l4_proto(c, a, IPPROTO_ICMP_);
    case TOK_PROTO_IP:   p_advance(p); return mk_ethertype(c, a, ETHERTYPE_IPV4);
    case TOK_PROTO_IP6:  p_advance(p); return mk_ethertype(c, a, ETHERTYPE_IPV6);
    case TOK_PROTO_ARP:  p_advance(p); return mk_ethertype(c, a, ETHERTYPE_ARP);

    case TOK_HOST: {
        p_advance(p);
        token_t* addr_tok = p_advance(p);
        if (addr_tok->type != TOK_IPV4) {
            cf_fail(c, "expected an IPv4 address after 'host'");
            return NULL;
        }
        node_t* ip = mk_ethertype(c, a, ETHERTYPE_IPV4);
        node_t* host = has_dir
            ? mk_host(c, a, dir, addr_tok->addr)
            : mk_or(c, a, mk_host(c, a, DIR_SRC, addr_tok->addr), mk_host(c, a, DIR_DST, addr_tok->addr));
        return mk_and(c, a, ip, host);
    }

    case TOK_PORT: {
        p_advance(p);
        token_t* num_tok = p_advance(p);
        if (num_tok->type != TOK_NUMBER || num_tok->num > 65535u) {
            cf_fail(c, "expected a port number (0-65535) after 'port'");
            return NULL;
        }
        node_t* ip = mk_ethertype(c, a, ETHERTYPE_IPV4);
        node_t* is_tcp_or_udp = mk_or(c, a, mk_ipproto(c, a, IPPROTO_TCP_), mk_ipproto(c, a, IPPROTO_UDP_));
        node_t* port = has_dir
            ? mk_port(c, a, dir, num_tok->num)
            : mk_or(c, a, mk_port(c, a, DIR_SRC, num_tok->num), mk_port(c, a, DIR_DST, num_tok->num));
        return mk_and(c, a, ip, mk_and(c, a, is_tcp_or_udp, port));
    }

    case TOK_NET: {
        p_advance(p);
        token_t* addr_tok = p_advance(p);
        if (addr_tok->type != TOK_IPV4) {
            cf_fail(c, "expected an IPv4 network address after 'net'");
            return NULL;
        }
        if (p_advance(p)->type != TOK_SLASH) {
            cf_fail(c, "expected '/' and a prefix length after 'net A.B.C.D'");
            return NULL;
        }
        token_t* len_tok = p_advance(p);
        if (len_tok->type != TOK_NUMBER || len_tok->num > 32u) {
            cf_fail(c, "expected a prefix length (0-32) after 'net A.B.C.D/'");
            return NULL;
        }
        uint8_t prefix_len = (uint8_t)len_tok->num;
        node_t* ip = mk_ethertype(c, a, ETHERTYPE_IPV4);
        node_t* net = has_dir
            ? mk_net(c, a, dir, addr_tok->addr, prefix_len)
            : mk_or(c, a, mk_net(c, a, DIR_SRC, addr_tok->addr, prefix_len),
                          mk_net(c, a, DIR_DST, addr_tok->addr, prefix_len));
        return mk_and(c, a, ip, net);
    }

    default:
        cf_fail(c, "expected a filter primitive (tcp/udp/icmp/ip/ip6/arp/host/port/net)");
        return NULL;
    }
}

static node_t* parse_not(parser_t* p) {
    if (p_peek(p)->type == TOK_NOT) {
        p_advance(p);
        node_t* operand = parse_not(p);
        node_t* n = mk_node(p->c, p->arena, N_NOT);
        if (n == NULL) return NULL;
        n->left = operand;
        return n;
    }
    if (p_peek(p)->type == TOK_LPAREN) {
        p_advance(p);
        node_t* inner = parse_expr(p);
        if (p_advance(p)->type != TOK_RPAREN) {
            cf_fail(p->c, "expected ')'");
            return NULL;
        }
        return inner;
    }
    return parse_primitive(p);
}

static node_t* parse_and(parser_t* p) {
    node_t* left = parse_not(p);
    while (p_peek(p)->type == TOK_AND) {
        p_advance(p);
        node_t* right = parse_not(p);
        left = mk_and(p->c, p->arena, left, right);
    }
    return left;
}

static node_t* parse_expr(parser_t* p) {
    node_t* left = parse_and(p);
    while (p_peek(p)->type == TOK_OR) {
        p_advance(p);
        node_t* right = parse_and(p);
        left = mk_or(p->c, p->arena, left, right);
    }
    return left;
}

/* ============================= Codegen ================================ */

/* Backpatch list: индексы инструкций и то, какое поле (jt или jf) в них
   ещё предстоит заполнить, когда узнаем реальный адрес перехода. Это
   классическая техника компиляции булевых выражений с коротким
   замыканием — см. комментарий в capfilter.h. */
typedef struct {
    int insn_idx[CF_MAX_INSNS];
    uint8_t is_jt[CF_MAX_INSNS];
    int count;
} patch_list_t;

static void pl_add(patch_list_t* pl, int idx, int is_jt) {
    pl->insn_idx[pl->count] = idx;
    pl->is_jt[pl->count] = (uint8_t)is_jt;
    pl->count++;
}

static void pl_append(patch_list_t* dst, const patch_list_t* src) {
    for (int i = 0; i < src->count; i++) {
        pl_add(dst, src->insn_idx[i], src->is_jt[i]);
    }
}

typedef struct {
    struct sock_filter insns[CF_MAX_INSNS];
    int n_insns;
    cf_ctx_t* c;
} cf_gen_t;

static int gen_push(cf_gen_t* g, uint16_t code, uint8_t jt, uint8_t jf, uint32_t k) {
    if (g->n_insns >= CF_MAX_INSNS) {
        cf_fail(g->c, "compiled filter is too large");
        return -1;
    }
    struct sock_filter* insn = &g->insns[g->n_insns];
    insn->code = code;
    insn->jt = jt;
    insn->jf = jf;
    insn->k = k;
    return g->n_insns++;
}

/* Заполняет jt/jf-поля всех инструкций в 'pl' так, чтобы они прыгали на
   'target_pc'. BPF-переходы относительны (от PC следующей инструкции) и
   умещаются в один байт — отсюда проверка на переполнение. */
static void pl_resolve(cf_gen_t* g, patch_list_t* pl, int target_pc) {
    for (int i = 0; i < pl->count; i++) {
        int idx = pl->insn_idx[i];
        int offset = target_pc - (idx + 1);
        if (offset < 0 || offset > 255) {
            cf_fail(g->c, "filter expression is too complex to compile to BPF (jump out of range)");
            return;
        }
        if (pl->is_jt[i]) {
            g->insns[idx].jt = (uint8_t)offset;
        } else {
            g->insns[idx].jf = (uint8_t)offset;
        }
    }
}

/* Один compare-leaf: грузит поле инструкциями load_insns[0..n_load) в A,
   затем сравнивает с k. jt/jf самого сравнения остаются 0 (заполнятся
   позже через out_t/out_f). */
static int emit_leaf(cf_gen_t* g, const struct sock_filter* load_insns, int n_load,
    uint32_t k, patch_list_t* out_t, patch_list_t* out_f) {
    for (int i = 0; i < n_load; i++) {
        if (gen_push(g, load_insns[i].code, load_insns[i].jt, load_insns[i].jf, load_insns[i].k) < 0) {
            return -1;
        }
    }
    int idx = gen_push(g, BPF_JMP | BPF_JEQ | BPF_K, 0, 0, k);
    if (idx < 0) {
        return -1;
    }
    pl_add(out_t, idx, 1);
    pl_add(out_f, idx, 0);
    return 0;
}

static uint32_t addr_to_u32(const uint8_t addr[4]) {
    return ((uint32_t)addr[0] << 24) | ((uint32_t)addr[1] << 16) | ((uint32_t)addr[2] << 8) | addr[3];
}

static uint32_t prefix_mask(uint8_t prefix_len) {
    if (prefix_len == 0) {
        return 0;
    }
    return prefix_len >= 32 ? 0xFFFFFFFFu : (~0u << (32 - prefix_len));
}

static int compile_node(cf_gen_t* g, const node_t* n, patch_list_t* out_t, patch_list_t* out_f) {
    if (g->c->failed) {
        return -1;
    }

    switch (n->kind) {
    case N_NOT:
        /* De Morgan для free: просто меняем местами, куда попадает true/false. */
        return compile_node(g, n->left, out_f, out_t);

    case N_AND: {
        patch_list_t lt = { 0 }, lf = { 0 };
        if (compile_node(g, n->left, &lt, &lf) < 0) return -1;
        pl_resolve(g, &lt, g->n_insns); /* left true -> сразу проваливаемся в код right */
        if (g->c->failed) return -1;
        patch_list_t rt = { 0 }, rf = { 0 };
        if (compile_node(g, n->right, &rt, &rf) < 0) return -1;
        pl_append(out_t, &rt);
        pl_append(out_f, &lf);
        pl_append(out_f, &rf);
        return 0;
    }

    case N_OR: {
        patch_list_t lt = { 0 }, lf = { 0 };
        if (compile_node(g, n->left, &lt, &lf) < 0) return -1;
        pl_resolve(g, &lf, g->n_insns); /* left false -> пробуем right */
        if (g->c->failed) return -1;
        patch_list_t rt = { 0 }, rf = { 0 };
        if (compile_node(g, n->right, &rt, &rf) < 0) return -1;
        pl_append(out_t, &lt);
        pl_append(out_t, &rt);
        pl_append(out_f, &rf);
        return 0;
    }

    case N_ETHERTYPE: {
        struct sock_filter load[] = { { BPF_LD | BPF_H | BPF_ABS, 0, 0, OFF_ETHERTYPE } };
        return emit_leaf(g, load, 1, n->k, out_t, out_f);
    }

    case N_IPPROTO: {
        struct sock_filter load[] = { { BPF_LD | BPF_B | BPF_ABS, 0, 0, OFF_IP_PROTO } };
        return emit_leaf(g, load, 1, n->k, out_t, out_f);
    }

    case N_HOST: {
        uint32_t off = (n->dir == DIR_SRC) ? OFF_IP_SRC : OFF_IP_DST;
        struct sock_filter load[] = { { BPF_LD | BPF_W | BPF_ABS, 0, 0, off } };
        return emit_leaf(g, load, 1, addr_to_u32(n->addr), out_t, out_f);
    }

    case N_NET: {
        uint32_t off = (n->dir == DIR_SRC) ? OFF_IP_SRC : OFF_IP_DST;
        uint32_t mask = prefix_mask(n->prefix_len);
        struct sock_filter load[] = {
            { BPF_LD | BPF_W | BPF_ABS, 0, 0, off },
            { BPF_ALU | BPF_AND | BPF_K, 0, 0, mask },
        };
        return emit_leaf(g, load, 2, addr_to_u32(n->addr) & mask, out_t, out_f);
    }

    case N_PORT: {
        /* X = (IP header's IHL nibble) * 4 -- BPF_MSH exists exactly for
           this ("masked shift"): load a byte, keep the low nibble, times
           4. That's the IPv4 header length in bytes, needed because TCP
           and UDP headers start right after it, at a variable offset. */
        struct sock_filter msh = { BPF_LDX | BPF_B | BPF_MSH, 0, 0, OFF_IP_IHL_BYTE };
        if (gen_push(g, msh.code, msh.jt, msh.jf, msh.k) < 0) return -1;
        /* BPF_IND: load at (k + X) -- k=14 lands on the L4 header's first
           2 bytes (src port) for both TCP and UDP, k=16 on the next 2
           (dst port), since both protocols put ports in the same spot. */
        uint32_t ind_k = (n->dir == DIR_SRC) ? OFF_IP_IHL_BYTE : (OFF_IP_IHL_BYTE + 2);
        struct sock_filter load[] = { { BPF_LD | BPF_H | BPF_IND, 0, 0, ind_k } };
        return emit_leaf(g, load, 1, n->k, out_t, out_f);
    }
    }

    cf_fail(g->c, "internal error: unknown AST node kind");
    return -1;
}

/* Классическая "принять весь кадр" константа для BPF_RET -- любое число
   >= максимального захватываемого кадра; 65535 -- обычный выбор
   tcpdump/pcap (снап-лен по умолчанию). */
#define CF_ACCEPT_LEN 65535u

int capfilter_compile(const char* expr, struct sock_fprog* out, char* err, int err_len) {
    if (out == NULL) {
        return -1;
    }
    out->filter = NULL;
    out->len = 0;

    if (expr == NULL || expr[0] == '\0') {
        return 0; /* "принимать всё" - не ошибка, см. заголовочный комментарий */
    }

    cf_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.err = err;
    ctx.err_len = err_len;

    cf_lex(&ctx, expr);
    if (ctx.failed) {
        return -1;
    }

    node_arena_t arena;
    arena.count = 0;
    parser_t parser = { &ctx, &arena };
    node_t* root = parse_expr(&parser);
    if (!ctx.failed && p_peek(&parser)->type != TOK_END) {
        cf_fail(&ctx, "unexpected trailing tokens in filter expression");
    }
    if (ctx.failed) {
        return -1;
    }

    cf_gen_t gen;
    gen.n_insns = 0;
    gen.c = &ctx;

    patch_list_t true_list = { 0 }, false_list = { 0 };
    if (compile_node(&gen, root, &true_list, &false_list) < 0) {
        return -1;
    }

    int accept_pc = gen.n_insns;
    pl_resolve(&gen, &true_list, accept_pc);
    if (ctx.failed) return -1;
    if (gen_push(&gen, BPF_RET | BPF_K, 0, 0, CF_ACCEPT_LEN) < 0) return -1;

    int reject_pc = gen.n_insns;
    pl_resolve(&gen, &false_list, reject_pc);
    if (ctx.failed) return -1;
    if (gen_push(&gen, BPF_RET | BPF_K, 0, 0, 0) < 0) return -1;

    struct sock_filter* filter = malloc(sizeof(struct sock_filter) * (size_t)gen.n_insns);
    if (filter == NULL) {
        cf_fail(&ctx, "out of memory compiling filter");
        return -1;
    }
    memcpy(filter, gen.insns, sizeof(struct sock_filter) * (size_t)gen.n_insns);

    out->filter = filter;
    out->len = (unsigned short)gen.n_insns;
    return 0;
}

void capfilter_free(struct sock_fprog* fprog) {
    if (fprog == NULL) {
        return;
    }
    free(fprog->filter);
    fprog->filter = NULL;
    fprog->len = 0;
}

void capfilter_print(const struct sock_fprog* fprog) {
    if (fprog == NULL || fprog->filter == NULL) {
        printf("(empty filter - accepts everything)\n");
        return;
    }
    for (unsigned short i = 0; i < fprog->len; i++) {
        const struct sock_filter* f = &fprog->filter[i];
        printf("%3u: code=0x%04x jt=%u jf=%u k=0x%x\n", i, f->code, f->jt, f->jf, f->k);
    }
}
