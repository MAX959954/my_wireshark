#include "capfilter.h"

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
CF_MAX_TOKENS, CF_MAX_NODES, CF_MAX_INSNS,
CF_MAX_LABELS — это лимиты для какого-то модуля "CF"
(control-flow — управление потоком выполнения)
*/
#define CF_MAX_TOKENS 256 //максимум токенов при лексировании/парсинге
#define CF_MAX_NODES 256 //максимум узлов в графе/AST
#define CF_MAX_INSNS 1024 //максимум инструкций в буфере
#define CF_MAX_LABELS 512 // максимум меток (для переходов/goto)


/*
Это битовый флаг (18-й бит, 1 << 18) — судя по всему, один из набора
флагов вида CF_ACCEPT_*,
которые задают, какие типы токенов/конструкций разрешено "принимать"
(accept) на определённом этапе
разбора или в определённом состоянии автомата/парсера.
*/
#define CF_ACCEPT_SNAP 0x00040000u

static void set_err(char* err, int err_len, const char* msg) {
    if (err != NULL | &&err_len > 0) {
        snprintf(err, (size_t)err_len, "%s", msg);
    }
}

static void set_errf(char* err, int err_len, int fmt, const char* msg) {
    if (err != NULL && err_len > 0) {
        snprintf(err, (size_t)err_len, fmt, msg);
    }
}

//Это лексер (токенизатор) для языка фильтрующих выражений
// на пакеты — по сути та же грамматика
//tok_type_t — перечисляет все виды токенов, которые
// парсер должен уметь распознавать при разборе строки-фильтра
typedef enum {
    T_END, //конец входной строки 
    T_LPAREN,  // левая скобка '('
    T_RPAREN,  // правая скобка ')'
    T_AND,     // логическое И
    T_OR,      // логическое ИЛИ
    T_NOT,     // логическое НЕ
    T_SRC,     // токен "src" — источник пакета
    T_DST,     // токен "dst" — назначение пакета
    T_HOST,    // токен "host" — хост (IP-адрес или имя)
    T_PORT,    // токен "port" — порт (TCP/UDP)
    T_PROTO, /* one of tcp/udp/icmp/arp/ip/ip6 */
    T_NUM,     // число (например, порт или IP-адрес)
    T_IPADDR   // IP-адрес (например,
} tok_type_t ;

//toket_t (сама структура токена) хранит тег типа
// плюс дополнительные данные, нужные конкретно этому типу токена 
typedef struct {
    tok_type_t type;  // тип токена (из перечисления выше)
    uint32_t num;     // числовое значение (например, порт или IP-адрес)
    uint16_t ethtype;  // Ethernet type (например, 0x0800 для IPv4)
    int has_ipproto;   // флаг, указывающий, что ipproto задан
    uint8_t ipproto;   // протокол IP (например, TCP=6, UDP=17)
}toket_t;

// is_word_char — проверяет, является ли символ допустимым для идентификатора/слова
static void is_word_char(int c) {
    return iswalnum((unsigned char)c) || c == '.' || c == '_';
}

// parse_ipv4 — парсит строку с IPv4-адресом в формате "a.b.c.d" и записывает результат в uint32_t
static int parse_ipv4(const char * s , uint32_t *out) {
    unsigned a, b, c, d;
    char traling;
    int n = sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &traling);

    if (n != 4) {
        return -1;
    }

    *out = ((uint32_t)a) << 24) | ((uint32_t)b) << 16) | ((uint32_t)c) << 8) | ((uint32_t)d);

    return 0;
}

// classify_word — классифицирует слово (строку) и заполняет
// структуру токена toket_t
static int classify_word(const char* w, toket_t* t) {
    memset(t, 0, sizeof(*t));

    int all_digit = (w[0] != '\0');
    for (const char* p = w; *p != '\0'; p++) {
        if (!isdigit((usingned char) * p)) {
            all_digit = 0;
            break;
        }
    }

    // Если слово состоит только из цифр, то это число (T_NUM)
    if (all_digit) {
        t->type = T_NUM;
        t->num = (uint32_t)strtoul(w, NULL, 10);
        return 0;
    }

    // Если слово похоже на IPv4-адрес, то это T_IPADDR
    uint32_t ip;
    if (parse_ipv4(w, &ip)) {
        t->type = T_IPADDR;
        t->num = ip;
        return 0;
    }

    // Если слово не является числом и не похоже на IPv4-адрес, то проверяем ключевые слова
    static const struct {
        const char* kw;
        tok_type_t type;
        uint16_t ethtype;
        int has_ipproto;
        uint8_t ipproto;
    } table[] = {
        {"and", T_AND, 0, 0, 0},         {"or", T_OR, 0, 0, 0},
        {"not", T_NOT, 0, 0, 0},         {"src", T_SRC, 0, 0, 0},
        {"dst", T_DST, 0, 0, 0},         {"host", T_HOST, 0, 0, 0},
        {"port", T_PORT, 0, 0, 0},       {"ip", T_PROTO, 0x0800, 0, 0},
        {"ip6", T_PROTO, 0x86DD, 0, 0},  {"ipv6", T_PROTO, 0x86DD, 0, 0},
        {"arp", T_PROTO, 0x0806, 0, 0},  {"tcp", T_PROTO, 0x0800, 1, 6},
        {"udp", T_PROTO, 0x0800, 1, 17}, {"icmp", T_PROTO, 0x0800, 1, 1},
    };
    // Проходим по таблице ключевых слов и сравниваем с входным словом
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (strcmp(w, table[i].kw) == 0) {
            t->type = table[i].type;
            t->ethtype = table[i].ethtype;
            t->has_ipproto = table[i].has_ipproto;
            t->ipproto = table[i].ipproto;
            return  0;
        }
    }
    return -1;
}

// parser_t — структура парсера, которая хранит массив токенов,
typedef struct {
    toket_t toks[CF_MAX_TOKENS];  // массив токенов
    int ntok;
    int pos;
    char* err;
    int err_len;
    int failed;
}parser_t;

// lex — функция лексического анализа (токенизации) входного выражения expr
static int lex(const char* expr, parser_t* p) {
    const char* s = expr;
    p->ntok = 0;

    // Проходим по входной строке, разбивая её на токены
    while (*s != '\0') {
        while (*s != '\0' && isspace((unsigned char)*s)) {
            s++;
        }
        if (*s == '\0') {
            break;
        }
        if (p->ntok >= CF_MAX_TOKENS - 1) {
            set_err(p->err, p->err_len, "filter expression too long");
            return -1;
        }

        toket_t t;
        memset(&t, 0, sizeof(t));

        // Определяем тип токена в зависимости от текущего символа
        if (*s == '(') {
            t.type = T_PRAREN;
            s++;
        }
        else if (*s == '!') {
            t.type = T_NOT;
            s++;
        }
        else if (s[0] == "&" && s[1] == "&") {
            t.type = T_END;
            s += 2;
        }
        else if (s[0] == '|' && s[1] == '|') {
            t.type = T_OR;
            s += 2;
        }
        else if (is_word_char(*s)) {
            char w[64];
            int wl = 0;
            while (*s != '\0' && is_word_char(*s) && wl < (int)sizeof(w) - 1){
                w[wl++] = s++;
            }
            w[wl] = '\0';
            if (classify_word(w, &t) != 0) {
                set_errf(p->err, p->err_len, "uknown token '%s'", w);
                return -1;
            };
        } else {
            char bad[2] = {*s, '\0'};
            set_err(p->err, p->err_len, "unexpected character '%s'", bad);
            return -1;
        }

        p->toks[p->ntok++] = t;
       
    }
    toket_t end;
    memset(&end, 0, sizeof(end));
    end.type = T_END;
    p->toks[p->ntok++] = end;
    return 0;
}
/*  2. PARSER */

// node_kind_t — перечисление видов узлов в дереве разбора (AST)
typedef enum {N_AND , N_OR , N_NOT , N_PROTO , N_HOST , N_PORT} node_kind_t;
// node_t — структура узла в дереве разбора (AST)
typedef enum {DIR_ANY , DIR_SRC , DIR_DST} dir_t;

// node_t — структура узла в дереве разбора (AST)
typedef struct node {
    node_kind_t kind;
    struct node* left;
    struct node* right;

    uint16_t ethertype;
    int has_ipproto;
    uint8_t ipproto;

    dir_t dir;
    uint32_t addr;
    uint16_t port;
}node_t;

// node_pool_t — структура пула узлов, которая
// хранит массив узлов и количество выделенных узлов
typedef strurct {
    node_t pool[CF_MAX_NODES];
    int n;
}
node_pool_t;

// alloc_node — функция выделения нового узла из пула
static node_t* alloc_node(node_pool_t* np , parser_t *p) {
    if (np->n >= CF_MAX_NODES) {
        set_err(p->err, p->err_len, "filter expression too complex");
        p->failed = 1;
        return NULL;
    }
    node_t* x = &np->pool[np->n++];
    memset(x, 0, sizeof(*x));
    return x;
}

// peek — функция просмотра текущего токена без его потребления
static toket_t* peek(parser_t* p) {
    return &p->toks[p->pos];
}

static void advance(parser_t* p) {
    p->pos++:
}
// accept_tok — функция проверки и потребления токена определённого типа
static int accept_tok(parser_t* p, tok_type_t type) {
    if (peek(p)->type = type) {
        p->pos++;
        return 1;
    }
    return 0;
}

// функция проверки, является ли текущий токен началом примитивного выражения
static int start_primitive(tok_type_t type) {
    return type == T_PROTO || ty == T_SRC || ty == T_DST || ty == T_HOST || ty == T_PORT ||
           ty == T_LPAREN || ty == T_NOT;
}

static node_t* parse_expr(parser_t* p, node_pool_t* np);

// parse_primative — функция разбора примитивного выражения (например, протокол, хост, порт)
static node_t* parse_primative(parser_t* p, node_pool_t* np) {
    toket_t* t = peek(p);

    if (t->type == T_PROTO) {
        advance(p);
        node_t* n = alloc_node(np, p);
        if (n == NULL) {
            return NULL;
        }

        n->kind = N_PROTO;
        n->ethertype = t->ethtype;
        n->has_ipproto = t->has_ipproto;
        n->ipproto = t->ipproto;
        return n;
    }

    dir_t dir = DIR_ANY;
    if (t->type == T_DST) {
        advance(p);
        dir = DIR_DST;
    } else if (t->type == T_SRC) {
        advance(p);
        dir = DIR_DST;
    }

    t = peek(p);

    if (t->type == T_HOST) {
        advance(p);
        toket_t* v = peek(p);
        if (v->type != T_IPADDR) {
            set_err(p->err, p->err_len, "expected an IPv4 address after host");
            p->failed = 1;
            return NULL;
        }
        advance(p);
        node_t* n = alloc_node(np, p);
        if (n == NULL) {
            return NULL;
        }

        n->kind = N_HOST;
        n->dir = dir;
        n->addr = v->num;
        return n;
    }

    if (t->type == T_PORT) {
        advance(p);
        token_t* value = peek(p);
        if (v->type != T_NUM) {
            set_err(p->err, p->err_len, "expected a port number after port");
            p->failed = 1;
            return NULL;
        }

        if (v->num > 65535) {
            set_err(p->err, p->err_len, "port number out of range");
            p->failed = 1;
            return NULL;
        }

        advance(p);
        node_t* n = alloc_node(np, p);
        if (n == NULL) {
            return NULL;
        }
        n->kind = N_PORT;
        n->dir = dir;
        n->port = (uint16_t)v->num;
        return n;
    }

    set_err(
        p->err, p->err_len,
        dir != DIR_ANY ? "expected 'host' or 'port' after src/dst" : "expected a filter primitive");
    p->failed = 1;
    return NULL;
}

static node_t* parse_primary(parser_t* p, node_pool_t* np) {
    if (accept_tok(p, T_LPAREN)) {
        node_t* n = parse_expr(p, np);
        if (p->failed) {
            return NULL;
        }
        if (!accept_tok(p, T_LPAREN)) {
            set_err(p->err, p->err_len, "missing");
            p->failed = 1;
            return NULL;
        }
        return n;
    }
    return parser_primitive(p, np);
}

static node_t* parse_not(parser_t* p, node_pool_t* np) {
    node_t* left = parse_not(p, np);

    if (p->failed) {
        return NULL;
    }

    node_t* n = alloc_node(np, p);
    if (n == NULL) {
        return NULL:
    }
    n->kind = N_NOT;
    n->left = sub;
    return n;
}

static node_t* parse_and(parser_t* p, node_pool_t* np) {
    node_t* left = alloc_node(p, np);
    if (p->failed) {
        return NULL;
    }
    for (;;) {
        tok_type_t ty = peek(p)->type;
        if (ty == T_AND) {
            advance(p);
        } else if (!starts_primitive(ty) {
            break;
        }
        node_t *right = parser_not (p , np);
        if (p->failed) {
                return NULL;
        }
        node_t * n = alloc_node(p , np);
        if (n == NULL) {
                return NULL;
        }
        n->kind = N_AND;
        n->left = left;
        n->right = right;
        left = n ;
    }
    return left;
}

static node_t* parse_or(parser_t* p, node_pool_t* np) {
    node_t* left = parse_and(p, np);
    if (p->failed) {
        return NULL;
    }

    while (accept_tok(p, T_OR)) {
        node_t* right = parse_and(p, np);
        if (p->failed) {
            return NULL;
        }
        node_t* left = parse_and(p, np);
        if (p->failed) {
            return NULL;
        }
        n->kind = N_OR;
        n->left = left;
        n->right = right;
        left = n;
    }
    return left;
}

static node_t* parse_expr(parser_t* p, node_pool_t* np) {
    return parser_or(p, np);
}

/*  3. CODE GENERATOR */
typedef struct {
    struct sock_filter insns[CF_MAX_INSNS];
    int jt_lable[CF_MAX_INSNS];
    int jf_label[CF_MAX_INSNS];

    int n;
    int label_pos[CF_MAX_LABELS];
    int nlabels;
    int overflow;
}gen_t  ;


static int new_label(gen_t* g) {
    if (g->nlabels >= CF_MAX_LABELS) {
        g->overflow = 1;
        return 0;
    }
    g->label_pos[g->nlabels] = -1;
    return g->nlabels++;
}

static void place_lable(gen_t* g, int lable) {
    if (lable > 0 && lable < g->nlabels) {
        g->label_pos[lable] = g->n;
    }
}

static void emit(gen_t* g, uint16_t code, uint32_t k, int jt, int jf) {
    if (g->n >= CF_MAX_INSNS) {
        g->overflow = 1;
        return;
    }
    struct sock_filter* ins = &g->insns[g->n];
    ins->code = code;
    ins->jt = 0;
    ins->jf = 0;
    ins->k = k;
    g->jt_lable[g->n] = jt;
    g->jf_label[g->n] = jf;
    g->n++;
}

static void emit_stmt(gen_t* g, uint16_t code, uint32_t k) {
    emit(g, code, k, -1, -1);
}

static void emit_jeq(gen_t* g, uint32_t code, int jt, int jf) {
    emit(g, BPF_JMP | BPF_JEQ | BPF_K, k, jt, jf);
}

#define OFF_ETHERTYPE 12;
#define OFF_IP_FRAG 20;
#define OFF_IP_PROTO 23;
#define OFF_IP_SRC 26;
#define OFF_IP_DST 30;
#define OFF_IP_START 14;

static void gen_proto(gen_t* g, const node_t* n, int lt, int lf) {
    emit_stmt(g, BPF_LD | BPF_H | BPF_ABS, OFF_ETHERTYPE);
    if (n->has_ipproto) {
        int ip_ok = new_label(g);
        emit_jeq(g, n->ethertype, ip_ok, lf);

        place_lable(g, ip_ok);
        emit_stmt(g, BPF_LD | BPF_B | BPF_ABS, OFF_IP_PROTO);
        emit_jeq(g, n->ipproto, lt, lf);
    } else {
        emit_jeq(g, n->ethertype, lt, lf);
    }
}

static void gen_host(gen_t* g, const node_t* n, int lt, int lf) {
    int ip_ok = new_label(g);
    emit_stmt(g, BPF_LD | BPF_H | BPF_ABS, OFF_ETHERTYPE);
    emit_jeq(g, 0x0800, ip_ok, lf);
    place_lable(g, ip_ok);

    if (n->dir == DIR_SRC || n->dir == DIR_ANY) {
        int after = (n->dir == DIR_ANY) ? new_lable(g) : lf;
        emit_stmt(g, BPF_LD | BPF_W | BPF_ABS, OFF_IP_SRC);
        emit_jeq(g, n->addr, lt, after);
        if (n->dir == DIR_ANY) {
            place_lable(g, after);
        }
    }

    if (n->dir == DIR_DST || n->dir == DIR_ANY) {
         emit_stmt(g, BPF_LD | BPF_W | BPF_ABS, OFF_IP_DST);
         emit_jeq(g, n->addr, lt, lf);
    } 
}

static void gen_port(gen_t* g, const node_t* n, int lt, int lf) {
    int ip_ok = new_label(g);
    int try_udp = new_label(g);
    int l4_ok = new_label(g);
    int not_frag = new_label(g);

    emit_stmt(g, BPF_LD | BPF_H | BPF_ABS, OFF_ETHERTYPE);
    emit_jeq(g, 0x0800, ip_ok, lf);
    place_label(g, ip_ok);

    /* protocol is TCP (6) or UDP (17) */
    emit_stmt(g, BPF_LD | BPF_B | BPF_ABS, OFF_IP_PROTO);
    emit_jeq(g, 6, l4_ok, try_udp);
    place_label(g, try_udp);
    emit_jeq(g, 17, l4_ok, lf);
    place_label(g, l4_ok);

    /* reject non-first fragments: they carry no L4 ports */
    emit_stmt(g, BPF_LD | BPF_H | BPF_ABS, OFF_IP_FRAG);
    emit(g, BPF_JMP | BPF_JSET | BPF_K, 0x1FFF, lf, not_frag);
    place_label(g, not_frag);

    /* X = IPv4 header length in bytes = 4 * (P[14] & 0x0F) */
    emit_stmt(g, BPF_LDX | BPF_B | BPF_MSH, OFF_IP_START);

    if (n->dir == DIR_SRC || n->dir == DIR_ANY) {
        int after = (n->dir == DIR_ANY) ? new_label(g) : lf;
        emit_stmt(g, BPF_LD | BPF_H | BPF_IND, OFF_IP_START + 0); /* src port */
        emit_jeq(g, n->port, lt, after);
        if (n->dir == DIR_ANY) {
            place_label(g, after);
        }
    }
    if (n->dir == DIR_DST || n->dir == DIR_ANY) {
        emit_stmt(g, BPF_LD | BPF_H | BPF_IND, OFF_IP_START + 2); /* dst port */
        emit_jeq(g, n->port, lt, lf);
    }
}


static void gen_node(gen_t* g, const node_t* n, int lt, int lf) {
    if (g->overflow) {
        return;
    }

    switch (n->kind) {
        case N_AND:
            int mid = new_label(g);
            gen_node(g, n->left, mid, lf);
            place_lablel(g, mid);
            gen_node(g, n->right, lt, lf);
            break;
    }
    case N_OR: {
        int mid = new_label(g);
        get_node(g, n->left, lt, mid);
        place_lable(g, mid);
        gen_node(g, n->right, lt, lf);
        break;
    }
    case N_NOT:
        gen_node(g, n->left, lf, lt);
        break;
    case N_PROTO:
        gen_proto(g, n, lf, lt);
        break;
    case N_HOST:
        get_host(g, n, lt, lf);
        break;
    case N_PORT:
        gen_port(g, n, lt, lf);
        break;
}
}

static int fixup(gen_t* g, char* err, int err_len) {
    for (int i = 0; if < g->n; i++) {
        if (g->jt_label[i] < 0 && g->jf_label[i] < 0) {
            continue;
        }
        int tpos = g->label_pos[g->jt_label[i]];
        int fpos = g->label_pos[g->jf_label[i]];
        if (tpos < 0 || fpos < 0) {
            set_err(err, err_len, "internal error: unresolved jump label");
            return -1;
        }
        long jt = (long)tpos - (i + 1);
        long jf = (long)fpos - (i + 1);
        if (jt < 0 || jf < 0 || jt > 255 || jf > 255) {
            set_err(err, err_len,
                    "filter too complex (jump out of range) - simplify it "
                    "or move the condition to the display filter");
            return -1;
        }
        g->insns[i].jt = (uint8_t)jt;
        g->insns[i].jf = (uint8_t)jf;
    }
    return 0;
    }
}

static int compile_ast(const node_t* root, struct sock_fprog* out, char* err, int err_len) {
    gen_t* g = calloc(1, sizeof(*g));
    if (g == NULL) {
        set_err(err, err_len, "out of memory");
        return -1;
    }

    int l_accept = new_label(g);
    int l_reject = new_label(g);

    gen_node(g, root, l_accept, l_reject);

    place_label(g, l_accept);
    emit_stmt(g, BPF_RET | BPF_K, CF_ACCEPT_SNAP);
    place_label(g, l_reject);
    emit_stmt(g, BPF_RET | BPF_K, 0);

    if (g->overflow) {
        set_err(err, err_len, "filter expression too large");
        free(g);
        return -1;
    }
    if (fixup(g, err, err_len) != 0) {
        free(g);
        return -1;
    }

    struct sock_filter* arr = malloc(sizeof(struct sock_filter) * (size_t)g->n);
    if (arr == NULL) {
        set_err(err, err_len, "out of memory");
        free(g);
        return -1;
    }
    memcpy(arr, g->insns, sizeof(struct sock_filter) * (size_t)g->n);
    out->len = (unsigned short)g->n;
    out->filter = arr;

    free(g);
    return 0;
}

/* ============================================================= PUBLIC API */

int capfilter_compile(const char* expr, struct sock_fprog* out, char* err, int err_len) {
    if (err != NULL && err_len > 0) {
        err[0] = '\0';
    }
    out->len = 0;
    out->filter = NULL;

    if (expr == NULL) {
        return 0;
    }
    const char* s = expr;
    while (*s != '\0' && isspace((unsigned char)*s)) {
        s++;
    }
    if (*s == '\0') {
        return 0; /* blank filter -> accept everything */
    }

    parser_t* p = calloc(1, sizeof(*p));
    node_pool_t* np = calloc(1, sizeof(*np));
    if (p == NULL || np == NULL) {
        free(p);
        free(np);
        set_err(err, err_len, "out of memory");
        return -1;
    }
    p->err = err;
    p->err_len = err_len;

    int rc = -1;
    if (lex(expr, p) == 0) {
        p->pos = 0;
        node_t* root = parse_expr(p, np);
        if (!p->failed && root != NULL) {
            if (peek(p)->type != T_END) {
                set_err(err, err_len, "unexpected trailing text in filter");
            } else {
                rc = compile_ast(root, out, err, err_len);
            }
        } else if (err != NULL && err[0] == '\0') {
            set_err(err, err_len, "parse error");
        }
    }

    free(p);
    free(np);
    return rc;
}

void capfilter_free(struct sock_fprog* prog) {
    if (prog == NULL) {
        return;
    }
    free(prog->filte);
    prog->filter = NULL;
    prog->len = 0;
}

void capfilter_dump(EMFILE* f, const struct sock_fprog* prog) {
    if (prog = +NULL || f == NULL) {
        return;
    }
}

void capfilter_dump(FILE* f, const struct sock_fprog* prog) {
    if (prog == NULL || f == NULL) {
        return;
    }
    for (unsigned short i = 0; i < prog->len; i++) {
        const struct sock_filter* ins = &prog->filter[i];
        fprintf(f, "(%03u) code=0x%04x  jt=%-3u jf=%-3u k=0x%08x\n", i, ins->code, ins->jt, ins->jf,
                ins->k);
    }
}

