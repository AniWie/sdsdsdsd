// veh_tracer3.c - VEH diagnostics for the StatelessConnect reject path.
// Freestanding: no CRT, no TLS; suitable for manual_map2.py + hijack_thread.py.
//
// PacketHandler::Incoming returns 0 on success and 1 on failure. Its local
// FBitReader is at rsp-0xd8 on the two ret instructions. The original packet
// view pointer remains at rsp+0x10.
//
// Build:
//   gcc -shared -nostdlib -o veh_tracer3.dll veh_tracer3.c \
//       -e tracer_entry -lkernel32 -luser32
#include <windows.h>

#define OUT_PATH "D:\\Games\\WeiMianYe\\bypass\\logs\\vtttttttg.out"
#define MAX_HITS 1024
#define EXPORT __declspec(dllexport)

enum {
    PH_RET_EARLY,
    PH_RET_MAIN,
    SC_EARLY_RETURN,
    SC_ERROR_RETURN,
    SC_CLOSE_CALL,
    SC_CONTROL_ENTRY,
    SC_PARSER_RETURN,
    SC_HEADER_FAIL,
    PH_INCOMING_ENTRY,
    SET_ERROR_BIT,
    SET_ERROR_DWORD,
    FBITREADER_CTOR,
    PH_CALL_COMPONENT70,
    SC_INCOMING_MAIN_RET,
    PH_CMP_SIL,
    PH_CALL_FUNCC_ENTRY,
    PH_CALL_VTABLE8,
    SC_INCOMING_ENTRY_ADDR,
    PH_COUNT_COMPONENTS,
    PH_COUNT_JS,
    PH_LOOP_ENTRY,
    SETERROR_BODY2,
    VALIDATOR_BITREAD,
    VALIDATOR_ENTRY,
    TYPE_COMPARE,
    BUNCH_PARSER_ENTRY,
    PH_CALL_INCOMING40,
    NSITES
};

static const unsigned long long SITES[NSITES] = {
    0x14235fde1, // PacketHandler::Incoming: early ret
    0x14235ffa0, // PacketHandler::Incoming: main ret; eax = error flag
    0x14403e4c2, // SC Incoming: early return; al = success flag
    0x14403e5ee, // SC Incoming: xor al,al after test [rdi+0x29],2
    0x14403ef6f, // call 0x144038220; edx = 0x1f, r15 = reader
    0x14403e800, // SC control entry; rdx = reader
    0x14403eb24, // header parser return; al = success, r15 = reader
    0x14403eb4c, // header-fail call 0x144038220; edx = 0x1e
    0x14235fb30, // PacketHandler::Incoming entry; rdx = packet view
    0x1413631a0, // FBitReader::SetError; rcx = reader, rdx = requested bits
    0x1413614e0, // dword serializer SetError fallback; rcx = reader
    0x14135ab40, // FBitReader ctor; rcx = data, rdx = bits
    0x1423614b1, // PH call [component_vtable+0x70] - preprocess
    0x14403e7f3, // SC Incoming main ret
    0x14235fbdb, // cmp byte [r13+1], sil
    0x14235fbe4, // call 0x142361400 (funcC)
    0x14235fc31, // call [component_vtable+8] — Incoming handler
    0x14403e490, // SC Incoming entry
    0x14235fbe9, // mov eax,[r13+0x1b0] — component count
    0x14235fc01, // js 0x14235fe02 after count-1
    0x14235fc20, // component loop entry
    0x141362db0, // SetError body 2 (the one the DR0 trap fired in)
    0x14409751b, // validator SHORT-branch bit read: r8 = bit index
    0x144096fd0, // StatelessConnect validator entry: rdx = its reader
    0x14408e58c, // cmp dl(type),r15b(expected) - THE accept compare
    0x14406bbf0, // NZ bunch parser entry: rcx=component? rdx=struct, r8=reader
    0x14235fc69, // PH call [component_vtable+0x40] Incoming per-component
};

static const unsigned char EXPECTED[NSITES] = {
    0xc3, 0xc3, 0xe9, 0x32, 0xe8, 0x40, 0x84, 0xe8,
    0x48, 0x40, 0x48, 0x48, 0xff, 0xc3, 0x41, 0xe8,
    0xff, 0x40, 0x41, 0x0f, 0x49, 0x48, 0x40, 0x48, 0x41, 0x48, 0xff
};

static const char *const SITE_NAMES[NSITES] = {
    "PacketHandler early ret",
    "PacketHandler main ret",
    "SC early return",
    "SC error-bit return",
    "SC close-path call",
    "SC control entry",
    "SC header parser return",
    "SC header-fail call",
    "PH Incoming ENTRY",
    "SetError call bit reader",
    "SetError call dword fallback",
    "FBitReader ctor",
    "PH call component+0x70 preprocess",
    "SC Incoming main ret",
    "PH cmp sil vs flag",
    "PH call funcC preprocessors",
    "PH call [vtable+8] IsValid",
    "SC Incoming ENTRY 0x14403e490",
    "PH component count",
    "PH component count js",
    "PH component loop entry",
    "SetError body 2 entry",
    "Validator bit read",
    "Validator entry",
    "Type compare",
    "NZ bunch parser ENTRY",
    "PH call component+0x40 Incoming"
};

static unsigned char orig[NSITES];
static volatile long hit_count;
static volatile long armed[NSITES];
static HANDLE g_out;
static PVOID g_veh;
static CRITICAL_SECTION g_lock;
// Hardware breakpoint DR0 on reader+0x29 (write trap): the exact RIP that
// sets the error bit. Guard pages were swallowed by game exception machinery.
static unsigned long long g_guard_page;      // unused (guard pages abandoned)
static DWORD g_guard_orig_prot;              // unused
static unsigned char *g_guard_reader;        // reader being watched
static volatile long g_dr_armed;
// v44: background re-arm thread. The old design relied on the trap-flag
// single-step (EFlags |= 0x100) to re-write the 0xCC right after the
// handler; the game's own exception machinery sometimes swallows that
// single-step, leaving a site disarmed forever (why the bunch-parser
// hook went silent after the first sessions). A dedicated thread
// re-arms any disarmed site every 2ms under the same lock the VEH uses,
// making ALL hooks effectively permanent.
static HANDLE g_rearm_thread;
static volatile long g_rearm_stop;

// v44.1: the 04:00 run proved that keeping int3 on the HOT-PATH sites
// (PH loop/cmp/count fire on EVERY packet) plus the per-write disk
// flush wrecked the reliable layer (cli_ack frozen, 30s timeout).
// Only the 4 diagnostic sites we actually need stay hooked:
static const int ARM_SITES[] = {
    BUNCH_PARSER_ENTRY,     // 0x14406bbf0 — where the channel starts parsing
    SC_INCOMING_ENTRY_ADDR, // 0x14403e490 — SC component incoming (reader pos)
    SC_PARSER_RETURN,       // 0x14403eb24 — parsed [ack seq chunks] + reader pos
    SC_CONTROL_ENTRY,       // 0x14403e800 — control entry (r8/r9 + reader)
};
#define N_ARM_SITES (int)(sizeof(ARM_SITES) / sizeof(ARM_SITES[0]))

static void rearm_site(int i) {
    unsigned char *p = (unsigned char *)SITES[i];
    DWORD oldp;
    if (armed[i])
        return;
    VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &oldp);
    orig[i] = *p;          // refresh orig (should equal EXPECTED)
    *p = 0xCC;
    VirtualProtect(p, 1, oldp, &oldp);
    armed[i] = 1;
}

static DWORD WINAPI rearm_thread(LPVOID param) {
    (void)param;
    while (!g_rearm_stop) {
        if (hit_count < MAX_HITS) {
            EnterCriticalSection(&g_lock);
            for (int k = 0; k < N_ARM_SITES; k++)
                rearm_site(ARM_SITES[k]);
            LeaveCriticalSection(&g_lock);
        }
        Sleep(5);
    }
    return 0;
}

static void wout(const char *s, int n) {
    DWORD w;
    WriteFile(g_out, s, n, &w, NULL);
    // v44.1: FlushFileBuffers REMOVED. The v44 run proved it breaks the
    // game's netcode: every wstr forced a synchronous disk flush while
    // holding g_lock on the network thread; ~100 flushes per packet
    // stalled the thread long enough (100-200ms) for the reliable
    // component's RTT window to expire our replies -> cli_ack frozen at
    // 0xfffc -> client never advanced -> 30s timeout (04:00 run, log
    // vtttttttf.out: 1033 hits/540KB in 30s). OS write-behind is
    // sufficient; the file is closed (flushed) at DETACH and the data
    // is readable while open (FILE_SHARE_READ).
}

static void wstr(const char *s) {
    int n = 0;
    while (s[n]) n++;
    wout(s, n);
}

static void whex(char *buf, unsigned long long v) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 16; i++)
        buf[15 - i] = hx[(v >> (4 * i)) & 0xF];
    buf[16] = 0;
}

static void wdec(char *buf, unsigned long long v) {
    char tmp[24];
    int i = 24;
    int j = 0;
    tmp[--i] = 0;
    do {
        tmp[--i] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while ((buf[j++] = tmp[i++]) != 0)
        ;
}

static void whex64(unsigned long long v) {
    char b[24];
    whex(b, v);
    wstr("0x");
    wstr(b);
}

static void whex8(unsigned char v) {
    static const char hx[] = "0123456789abcdef";
    char b[4];
    b[0] = '0'; b[1] = 'x';
    b[2] = hx[v >> 4]; b[3] = hx[v & 0xF];
    wout(b, 4);
}

static void wnum(unsigned long long v) {
    char b[24];
    wdec(b, v);
    wstr(b);
}

static void dump_data(unsigned long long data, unsigned long long bits) {
    static const char hx[] = "0123456789abcdef";
    char hex[3 * 96];
    unsigned long long n;
    if (!data || !bits || bits > 0x10000000ULL)
        return;
    n = (bits + 7) / 8;
    if (n > 96) n = 96;
    wstr("  data[0:");
    wnum(n);
    wstr("]=");
    for (unsigned long long i = 0; i < n; i++) {
        unsigned char c = ((const unsigned char *)data)[i];
        hex[3 * i] = hx[c >> 4];
        hex[3 * i + 1] = hx[c & 0xF];
        hex[3 * i + 2] = (i + 1 == n) ? 0 : ' ';
    }
    wout(hex, (int)(3 * n - 1));
    wstr("\n");
}

static void dump_reader(const unsigned char *reader) {
    unsigned char flags29;
    unsigned long long limit, pos, data;
    if (!reader)
        return;
    flags29 = reader[0x29];
    data = *(const unsigned long long *)(reader + 0x90);
    limit = *(const unsigned long long *)(reader + 0xa0);
    pos = *(const unsigned long long *)(reader + 0xa8);
    wstr("  reader="); whex64((unsigned long long)reader);
    wstr(" flags29="); whex8(flags29);
    wstr(" limit="); wnum(limit);
    wstr(" pos="); wnum(pos);
    wstr(" data="); whex64(data);
    wstr("\n");
    if (pos > limit) {
        wstr("  OVERREAD pos-limit="); wnum(pos - limit); wstr(" bits\n");
    } else {
        wstr("  remaining="); wnum(limit - pos); wstr(" bits\n");
    }
    dump_data(data, limit);
}

static void dump_packet_view_ptr(const unsigned char *view) {
    unsigned long long data, bytes, bits;
    if (!view)
        return;
    data = *(const unsigned long long *)(view + 0x00);
    bytes = *(const unsigned long long *)(view + 0x08);
    bits = *(const unsigned int *)(view + 0x10);
    wstr("  pv.view="); whex64((unsigned long long)view);
    wstr(" pv.data="); whex64(data);
    wstr(" pv.bytes="); wnum(bytes);
    wstr(" pv.bits="); wnum(bits);
    wstr("\n");
    dump_data(data, bits);
}

static void dump_packet_view(unsigned long long rsp) {
    dump_packet_view_ptr(*(const unsigned char *const *)(rsp + 0x10));
}

static void dump_stack(unsigned long long rsp) {
    const unsigned long long *sp = (const unsigned long long *)rsp;
    int shown = 0;
    wstr("  stack-code-refs:");
    for (int i = 0; i < 64 && shown < 16; i++) {
        unsigned long long v = sp[i];
        if (v >= 0x140000000ULL && v < 0x14a000000ULL) {
            wstr("\n    ["); wnum((unsigned long long)i); wstr("] ");
            whex64(v);
            shown++;
        }
    }
    wstr("\n");
}

static int find_site(unsigned long long rip) {
    for (int i = 0; i < NSITES; i++)
        if (rip == SITES[i]) return i;
    return -1;
}

static LONG CALLBACK veh(struct _EXCEPTION_POINTERS *ep) {
    EXCEPTION_RECORD *rec = ep->ExceptionRecord;
    CONTEXT *ctx = ep->ContextRecord;

    if (rec->ExceptionCode == EXCEPTION_BREAKPOINT) {
        int site = find_site((unsigned long long)rec->ExceptionAddress);
        unsigned char *p;
        DWORD oldp;
        if (site < 0)
            return EXCEPTION_CONTINUE_SEARCH;

        EnterCriticalSection(&g_lock);
        // v44: identical byte-restore semantics as the proven v41 build
        // (restore orig byte; resume exactly as before — NO RIP rewinding,
        // NO TF single-step). The ONLY change: the site is left disarmed
        // and a dedicated background thread re-writes the 0xCC within
        // 2ms, so hooks never stay dead (the old TF-based re-arm was
        // swallowed by the game's exception machinery and silently
        // killed sites after the first sessions).
        p = (unsigned char *)SITES[site];
        VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &oldp);
        *p = orig[site];
        VirtualProtect(p, 1, oldp, &oldp);
        armed[site] = 0;   // re-arm thread will re-patch within 2ms
        InterlockedIncrement(&hit_count);

        wstr("=== HIT tid="); wnum(GetCurrentThreadId());
        wstr(" addr="); whex64(SITES[site]);
        wstr(" site="); wstr(SITE_NAMES[site]);
        wstr(" ===\n");

        if (site == PH_INCOMING_ENTRY) {
            wstr("  PH Incoming ENTRY\n");
            dump_packet_view_ptr((const unsigned char *)ctx->Rdx);
        } else if (site == PH_RET_EARLY || site == PH_RET_MAIN) {
            unsigned char result = (unsigned char)(ctx->Rax & 0xFF);
            wstr("  Incoming return="); whex8(result);
            wstr(result ? " (failure)\n" : " (success)\n");
            dump_packet_view(ctx->Rsp);
            if (site == PH_RET_MAIN)
                dump_reader((const unsigned char *)(ctx->Rsp - 0xd8));
        } else if (site == SC_EARLY_RETURN) {
            unsigned char result = (unsigned char)(ctx->Rax & 0xFF);
            wstr("  SC Incoming return="); whex8(result);
            wstr(result ? " (success)\n" : " (failure)\n");
            dump_reader((const unsigned char *)ctx->Rdi);
        } else if (site == SC_ERROR_RETURN) {
            wstr("  SC Incoming return=0x00 (failure)\n");
            wstr("  reject instruction: 0x14403e5e8 test byte ptr [rdi+0x29],2\n");
            dump_reader((const unsigned char *)ctx->Rdi);
        } else if (site == SC_CLOSE_CALL) {
            wstr("  call target=0x0000000144038220 reason=");
            whex8((unsigned char)(ctx->Rdx & 0xFF));
            wstr("\n");
            dump_reader((const unsigned char *)ctx->R15);
        } else if (site == SC_CONTROL_ENTRY) {
            wstr("  SC control entry r8=");
            whex8((unsigned char)(ctx->R8 & 0xFF));
            wstr(" r9="); whex8((unsigned char)(ctx->R9 & 0xFF));
            wstr("\n");
            dump_reader((const unsigned char *)ctx->Rdx);
        } else if (site == SC_PARSER_RETURN) {
            const unsigned char *header = (const unsigned char *)(ctx->Rbp - 0x80);
            unsigned char result = (unsigned char)(ctx->Rax & 0xFF);
            unsigned short ack = *(const unsigned short *)(header + 0x28);
            unsigned short seq = *(const unsigned short *)(header + 0x2a);
            unsigned long long chunks = *(const unsigned long long *)(header + 0x20);
            wstr("  Header parse return="); whex8(result);
            wstr(result ? " (success)\n" : " (failure)\n");
            wstr("  ack="); wnum(ack);
            wstr(" seq="); wnum(seq);
            wstr(" chunks="); wnum(chunks);
            wstr("\n");
            if (chunks > 8) chunks = 8;
            for (unsigned long long i = 0; i < chunks; i++) {
                wstr("  chunk["); wnum(i); wstr("]=");
                whex64(*(const unsigned int *)(header + 4 * i));
                wstr("\n");
            }
            dump_reader((const unsigned char *)ctx->R15);
        } else if (site == SC_HEADER_FAIL) {
            wstr("  header-fail call target=0x0000000144038220 reason=");
            whex8((unsigned char)(ctx->Rdx & 0xFF));
            wstr("\n");
            dump_reader((const unsigned char *)ctx->R15);
        } else if (site == SET_ERROR_BIT || site == SET_ERROR_DWORD) {
            wstr("  SetError call requested=");
            wnum(ctx->Rdx);
            wstr(" bits; error setter applies or [reader+0x29],2\n");
            dump_reader((const unsigned char *)ctx->Rcx);
			        } else if (site == PH_CALL_COMPONENT70) {
            wstr("  PH call [component+0x70]: rcx="); whex64(ctx->Rcx);
            wstr(" rax(vtable)="); whex64(ctx->Rax);
            wstr(" r9="); whex64(ctx->R9); wstr("\n");
            if (ctx->Rcx) {
                // component+0x14 = flag (from funcC disasm: mov [r14+0x14], esi)
                unsigned int flag = *(const unsigned int *)(ctx->Rcx + 0x14);
                wstr("  component+0x14="); wnum(flag); wstr("\n");
            }
        } else if (site == SC_INCOMING_MAIN_RET) {
            wstr("  SC Incoming main ret, eax="); whex8((unsigned char)(ctx->Rax & 0xFF));
            wstr("\n");
            dump_reader((const unsigned char *)ctx->R15);
        } else if (site == FBITREADER_CTOR) {
            wstr("  FBitReader ctor this="); whex64(ctx->Rcx);
            wstr(" data="); whex64(ctx->Rdx);
            wstr(" bits="); whex64(ctx->R8);
            wstr(" r9="); whex64(ctx->R9); wstr("\n");
            if (ctx->Rdx && ctx->R8 > 0 && ctx->R8 <= 4096) {
                unsigned long long n = (ctx->R8 + 7) / 8;
                if (n > 96) n = 96;
                wstr("  ctor data[0:"); wnum(n); wstr("]=");
                for (unsigned long long i = 0; i < n; i++) {
                    whex8(((const unsigned char *)ctx->Rdx)[i]);
                    wstr(" ");
                }
                wstr("\n");
            }
        } else if (site == PH_CMP_SIL) {
            unsigned char at_r13_p1 = ctx->R13 ? *(const unsigned char *)(ctx->R13 + 1) : 0xFF;
            unsigned char sil_val = (unsigned char)(ctx->Rsi & 0xFF);
            wstr("  PH cmp [r13+1]="); whex8(at_r13_p1);
            wstr(" vs sil="); whex8(sil_val);
            wstr(" equal="); wnum(at_r13_p1 == sil_val ? 1 : 0);
            wstr(" r13="); whex64(ctx->R13); wstr("\n");
            if (ctx->R13) {
                unsigned int count = *(const unsigned int *)(ctx->R13 + 0x1b0);
                unsigned long long array = *(const unsigned long long *)(ctx->R13 + 0x1a8);
                wstr("  components count="); wnum(count);
                wstr(" array="); whex64(array); wstr("\n");
                if (array && count > 0 && count < 16) {
                    for (unsigned int ci = 0; ci < count; ci++) {
                        unsigned long long comp = *(const unsigned long long *)(array + ci * 16);
                        wstr("  comp["); wnum(ci); wstr("]="); whex64(comp);
                        if (comp) {
                            unsigned long long vt = *(const unsigned long long *)comp;
                            wstr(" vtable="); whex64(vt);
                        }
                        wstr("\n");
                    }
                }
            }
        } else if (site == PH_CALL_FUNCC_ENTRY) {
            wstr("  PH call funcC: rcx="); whex64(ctx->Rcx);
            wstr(" r13="); whex64(ctx->R13); wstr("\n");
            if (ctx->R13) {
                unsigned int count = *(const unsigned int *)(ctx->R13 + 0x1b0);
                unsigned char flag = *(const unsigned char *)(ctx->R13 + 1);
                wstr("  [r13+0x1b0] components="); wnum(count);
                wstr(" [r13+1]="); whex8(flag); wstr("\n");
            }
        } else if (site == PH_CALL_VTABLE8) {
            wstr("  PH call [vtable+8]: rcx(component)="); whex64(ctx->Rcx);
            wstr(" rax(vtable)="); whex64(ctx->Rax); wstr("\n");
            if (ctx->Rcx) {
                unsigned long long vt = *(const unsigned long long *)ctx->Rcx;
                unsigned int flag14 = *(const unsigned int *)(ctx->Rcx + 0x14);
                wstr("  comp+0="); whex64(vt);
                wstr(" comp+0x14="); wnum(flag14);
                wstr(" comp+0x1b="); whex8(*(const unsigned char *)(ctx->Rcx + 0x1b));
                wstr("\n");
                // version-check fields read by comp Incoming 0x14408eac0:
                // [comp+0x150] = bit count for SerializeInt, [comp+0x158] =
                // expected value; mismatch -> SetError -> reject.
                unsigned int bits150 = *(const unsigned int *)(ctx->Rcx + 0x150);
                unsigned int exp158 = *(const unsigned int *)(ctx->Rcx + 0x158);
                wstr("  comp+0x150(bits)="); wnum(bits150);
                wstr(" comp+0x158(expected)="); wnum(exp158);
                wstr(" comp+0x15c="); whex8(*(const unsigned char *)(ctx->Rcx + 0x15c));
                wstr(" comp+0x160="); wnum(*(const unsigned int *)(ctx->Rcx + 0x160));
                wstr("\n");
                // v29: the validator (0x144097480) success also requires
                // *([comp+8])[0] == 0. Dump comp+8 ptr + its target bytes.
                unsigned long long p8 = *(const unsigned long long *)(ctx->Rcx + 8);
                wstr("  comp+8->"); whex64(p8); wstr(":");
                if (p8 > 0x10000 && p8 < 0x7FFFFFFFFFFFULL) {
                    for (int i = 0; i < 8; i++) {
                        wstr(" "); whex8(((const unsigned char *)p8)[i]);
                    }
                } else {
                    wstr(" <invalid>");
                }
                wstr("\n");
                // comp state + handshake fields
                wstr("  comp+0x10(state)="); whex8(*(const unsigned char *)(ctx->Rcx + 0x10));
                wstr(" comp+0x164="); wnum(*(const unsigned int *)(ctx->Rcx + 0x164));
                wstr(" comp+0x80="); wnum(*(const unsigned int *)(ctx->Rcx + 0x80));
                wstr("\n");
                // v30: handshake secret state compared at 0x14408e5fa-e616:
                // [rdi+0x11d] (qword), [rdi+0x125] (qword), [rdi+0x12d] (dword)
                wstr("  comp+0x11d=");
                whex64(*(const unsigned long long *)((unsigned char *)ctx->Rcx + 0x11d));
                wstr(" comp+0x125=");
                whex64(*(const unsigned long long *)((unsigned char *)ctx->Rcx + 0x125));
                wstr(" comp+0x12d=");
                whex64(*(const unsigned long long *)((unsigned char *)ctx->Rcx + 0x12d));
                wstr("\n");
            }
        } else if (site == SC_INCOMING_ENTRY_ADDR) {
            wstr("  SC Incoming ENTRY: rcx="); whex64(ctx->Rcx);
            wstr(" rdx(reader)="); whex64(ctx->Rdx);
            wstr(" r8="); whex64(ctx->R8);
            wstr(" r9="); whex64(ctx->R9); wstr("\n");
            if (ctx->Rdx)
                dump_reader((const unsigned char *)ctx->Rdx);
        } else if (site == PH_COUNT_COMPONENTS) {
            wstr("  PH count components=");
            if (ctx->R13)
                wnum(*(const unsigned int *)(ctx->R13 + 0x1b0));
            else
                wstr("<null>");
            wstr("\n");
        } else if (site == PH_COUNT_JS) {
            wstr("  PH count-1="); whex64(ctx->Rax & 0xFFFFFFFF);
            wstr(" js_taken="); wnum((ctx->EFlags & 0x80) ? 1 : 0);
            wstr("\n");
        } else if (site == PH_LOOP_ENTRY) {
            const unsigned char *reader = (const unsigned char *)(ctx->Rbp - 0x90);
            wstr("  PH loop index="); wnum(ctx->R15);
            wstr(" byte_offset="); wnum(ctx->R12); wstr("\n");
            dump_reader(reader);
            // Guard pages get swallowed by the game's own exception machinery
            // (proven: page protection flipped to plain RW with no VEH hit).
            // Use a hardware breakpoint instead: DR0 = reader+0x29, write trap.
            // The trap raises EXCEPTION_SINGLE_STEP with Dr6 bit0 set - the
            // same VEH path our int3 re-arm uses, so nothing can swallow it
            // without us seeing the record first.
            if (g_dr_armed == 0 && reader) {
                g_guard_reader = (unsigned char *)reader;
                ctx->Dr0 = (unsigned long long)(reader + 0x29);
                ctx->Dr7 = (ctx->Dr7 & ~0xFULL) | 0xD0001ULL;
                // bit0 LE (local enable), bits 16-19: RW=01 (write), LEN=00 (1 byte)
                g_dr_armed = 1;
                wstr("  DR0 armed on reader+0x29=");
                whex64(ctx->Dr0); wstr("\n");
            }
        } else if (site == TYPE_COMPARE) {
            wstr("  TYPE COMPARE: dl(packet)="); whex8((unsigned char)(ctx->Rdx & 0xFF));
            wstr(" r15b(expected)="); whex8((unsigned char)(ctx->R15 & 0xFF));
            wstr("\n");
            if (ctx->Rbp && ctx->Rsp && ctx->Rbp < ctx->Rsp + 0x2000 && ctx->Rbp > ctx->Rsp) {
                wstr("  ts[rbp-0x80]=");
                for (int i = 0; i < 8; i++) {
                    whex8(((const unsigned char *)(ctx->Rbp - 0x80))[i]);
                    wstr(" ");
                }
                wstr("\n");
            }
        } else if (site == BUNCH_PARSER_ENTRY) {
            // 0x14406bbf0: NZ bunch parser entry.
            // args: rcx=[rsi+0x1a38] ctx, rdx=24B out-struct (rbp-0x80), r8=reader(r15)
            wstr("  NZ BUNCH PARSER entry: rcx="); whex64(ctx->Rcx);
            wstr(" rdx(out)="); whex64(ctx->Rdx);
            wstr(" r8(reader)="); whex64(ctx->R8);
            wstr("\n");
            if (ctx->R8) {
                dump_reader((const unsigned char *)ctx->R8);
                // also dump 64 bytes of reader data at current bit pos
                // reader layout (from earlier dumps): +0x90 data ptr? no —
                // the FBitReader this-pointer layout: [rax]=vtable,
                // reader+0xa0 limit, +0xa8 pos, +0x90 data? verified in
                // HANDSHAKE_ANALYSIS: [rdx+0x90] buffer, +0xa0 limit,
                // +0xa8 pos.
                const unsigned char *rd = (const unsigned char *)ctx->R8;
                unsigned long long pos = *(const unsigned long long *)(rd + 0xa8);
                unsigned long long lim = *(const unsigned long long *)(rd + 0xa0);
                const unsigned char *dat = *(const unsigned char **)(rd + 0x90);
                if (dat && lim > pos && lim - pos >= 8) {
                    unsigned long long first = pos >> 3;
                    wstr("  bunch-in bytes from bit "); wnum(pos); wstr(":\n  ");
                    for (int i = 0; i < 40 && first + i < (lim + 7) / 8; i++) {
                        whex8(dat[first + i]); wstr(" ");
                    }
                    wstr("\n");
                }
            }
        } else if (site == PH_CALL_INCOMING40) {
            // 0x14235fc69: call [component_vtable+0x40] — per-component
            // Incoming dispatch. rax=vtable, rcx=component(rdi), r15/rdx=reader.
            wstr("  PH component Incoming: vtable="); whex64(ctx->Rax);
            wstr(" comp(rcx)="); whex64(ctx->Rcx);
            wstr(" target="); whex64(*(const unsigned long long *)(ctx->Rax + 0x40));
            wstr("\n");
        } else if (site == VALIDATOR_ENTRY) {
            wstr("  VALIDATOR entry: rcx="); whex64(ctx->Rcx);
            wstr(" rdx(reader)="); whex64(ctx->Rdx);
            wstr(" r8(struct)="); whex64(ctx->R8);
            wstr("\n");
            if (ctx->Rdx) {
                dump_reader((const unsigned char *)ctx->Rdx);
            }
            if (ctx->R8) {
                wstr("  struct[0:32]=");
                for (int i = 0; i < 32; i++) {
                    whex8(((const unsigned char *)ctx->R8)[i]);
                    wstr(" ");
                }
                wstr("\n");
            }
        } else if (site == VALIDATOR_BITREAD) {
            // 0x14409751b: test byte [rdx+rax], sil - r8 = bit position,
            // rax = reader->data, sil = single-bit mask, rbx = reader.
            unsigned long long bitpos = ctx->R8;
            unsigned char byte_val = 0, mask = (unsigned char)(ctx->Rsi & 0xFF);
            if (ctx->Rax && ctx->Rdx < 0x100000)
                byte_val = ((const unsigned char *)(ctx->Rax + ctx->Rdx))[0];
            wstr("  VALIDATOR bit read: bitpos(r8)="); wnum(bitpos);
            wstr(" bit_value="); wnum((byte_val & mask) ? 1 : 0);
            wstr(" mask="); whex8(mask);
            wstr(" reader_pos="); wnum(*(const unsigned long long *)(ctx->Rbx + 0xa8));
            wstr("\n");
        } else if (site == SETERROR_BODY2) {
            // rcx = reader being errored; [rsp] = return address = the EXACT
            // caller instruction+5 in the component. Dump caller code too.
            unsigned long long ret_addr = *(const unsigned long long *)ctx->Rsp;
            wstr("  SetError2 ENTRY: reader(rcx)="); whex64(ctx->Rcx);
            wstr(" requested(rdx)="); wnum(ctx->Rdx);
            wstr("\n  caller_ret_addr="); whex64(ret_addr);
            wstr(" caller_instr="); whex64(ret_addr - 5);
            wstr("\n  caller code[ret-37..ret-5+16]=");
            for (int i = -32; i < 16; i++) {
                whex8(((const unsigned char *)(ret_addr + i))[0]);
                wstr(" ");
            }
            wstr("\n");
            dump_reader((const unsigned char *)ctx->Rcx);
        }
        dump_stack(ctx->Rsp);

        // v44: NO trap-flag single-step re-arm — that mechanism is what
        // silently lost sites when the game swallowed the single-step.
        // The dedicated rearm_thread re-patches within 2ms. (DR0 write
        // traps are still handled in the SINGLE_STEP branch below; the
        // DR0 arm happens in the PH loop-entry handler.)
        LeaveCriticalSection(&g_lock);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (rec->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // DR0 write trap on reader+0x29? Dr6 bit0 = B0 triggered.
        if (g_dr_armed && (ctx->Dr6 & 1)) {
            unsigned long long trap_rip = (unsigned long long)ctx->Rip;
            g_dr_armed = 0;
            ctx->Dr0 = 0;
            ctx->Dr7 &= ~0xFULL;
            ctx->Dr6 = 0;
            EnterCriticalSection(&g_lock);
            wstr("=== DR0 WRITE TRAP tid="); wnum(GetCurrentThreadId());
            wstr("\n  faulting_rip="); whex64(trap_rip);
            wstr(" (exact instruction setting reader+0x29 error bit)\n");
            wstr("  code[Rip-32..Rip+32]=");
            for (int i = -32; i < 32; i++) {
                whex8(((const unsigned char *)(trap_rip + i))[0]);
                wstr(" ");
            }
            wstr("\n");
            if (g_guard_reader)
                dump_reader(g_guard_reader);
            LeaveCriticalSection(&g_lock);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        // v44: stray single-steps (including the game's own TF usage) are
        // now harmless: just clear TF and continue. Site re-arm is the
        // rearm_thread's job, not the TF handler's.
        ctx->EFlags &= ~0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

EXPORT BOOL WINAPI tracer_entry(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)h; (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        g_out = CreateFileA(OUT_PATH, GENERIC_WRITE, FILE_SHARE_READ,
                            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (g_out == INVALID_HANDLE_VALUE)
            return FALSE;
        InitializeCriticalSection(&g_lock);

        // Refuse to patch if the build does not match the dumped code.
        for (int i = 0; i < NSITES; i++) {
            if (*(const unsigned char *)SITES[i] != EXPECTED[i]) {
                wstr("SITE MISMATCH addr="); whex64(SITES[i]);
                wstr(" expected="); whex8(EXPECTED[i]);
                wstr(" actual="); whex8(*(const unsigned char *)SITES[i]);
                wstr("\n");
                CloseHandle(g_out);
                return FALSE;
            }
        }

        g_veh = AddVectoredExceptionHandler(1, veh);
        if (!g_veh) {
            CloseHandle(g_out);
            return FALSE;
        }
        // v44.1: patch ONLY the 4 diagnostic sites. The other 23 hot-path
        // sites (PH loop etc., firing every packet) stay pristine — the
        // v44 run showed patching them all + disk-flush-per-write froze
        // the reliable layer (cli_ack stuck at 0xfffc, 30s timeout).
        for (int k = 0; k < N_ARM_SITES; k++) {
            int i = ARM_SITES[k];
            unsigned char *p = (unsigned char *)SITES[i];
            DWORD oldp;
            VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &oldp);
            orig[i] = *p;
            *p = 0xCC;
            VirtualProtect(p, 1, oldp, &oldp);
            armed[i] = 1;
        }
        // v44: persistent re-arm thread (fixes the one-shot hook loss).
        g_rearm_stop = 0;
        g_rearm_thread = CreateThread(NULL, 0, rearm_thread, NULL, 0, NULL);
        wstr("veh_tracer3 v44.1 armed: 4 diagnostic sites only, no flush\n");
        return TRUE;
    }
    if (reason == DLL_PROCESS_DETACH) {
        if (g_rearm_thread) {
            g_rearm_stop = 1;
            WaitForSingleObject(g_rearm_thread, 2000);
            CloseHandle(g_rearm_thread);
            g_rearm_thread = NULL;
        }
        for (int i = 0; i < NSITES; i++) {
            if (armed[i]) {
                unsigned char *p = (unsigned char *)SITES[i];
                DWORD oldp;
                VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &oldp);
                *p = orig[i];
                VirtualProtect(p, 1, oldp, &oldp);
                armed[i] = 0;
            }
        }
        if (g_veh)
            RemoveVectoredExceptionHandler(g_veh);
        wstr("veh_tracer3 v44 detached\n");
        CloseHandle(g_out);
    }
    return TRUE;
}
