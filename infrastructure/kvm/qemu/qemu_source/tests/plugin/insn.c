/*
 * Copyright (C) 2018, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint64_t insn_count;
static bool do_inline;

static void vcpu_insn_exec_before(unsigned int cpu_index, void *udata)
{
    static uint64_t last_pc;
    uint64_t this_pc = GPOINTER_TO_UINT(udata);
    if (this_pc == last_pc) {
        g_autofree gchar *out = g_strdup_printf("detected repeat execution @ 0x%"
                                                PRIx64 "\n", this_pc);
        qemu_plugin_outs(out);
    }
    last_pc = this_pc;
    insn_count++;
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    size_t i;

    for (i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

        if (do_inline) {
            qemu_plugin_register_vcpu_insn_exec_inline(
                insn, QEMU_PLUGIN_INLINE_ADD_U64, &insn_count, 1);
        } else {
            uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, vcpu_insn_exec_before, QEMU_PLUGIN_CB_NO_REGS,
                GUINT_TO_POINTER(vaddr));
        }
    }
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_autofree gchar *out = g_strdup_printf("insns: %" PRIu64 "\n", insn_count);
    qemu_plugin_outs(out);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_autofree char **tokens = g_strsplit(opt, "=", 2);
        if (g_strcmp0(tokens[0], "inline") == 0) {
            if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &do_inline)) {
                fprintf(stderr, "boolean argument parsing failed: %s\n", opt);
                return -1;
            }
        } else {
            fprintf(stderr, "option parsing failed: %s\n", opt);
            return -1;
        }
    }

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
