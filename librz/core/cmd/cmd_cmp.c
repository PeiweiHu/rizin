// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_cmp.h"

RZ_API void rz_core_cmpwatch_free(RzCoreCmpWatcher *w) {
	free(w->ndata);
	free(w->odata);
	free(w);
}

RZ_API RzCoreCmpWatcher *rz_core_cmpwatch_get(RzCore *core, ut64 addr) {
	RzListIter *iter;
	RzCoreCmpWatcher *w;
	rz_list_foreach (core->watchers, iter, w) {
		if (addr == w->addr) {
			return w;
		}
	}
	return NULL;
}

RZ_API bool rz_core_cmpwatch_add(RzCore *core, ut64 addr, int size, const char *cmd) {
	RzCoreCmpWatcher *cmpw;
	if (size < 1) {
		return false;
	}
	cmpw = rz_core_cmpwatch_get(core, addr);
	if (!cmpw) {
		cmpw = RZ_NEW(RzCoreCmpWatcher);
		if (!cmpw) {
			return false;
		}
		cmpw->addr = addr;
	}
	cmpw->size = size;
	snprintf(cmpw->cmd, sizeof(cmpw->cmd), "%s", cmd);
	cmpw->odata = NULL;
	cmpw->ndata = malloc(size);
	if (!cmpw->ndata) {
		free(cmpw);
		return false;
	}
	rz_io_read_at(core->io, addr, cmpw->ndata, size);
	rz_list_append(core->watchers, cmpw);
	return true;
}

RZ_API int rz_core_cmpwatch_del(RzCore *core, ut64 addr) {
	int ret = false;
	RzCoreCmpWatcher *w;
	RzListIter *iter, *iter2;
	rz_list_foreach_safe (core->watchers, iter, iter2, w) {
		if (w->addr == addr || addr == UT64_MAX) {
			rz_list_delete(core->watchers, iter);
			ret = true;
		}
	}
	return ret;
}

RZ_API void rz_core_cmpwatch_show(RzCore *core, ut64 addr, RzCompareOutputMode mode) {
	char cmd[128];
	RzListIter *iter;
	RzCoreCmpWatcher *w;
	rz_list_foreach (core->watchers, iter, w) {
		int is_diff = w->odata ? memcmp(w->odata, w->ndata, w->size) : 0;
		switch (mode) {
		case RZ_COMPARE_MODE_RIZIN:
			rz_cons_printf("cw 0x%08" PFMT64x " %d %s%s\n",
				w->addr, w->size, w->cmd, is_diff ? " # differs" : "");
			break;
		case RZ_COMPARE_MODE_DIFF: // diff
			if (is_diff) {
				rz_cons_printf("0x%08" PFMT64x " has changed\n", w->addr);
			}
		case RZ_COMPARE_MODE_DEFAULT:
			rz_cons_printf("0x%08" PFMT64x "%s\n", w->addr, is_diff ? " modified" : "");
			snprintf(cmd, sizeof(cmd), "%s@%" PFMT64d "!%d",
				w->cmd, w->addr, w->size);
			rz_core_cmd0(core, cmd);
			break;
		default:
			rz_warn_if_reached();
		}
	}
}

RZ_API bool rz_core_cmpwatch_update(RzCore *core, ut64 addr) {
	RzCoreCmpWatcher *w;
	RzListIter *iter;
	rz_list_foreach (core->watchers, iter, w) {
		free(w->odata);
		w->odata = w->ndata;
		w->ndata = malloc(w->size);
		if (!w->ndata) {
			return false;
		}
		rz_io_read_at(core->io, w->addr, w->ndata, w->size);
	}
	return !rz_list_empty(core->watchers);
}

RZ_API bool rz_core_cmpwatch_revert(RzCore *core, ut64 addr) {
	RzCoreCmpWatcher *w;
	int ret = false;
	RzListIter *iter;
	rz_list_foreach (core->watchers, iter, w) {
		if (w->addr == addr || addr == UT64_MAX) {
			if (w->odata) {
				free(w->ndata);
				w->ndata = w->odata;
				w->odata = NULL;
				ret = true;
			}
		}
	}
	return ret;
}

static int rizin_compare_words(RzCore *core, ut64 of, ut64 od, int len, int ws) {
	int i;
	bool useColor = rz_config_get_i(core->config, "scr.color") != 0;
	utAny v0, v1;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	for (i = 0; i < len; i += ws) {
		memset(&v0, 0, sizeof(v0));
		memset(&v1, 0, sizeof(v1));
		rz_io_read_at(core->io, of + i, (ut8 *)&v0, ws);
		rz_io_read_at(core->io, od + i, (ut8 *)&v1, ws);
		char ch = (v0.v64 == v1.v64) ? '=' : '!';
		const char *color = useColor ? ch == '=' ? "" : pal->graph_false : "";
		const char *colorEnd = useColor ? Color_RESET : "";

		if (useColor) {
			rz_cons_printf("%s0x%08" PFMT64x "  " Color_RESET, pal->offset, of + i);
		} else {
			rz_cons_printf("0x%08" PFMT64x "  ", of + i);
		}
		switch (ws) {
		case 1:
			rz_cons_printf("%s0x%02x %c 0x%02x%s\n", color,
				(ut32)(v0.v8 & 0xff), ch, (ut32)(v1.v8 & 0xff), colorEnd);
			break;
		case 2:
			rz_cons_printf("%s0x%04hx %c 0x%04hx%s\n", color,
				v0.v16, ch, v1.v16, colorEnd);
			break;
		case 4:
			rz_cons_printf("%s0x%08" PFMT32x " %c 0x%08" PFMT32x "%s\n", color,
				v0.v32, ch, v1.v32, colorEnd);
			//rz_core_cmdf (core, "fd@0x%"PFMT64x, v0.v32);
			if (v0.v32 != v1.v32) {
				//	rz_core_cmdf (core, "fd@0x%"PFMT64x, v1.v32);
			}
			break;
		case 8:
			rz_cons_printf("%s0x%016" PFMT64x " %c 0x%016" PFMT64x "%s\n",
				color, v0.v64, ch, v1.v64, colorEnd);
			//rz_core_cmdf (core, "fd@0x%"PFMT64x, v0.v64);
			if (v0.v64 != v1.v64) {
				//	rz_core_cmdf (core, "fd@0x%"PFMT64x, v1.v64);
			}
			break;
		}
	}
	return 0;
}

static int rizin_compare_unified(RzCore *core, ut64 of, ut64 od, int len) {
	int i, min, inc = 16;
	ut8 *f, *d;
	if (len < 1) {
		return false;
	}
	f = malloc(len);
	if (!f) {
		return false;
	}
	d = malloc(len);
	if (!d) {
		free(f);
		return false;
	}
	rz_io_read_at(core->io, of, f, len);
	rz_io_read_at(core->io, od, d, len);
	int headers = B_IS_SET(core->print->flags, RZ_PRINT_FLAGS_HEADER);
	if (headers) {
		B_UNSET(core->print->flags, RZ_PRINT_FLAGS_HEADER);
	}
	for (i = 0; i < len; i += inc) {
		min = RZ_MIN(16, (len - i));
		if (!memcmp(f + i, d + i, min)) {
			rz_cons_printf("  ");
			rz_print_hexdiff(core->print, of + i, f + i, of + i, f + i, min, 0);
		} else {
			rz_cons_printf("- ");
			rz_print_hexdiff(core->print, of + i, f + i, od + i, d + i, min, 0);
			rz_cons_printf("+ ");
			rz_print_hexdiff(core->print, od + i, d + i, of + i, f + i, min, 0);
		}
	}
	if (headers) {
		B_SET(core->print->flags, RZ_PRINT_FLAGS_HEADER);
	}
	return true;
}

static bool core_cmp_bits(RzCore *core, ut64 addr) {
	const bool scr_color = rz_config_get_i(core->config, "scr.color");
	int i;
	ut8 a, b;
	if (!rz_io_read_at(core->io, core->offset, &a, 1) || !rz_io_read_at(core->io, addr, &b, 1)) {
		return false;
	}
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	const char *color = scr_color ? pal->offset : "";
	const char *color_end = scr_color ? Color_RESET : "";
	if (rz_config_get_i(core->config, "hex.header")) {
		char *n = rz_str_newf("0x%08" PFMT64x, core->offset);
		const char *extra = rz_str_pad(' ', strlen(n) - 10);
		free(n);
		rz_cons_printf("%s- offset -%s  7 6 5 4 3 2 1 0%s\n", color, extra, color_end);
	}
	color = scr_color ? pal->graph_false : "";
	color_end = scr_color ? Color_RESET : "";

	rz_cons_printf("%s0x%08" PFMT64x "%s  ", color, core->offset, color_end);
	for (i = 7; i >= 0; i--) {
		bool b0 = (a & 1 << i) ? 1 : 0;
		bool b1 = (b & 1 << i) ? 1 : 0;
		color = scr_color ? (b0 == b1) ? "" : b0 ? pal->graph_true
							 : pal->graph_false
				  : "";
		color_end = scr_color ? Color_RESET : "";
		rz_cons_printf("%s%d%s ", color, b0, color_end);
	}
	color = scr_color ? pal->graph_true : "";
	color_end = scr_color ? Color_RESET : "";
	rz_cons_printf("\n%s0x%08" PFMT64x "%s  ", color, addr, color_end);
	for (i = 7; i >= 0; i--) {
		bool b0 = (a & 1 << i) ? 1 : 0;
		bool b1 = (b & 1 << i) ? 1 : 0;
		color = scr_color ? (b0 == b1) ? "" : b1 ? pal->graph_true
							 : pal->graph_false
				  : "";
		color_end = scr_color ? Color_RESET : "";
		rz_cons_printf("%s%d%s ", color, b1, color_end);
	}
	rz_cons_newline();

	return true;
}

// c
RZ_IPI RzCmdStatus rz_cmd_cmp_string_handler(RzCore *core, int argc, const char **argv) {
	ut64 val = UT64_MAX;
	char *unescaped = strdup(argv[1]);
	int len = rz_str_unescape(unescaped);
	val = rz_cmp_compare(core, (ut8 *)unescaped, len, RZ_COMPARE_MODE_DEFAULT);
	free(unescaped);
	if (val != UT64_MAX) {
		core->num->value = val;
		return RZ_CMD_STATUS_OK;
	}
	return RZ_CMD_STATUS_ERROR;
}

// c1
RZ_IPI RzCmdStatus rz_cmd_cmp_num1_handler(RzCore *core, int argc, const char **argv) {
	return core_cmp_bits(core, rz_num_math(core->num, argv[1])) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// c2
RZ_IPI RzCmdStatus rz_cmd_cmp_num2_handler(RzCore *core, int argc, const char **argv) {
	ut16 v16 = (ut16)rz_num_math(core->num, argv[1]);
	ut64 val = rz_cmp_compare(core, (ut8 *)&v16, sizeof(v16), RZ_COMPARE_MODE_DEFAULT);
	if (val != UT64_MAX) {
		core->num->value = val;
		return RZ_CMD_STATUS_OK;
	}
	return RZ_CMD_STATUS_ERROR;
}

// c4
RZ_IPI RzCmdStatus rz_cmd_cmp_num4_handler(RzCore *core, int argc, const char **argv) {
	ut32 v32 = (ut32)rz_num_math(core->num, argv[1]);
	ut64 val = rz_cmp_compare(core, (ut8 *)&v32, sizeof(v32), RZ_COMPARE_MODE_DEFAULT);
	if (val != UT64_MAX) {
		core->num->value = val;
		return RZ_CMD_STATUS_OK;
	}
	return RZ_CMD_STATUS_ERROR;
}

// c8
RZ_IPI RzCmdStatus rz_cmd_cmp_num8_handler(RzCore *core, int argc, const char **argv) {
	ut64 v64 = rz_num_math(core->num, argv[1]);
	ut64 val = rz_cmp_compare(core, (ut8 *)&v64, sizeof(v64), RZ_COMPARE_MODE_DEFAULT);
	if (val != UT64_MAX) {
		core->num->value = val;
		return RZ_CMD_STATUS_OK;
	}
	return RZ_CMD_STATUS_ERROR;
}

// cc
RZ_IPI RzCmdStatus rz_cmd_cmp_hex_block_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr = rz_num_math(core->num, argv[1]);
	bool col = core->cons->columns > 123;
	ut8 *b = malloc(core->blocksize);
	if (b) {
		memset(b, 0xff, core->blocksize);
		rz_io_read_at(core->io, addr, b, core->blocksize);
		rz_print_hexdiff(core->print, core->offset, core->block, addr, b, core->blocksize, col);
	}
	free(b);
	return RZ_CMD_STATUS_OK;
}

// ccc
RZ_IPI RzCmdStatus rz_cmd_cmp_hex_diff_lines_handler(RzCore *core, int argc, const char **argv) {
	ut32 oflags = core->print->flags;
	core->print->flags |= RZ_PRINT_FLAGS_DIFFOUT;
	ut64 addr = rz_num_math(core->num, argv[1]);
	bool col = core->cons->columns > 123;
	ut8 *b = malloc(core->blocksize);
	if (b) {
		memset(b, 0xff, core->blocksize);
		rz_io_read_at(core->io, addr, b, core->blocksize);
		rz_print_hexdiff(core->print, core->offset, core->block, addr, b, core->blocksize, col);
	}
	free(b);
	core->print->flags = oflags;
	return RZ_CMD_STATUS_OK;
}

// ccd
RZ_IPI RzCmdStatus rz_cmd_cmp_disasm_handler(RzCore *core, int argc, const char **argv) {
	RzList *cmp = rz_cmp_disasm(core, argv[1]);
	bool ret = rz_cmp_disasm_print(core, cmp, false);
	rz_list_free(cmp);
	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cf
RZ_IPI RzCmdStatus rz_cmd_cmp_file_handler(RzCore *core, int argc, const char **argv) {
	FILE *fd = rz_sys_fopen(argv[1], "rb");
	ut64 val = UT64_MAX;
	if (!fd) {
		RZ_LOG_ERROR("Cannot open file: %s\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	RzCmdStatus stat = RZ_CMD_STATUS_ERROR;
	ut8 *buf = (ut8 *)malloc(core->blocksize);
	if (!buf) {
		goto return_goto;
	}
	if (fread(buf, 1, core->blocksize, fd) < 1) {
		RZ_LOG_ERROR("Cannot read file: %s\n", argv[1]);
		goto return_goto;
	}
	val = rz_cmp_compare(core, buf, core->blocksize, RZ_COMPARE_MODE_DEFAULT);
	if (val == UT64_MAX) {
		goto return_goto;
	}
	core->num->value = val;
	stat = RZ_CMD_STATUS_OK;

return_goto:
	free(buf);
	fclose(fd);
	return stat;
}

// cu
RZ_IPI RzCmdStatus rz_cmd_cmp_unified_handler(RzCore *core, int argc, const char **argv) {
	rizin_compare_unified(core, core->offset, rz_num_math(core->num, argv[1]), core->blocksize);
	return RZ_CMD_STATUS_OK;
}

// cu1
RZ_IPI RzCmdStatus rz_cmd_cmp_unified1_handler(RzCore *core, int argc, const char **argv) {
	rizin_compare_words(core, core->offset, rz_num_math(core->num, argv[1]), core->blocksize, 1);
	return RZ_CMD_STATUS_OK;
}

// cu2
RZ_IPI RzCmdStatus rz_cmd_cmp_unified2_handler(RzCore *core, int argc, const char **argv) {
	rizin_compare_words(core, core->offset, rz_num_math(core->num, argv[1]), core->blocksize, 2);
	return RZ_CMD_STATUS_OK;
}

// cu4
RZ_IPI RzCmdStatus rz_cmd_cmp_unified4_handler(RzCore *core, int argc, const char **argv) {
	rizin_compare_words(core, core->offset, rz_num_math(core->num, argv[1]), core->blocksize, 4);
	return RZ_CMD_STATUS_OK;
}

// cu8
RZ_IPI RzCmdStatus rz_cmd_cmp_unified8_handler(RzCore *core, int argc, const char **argv) {
	rizin_compare_words(core, core->offset, rz_num_math(core->num, argv[1]), core->blocksize, 8);
	return RZ_CMD_STATUS_OK;
}

// cud
RZ_IPI RzCmdStatus rz_cmd_cmp_unified_disasm_handler(RzCore *core, int argc, const char **argv) {
	RzList *cmp = rz_cmp_disasm(core, argv[1]);
	bool ret = rz_cmp_disasm_print(core, cmp, true);
	rz_list_free(cmp);
	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cw
RZ_IPI RzCmdStatus rz_cmd_cmp_add_memory_watcher_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_cmpwatch_add(core, core->offset, atoi(argv[0]), argv[1]) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cwl
RZ_IPI RzCmdStatus rz_cmd_cmp_list_compare_watchers_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *output) {
	RzOutputMode mode = output->mode;
	switch (mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_core_cmpwatch_show(core, UT64_MAX, RZ_COMPARE_MODE_DEFAULT);
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		rz_core_cmpwatch_show(core, UT64_MAX, RZ_COMPARE_MODE_RIZIN);
		break;
	default:
		rz_warn_if_reached();
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

// cwr
RZ_IPI RzCmdStatus rz_cmd_cmp_reset_watcher_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_cmpwatch_revert(core, core->offset) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cwu
RZ_IPI RzCmdStatus rz_cmd_cmp_update_watcher_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_cmpwatch_update(core, core->offset) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cx
RZ_IPI RzCmdStatus rz_cmd_cmp_hexpair_string_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *output) {
	RzCompareOutputMode mode;
	RzOutputMode omode = output->mode;
	switch (omode) {
	case RZ_OUTPUT_MODE_STANDARD:
		mode = RZ_COMPARE_MODE_DEFAULT;
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		mode = RZ_COMPARE_MODE_RIZIN;
		break;
	default:
		rz_warn_if_reached();
		return RZ_CMD_STATUS_ERROR;
	}
	RzStrBuf *concat_argv = rz_strbuf_new(NULL);
	for (int i = 0; i < argc; i++) {
		rz_strbuf_append(concat_argv, argv[i]);
	}
	char *input = rz_strbuf_drain(concat_argv);
	rz_strbuf_free(concat_argv);

	unsigned char *buf;
	ut64 val;
	int ret = false;
	if (!(buf = (ut8 *)malloc(strlen(input) + 1))) {
		goto return_goto;
	}
	ret = rz_hex_bin2str(core->block, strlen(input) / 2, (char *)buf);
	for (int i = 0; i < ret * 2; i++) {
		if (input[i] == '.') {
			input[i] = buf[i];
		}
	}
	ret = rz_hex_str2bin(input, buf);
	if (ret < 1) {
		RZ_LOG_ERROR("Cannot parse hexpair\n");
		ret = false;
		goto return_goto;
	}

	val = rz_cmp_compare(core, buf, ret, mode);
	if (val == UT64_MAX) {
		ret = false;
		goto return_goto;
	}
	core->num->value = val;
	ret = true;

return_goto:
	free(input);
	free(buf);
	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cX
RZ_IPI RzCmdStatus rz_cmd_cmp_hex_block_hexdiff_handler(RzCore *core, int argc, const char **argv) {
	unsigned char *buf = malloc(core->blocksize);
	bool ret = false;
	if (!buf) {
		goto return_goto;
	}
	if (!rz_io_read_at(core->io, rz_num_math(core->num, argv[1]), buf, core->blocksize)) {
		RZ_LOG_ERROR("Cannot read hexdump\n");
		goto return_goto;
	}

	ut64 val = rz_cmp_compare(core, buf, core->blocksize, RZ_COMPARE_MODE_DEFAULT);
	if (val == UT64_MAX) {
		goto return_goto;
	}
	core->num->value = val;
	ret = true;

return_goto:
	free(buf);
	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}
