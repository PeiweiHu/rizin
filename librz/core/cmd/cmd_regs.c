// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

static RzList *filter_reg_items(RzReg *reg, RZ_NULLABLE const char *filter) {
	rz_return_val_if_fail(reg, NULL);
	// default
	if (!filter || !*filter) {
		// default selection (only gpr, omit smaller regs that are fully covered by larger ones)
		return rz_reg_filter_items_covered(reg->regset[RZ_REG_TYPE_GPR].regs);
	}
	// all
	if (!strcmp(filter, "all")) {
		return rz_list_clone(reg->allregs);
	}
	// bit size
	char *end = NULL;
	unsigned long bits = strtoul(filter, &end, 0);
	if (!*end) {
		RzList *ret = rz_list_new();
		if (!ret) {
			return NULL;
		}
		RzListIter *iter;
		RzRegItem *ri;
		rz_list_foreach (reg->regset[RZ_REG_TYPE_GPR].regs, iter, ri) {
			if (ri->size == bits) {
				rz_list_push(ret, ri);
			}
		}
		return ret;
	}
	// type
	int type = rz_reg_type_by_name(filter);
	if (type >= 0) {
		return rz_list_clone(reg->regset[type].regs);
	}
	// single register name
	RzRegItem *ri = rz_reg_get(reg, filter, RZ_REG_TYPE_ANY);
	if (!ri) {
		return NULL;
	}
	return rz_list_new_from_array((const void **)&ri, 1);
}

static void print_reg_not_found(const char *arg) {
	RZ_LOG_ERROR("No such register or register type: \"%s\"\n", rz_str_get(arg));
}

RZ_IPI RzCmdStatus rz_regs_handler(RzCore *core, RzReg *reg, int argc, const char **argv, RzCmdStateOutput *state) {
	const char *filter = argc > 1 ? argv[1] : NULL;
	RzList *ritems = filter_reg_items(reg, filter);
	if (!ritems) {
		print_reg_not_found(filter);
		return RZ_CMD_STATUS_ERROR;
	}
	// TODO: print regs
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_regs_columns_handler(RzCore *core, RzReg *reg, int argc, const char **argv) {
	const char *filter = argc > 1 ? argv[1] : NULL;
	RzList *ritems = filter_reg_items(reg, filter);
	if (!ritems) {
		print_reg_not_found(filter);
		return RZ_CMD_STATUS_ERROR;
	}
	// TODO: print regs
	return RZ_CMD_STATUS_OK;
}
