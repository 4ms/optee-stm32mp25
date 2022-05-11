// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, STMicroelectronics
 * Author: Yannick Fertre <yannick.fertre@st.com> for STMicroelectronics.
 */
#include <display.h>
#include <drivers/clk.h>
#include <drivers/clk_dt.h>
#include <drivers/frame_buffer.h>
#include <drivers/stm32_etzpc.h>
#include <drivers/stm32_firewall.h>
#include <drivers/stm32_gpio.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <stm32_util.h>
#include <trace.h>
#include <types_ext.h>

struct ltdc_device {
	vaddr_t regs;
	struct io_pa_va io_base;
	struct clk *clock;
	struct stm32_pinctrl_list *pinctrl_list;
	struct itr_handler *itr0;
	struct itr_handler *itr1;
	int pinctrl_count;
	bool end_of_frame;
	bool activate;
};

#define LTDC_IDR	0x0000
#define LTDC_LCR	0x0004
#define LTDC_SSCR	0x0008
#define LTDC_BPCR	0x000C
#define LTDC_AWCR	0x0010
#define LTDC_TWCR	0x0014
#define LTDC_GCR	0x0018
#define LTDC_SRCR	0x0024
#define LTDC_IER2	0x0064
#define LTDC_ISR2	0x0068
#define LTDC_ICR2	0x006C
#define IER_LIE		BIT(0)		/* Line Interrupt Enable */
#define IER_FUWIE	BIT(1)		/* Fifo Underrun Warning Interrupt Enable */
#define IER_TERRIE	BIT(2)		/* Transfer ERRor Interrupt Enable */
#define IER_RRIE	BIT(3)		/* Register Reload Interrupt Enable */
#define IER_FUKIE	BIT(6)		/* Fifo Underrun Killing Interrupt Enable */
#define IER_CRCIE	BIT(7)		/* CRC Error Interrupt Enable */
#define IER_FURIE	BIT(8)		/* Fifo Underrun at Rotation Interrupt Enable */
#define ISR_LIF		BIT(0)		/* Line Interrupt Flag */
#define ISR_FUWIF	BIT(1)		/* Fifo Underrun Warning Interrupt Flag */
#define ISR_TERRIF	BIT(2)		/* Transfer ERRor Interrupt Flag */
#define ISR_RRIF	BIT(3)		/* Register Reload Interrupt Flag */
#define ISR_FUKIF	BIT(6)		/* Fifo Underrun Killing Interrupt Flag */
#define ISR_CRCIF	BIT(7)		/* CRC Error Interrupt Flag */
#define ISR_FURIF	BIT(8)		/* Fifo Underrun at Rotation Interrupt Flag */

#define ID_HWVER_40100		0x040100
#define GCR_LTDCEN		BIT(0)
#define LTDC_BPCR_AHBP		GENMASK_32(27, 16)
#define LTDC_BPCR_AVBP		GENMASK_32(10, 0)
#define LTDC_LXWHPCR_WHSTPOS	GENMASK_32(11, 0)
#define LTDC_LXWHPCR_WHSPPOS	GENMASK_32(31, 16)
#define LTDC_LXWVPCR_WVSTPOS	GENMASK_32(11, 0)
#define LTDC_LXWVPCR_WVSPPOS	GENMASK_32(31, 16)
#define LTDC_LXCFBLR_CFBLL	GENMASK_32(12, 0)
#define LTDC_LXCFBLR_CFBP	GENMASK_32(28, 16)
#define LTDC_LXPFCR_PF		GENMASK_32(2,  0)
#define LTDC_LXCACR_CONSTA	GENMASK_32(7, 0)
#define LXBFCR_BF2		GENMASK_32(2, 0)
#define LXBFCR_BF1		GENMASK_32(10, 8)
#define LTDC_LXCFBLNR_CFBLNBR	GENMASK_32(10, 0)
#define LTDC_LXDCCR_DCBLUE	GENMASK_32(7, 0)
#define LTDC_LXDCCR_DCGREEN	GENMASK_32(15, 8)
#define LTDC_LXDCCR_DCRED	GENMASK_32(23, 16)
#define LTDC_LXDCCR_DCALPHA	GENMASK_32(31, 24)
#define LTDC_LXCFBAR_CFBADD	GENMASK_32(31, 0)

enum ltdc_pix_fmt {
	LXPFCR_PF_ARGB8888,
	LXPFCR_PF_ABGR8888,
	LXPFCR_PF_RGBA8888,
	LXPFCR_PF_BGRA8888,
	LXPFCR_PF_RGB565,
	LXPFCR_PF_BGR565,
	LXPFCR_PF_RGB888
};

/* Within mask LTDC_LXBFCR_BF1 */
#define LXBFCR_BF1_PAXCA	0x600	/* Pixel Alpha x Constant Alpha */
#define LXBFCR_BF1_CA		0x400	/* Constant Alpha */
/* Within mask LTDC_LXBFCR_BF2 */
#define LXBFCR_BF2_PAXCA	0x007	/* 1 - (Pixel Alpha x Constant Alpha) */
#define LXBFCR_BF2_CA		0x005	/* 1 - Constant Alpha */

#define LAY_OFS(a)	(0x100 + (a))
#define LTDC_L2RCR	LAY_OFS(0x108)
#define LXCR_RCR_IMR	BIT(0)
#define LXCR_RCR_VBR	BIT(1)
#define LTDC_L2CR	LAY_OFS(0x10c)
#define LXCR_LEN	BIT(0)
#define LTDC_L2WHPCR	LAY_OFS(0x110)
#define LTDC_L2WVPCR	LAY_OFS(0x114)
#define LTDC_L2PFCR	LAY_OFS(0x11c)
#define LTDC_L2CACR	LAY_OFS(0x120)
#define LTDC_L2DCCR	LAY_OFS(0x124)
#define LTDC_L2BFCR	LAY_OFS(0x128)
#define LTDC_L2CFBAR	LAY_OFS(0x134)
#define LTDC_L2CFBLR	LAY_OFS(0x138)
#define LTDC_L2CFBLNR	LAY_OFS(0x13c)

/* Timeout when polling on status */
#define LTDC_TIMEOUT_US	U(100000)

#if (TRACE_LEVEL < TRACE_DEBUG)
#define dump_reg_ltdc(...)   ((void)0)
#else
#define DUMP_REG(name)	DMSG("%-16s (%#05x) 0x%08x\n", \
			     #name, name, io_read32(base + name))

static void dump_reg_ltdc(vaddr_t base)
{
	DUMP_REG(LTDC_IDR);
	DUMP_REG(LTDC_LCR);
	DUMP_REG(LTDC_SSCR);
	DUMP_REG(LTDC_BPCR);
	DUMP_REG(LTDC_AWCR);
	DUMP_REG(LTDC_TWCR);

	DUMP_REG(LTDC_L2CR);
	DUMP_REG(LTDC_L2WHPCR);
	DUMP_REG(LTDC_L2WVPCR);
	DUMP_REG(LTDC_L2PFCR);
	DUMP_REG(LTDC_L2CACR);
	DUMP_REG(LTDC_L2DCCR);
	DUMP_REG(LTDC_L2BFCR);
	DUMP_REG(LTDC_L2CFBAR);
	DUMP_REG(LTDC_L2CFBLR);
	DUMP_REG(LTDC_L2CFBLNR);
}
#endif

static TEE_Result stm32_ltdc_init(void *device)
{
	struct ltdc_device *ldev = device;
	TEE_Result ret = TEE_SUCCESS;
	uint32_t gcr = 0;
	const struct stm32_firewall_cfg sec_cfg[] = {
		{ FWLL_SEC_RW | FWLL_NSEC_READ | FWLL_MASTER(0) },
		{ }, /* Null terminated */
	};

	clk_enable(ldev->clock);

	gcr = io_read32(ldev->regs + LTDC_GCR);
	if (!(gcr & GCR_LTDCEN)) {
		EMSG("CRTC must be started first");
		ret = TEE_ERROR_GENERIC;
		goto err;
	}

	ret = stm32_pinctrl_set_secure_cfg(ldev->pinctrl_list, true);
	if (ret) {
		/* Restore pins to non-secure state, should not fail */
		if (stm32_pinctrl_set_secure_cfg(ldev->pinctrl_list, false))
			panic();

		goto err;
	}

	/* LTDC goes non-secure read, secure write */
	ret = stm32_firewall_set_config(virt_to_phys((void *)ldev->regs),
					0, sec_cfg);
	if (ret)
		goto err;

	return ret;
err:
	clk_disable(ldev->clock);

	return ret;
}

static TEE_Result stm32_ltdc_final(void *device)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct ltdc_device *ldev = device;
	uint64_t timeout_ref = 0;
	const struct stm32_firewall_cfg sec_cfg[] = {
		{ FWLL_NSEC_RW | FWLL_MASTER(0) },
		{ }, /* Null terminated */
	};

	if (!ldev->activate)
		goto out;

	/* Disable secure layer */
	io_clrbits32(ldev->regs + LTDC_L2CR, LXCR_LEN);

	/* Reload configuration immediately. */
	io_write32(ldev->regs + LTDC_L2RCR, LXCR_RCR_VBR);

	ldev->end_of_frame = false;

	/* Enable line IRQ */
	io_setbits32(ldev->regs + LTDC_IER2, IER_LIE);

	/* wait end of frame */
	timeout_ref = timeout_init_us(LTDC_TIMEOUT_US);
	while (!timeout_elapsed(timeout_ref))
		if (ldev->end_of_frame)
			break;

	/* Disable IRQs */
	io_clrbits32(ldev->regs + LTDC_IER2, IER_LIE | IER_FUKIE | IER_TERRIE);

	/* Allow an almost silent failure here */
	if (!ldev->end_of_frame)
		EMSG("ltdc: Did not receive end of frame interrupt");

	ret = stm32_firewall_set_config(virt_to_phys((void *)ldev->regs),
					0, sec_cfg);
	if (ret)
		goto out;

	ret = stm32_pinctrl_set_secure_cfg(ldev->pinctrl_list, false);
	/* Restoring non-secure state for pins should not fail */
	assert(ret == TEE_SUCCESS);

out:
	clk_disable(ldev->clock);

	ldev->activate = false;

	return ret;
}

static TEE_Result stm32_ltdc_activate(void *device,
				      const struct frame_buffer *fb,
				      uint32_t x0, uint32_t y0)
{
	struct ltdc_device *ldev = device;
	paddr_t fb_pbase = virt_to_phys(fb->base);
	TEE_Result ret = TEE_SUCCESS;
	uint32_t value = 0;
	uint32_t x1 = 0;
	uint32_t y1 = 0;
	uint32_t width_crtc = 0;
	uint32_t height_crtc = 0;
	uint32_t bpcr = 0;
	uint32_t awcr = 0;

	if (!fb) {
		ret = TEE_ERROR_GENERIC;
		goto err;
	}

	x1 = x0 + fb->width;
	y1 = y0 + fb->height;

	/* Check framebuffer size */
	awcr = io_read32(ldev->regs + LTDC_AWCR);
	bpcr = io_read32(ldev->regs + LTDC_BPCR);

	height_crtc = (awcr & 0xffff) - (bpcr & 0xffff);
	width_crtc = (awcr >> 16) - (bpcr >> 16);

	if (fb->height > height_crtc || fb->width > width_crtc) {
		EMSG("framebuffer size %dx%d exceed size of panel %dx%d",
		     fb->width, fb->height, width_crtc, height_crtc);
		ret = TEE_ERROR_GENERIC;
		goto err;
	}

	DMSG("LTDC base %"PRIxVA", FB base %#"PRIxPA, ldev->regs, fb_pbase);

	/* Configure the horizontal start and stop position */
	value = (x0 + ((bpcr & LTDC_BPCR_AHBP) >> 16) + 1) |
		((x1 + ((bpcr & LTDC_BPCR_AHBP) >> 16)) << 16);
	io_clrsetbits32(ldev->regs + LTDC_L2WHPCR,
			LTDC_LXWHPCR_WHSTPOS | LTDC_LXWHPCR_WHSPPOS, value);

	/* Configure the vertical start and stop position */
	value = (y0 + (bpcr & LTDC_BPCR_AVBP) + 1) |
		((y1 + (bpcr & LTDC_BPCR_AVBP)) << 16);

	io_clrsetbits32(ldev->regs + LTDC_L2WVPCR,
			LTDC_LXWVPCR_WVSTPOS | LTDC_LXWVPCR_WVSPPOS, value);

	/* Specifies the pixel format, hard coded */
	io_clrbits32(ldev->regs + LTDC_L2PFCR, LTDC_LXPFCR_PF);
	io_setbits32(ldev->regs + LTDC_L2PFCR, LXPFCR_PF_ARGB8888);

	/* Configure the default color values, hard coded */
	io_clrbits32(ldev->regs + LTDC_L2DCCR,
		     LTDC_LXDCCR_DCBLUE | LTDC_LXDCCR_DCGREEN |
		     LTDC_LXDCCR_DCRED | LTDC_LXDCCR_DCALPHA);
	io_setbits32(ldev->regs + LTDC_L2DCCR, 0x00FFFFFF);

	/* Specifies the constant alpha value, hard coded. */
	io_clrbits32(ldev->regs + LTDC_L2CACR, LTDC_LXCACR_CONSTA);
	io_setbits32(ldev->regs + LTDC_L2CACR, 0xFF);

	/* Specifies the blending factors, hard coded. */
	io_clrbits32(ldev->regs + LTDC_L2BFCR, LXBFCR_BF2 | LXBFCR_BF1);
	io_setbits32(ldev->regs + LTDC_L2BFCR,
		     LXBFCR_BF1_PAXCA | LXBFCR_BF2_PAXCA);

	/* Configure the color frame buffer start address. */
	io_clrbits32(ldev->regs + LTDC_L2CFBAR, LTDC_LXCFBAR_CFBADD);
	io_setbits32(ldev->regs + LTDC_L2CFBAR, fb_pbase);

	/* Configure the color frame buffer pitch in byte, assuming ARGB32. */
	value =	((fb->width * 4) << 16) | (((x1 - x0) * 4)  + 3);
	io_clrsetbits32(ldev->regs + LTDC_L2CFBLR,
			LTDC_LXCFBLR_CFBLL | LTDC_LXCFBLR_CFBP, value);

	/* Configure the frame buffer line number. */
	io_clrsetbits32(ldev->regs + LTDC_L2CFBLNR,
			LTDC_LXCFBLNR_CFBLNBR, fb->height);

	/* Enable LTDC_Layer by setting LEN bit. */
	io_setbits32(ldev->regs + LTDC_L2CR, LXCR_LEN);

	/* Reload configuration at next vertical blanking. */
	io_write32(ldev->regs + LTDC_L2RCR, LXCR_RCR_VBR);

	/* Enable IRQs */
	io_setbits32(ldev->regs + LTDC_IER2, IER_FUKIE | IER_TERRIE);

	ldev->activate = true;

	return ret;
err:
	dump_reg_ltdc(ldev->regs);

	return ret;
}

static TEE_Result stm32_ltdc_get_display_size(void *device,
					      uint32_t *width,
					      uint32_t *height)
{
	struct ltdc_device *ldev = device;
	TEE_Result ret = TEE_SUCCESS;
	uint32_t bpcr = 0;
	uint32_t awcr = 0;
	uint32_t gcr = 0;

	assert(ldev && ldev->regs);

	if (!width || !height)
		return TEE_ERROR_BAD_PARAMETERS;

	clk_enable(ldev->clock);

	gcr = io_read32(ldev->regs + LTDC_GCR);
	if (!(gcr & GCR_LTDCEN)) {
		EMSG("CRTC must be started first");
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	awcr = io_read32(ldev->regs + LTDC_AWCR);
	bpcr = io_read32(ldev->regs + LTDC_BPCR);

	*height = (awcr & 0xffff) - (bpcr & 0xffff);
	*width = (awcr >> 16) - (bpcr >> 16);
out:
	clk_disable(ldev->clock);

	return ret;
}

static enum itr_return stm32_ltdc_it_handler(struct itr_handler *handler)
{
	struct ltdc_device *ldev = handler->data;
	uint32_t irq_status = 0;

	irq_status = io_read32(ldev->regs + LTDC_ISR2);
	io_write32(ldev->regs + LTDC_ICR2, irq_status);

	if (irq_status & ISR_FUKIF)
		EMSG("ltdc fifo underrun: please verify display mode");

	if (irq_status & ISR_TERRIF)
		EMSG("ltdc transfer error");

	if (irq_status & ISR_LIF)
		ldev->end_of_frame = true;

	return ITRR_HANDLED;
}
DECLARE_KEEP_PAGER(stm32_ltdc_it_handler);

static struct disp_dev_list ltdc_dev = {
	.device_init = stm32_ltdc_init,
	.device_final = stm32_ltdc_final,
	.device_activate = stm32_ltdc_activate,
	.device_get_display_size = stm32_ltdc_get_display_size,
};

static TEE_Result stm32_ltdc_probe(const void *fdt, int node,
				   const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct ltdc_device *ldev = NULL;
	struct dt_node_info dt_info = { };
	uint32_t hwid = 0;
	const uint32_t *cuint = NULL;
	uint32_t interrupt0 = 0;
	uint32_t interrupt1 = 0;
	int len = 0;

	ldev = calloc(1, sizeof(*ldev));
	if (!ldev)
		return TEE_ERROR_OUT_OF_MEMORY;

	_fdt_fill_device_info(fdt, &dt_info, node);

	if (dt_info.reg == DT_INFO_INVALID_REG ||
	    dt_info.reg_size == DT_INFO_INVALID_REG_SIZE ||
	    dt_info.clock == DT_INFO_INVALID_CLOCK ||
	    dt_info.interrupt == DT_INFO_INVALID_INTERRUPT)
		goto err;

	ldev->io_base.pa = dt_info.reg;
	if (ldev->io_base.pa == 0)
		panic("LTDC iomem missing");

	ldev->regs = io_pa_or_va_secure(&ldev->io_base, dt_info.reg_size);

	res = clk_dt_get_by_index(fdt, node, 0, &ldev->clock);
	if (res)
		goto err;

	clk_enable(ldev->clock);

	hwid = io_read32(ldev->regs + LTDC_IDR);

	if (hwid != ID_HWVER_40100) {
		EMSG("LTDC hardware version not supported: 0x%x", hwid);
		res = TEE_ERROR_NOT_SUPPORTED;
		goto err;
	}

	cuint = fdt_getprop(fdt, node, "interrupts", &len);
	if (cuint) {
		interrupt0 = (uint32_t)fdt32_to_cpu(*(cuint + 1)) + 32;
		interrupt1 = (uint32_t)fdt32_to_cpu(*(cuint + 4)) + 32;
	}

	ldev->itr0 = itr_alloc_add((size_t)interrupt0,
				   stm32_ltdc_it_handler,
				   ITRF_TRIGGER_LEVEL,
				   (void *)ldev);
	if (!ldev->itr0) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	ldev->itr1 = itr_alloc_add((size_t)interrupt1,
				   stm32_ltdc_it_handler,
				   ITRF_TRIGGER_LEVEL,
				   (void *)ldev);
	if (!ldev->itr1) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	itr_enable(ldev->itr0->it);
	itr_enable(ldev->itr1->it);

	res = stm32_pinctrl_dt_get_by_index(fdt, node, 0, &ldev->pinctrl_list);
	if (res)
		goto err;

	stm32_pinctrl_load_config(ldev->pinctrl_list);

	ltdc_dev.device = ldev;
	display_register_device(&ltdc_dev);

	/* Force the LTDC to non secure access */
	stm32_ltdc_final(ldev);

	return TEE_SUCCESS;
err:
	free(ldev);

	return res;
}

static const struct dt_device_match ltdc_match_table[] = {
	{ .compatible = "st,stm32-ltdc" },
	{ }
};

DEFINE_DT_DRIVER(stm32_ltdc_dt_driver) = {
	.name = "stm32-ltdc",
	.match_table = ltdc_match_table,
	.probe = stm32_ltdc_probe,
};
