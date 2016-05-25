/*
 * netsniff-ng - the packet sniffing beast
 * Subject to the GPL, version 2.
 */

#include <curses.h>

#include "ui.h"
#include "xmalloc.h"

static enum ui_type ui = UI_CURSES;

#define ui_print_yx(y, x, fmt, ...) \
do { \
	if (ui == UI_CURSES) \
		mvprintw(y, x, fmt, ##__VA_ARGS__); \
	else \
		printf(fmt, ##__VA_ARGS__); \
} while (0)

static void ui_color_on(int color)
{
	if (ui == UI_CURSES)
		attron(color);
}

static void ui_color_off(int color)
{
	if (ui == UI_CURSES)
		attroff(color);
}

void ui_init(enum ui_type mode)
{
	ui = mode;
}

void ui_table_init(struct ui_table *tbl)
{
	memset(tbl, 0, sizeof(*tbl));

	if (ui == UI_CURSES)
		getsyx(tbl->y, tbl->x);

	tbl->width       = COLS;
	tbl->height      = LINES - 2;
	tbl->col_pad     = 1;
	tbl->default_col = "*";

	INIT_LIST_HEAD(&tbl->cols);
}

void ui_table_uninit(struct ui_table *tbl)
{
	struct ui_col *col, *tmp;

	list_for_each_entry_safe(col, tmp, &tbl->cols, entry)
		xfree(col);
}

void ui_table_pos_set(struct ui_table *tbl, int y, int x)
{
	tbl->y      = y;
	tbl->x      = x;
}

int ui_table_rows_count(struct ui_table *tbl)
{
	return tbl->rows_count;
}

static struct ui_col *ui_table_col_get(struct ui_table *tbl, uint32_t id)
{
	struct ui_col *col;

	list_for_each_entry(col, &tbl->cols, entry) {
		if (col->id == id)
			return col;
	}

	bug();
}

static void __ui_table_pos_update(struct ui_table *tbl)
{
	struct ui_col *col;
	uint32_t pos = tbl->x;

	list_for_each_entry(col, &tbl->cols, entry) {
		col->pos  = pos;
		pos      += col->len + tbl->col_pad;
	}
}

void ui_table_col_add(struct ui_table *tbl, uint32_t id, char *name, uint32_t len)
{
	struct ui_col *col = xzmalloc(sizeof(*col));

	col->id    = id;
	col->name  = name;
	col->len   = len;
	col->align = UI_ALIGN_LEFT;

	list_add_tail(&col->entry, &tbl->cols);

	__ui_table_pos_update(tbl);
}

void ui_table_col_color_set(struct ui_table *tbl, int col_id, int color)
{
	struct ui_col *col = ui_table_col_get(tbl, col_id);

	col->color = color;
}

void ui_table_col_align_set(struct ui_table *tbl, int col_id, enum ui_align align)
{
	struct ui_col *col = ui_table_col_get(tbl, col_id);

	col->align = align;
}

void ui_table_default_col_set(struct ui_table *tbl, const char *col)
{
	tbl->default_col = col;
}

void ui_table_data_bind_set(struct ui_table *tbl,
			    void (*func)(struct ui_table *tbl,
					 int col_id, const void *data))
{
	tbl->data_bind = func;
}

void ui_table_data_bind(struct ui_table *tbl, int col_id, const void *data)
{
	struct ui_col *col = ui_table_col_get(tbl, col_id);

	bug_on(!tbl);
	bug_on(!tbl->data_bind);

	tbl->data_bind(tbl, col->id, data);
}

void ui_table_col_print_set(struct ui_table *tbl,
			    void (*func)(struct ui_table *tbl,
					 int col_id, const char *str))
{
	tbl->col_print = func;
}

void ui_table_row_add(struct ui_table *tbl)
{
	tbl->rows_count++;

	if (ui == UI_STDOUT)
		printf("\n");
}

void ui_table_clear(struct ui_table *tbl)
{
	int y;

	tbl->rows_count = 0;

	for (y = tbl->y + 1; y < tbl->y + tbl->height; y++) {
		ui_print_yx(y, tbl->x, "%*s", tbl->width, " ");
	}
}

#define UI_ALIGN_COL(col) (((col)->align == UI_ALIGN_LEFT) ? "%-*.*s" : "%*.*s")

static void __ui_table_row_print(struct ui_table *tbl, struct ui_col *col,
				 const char *str)
{
	const char *tmp;
	int rows_y;

	if (!str || !strlen(str))
		tmp = tbl->default_col;
	else
		tmp = str;

	if (tbl->col_print) {
		tbl->col_print(tbl, col->id, str);
		return;
	}

	rows_y = tbl->y + tbl->rows_count;

	ui_print_yx(rows_y, col->pos, UI_ALIGN_COL(col), col->len, col->len, tmp);
	ui_print_yx(rows_y, col->pos + col->len, "%*s", tbl->col_pad, " ");
}

void ui_table_row_print(struct ui_table *tbl, uint32_t col_id, const char *str)
{
	struct ui_col *col = ui_table_col_get(tbl, col_id);

	ui_color_on(col->color);
	__ui_table_row_print(tbl, col, str);
	ui_color_off(col->color);
}

void ui_table_header_color_set(struct ui_table *tbl, int color)
{
	tbl->hdr_color = color;
}

void ui_table_height_set(struct ui_table *tbl, int height)
{
	tbl->height = height;
}

void ui_table_header_print(struct ui_table *tbl)
{
	struct ui_col *col;
	int max_width = tbl->width;
	int width = 0;

	ui_color_on(tbl->hdr_color);

	if (ui == UI_CURSES)
		ui_print_yx(tbl->y, tbl->x, "%-*.*s", max_width - tbl->x,
				max_width - tbl->x, "");

	ui_print_yx(tbl->y, tbl->x, "%s", "");

	list_for_each_entry(col, &tbl->cols, entry) {
		__ui_table_row_print(tbl, col, col->name);
		width += col->len + tbl->col_pad;
	}

	if (ui == UI_CURSES)
		ui_print_yx(tbl->y, width, "%*s", max_width - width, " ");

	ui_color_off(tbl->hdr_color);
}
