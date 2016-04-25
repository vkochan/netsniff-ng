#ifndef UI_H
#define UI_H

#include <stdbool.h>
#include <inttypes.h>

#include "list.h"

enum ui_type {
	UI_CURSES,
	UI_STDOUT,
};

enum ui_align {
	UI_ALIGN_LEFT,
	UI_ALIGN_RIGHT,
};

struct ui_col {
	struct list_head entry;
	uint32_t id;
	char *name;
	uint32_t len;
	int pos;
	int color;
	enum ui_align align;
};

struct ui_table {
	int y;
	int x;
	int rows_y;
	struct list_head cols;
	int hdr_color;
	int col_pad;
	int width;
	int height;
	const char *default_col;

	void (*data_bind)(struct ui_table *tbl, int col_id, const void *data);
	void (*col_print)(struct ui_table *tbl, int col_id, const char *str);
};

extern void ui_init(enum ui_type mode);

extern void ui_table_init(struct ui_table *tbl);
extern void ui_table_uninit(struct ui_table *tbl);
extern void ui_table_clear(struct ui_table *tbl);
extern void ui_table_pos_set(struct ui_table *tbl, int y, int x);
extern void ui_table_height_set(struct ui_table *tbl, int height);

extern void ui_table_col_add(struct ui_table *tbl, uint32_t id, char *name,
			     uint32_t len);
extern void ui_table_col_color_set(struct ui_table *tbl, int col_id, int color);
extern void ui_table_col_align_set(struct ui_table *tbl, int col_id, enum ui_align align);
extern void ui_table_default_col_set(struct ui_table *tbl, const char *col);
extern void ui_table_col_print_set(struct ui_table *tbl,
				   void (*func)(struct ui_table *tbl,
						int col_id, const char *str));

extern void ui_table_data_bind_set(struct ui_table *tbl,
				   void (*func)(struct ui_table *tbl,
						int col_id, const void *data));
extern void ui_table_data_bind(struct ui_table *tbl, int col_id, const void *data);

extern void ui_table_row_add(struct ui_table *tbl);
extern void ui_table_row_print(struct ui_table *tbl, uint32_t col_id,
			       const char *str);

extern void ui_table_header_color_set(struct ui_table *tbl, int color);
extern void ui_table_header_print(struct ui_table *tbl);

#endif /* UI_H */
