/*******************************************************************************
 * BSD 3-Clause License
 *
 * Copyright (c) 2017, Matt Davis (enferex) https://github.com/enferex
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
#include "config.h"
#ifdef HAVE_LIBNCURSES
#include "asrepl.h"
#undef ERR
#include <stdarg.h>
#include <ncurses.h>
#include <panel.h>
#include <string.h>
#include "tui.h"

#define ROWS LINES

/* Only accessable from tui.c */
static WINDOW *tui_wins[TUI_WIN_MAX];
static PANEL  *tui_pans[TUI_WIN_MAX];

void tui_init(void)
{
    int r, c;
    WINDOW *reg_win, *stat_win, *frame_win, *input_win;
    
    initscr();
    r = (ROWS * 2) / 3;
    c = COLS / 2;

    /* Register windows (top left) */
    reg_win = tui_wins[TUI_WIN_REG] = newwin(r, c, 0, 0);
    box(reg_win, 0, 0);
    mvwprintw(reg_win, 0, 3, "=[ Registers ]=");
    wmove(reg_win, 1, 1);

    /* Status window (top right) */
    stat_win = tui_wins[TUI_WIN_STATUS] = newwin(r, c, 0, c*1);
    box(stat_win, 0, 0);
    mvwprintw(stat_win, 0, 3, "=[ Status ]=");
    wmove(stat_win, 1, 1);

    /* REPL window frame (bottom, just for the border) */
    frame_win = tui_wins[TUI_WIN_FRAME] = newwin(ROWS-r, COLS, r, 0);
    box(frame_win, 0, 0);
    mvwprintw(frame_win, 0, 3, "=[ Input/Output ]=");

    /* REPL... the actual input window */
    input_win = tui_wins[TUI_WIN_REPL] = newwin(ROWS-r-2, COLS-2, r + 1, 1);
    scrollok(input_win, TRUE);
    wsetscrreg(input_win, 0, ROWS-r-2);
    
    /* Panels */ 
    tui_pans[TUI_WIN_STATUS] = new_panel(stat_win);
    tui_pans[TUI_WIN_REG]    = new_panel(reg_win);
    tui_pans[TUI_WIN_FRAME]  = new_panel(frame_win);
    tui_pans[TUI_WIN_REPL]   = new_panel(input_win);

    /* Draw */
    tui_update();
}

char *tui_readline(const char *prompt)
{
    char buffer[MAX_ASM_LINE] = {0};
    const int r = (ROWS * 2) / 3;
    WINDOW *win = tui_wins[TUI_WIN_REPL];
    mvwprintw(win, ROWS-r-3, 0, prompt);
    mvwgetnstr(win, ROWS-r-3, strlen(prompt), buffer, MAX_ASM_LINE-1);
    return strdup(buffer);
}

void tui_write(tui_window_e windex, const char *fmt, ...)
{
    va_list vlist;
    WINDOW *win;

    if (windex < 0 || windex >= TUI_WIN_MAX)
      return; /* Invalid */

    if ((win = tui_wins[windex]) == NULL)
      return;

    va_start(vlist, fmt);
    vwprintw(win, fmt, vlist);
    va_end(vlist);
    wrefresh(win);
}

void tui_update(void)
{
    update_panels();
    doupdate();
}

void tui_exit(void)
{
    endwin();
}

#endif /* HAVE_LIBNCURSES */
