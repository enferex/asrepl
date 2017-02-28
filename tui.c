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
#ifdef HAVE_NCURSES
#include <ncurses.h>
#include <panel.h>
#include "tui.h"

#define ROWS LINES

/* Only accessable from tui.c */
static WINDOW *reg_win, *out_win, *stat_win, *repl_win;
static PANEL  *reg_pan, *out_pan, *stat_pan, *repl_pan;

void tui_init(void)
{
    int r, c;
    initscr();
    raw();                /* Disable buffer ing and recv ctrl-c and ctrl-z */
    keypad(stdscr, TRUE); /* Enable keypad and arrows                      */

    r = (ROWS * 2) / 3;
    c = COLS / 3;

    /* Register windows (top left) */
    reg_win = newwin(r, c, 0, 0);
    box(reg_win, 0, 0);
    mvwprintw(reg_win, 0, 3, "=[ Registers ]=");

    /* Output window (top middle) */
    out_win = newwin(r, c, 0, c*1);
    box(out_win, 0, 0);
    mvwprintw(out_win, 0, 3, "=[ Output ]=");
    
    /* Status window (top right) */
    stat_win = newwin(r, c, 0, c*2);
    box(stat_win, 0, 0);
    mvwprintw(stat_win, 0, 3, "=[ Status ]=");

    /* REPL window (bottom) */
    repl_win = newwin(ROWS-r, COLS,  r, 0);
    box(repl_win, 0, 0);
    mvwprintw(repl_win, 0, 3, "=[ Input ]=");
    
    /* Panels */ 
    stat_pan = new_panel(stat_win);
    reg_pan  = new_panel(reg_win);
    out_pan  = new_panel(out_win);
    repl_pan = new_panel(repl_win);

    /* Draw */
    tui_update();
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

#endif /* HAVE_NCURSES */
