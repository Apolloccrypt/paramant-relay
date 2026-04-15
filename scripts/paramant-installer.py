#!/usr/bin/env python3
"""
paramant-installer — ParamantOS TUI disk installer
Text-based wizard; also supports unattended install via YAML/JSON config.

Usage:
  paramant-installer                          # interactive wizard
  paramant-installer --config install.yaml   # unattended (YAML)
  paramant-installer --config install.json   # unattended (JSON)
  paramant-installer --dump-config           # print example config and exit

Navigation: ↑↓ move  Enter/Space select  Esc/← back  Tab next field
"""

import curses
import subprocess
import sys
import os
import re
import json
import argparse
import ipaddress
import textwrap
import shutil
import time
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Any

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

VERSION = "2.4.5"
MOUNT   = "/mnt"
LOG     = "/tmp/paramant-install.log"   # overwritten after root check in main()

# ──────────────────────────────────────────────────────────────────────────────
# Config dataclasses
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class NetConfig:
    interface: str = ""
    mode: str = "dhcp"          # dhcp | static
    address: str = ""
    prefix: int = 24
    gateway: str = ""
    dns: List[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])

@dataclass
class Partition:
    device: str = ""
    size: str = "rest"          # e.g. "512M", "8G", "rest"
    ptype: str = "root"         # efi | bios_boot | swap | root | data
    fmt: str = "ext4"           # fat32 | ext4 | xfs | btrfs | swap | none
    mountpoint: str = "/"

@dataclass
class StorageConfig:
    mode: str = "whole_disk"    # whole_disk | manual
    disk: str = ""
    firmware: str = ""          # uefi | bios (auto-detected)
    partitions: List[Partition] = field(default_factory=list)

@dataclass
class InstallConfig:
    language: str   = "en_US.UTF-8"
    keyboard: str   = "us"
    hostname: str   = "paramant"
    username: str   = "paramant"
    password: str   = ""
    ssh_key: str    = ""
    network: NetConfig      = field(default_factory=NetConfig)
    storage: StorageConfig  = field(default_factory=StorageConfig)
    unattended: bool = False

# ──────────────────────────────────────────────────────────────────────────────
# TUI — curses wrapper
# ──────────────────────────────────────────────────────────────────────────────

# Color pair IDs
_C_NORMAL   = 1   # green on black
_C_HEADER   = 2   # black on green  (header bar + selected items)
_C_ERROR    = 3   # bright red on black
_C_WARN     = 4   # yellow on black
_C_INFO     = 5   # cyan on black
_C_DIM      = 6   # dim white on black
_C_TITLE    = 7   # bold green on black (dialog titles)

FOOTER_HINTS = "↑↓ Move   Enter Accept   Esc Back   Ctrl-C Quit"

class TUI:
    def __init__(self, stdscr):
        self.s = stdscr
        curses.curs_set(0)
        curses.start_color()
        curses.use_default_colors()

        curses.init_pair(_C_NORMAL,  curses.COLOR_GREEN,  curses.COLOR_BLACK)
        curses.init_pair(_C_HEADER,  curses.COLOR_BLACK,  curses.COLOR_GREEN)
        curses.init_pair(_C_ERROR,   curses.COLOR_RED,    curses.COLOR_BLACK)
        curses.init_pair(_C_WARN,    curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(_C_INFO,    curses.COLOR_CYAN,   curses.COLOR_BLACK)
        curses.init_pair(_C_DIM,     curses.COLOR_WHITE,  curses.COLOR_BLACK)
        curses.init_pair(_C_TITLE,   curses.COLOR_GREEN,  curses.COLOR_BLACK)

        self.s.keypad(True)
        self.s.timeout(-1)

    # ── Layout helpers ─────────────────────────────────────────────────────────

    @property
    def rows(self): return self.s.getmaxyx()[0]
    @property
    def cols(self): return self.s.getmaxyx()[1]

    def _draw_chrome(self, step_label: str = ""):
        """Draw header and footer bars."""
        h, w = self.rows, self.cols
        # Header
        title = f"  ParamantOS Installer v{VERSION}"
        right = f"{step_label}  " if step_label else ""
        hdr   = title + " " * (w - len(title) - len(right)) + right
        try:
            self.s.addstr(0, 0, hdr[:w], curses.color_pair(_C_HEADER))
        except curses.error:
            pass
        # Footer
        ftr = f"  {FOOTER_HINTS}"
        ftr = ftr[:w - 1].ljust(w - 1)
        try:
            self.s.addstr(h - 1, 0, ftr, curses.color_pair(_C_HEADER))
        except curses.error:
            pass

    def _clear_body(self):
        h, w = self.rows, self.cols
        blank = " " * w
        for row in range(1, h - 1):
            try:
                self.s.addstr(row, 0, blank)
            except curses.error:
                pass

    def _box(self, y: int, x: int, h: int, w: int):
        """Draw a single-line ASCII box."""
        try:
            self.s.addstr(y,       x,     "┌" + "─" * (w - 2) + "┐", curses.color_pair(_C_NORMAL))
            self.s.addstr(y + h-1, x,     "└" + "─" * (w - 2) + "┘", curses.color_pair(_C_NORMAL))
            for row in range(y + 1, y + h - 1):
                self.s.addstr(row, x,         "│", curses.color_pair(_C_NORMAL))
                self.s.addstr(row, x + w - 1, "│", curses.color_pair(_C_NORMAL))
        except curses.error:
            pass

    def _center_box(self, inner_h: int, inner_w: int) -> Tuple[int, int]:
        """Return (y, x) top-left of a centered box of size inner_h × inner_w."""
        box_h = inner_h + 4   # title row + blank + content + blank + border
        box_w = inner_w + 4
        y = max(1, (self.rows - box_h) // 2)
        x = max(0, (self.cols - box_w) // 2)
        return y, x

    # ── Public widgets ─────────────────────────────────────────────────────────

    def message(self, title: str, text: str, style: str = "info",
                step: str = "") -> None:
        """Show a message box. Press Enter or Esc to dismiss."""
        lines = textwrap.wrap(text, self.cols - 10) or [text]
        inner_w = max(len(title) + 4, max(len(l) for l in lines) + 2, 40)
        inner_h = len(lines) + 2
        y, x = self._center_box(inner_h, inner_w)
        bh = inner_h + 4
        bw = inner_w + 4

        color = {
            "info":  _C_INFO,
            "error": _C_ERROR,
            "warn":  _C_WARN,
            "ok":    _C_NORMAL,
        }.get(style, _C_INFO)

        self.s.erase()
        self._draw_chrome(step)
        self._box(y, x, bh, bw)

        # Title
        self.s.addstr(y, x + 2, f" {title} ",
                      curses.color_pair(_C_HEADER))
        # Body
        for i, line in enumerate(lines):
            try:
                self.s.addstr(y + 2 + i, x + 3, line,
                              curses.color_pair(color))
            except curses.error:
                pass
        # Hint
        hint = "[ Press Enter ]"
        try:
            self.s.addstr(y + bh - 2, x + (bw - len(hint)) // 2, hint,
                          curses.color_pair(_C_DIM))
        except curses.error:
            pass

        self.s.refresh()
        while True:
            k = self.s.getch()
            if k in (10, 13, 27, curses.KEY_ENTER, ord(' ')):
                break

    def confirm(self, title: str, text: str, step: str = "") -> bool:
        """Yes/No dialog. Returns True for Yes, False for No/Esc."""
        lines = textwrap.wrap(text, self.cols - 10) or [text]
        inner_w = max(len(title) + 4, max(len(l) for l in lines) + 2, 44)
        inner_h = len(lines) + 3
        y, x = self._center_box(inner_h, inner_w)
        bh = inner_h + 4
        bw = inner_w + 4

        choice = 0   # 0 = Yes, 1 = No

        while True:
            self.s.erase()
            self._draw_chrome(step)
            self._box(y, x, bh, bw)
            self.s.addstr(y, x + 2, f" {title} ",
                          curses.color_pair(_C_HEADER))

            for i, line in enumerate(lines):
                try:
                    self.s.addstr(y + 2 + i, x + 3, line,
                                  curses.color_pair(_C_DIM))
                except curses.error:
                    pass

            btn_y = y + bh - 3
            yes_x = x + bw // 2 - 10
            no_x  = x + bw // 2 + 2

            yes_attr = (curses.color_pair(_C_HEADER)
                        if choice == 0 else curses.color_pair(_C_NORMAL))
            no_attr  = (curses.color_pair(_C_HEADER)
                        if choice == 1 else curses.color_pair(_C_NORMAL))

            try:
                self.s.addstr(btn_y, yes_x, "[ Yes ]", yes_attr)
                self.s.addstr(btn_y, no_x,  "[ No  ]", no_attr)
            except curses.error:
                pass

            self.s.refresh()
            k = self.s.getch()

            if k in (curses.KEY_LEFT, curses.KEY_RIGHT, ord('\t')):
                choice = 1 - choice
            elif k in (10, 13, curses.KEY_ENTER):
                return choice == 0
            elif k == 27:
                return False

    def menu(self, title: str, items: List[Tuple[str, str]],
             default: int = 0, step: str = "",
             subtitle: str = "") -> int:
        """
        Scrollable menu. Returns selected index, or -1 for back/Esc.
        items: list of (label, description) tuples.
        """
        if not items:
            return -1

        max_items = len(items)
        label_w   = max(len(it[0]) for it in items) + 2
        desc_w    = max((len(it[1]) for it in items), default=0)
        inner_w   = min(max(label_w + desc_w + 4, len(title) + 4, 50),
                        self.cols - 6)
        visible   = min(max_items, self.rows - 10)
        inner_h   = visible + (2 if subtitle else 1)

        y, x = self._center_box(inner_h, inner_w)
        bw = inner_w + 4
        bh = inner_h + 4

        current = max(0, min(default, max_items - 1))
        scroll  = max(0, current - visible + 1)

        while True:
            self.s.erase()
            self._draw_chrome(step)
            self._box(y, x, bh, bw)
            self.s.addstr(y, x + 2, f" {title} ",
                          curses.color_pair(_C_HEADER))

            if subtitle:
                try:
                    self.s.addstr(y + 2, x + 3,
                                  subtitle[:inner_w], curses.color_pair(_C_DIM))
                except curses.error:
                    pass

            row_start = y + 2 + (1 if subtitle else 0)
            for i in range(visible):
                idx = scroll + i
                if idx >= max_items:
                    break
                lbl, desc = items[idx]
                line = f" {lbl:<{label_w - 1}} {desc}"
                line = line[:inner_w]
                attr = (curses.color_pair(_C_HEADER)
                        if idx == current
                        else curses.color_pair(_C_NORMAL))
                try:
                    self.s.addstr(row_start + i, x + 2, line.ljust(inner_w), attr)
                except curses.error:
                    pass

            # Scroll indicator
            if max_items > visible:
                pct = int((scroll / max(1, max_items - visible)) * (bh - 4))
                try:
                    self.s.addstr(y + 2 + pct, x + bw - 1, "█",
                                  curses.color_pair(_C_DIM))
                except curses.error:
                    pass

            self.s.refresh()
            k = self.s.getch()

            if k == curses.KEY_UP and current > 0:
                current -= 1
                if current < scroll:
                    scroll = current
            elif k == curses.KEY_DOWN and current < max_items - 1:
                current += 1
                if current >= scroll + visible:
                    scroll = current - visible + 1
            elif k == curses.KEY_PPAGE:
                current = max(0, current - visible)
                scroll  = max(0, scroll - visible)
            elif k == curses.KEY_NPAGE:
                current = min(max_items - 1, current + visible)
                scroll  = min(max(0, max_items - visible), scroll + visible)
            elif k == curses.KEY_HOME:
                current = 0; scroll = 0
            elif k == curses.KEY_END:
                current = max_items - 1
                scroll  = max(0, max_items - visible)
            elif k in (10, 13, curses.KEY_ENTER):
                return current
            elif k == 27 or k == curses.KEY_LEFT:
                return -1

    def inputbox(self, title: str, prompt: str,
                 default: str = "", password: bool = False,
                 step: str = "", hint: str = "") -> Optional[str]:
        """
        Single-line input. Returns string, or None for Esc/back.
        """
        inner_w = min(max(len(title) + 4, len(prompt) + 4, 50), self.cols - 6)
        inner_h = 3 + (1 if hint else 0)
        y, x    = self._center_box(inner_h, inner_w)
        bw = inner_w + 4

        buf    = list(default)
        cursor = len(buf)
        curses.curs_set(1)

        try:
            while True:
                self.s.erase()
                self._draw_chrome(step)
                self._box(y, x, inner_h + 4, bw)
                self.s.addstr(y, x + 2, f" {title} ",
                              curses.color_pair(_C_HEADER))

                try:
                    self.s.addstr(y + 2, x + 3,
                                  prompt[:inner_w], curses.color_pair(_C_DIM))
                except curses.error:
                    pass

                # Input field
                display = ("*" * len(buf) if password else "".join(buf))
                field_w = inner_w - 2
                # Show end of buffer if too long
                start = max(0, cursor - field_w + 1)
                visible_text = display[start:start + field_w]
                field_y = y + 3
                field_x = x + 3
                try:
                    self.s.addstr(field_y, field_x,
                                  visible_text.ljust(field_w),
                                  curses.color_pair(_C_NORMAL) | curses.A_UNDERLINE)
                    self.s.move(field_y, field_x + min(cursor - start, field_w - 1))
                except curses.error:
                    pass

                if hint:
                    try:
                        self.s.addstr(y + inner_h + 1, x + 3,
                                      hint[:inner_w], curses.color_pair(_C_DIM))
                    except curses.error:
                        pass

                self.s.refresh()
                k = self.s.getch()

                if k in (10, 13, curses.KEY_ENTER):
                    return "".join(buf)
                elif k == 27:
                    return None
                elif k in (curses.KEY_BACKSPACE, 127, 8):
                    if cursor > 0:
                        buf.pop(cursor - 1)
                        cursor -= 1
                elif k == curses.KEY_DC:
                    if cursor < len(buf):
                        buf.pop(cursor)
                elif k == curses.KEY_LEFT and cursor > 0:
                    cursor -= 1
                elif k == curses.KEY_RIGHT and cursor < len(buf):
                    cursor += 1
                elif k == curses.KEY_HOME:
                    cursor = 0
                elif k == curses.KEY_END:
                    cursor = len(buf)
                elif 32 <= k <= 126:
                    buf.insert(cursor, chr(k))
                    cursor += 1
        finally:
            curses.curs_set(0)

    def progress_screen(self, title: str, step: str = ""):
        """
        Returns a callable update(line) that appends a line to the scroll log.
        Call update(None) to finalize (show "Done, press Enter").
        """
        inner_w = min(self.cols - 6, 76)
        visible = self.rows - 10
        y, x    = self._center_box(visible, inner_w)
        bh = visible + 4
        bw = inner_w + 4
        log_lines: List[str] = []

        def update(line: Optional[str]):
            if line is not None:
                log_lines.append(line.rstrip())

            self.s.erase()
            self._draw_chrome(step)
            self._box(y, x, bh, bw)
            self.s.addstr(y, x + 2, f" {title} ",
                          curses.color_pair(_C_HEADER))

            show = log_lines[-(visible - 1):]
            for i, l in enumerate(show):
                color = _C_ERROR  if l.startswith("error:") else \
                        _C_WARN   if l.startswith("warning:") else \
                        _C_NORMAL
                try:
                    self.s.addstr(y + 2 + i, x + 2,
                                  l[:inner_w].ljust(inner_w),
                                  curses.color_pair(color))
                except curses.error:
                    pass

            if line is None:
                hint = "[ Press Enter to continue ]"
                try:
                    self.s.addstr(y + bh - 2,
                                  x + (bw - len(hint)) // 2,
                                  hint, curses.color_pair(_C_DIM))
                except curses.error:
                    pass

            self.s.refresh()

            if line is None:
                while self.s.getch() not in (10, 13, curses.KEY_ENTER):
                    pass

        return update

    def partition_editor(self, disk: str, firmware: str,
                         step: str = "") -> Optional[List[Partition]]:
        """
        Interactive partition editor.
        Returns list of Partition objects, or None to cancel.
        """
        # Seed with a sane default layout based on firmware
        parts: List[Partition] = []
        if firmware == "uefi":
            parts.append(Partition(device=f"{disk}p1", size="512M",
                                   ptype="efi",  fmt="fat32",  mountpoint="/boot"))
            parts.append(Partition(device=f"{disk}p2", size="4G",
                                   ptype="swap", fmt="swap",   mountpoint="[swap]"))
            parts.append(Partition(device=f"{disk}p3", size="rest",
                                   ptype="root", fmt="ext4",   mountpoint="/"))
        else:
            parts.append(Partition(device=f"{disk}1", size="1M",
                                   ptype="bios_boot", fmt="none", mountpoint=""))
            parts.append(Partition(device=f"{disk}2", size="4G",
                                   ptype="swap",      fmt="swap", mountpoint="[swap]"))
            parts.append(Partition(device=f"{disk}3", size="rest",
                                   ptype="root",      fmt="ext4", mountpoint="/"))

        ACTIONS = ["Add", "Delete", "Edit", "Done", "Cancel"]
        COL_W   = [12, 7, 10, 7, 12]   # device, size, type, format, mountpoint

        def draw():
            self.s.erase()
            self._draw_chrome(step)
            h, w = self.rows, self.cols
            inner_w = min(w - 4, 72)
            y = 2; x = (w - inner_w) // 2
            bw = inner_w + 2
            bh = len(parts) + 7
            self._box(y, x, bh, bw)
            self.s.addstr(y, x + 2, f" Manual Partitioning — {disk} ",
                          curses.color_pair(_C_HEADER))
            # Header row
            hdr = (f"{'Device':<12}  {'Size':<7}  {'Type':<10}  "
                   f"{'Format':<7}  {'Mountpoint':<12}")
            try:
                self.s.addstr(y + 2, x + 2, hdr[:inner_w],
                              curses.color_pair(_C_INFO) | curses.A_BOLD)
                self.s.addstr(y + 3, x + 2, "─" * min(inner_w, 60),
                              curses.color_pair(_C_DIM))
            except curses.error:
                pass
            # Partition rows
            for i, p in enumerate(parts):
                row = (f"{p.device:<12}  {p.size:<7}  {p.ptype:<10}  "
                       f"{p.fmt:<7}  {p.mountpoint:<12}")
                try:
                    self.s.addstr(y + 4 + i, x + 2, row[:inner_w],
                                  curses.color_pair(_C_NORMAL))
                except curses.error:
                    pass
            # Actions
            action_y = y + 4 + len(parts) + 1
            offset = x + 2
            for i, a in enumerate(ACTIONS):
                lbl = f"[{a}]"
                attr = curses.color_pair(_C_NORMAL)
                try:
                    self.s.addstr(action_y, offset, lbl, attr)
                except curses.error:
                    pass
                offset += len(lbl) + 2
            self.s.refresh()

        # Simple action loop — arrow keys cycle through actions
        action_idx = 0
        while True:
            draw()
            # Highlight selected action
            h, w = self.rows, self.cols
            inner_w = min(w - 4, 72)
            y = 2; x = (w - inner_w) // 2
            action_y = y + 4 + len(parts) + 1
            offset = x + 2
            for i, a in enumerate(ACTIONS):
                lbl = f"[{a}]"
                attr = (curses.color_pair(_C_HEADER)
                        if i == action_idx else curses.color_pair(_C_NORMAL))
                try:
                    self.s.addstr(action_y, offset, lbl, attr)
                except curses.error:
                    pass
                offset += len(lbl) + 2
            self.s.refresh()

            k = self.s.getch()
            if k == curses.KEY_LEFT:
                action_idx = (action_idx - 1) % len(ACTIONS)
            elif k == curses.KEY_RIGHT:
                action_idx = (action_idx + 1) % len(ACTIONS)
            elif k in (10, 13, curses.KEY_ENTER):
                action = ACTIONS[action_idx]
                if action == "Done":
                    # Validate: must have a root partition
                    has_root = any(p.ptype == "root" for p in parts)
                    has_efi  = (firmware != "uefi" or
                                any(p.ptype == "efi" for p in parts))
                    if not has_root:
                        self.message("Validation",
                                     "No root (/) partition defined.",
                                     "error", step)
                        continue
                    if not has_efi:
                        self.message("Validation",
                                     "UEFI requires an EFI partition.",
                                     "error", step)
                        continue
                    return parts
                elif action == "Cancel":
                    return None
                elif action == "Add":
                    n = len(parts) + 1
                    dev = f"{disk}p{n}" if "nvme" in disk or "mmcblk" in disk \
                          else f"{disk}{n}"
                    p = Partition(device=dev)
                    # Ask size
                    size = self.inputbox("Add Partition",
                                         f"Size for {dev} (e.g. 512M, 8G, rest):",
                                         "rest", step=step)
                    if size is None:
                        continue
                    p.size = size
                    # Type
                    t_idx = self.menu("Partition Type",
                        [("root","Root filesystem (/)"),
                         ("efi", "EFI System Partition"),
                         ("swap","Swap space"),
                         ("data","Data / other"),
                         ("bios_boot","BIOS boot (GRUB, 1MB)")],
                        step=step)
                    if t_idx < 0:
                        continue
                    p.ptype = ["root","efi","swap","data","bios_boot"][t_idx]
                    # Format
                    fmt_opts = {
                        "root":      [("ext4","ext4"),("xfs","XFS"),("btrfs","btrfs")],
                        "efi":       [("fat32","FAT32")],
                        "swap":      [("swap","swap")],
                        "data":      [("ext4","ext4"),("xfs","XFS"),("btrfs","btrfs")],
                        "bios_boot": [("none","none (raw)")],
                    }
                    f_items = fmt_opts.get(p.ptype, [("ext4","ext4")])
                    f_idx = self.menu("Format", f_items, step=step)
                    if f_idx < 0:
                        continue
                    p.fmt = f_items[f_idx][0]
                    # Mountpoint
                    default_mp = {"root":"/","efi":"/boot","swap":"[swap]",
                                  "data":"/data","bios_boot":""}.get(p.ptype,"")
                    mp = self.inputbox("Mountpoint",
                                       "Mount point (leave blank for swap/bios_boot):",
                                       default_mp, step=step)
                    if mp is None:
                        continue
                    p.mountpoint = mp
                    parts.append(p)

                elif action == "Delete":
                    if not parts:
                        continue
                    del_items = [(p.device, p.mountpoint) for p in parts]
                    idx = self.menu("Delete Partition", del_items, step=step)
                    if idx >= 0:
                        del parts[idx]

                elif action == "Edit":
                    if not parts:
                        continue
                    edit_items = [(p.device, p.mountpoint) for p in parts]
                    idx = self.menu("Edit Partition", edit_items, step=step)
                    if idx < 0:
                        continue
                    p = parts[idx]
                    new_size = self.inputbox("Edit Size", "New size:", p.size, step=step)
                    if new_size:
                        p.size = new_size
                    new_mp = self.inputbox("Edit Mountpoint",
                                           "Mount point:", p.mountpoint, step=step)
                    if new_mp is not None:
                        p.mountpoint = new_mp

            elif k == 27:
                return None


# ──────────────────────────────────────────────────────────────────────────────
# Installer steps  (each returns True to proceed, False to go back)
# ──────────────────────────────────────────────────────────────────────────────

LANGUAGES = [
    ("en_US.UTF-8", "English (United States)"),
    ("en_GB.UTF-8", "English (United Kingdom)"),
    ("de_DE.UTF-8", "German / Deutsch"),
    ("nl_NL.UTF-8", "Dutch / Nederlands"),
    ("fr_FR.UTF-8", "French / Français"),
    ("es_ES.UTF-8", "Spanish / Español"),
    ("pl_PL.UTF-8", "Polish / Polski"),
    ("pt_BR.UTF-8", "Portuguese (Brazil)"),
    ("ja_JP.UTF-8", "Japanese / 日本語"),
    ("zh_CN.UTF-8", "Chinese Simplified / 简体中文"),
]

KEYBOARDS = [
    ("us",      "English (US)"),
    ("gb",      "English (UK)"),
    ("de",      "German (de)"),
    ("de-latin1","German (de-latin1)"),
    ("nl",      "Dutch (nl)"),
    ("fr",      "French (fr)"),
    ("be-latin1","Belgian (be-latin1)"),
    ("es",      "Spanish (es)"),
    ("pl2",     "Polish (pl2)"),
    ("br-abnt2","Brazilian (br-abnt2)"),
    ("dvorak",  "Dvorak"),
    ("colemak", "Colemak"),
]

def step_welcome(ui: TUI, cfg: InstallConfig) -> bool:
    return ui.confirm(
        "Welcome to ParamantOS Installer",
        f"This wizard installs ParamantOS v{VERSION} to a local disk.\n\n"
        "The selected disk will be COMPLETELY WIPED.\n\n"
        "Make sure you have a backup of any data you want to keep.\n\n"
        "Press Yes to continue, No to exit.",
        step="Welcome",
    )

def step_language(ui: TUI, cfg: InstallConfig) -> bool:
    default = next((i for i, (k, _) in enumerate(LANGUAGES)
                    if k == cfg.language), 0)
    idx = ui.menu("Language / Sprache / Langue",
                  [(v, k) for k, v in LANGUAGES],
                  default=default, step="1/9 Language")
    if idx < 0:
        return False
    cfg.language = LANGUAGES[idx][0]
    return True

def step_keyboard(ui: TUI, cfg: InstallConfig) -> bool:
    default = next((i for i, (k, _) in enumerate(KEYBOARDS)
                    if k == cfg.keyboard), 0)
    idx = ui.menu("Keyboard Layout",
                  KEYBOARDS, default=default,
                  step="2/9 Keyboard",
                  subtitle="Choose the keyboard layout for the installed system.")
    if idx < 0:
        return False
    cfg.keyboard = KEYBOARDS[idx][0]
    # Apply immediately so the rest of the wizard is usable
    try:
        subprocess.run(["loadkeys", cfg.keyboard],
                       capture_output=True, timeout=5)
    except Exception:
        pass
    return True

def step_network(ui: TUI, cfg: InstallConfig) -> bool:
    # Detect interfaces
    try:
        out = subprocess.check_output(
            ["ip", "-o", "link", "show"],
            stderr=subprocess.DEVNULL, text=True, timeout=5
        )
        ifaces = [l.split(":")[1].strip() for l in out.strip().splitlines()
                  if "lo" not in l]
    except Exception:
        ifaces = []

    if not ifaces:
        ifaces = ["eth0"]

    # Select interface
    iface_items = [(i, "") for i in ifaces]
    default_if  = next((j for j, (i, _) in enumerate(iface_items)
                        if i == cfg.network.interface), 0)
    idx = ui.menu("Network Interface",
                  iface_items, default=default_if, step="3/9 Network",
                  subtitle="Select the network interface to configure.")
    if idx < 0:
        return False
    cfg.network.interface = ifaces[idx]

    # DHCP or static?
    mode_idx = ui.menu("Network Configuration",
        [("dhcp",   "DHCP — automatic (recommended)"),
         ("static", "Static IP — manual configuration")],
        default=(0 if cfg.network.mode == "dhcp" else 1),
        step="3/9 Network")
    if mode_idx < 0:
        return False
    cfg.network.mode = ["dhcp", "static"][mode_idx]

    if cfg.network.mode == "static":
        # IP address
        addr = ui.inputbox("Static IP", "IP address (e.g. 192.168.1.100):",
                           cfg.network.address or "", step="3/9 Network",
                           hint="IPv4 address for this machine")
        if addr is None:
            return False
        try:
            ipaddress.IPv4Address(addr)
        except ValueError:
            ui.message("Invalid IP", f"'{addr}' is not a valid IPv4 address.",
                       "error", "3/9 Network")
            return False
        cfg.network.address = addr

        # Prefix
        prefix = ui.inputbox("Subnet prefix", "Prefix length (e.g. 24 for /24):",
                              str(cfg.network.prefix), step="3/9 Network")
        if prefix is None:
            return False
        try:
            cfg.network.prefix = int(prefix)
            assert 1 <= cfg.network.prefix <= 32
        except Exception:
            ui.message("Invalid prefix",
                       f"'{prefix}' is not a valid prefix length (1–32).",
                       "error", "3/9 Network")
            return False

        # Gateway
        gw = ui.inputbox("Default gateway", "Gateway IP (e.g. 192.168.1.1):",
                         cfg.network.gateway or "", step="3/9 Network")
        if gw is None:
            return False
        cfg.network.gateway = gw

        # DNS
        dns = ui.inputbox("DNS servers",
                          "DNS servers, comma-separated (e.g. 1.1.1.1,8.8.8.8):",
                          ",".join(cfg.network.dns), step="3/9 Network")
        if dns is None:
            return False
        cfg.network.dns = [d.strip() for d in dns.split(",") if d.strip()]

    return True

def _list_disks() -> List[Tuple[str, str]]:
    """Return list of (device, description) for installable disks."""
    try:
        out = subprocess.check_output(
            ["lsblk", "-d", "-o", "NAME,SIZE,MODEL", "--noheadings"],
            stderr=subprocess.DEVNULL, text=True, timeout=10
        )
        disks = []
        for line in out.strip().splitlines():
            parts = line.split(None, 2)
            if not parts:
                continue
            name  = f"/dev/{parts[0]}"
            size  = parts[1] if len(parts) > 1 else "?"
            model = parts[2].strip() if len(parts) > 2 else ""
            # Skip loop, sr, rom devices
            if any(x in parts[0] for x in ("loop", "sr", "rom", "ram")):
                continue
            disks.append((name, f"{size}  {model}"))
        return disks
    except Exception:
        return []

def step_disk(ui: TUI, cfg: InstallConfig) -> bool:
    # Detect firmware
    cfg.storage.firmware = "uefi" if os.path.isdir("/sys/firmware/efi") else "bios"

    disks = _list_disks()
    if not disks:
        ui.message("No Disks Found",
                   "No installable disks were detected.\n"
                   "Ensure a disk is connected and try again.",
                   "error", "4/9 Storage")
        return False

    default = next((i for i, (d, _) in enumerate(disks)
                    if d == cfg.storage.disk), 0)
    idx = ui.menu("Select Target Disk",
                  disks, default=default, step="4/9 Storage",
                  subtitle="ALL DATA ON THE SELECTED DISK WILL BE ERASED.")
    if idx < 0:
        return False
    cfg.storage.disk = disks[idx][0]

    # Whole disk or manual?
    mode_idx = ui.menu("Partitioning Mode",
        [("whole_disk", "Automatic — use entire disk (recommended)"),
         ("manual",     "Manual — custom partition layout (advanced)")],
        default=(0 if cfg.storage.mode == "whole_disk" else 1),
        step="4/9 Storage")
    if mode_idx < 0:
        return False
    cfg.storage.mode = ["whole_disk", "manual"][mode_idx]

    if cfg.storage.mode == "manual":
        parts = ui.partition_editor(cfg.storage.disk,
                                    cfg.storage.firmware,
                                    step="4/9 Storage")
        if parts is None:
            return False
        cfg.storage.partitions = parts

    return True

def step_hostname(ui: TUI, cfg: InstallConfig) -> bool:
    name = ui.inputbox("Hostname",
                       "Enter a hostname for this relay node:",
                       cfg.hostname, step="5/9 Hostname",
                       hint="Letters, numbers, hyphens only. E.g. relay-01")
    if name is None:
        return False
    name = re.sub(r"[^a-zA-Z0-9-]", "-", name).strip("-") or "paramant"
    cfg.hostname = name
    return True

def step_user(ui: TUI, cfg: InstallConfig) -> bool:
    # Username
    uname = ui.inputbox("Admin User", "Username:",
                        cfg.username, step="6/9 User",
                        hint="This user will have sudo access.")
    if uname is None:
        return False
    cfg.username = re.sub(r"[^a-z0-9_-]", "", uname.lower()) or "paramant"

    # Password (twice)
    while True:
        pw1 = ui.inputbox("Password", f"Password for '{cfg.username}':",
                          "", password=True, step="6/9 User")
        if pw1 is None:
            return False
        if len(pw1) < 8:
            ui.message("Weak Password",
                       "Password must be at least 8 characters.",
                       "warn", "6/9 User")
            continue
        pw2 = ui.inputbox("Confirm Password", "Repeat password:",
                          "", password=True, step="6/9 User")
        if pw2 is None:
            return False
        if pw1 != pw2:
            ui.message("Mismatch", "Passwords do not match.", "warn", "6/9 User")
            continue
        cfg.password = pw1
        break

    # SSH key (optional) — M2: validate format before accepting
    while True:
        key = ui.inputbox("SSH Public Key",
                          "Paste SSH public key (optional, Enter to skip):",
                          cfg.ssh_key, step="6/9 User",
                          hint="e.g. ssh-ed25519 AAAA...  You can add keys later.")
        if key is None:
            break
        key = key.strip()
        if not key:
            cfg.ssh_key = ""
            break
        _valid_types = (
            "ssh-ed25519", "ssh-rsa", "ssh-dss",
            "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
            "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
        )
        _parts = key.split()
        if len(_parts) >= 2 and _parts[0] in _valid_types:
            cfg.ssh_key = key
            break
        ui.message("Invalid Key",
                   "Key must start with ssh-ed25519, ssh-rsa, or ecdsa-sha2-*.\n"
                   "Leave blank to skip.",
                   "warn", "6/9 User")
    return True

def step_summary(ui: TUI, cfg: InstallConfig) -> bool:
    net_line = (f"DHCP on {cfg.network.interface}"
                if cfg.network.mode == "dhcp"
                else f"{cfg.network.address}/{cfg.network.prefix} "
                     f"gw {cfg.network.gateway}")
    parts_line = ("automatic" if cfg.storage.mode == "whole_disk"
                  else f"{len(cfg.storage.partitions)} custom partition(s)")

    summary = (
        f"Language : {cfg.language}\n"
        f"Keyboard : {cfg.keyboard}\n"
        f"Hostname : {cfg.hostname}\n"
        f"User     : {cfg.username}\n"
        f"Network  : {net_line}\n"
        f"Disk     : {cfg.storage.disk}  ({parts_line})\n"
        f"Firmware : {cfg.storage.firmware.upper()}\n\n"
        f"ALL DATA ON {cfg.storage.disk} WILL BE ERASED.\n\n"
        f"Continue with installation?"
    )
    return ui.confirm("Installation Summary", summary, step="7/9 Confirm")


# ──────────────────────────────────────────────────────────────────────────────
# Disk operations
# ──────────────────────────────────────────────────────────────────────────────

def _parse_size_to_mib(size_str: str) -> int:
    """Parse a human size string (512M, 4G, 1.5GiB, 512MiB) → integer MiB.
    Used to compute cumulative absolute parted offsets in manual mode."""
    s = size_str.strip().upper()
    m = re.match(r'^(\d+(?:\.\d+)?)\s*(GIB|MIB|TIB|G|M|T)$', s)
    if not m:
        raise ValueError(
            f"Cannot parse size {size_str!r}. Use M/MiB, G/GiB, or T/TiB."
        )
    val, unit = float(m.group(1)), m.group(2)
    factors: dict = {
        "M": 1, "MIB": 1,
        "G": 1000, "GIB": 1024,
        "T": 1_000_000, "TIB": 1_048_576,
    }
    return max(1, int(val * factors[unit]))


def _run(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    with open(LOG, "a") as f:
        f.write(f"$ {' '.join(cmd)}\n")
    result = subprocess.run(cmd, capture_output=True, text=True)
    with open(LOG, "a") as f:
        if result.stdout:
            f.write(result.stdout)
        if result.stderr:
            f.write(result.stderr)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\n"
            f"stderr: {result.stderr.strip()}"
        )
    return result

def _part_device(disk: str, n: int) -> str:
    if any(x in disk for x in ("nvme", "mmcblk")):
        return f"{disk}p{n}"
    return f"{disk}{n}"

def _wait_for_device(dev: str, timeout: int = 15) -> bool:
    for _ in range(timeout):
        if os.path.exists(dev):
            return True
        try:
            subprocess.run(["partprobe"], capture_output=True, timeout=2)
        except Exception:
            pass
        time.sleep(1)
    return False

def partition_disk(cfg: InstallConfig, update) -> Tuple[str, str]:
    """
    Partition the disk according to cfg.storage.
    Returns (part1_dev, part2_dev) — EFI/BIOS-boot and root.
    For manual mode, sets up all listed partitions.
    """
    disk = cfg.storage.disk
    fw   = cfg.storage.firmware

    update(f"Wiping {disk}...")
    try:
        _run(["wipefs", "-a", disk])
        _run(["dd", "if=/dev/zero", f"of={disk}", "bs=1M", "count=2"])
    except Exception:
        pass  # best-effort

    if cfg.storage.mode == "whole_disk":
        update(f"Partitioning {disk} ({fw.upper()})...")
        _run(["parted", "-s", disk, "--", "mklabel", "gpt"])

        if fw == "uefi":
            _run(["parted", "-s", disk, "--",
                  "mkpart", "ESP", "fat32", "1MiB", "513MiB"])
            _run(["parted", "-s", disk, "--", "set", "1", "esp", "on"])
            _run(["parted", "-s", disk, "--",
                  "mkpart", "primary", "ext4", "513MiB", "100%"])
            part1 = _part_device(disk, 1)
            part2 = _part_device(disk, 2)
        else:
            _run(["parted", "-s", disk, "--",
                  "mkpart", "primary", "1MiB", "2MiB"])
            _run(["parted", "-s", disk, "--", "set", "1", "bios_grub", "on"])
            _run(["parted", "-s", disk, "--",
                  "mkpart", "primary", "ext4", "2MiB", "100%"])
            part1 = _part_device(disk, 1)
            part2 = _part_device(disk, 2)

        try:
            subprocess.run(["partprobe", disk], capture_output=True, timeout=5)
        except Exception:
            pass

        if not _wait_for_device(part2):
            raise RuntimeError(
                f"Partition {part2} did not appear after 15s. "
                "Check disk health."
            )

        update(f"Formatting partitions...")
        if fw == "uefi":
            _run(["mkfs.fat", "-F", "32", "-n", "ESP", part1])
        _run(["mkfs.ext4", "-L", "nixos", "-F", part2])

        return part1, part2

    else:
        # Manual mode — track cumulative absolute offsets so parted gets
        # valid non-overlapping start/end positions.
        update("Partitioning disk (manual layout)...")
        _run(["parted", "-s", disk, "--", "mklabel", "gpt"])
        offset_mib = 1   # start after the standard 1 MiB alignment gap
        for i, p in enumerate(cfg.storage.partitions):
            part_start = f"{offset_mib}MiB"
            if p.size == "rest":
                part_end = "100%"
                # Don't advance offset — this must be the last partition
            else:
                size_mib  = _parse_size_to_mib(p.size)
                part_end  = f"{offset_mib + size_mib}MiB"
                offset_mib += size_mib

            ptype_map = {"efi": "fat32", "root": "ext4",
                         "data": "ext4", "swap": "linux-swap",
                         "bios_boot": ""}
            fstype = ptype_map.get(p.ptype, "ext4")
            args = ["parted", "-s", disk, "--", "mkpart", "primary"]
            if fstype:
                args.append(fstype)
            args += [part_start, part_end]
            _run(args)

            n = str(i + 1)
            if p.ptype == "efi":
                _run(["parted", "-s", disk, "--", "set", n, "esp", "on"])
            if p.ptype == "bios_boot":
                _run(["parted", "-s", disk, "--", "set", n, "bios_grub", "on"])

        try:
            subprocess.run(["partprobe", disk], capture_output=True, timeout=5)
        except Exception:
            pass
        time.sleep(2)

        update("Formatting partitions...")
        for i, p in enumerate(cfg.storage.partitions):
            dev = _part_device(disk, i + 1)
            if not _wait_for_device(dev, 10):
                raise RuntimeError(f"Partition {dev} did not appear.")
            if p.fmt == "fat32":
                _run(["mkfs.fat", "-F", "32", dev])
            elif p.fmt in ("ext4", "xfs", "btrfs"):
                _run([f"mkfs.{p.fmt}", "-F", dev] if p.fmt == "ext4"
                     else [f"mkfs.{p.fmt}", dev])
            elif p.fmt == "swap":
                _run(["mkswap", dev])
            # none → skip

        root_p = next((cfg.storage.partitions.index(p) + 1
                       for p in cfg.storage.partitions if p.ptype == "root"), 2)
        efi_p  = next((cfg.storage.partitions.index(p) + 1
                       for p in cfg.storage.partitions if p.ptype == "efi"), 1)
        return _part_device(disk, efi_p), _part_device(disk, root_p)


def mount_partitions(cfg: InstallConfig,
                     part1: str, part2: str, update) -> None:
    update(f"Mounting {part2} → {MOUNT}...")
    _run(["mount", part2, MOUNT])

    if cfg.storage.firmware == "uefi":
        boot = os.path.join(MOUNT, "boot")
        os.makedirs(boot, exist_ok=True)
        update(f"Mounting {part1} → {boot}...")
        _run(["mount", part1, boot])

    # Mount additional partitions (manual mode)
    if cfg.storage.mode == "manual":
        for i, p in enumerate(cfg.storage.partitions):
            if p.ptype in ("root", "efi", "bios_boot"):
                continue
            dev = _part_device(cfg.storage.disk, i + 1)
            if p.mountpoint and p.mountpoint not in ("", "[swap]"):
                mp = os.path.join(MOUNT, p.mountpoint.lstrip("/"))
                os.makedirs(mp, exist_ok=True)
                _run(["mount", dev, mp])
            elif p.fmt == "swap":
                _run(["swapon", dev], check=False)


def umount_all(firmware: str) -> None:
    if firmware == "uefi":
        subprocess.run(["umount", f"{MOUNT}/boot"],
                       capture_output=True)
    for sub in ("dev/pts", "dev", "proc", "sys"):
        subprocess.run(["umount", f"{MOUNT}/{sub}"],
                       capture_output=True)
    subprocess.run(["umount", MOUNT], capture_output=True)


# ──────────────────────────────────────────────────────────────────────────────
# NixOS configuration generation
# ──────────────────────────────────────────────────────────────────────────────

def _nix_net(cfg: InstallConfig) -> str:
    iface = cfg.network.interface or "eth0"
    if cfg.network.mode == "dhcp":
        return f'  networking.interfaces.{iface}.useDHCP = true;'
    dns_list = " ".join(f'"{d}"' for d in cfg.network.dns)
    return (
        f'  networking.interfaces.{iface}.ipv4.addresses = [{{\n'
        f'    address = "{cfg.network.address}";\n'
        f'    prefixLength = {cfg.network.prefix};\n'
        f'  }}];\n'
        f'  networking.defaultGateway = "{cfg.network.gateway}";\n'
        f'  networking.nameservers = [ {dns_list} ];'
    )

def write_nixos_config(cfg: InstallConfig, nixcfg: str, update) -> None:
    """Inject ParamantOS config + hardware config into /mnt/etc/nixos/."""
    src = "/etc/paramantos-src"
    if not os.path.isdir(src):
        # Fallback: find via paramant-help in Nix store
        try:
            ph = subprocess.check_output(
                ["which", "paramant-help"], text=True).strip()
            candidate = os.path.dirname(os.path.realpath(ph))
            if os.path.isdir(candidate):
                src = candidate
        except Exception:
            pass
    if not os.path.isdir(src):
        src = "/etc/nixos"

    update(f"Copying ParamantOS config from {src}...")
    for fname in ("configuration.nix", "module.nix", "scripts.nix",
                  "paramant-relay.nix", "flake.nix", "flake.lock"):
        fsrc = os.path.join(src, fname)
        if os.path.isfile(fsrc):
            shutil.copy(fsrc, os.path.join(nixcfg, fname))
            update(f"  Copied {fname}")

    scripts_src = os.path.join(src, "scripts")
    if os.path.isdir(scripts_src):
        shutil.copytree(scripts_src,
                        os.path.join(nixcfg, "scripts"),
                        dirs_exist_ok=True)
        update("  Copied scripts/")

    # hardware.nix ← generated hardware-configuration.nix
    hw_src = os.path.join(nixcfg, "hardware-configuration.nix")
    hw_dst = os.path.join(nixcfg, "hardware.nix")

    if cfg.storage.firmware == "uefi":
        # Write a minimal hardware.nix that *imports* the generated
        # hardware-configuration.nix and overrides only the bootloader.
        # This matches what paramant-install.sh does and avoids any
        # fragile line-by-line content manipulation.
        with open(hw_dst, "w") as f:
            f.write("# Generated by paramant-installer — UEFI/systemd-boot\n")
            f.write("{ config, lib, pkgs, ... }:\n")
            f.write("{\n")
            f.write("  imports = [ ./hardware-configuration.nix ];\n\n")
            f.write("  boot.loader.systemd-boot.enable        = lib.mkForce true;\n")
            f.write("  boot.loader.efi.canTouchEfiVariables   = lib.mkForce true;\n")
            f.write("  boot.loader.grub.enable                = lib.mkForce false;\n")
            f.write("  boot.loader.grub.efiSupport            = lib.mkForce false;\n")
            f.write("  boot.loader.grub.efiInstallAsRemovable = lib.mkForce false;\n")
            f.write("}\n")
        update("  Patched hardware.nix for UEFI/systemd-boot")
    else:
        # BIOS/legacy: GRUB must know which disk to install its MBR to.
        # Without boot.loader.grub.device nixos-install always fails with
        # "You must set boot.loader.grub.devices or boot.loader.systemd-boot".
        disk = cfg.storage.disk
        with open(hw_dst, "w") as f:
            f.write("# Generated by paramant-installer — BIOS/legacy GRUB\n")
            f.write("{ config, lib, pkgs, ... }:\n")
            f.write("{\n")
            f.write("  imports = [ ./hardware-configuration.nix ];\n\n")
            f.write(f"  boot.loader.grub.enable                = lib.mkForce true;\n")
            f.write(f'  boot.loader.grub.device                = lib.mkForce "{disk}";\n')
            f.write(f"  boot.loader.grub.efiSupport            = lib.mkForce false;\n")
            f.write(f"  boot.loader.grub.efiInstallAsRemovable = lib.mkForce false;\n")
            f.write(f"  boot.loader.efi.canTouchEfiVariables   = lib.mkForce false;\n")
            f.write(f"  boot.loader.grub.useOSProber           = false;\n")
            f.write(f"  boot.loader.grub.splashImage           = null;\n")
            f.write("}\n")
        update(f"  Patched hardware.nix for BIOS/legacy GRUB (device: {disk})")

    # Patch hostname
    cfg_path = os.path.join(nixcfg, "configuration.nix")
    if os.path.isfile(cfg_path):
        with open(cfg_path) as f:
            content = f.read()
        content = re.sub(
            r'networking\.hostName\s*=\s*"[^"]*"',
            f'networking.hostName = "{cfg.hostname}"',
            content
        )
        # Inject i18n.defaultLocale only if missing
        if "i18n.defaultLocale" not in content:
            content = content.replace(
                "networking.hostName",
                f'\n  i18n.defaultLocale = "{cfg.language}";\n  networking.hostName',
                1
            )
        # Inject console.keyMap only if not already defined (configuration.nix may already set it)
        if "console.keyMap" not in content:
            content = content.replace(
                "networking.hostName",
                f'  console.keyMap = "{cfg.keyboard}";\n  networking.hostName',
                1
            )
        # Inject network config after the hostName line (inside the module block)
        if "networking.interfaces" not in content and "useDHCP" not in content:
            net_line = _nix_net(cfg)
            # Insert directly after networking.hostName = "..."; — guaranteed inside { }
            content = re.sub(
                r'(networking\.hostName\s*=\s*"[^"]*";)',
                r'\1\n' + net_line,
                content,
                count=1
            )

        with open(cfg_path, "w") as f:
            f.write(content)
        update(f"  Patched configuration.nix (hostname, locale, network)")

    update("ParamantOS config ready.")


# ──────────────────────────────────────────────────────────────────────────────
# Installation step (8/9)
# ──────────────────────────────────────────────────────────────────────────────

def step_install(ui: TUI, cfg: InstallConfig) -> bool:
    update = ui.progress_screen("Installing ParamantOS", step="8/9 Install")

    update(f"Log file: {LOG}")
    update("")

    try:
        # ── Partition + format ────────────────────────────────────────────────
        update("━━ Partitioning ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        part1, part2 = partition_disk(cfg, update)
        update(f"  EFI/Boot : {part1}")
        update(f"  Root     : {part2}")

        # ── Mount ─────────────────────────────────────────────────────────────
        update("")
        update("━━ Mounting ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        mount_partitions(cfg, part1, part2, update)
        update(f"  Mounted {part2} → {MOUNT}")

        # ── Hardware config ────────────────────────────────────────────────────
        update("")
        update("━━ Hardware config ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        nixcfg = f"{MOUNT}/etc/nixos"
        result = subprocess.run(
            ["nixos-generate-config", "--root", MOUNT],
            capture_output=True, text=True
        )
        with open(LOG, "a") as f:
            f.write(result.stdout + result.stderr)
        if result.returncode != 0:
            raise RuntimeError(f"nixos-generate-config failed:\n{result.stderr}")
        update("  Hardware configuration generated.")

        # ── ParamantOS config ──────────────────────────────────────────────────
        update("")
        update("━━ ParamantOS config ━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        write_nixos_config(cfg, nixcfg, update)

        # ── nixos-install ──────────────────────────────────────────────────────
        update("")
        update("━━ ParamantOS install ━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        update("  This takes several minutes — please wait...")
        update("")

        env = os.environ.copy()
        env["NIX_CONFIG"] = (
            "experimental-features = nix-command flakes\n"
            "flake-registry = "
        )

        proc = subprocess.Popen(
            ["nixos-install", "--root", MOUNT,
             "--flake", f"{MOUNT}/etc/nixos#paramant",
             "--no-root-passwd",
             "--no-channel-copy",
             "--option", "flake-registry", "",
             "--option", "substituters", "",
             "--option", "trusted-substituters", ""],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, env=env
        )
        with open(LOG, "a") as logf:
            for line in proc.stdout:
                logf.write(line)
                update(line.rstrip())
        proc.wait()

        if proc.returncode != 0:
            update("")
            update(f"error: ParamantOS installer exited with code {proc.returncode}")
            update("")
            update("Common causes:")
            update("  • Missing Nix store paths (ISO may be incomplete)")
            update("  • Disk full during installation")
            update("  • Config syntax error in configuration.nix")
            update(f"  Full log: {LOG}")
            update(None)   # wait for Enter
            umount_all(cfg.storage.firmware)
            return False

        # ── Set password ───────────────────────────────────────────────────────
        update("")
        update("━━ Setting password ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        pw_result = subprocess.run(
            ["nixos-enter", "--root", MOUNT, "--",
             "chpasswd"],
            input=f"{cfg.username}:{cfg.password}",
            capture_output=True, text=True
        )
        with open(LOG, "a") as f:
            f.write(pw_result.stderr)
        if pw_result.returncode != 0:
            update(f"warning: chpasswd failed: {pw_result.stderr.strip()}")
        else:
            update(f"  Password set for '{cfg.username}'.")

        # ── SSH key ────────────────────────────────────────────────────────────
        if cfg.ssh_key:
            ssh_dir = f"{MOUNT}/home/{cfg.username}/.ssh"
            os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
            with open(f"{ssh_dir}/authorized_keys", "a") as f:
                f.write(cfg.ssh_key + "\n")
            os.chmod(f"{ssh_dir}/authorized_keys", 0o600)
            subprocess.run(
                ["nixos-enter", "--root", MOUNT, "--",
                 "chown", "-R",
                 f"{cfg.username}:{cfg.username}",
                 f"/home/{cfg.username}/.ssh"],
                capture_output=True
            )
            update(f"  SSH key added for '{cfg.username}'.")

        # ── Unmount ────────────────────────────────────────────────────────────
        update("")
        update("━━ Unmounting ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        subprocess.run(["sync"])
        umount_all(cfg.storage.firmware)
        update("  All partitions unmounted cleanly.")
        update("")
        update("━━ Installation complete! ━━━━━━━━━━━━━━━━━━━━━━━")
        update("")
        update(f"  Log: {LOG}")

        update(None)   # wait for Enter
        return True

    except Exception as exc:
        update("")
        update(f"error: {exc}")
        update("")
        update(f"Full log: {LOG}")
        update(None)
        try:
            umount_all(cfg.storage.firmware)
        except Exception:
            pass
        return False


def step_done(ui: TUI, cfg: InstallConfig) -> None:
    reboot = ui.confirm(
        "Installation Complete",
        f"ParamantOS has been installed to {cfg.storage.disk}.\n\n"
        f"Login: {cfg.username} / <your password>\n"
        f"Setup wizard runs automatically on first boot.\n\n"
        f"Remove the USB drive and reboot now?",
        step="9/9 Done"
    )
    if reboot:
        subprocess.run(["reboot"])


# ──────────────────────────────────────────────────────────────────────────────
# Unattended mode
# ──────────────────────────────────────────────────────────────────────────────

EXAMPLE_CONFIG = """# paramant-installer config — unattended install
language: en_US.UTF-8
keyboard: us
hostname: relay-01

user:
  name: paramant
  password: "ChangeMe123"
  ssh_key: ""          # optional: paste ssh-ed25519 AAAA... here

network:
  interface: eth0
  mode: dhcp           # or: static
  # address: 192.168.1.100
  # prefix: 24
  # gateway: 192.168.1.1
  # dns: [1.1.1.1, 8.8.8.8]

storage:
  mode: whole_disk     # or: manual
  disk: /dev/sda
  # partitions:        # only for manual mode
  #   - size: 512M
  #     type: efi
  #     format: fat32
  #     mountpoint: /boot
  #   - size: 4G
  #     type: swap
  #     format: swap
  #     mountpoint: "[swap]"
  #   - size: rest
  #     type: root
  #     format: ext4
  #     mountpoint: /
"""

def load_config(path: str) -> InstallConfig:
    with open(path) as f:
        raw = f.read()

    if path.endswith(".json"):
        data = json.loads(raw)
    elif HAS_YAML:
        data = yaml.safe_load(raw)
    else:
        raise RuntimeError("PyYAML not available. Use JSON config or install pyyaml.")

    cfg = InstallConfig()
    cfg.unattended = True

    cfg.language = data.get("language", cfg.language)
    cfg.keyboard = data.get("keyboard", cfg.keyboard)
    cfg.hostname  = data.get("hostname",  cfg.hostname)

    user = data.get("user", {})
    cfg.username = user.get("name", cfg.username)
    cfg.password = user.get("password", "")
    cfg.ssh_key  = user.get("ssh_key",  "")

    net = data.get("network", {})
    cfg.network.interface = net.get("interface", "")
    cfg.network.mode      = net.get("mode", "dhcp")
    cfg.network.address   = net.get("address", "")
    cfg.network.prefix    = int(net.get("prefix", 24))
    cfg.network.gateway   = net.get("gateway", "")
    cfg.network.dns       = net.get("dns", cfg.network.dns)

    store = data.get("storage", {})
    cfg.storage.mode = store.get("mode", "whole_disk")
    cfg.storage.disk = store.get("disk", "")
    cfg.storage.firmware = "uefi" if os.path.isdir("/sys/firmware/efi") else "bios"

    for p in store.get("partitions", []):
        cfg.storage.partitions.append(Partition(
            size=p.get("size", "rest"),
            ptype=p.get("type", "root"),
            fmt=p.get("format", "ext4"),
            mountpoint=p.get("mountpoint", "/"),
        ))

    # Validate required fields
    if not cfg.storage.disk:
        raise ValueError("storage.disk must be specified in unattended config")
    # M3: validate disk path — must be /dev/sdX, /dev/vdX, /dev/nvmeXnY, or /dev/hdX
    import re as _re
    if not _re.match(r'^/dev/(sd[a-z]|vd[a-z]|hd[a-z]|nvme\d+n\d+)$', cfg.storage.disk):
        raise ValueError(
            f"storage.disk '{cfg.storage.disk}' is not a valid block device path "
            "(expected /dev/sdX, /dev/vdX, /dev/nvmeXnY, or /dev/hdX)"
        )
    if not cfg.password:
        raise ValueError("user.password must be specified in unattended config")

    return cfg


def run_unattended(cfg: InstallConfig) -> int:
    """Run installation without curses, logging directly to stdout."""
    print(f"ParamantOS Installer v{VERSION} — unattended mode")
    print(f"Log: {LOG}")
    print()

    def update(line):
        if line is not None:
            print(line)
            with open(LOG, "a") as f:
                f.write(line + "\n")

    try:
        print("Partitioning...")
        part1, part2 = partition_disk(cfg, update)
        print("Mounting...")
        mount_partitions(cfg, part1, part2, update)
        print("Generating hardware config...")
        result = subprocess.run(
            ["nixos-generate-config", "--root", MOUNT],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"ERROR: hardware detection failed: {result.stderr}")
            return 1
        nixcfg = f"{MOUNT}/etc/nixos"
        write_nixos_config(cfg, nixcfg, update)

        env = os.environ.copy()
        env["NIX_CONFIG"] = (
            "experimental-features = nix-command flakes\n"
            "flake-registry = "
        )
        print("\nInstalling ParamantOS (this takes several minutes)...\n")
        with open(LOG, "a") as logf:
            proc = subprocess.Popen(
                ["nixos-install", "--root", MOUNT,
                 "--flake", f"{MOUNT}/etc/nixos#paramant",
                 "--no-root-passwd",
                 "--no-channel-copy",
                 "--option", "flake-registry", "",
                 "--option", "substituters", "",
                 "--option", "trusted-substituters", ""],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, env=env
            )
            for line in proc.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()
                logf.write(line)
            proc.wait()

        if proc.returncode != 0:
            print(f"\nERROR: ParamantOS installation failed (exit {proc.returncode})")
            print(f"Full log: {LOG}")
            umount_all(cfg.storage.firmware)
            return 1

        subprocess.run(
            ["nixos-enter", "--root", MOUNT, "--", "chpasswd"],
            input=f"{cfg.username}:{cfg.password}", capture_output=True, text=True
        )
        if cfg.ssh_key:
            ssh_dir = f"{MOUNT}/home/{cfg.username}/.ssh"
            os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
            with open(f"{ssh_dir}/authorized_keys", "a") as f:
                f.write(cfg.ssh_key + "\n")
            os.chmod(f"{ssh_dir}/authorized_keys", 0o600)

        subprocess.run(["sync"])
        umount_all(cfg.storage.firmware)
        print("\nInstallation complete.")
        return 0

    except Exception as exc:
        print(f"\nFATAL: {exc}")
        print(f"Log: {LOG}")
        try:
            umount_all(cfg.storage.firmware)
        except Exception:
            pass
        return 1


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def _check_root():
    if os.geteuid() != 0:
        print("paramant-installer must run as root.")
        print("")
        print("  Run:  sudo paramant-installer")
        print("")
        print("On the ParamantOS ISO, sudo is passwordless for the paramant user.")
        print("paramant-boot-choice launches this automatically with sudo.")
        sys.exit(1)

def _init_log() -> str:
    """Create timestamped log file. Falls back to /root/ if /tmp fails."""
    global LOG
    candidate = f"/tmp/paramant-install-{int(time.time())}.log"
    try:
        open(candidate, "w").close()
        LOG = candidate
    except OSError:
        LOG = "/root/paramant-install.log"
    return LOG

def _check_nixos_install():
    if not shutil.which("nixos-install"):
        print("ParamantOS installer not found.")
        print("This installer must be run from the ParamantOS ISO.")
        sys.exit(1)

def interactive_main(stdscr, cfg: InstallConfig) -> int:
    ui = TUI(stdscr)

    STEPS = [
        step_welcome,
        step_language,
        step_keyboard,
        step_network,
        step_disk,
        step_hostname,
        step_user,
        step_summary,
    ]

    i = 0
    while i < len(STEPS):
        result = STEPS[i](ui, cfg)
        if result:
            i += 1
        elif i > 0:
            i -= 1   # go back
        else:
            # back on welcome = exit
            return 0

    success = step_install(ui, cfg)
    if success:
        step_done(ui, cfg)
    return 0 if success else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"ParamantOS Installer v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", metavar="FILE",
                        help="Unattended install config (YAML or JSON)")
    parser.add_argument("--dump-config", action="store_true",
                        help="Print example config file and exit")
    args = parser.parse_args()

    if args.dump_config:
        print(EXAMPLE_CONFIG)
        return 0

    _check_root()
    _init_log()
    _check_nixos_install()

    if args.config:
        cfg = load_config(args.config)
        return run_unattended(cfg)

    # Interactive TUI
    cfg = InstallConfig()
    try:
        return curses.wrapper(interactive_main, cfg)
    except KeyboardInterrupt:
        print("\nAborted.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
