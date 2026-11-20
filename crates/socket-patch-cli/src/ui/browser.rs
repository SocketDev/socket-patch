//! The full-screen browser of `list` and `show`: a table of rows to pick
//! from, and a page to read when one is opened (a patch: what it fixes,
//! what was measured about it, the diff of each file).
//!
//! It draws on the terminal's alternate screen, so the scrollback is left
//! exactly as it was, and it redraws the whole frame whenever the terminal
//! changes size: nothing on screen depends on how the terminal re-wrapped
//! what was drawn before, which is what an inline menu cannot survive.
//!
//! The table can be shown before everything about its rows is known: the
//! caller sends what it learns afterwards ([`Update`]) and the rows fill
//! in where they stand. Opening a row asks the caller for its page, which
//! arrives the same way.
//!
//! Everything that decides what is on screen is pure ([`State`]: the keys,
//! the scrolling, the frames), so it is tested byte for byte; the terminal
//! handling around it is Unix-only, and elsewhere [`run`] and [`read`]
//! hand their input back for the caller's inline fallback.

#![cfg_attr(not(unix), allow(dead_code))]

use std::sync::mpsc::Receiver;

use super::Style;

/// One cell of a table row.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Cell {
    pub text: String,
    /// The SGR color the text is painted in, where color is on.
    pub paint: Option<&'static str>,
}

impl Cell {
    pub(crate) fn plain(text: impl Into<String>) -> Cell {
        Cell {
            text: text.into(),
            paint: None,
        }
    }

    pub(crate) fn painted(text: impl Into<String>, paint: Option<&'static str>) -> Cell {
        Cell {
            text: text.into(),
            paint,
        }
    }
}

/// One column of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Column {
    pub title: &'static str,
    /// When the terminal is too narrow for every column, the one with the
    /// highest number goes first; `0` always stays.
    pub gives_way: u8,
}

/// The rows to pick from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Table {
    pub title: String,
    pub columns: Vec<Column>,
    /// One cell per column in each row.
    pub rows: Vec<Vec<Cell>>,
}

/// What opening a row shows: lines to scroll through (they may carry
/// color), under a title that stays put.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Page {
    pub title: String,
    pub lines: Vec<String>,
    /// Places to jump between (the first line of each file's diff), as
    /// `(line, name)` in line order.
    pub marks: Vec<(usize, String)>,
}

/// What the caller learned since the table went up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Update {
    /// The cells of row `.0`, replacing the ones it had.
    Row(usize, Vec<Cell>),
    /// What is still being loaded, shown beside the title; empty once
    /// nothing is.
    Note(String),
    /// The page of row `.0`, asked for when it was opened, or why there
    /// is none.
    Page(usize, Result<Page, String>),
}

/// What a key press asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    Up,
    Down,
    PageUp,
    PageDown,
    First,
    Last,
    Left,
    Right,
    /// The next and the previous mark of a page.
    Next,
    Prev,
    Open,
    /// Leave the page for the table, or the table for the shell.
    Back,
    /// A key with no use here.
    Other,
}

/// The key a terminal sent as `bytes` (one read: an escape sequence
/// arrives whole). The arrows and their `less` letters move, Enter opens,
/// `n`/`p` step through a page's marks, and `q`, a bare Esc, Backspace
/// and Ctrl-C go back.
fn decode(bytes: &[u8]) -> Key {
    match bytes {
        [b'\r'] | [b'\n'] => Key::Open,
        [b'q'] | [b'Q'] | [0x1b] | [0x03] | [0x04] | [0x7f] | [0x08] => Key::Back,
        [b'k'] | [0x1b, b'[', b'A'] | [0x1b, b'O', b'A'] => Key::Up,
        [b'j'] | [0x1b, b'[', b'B'] | [0x1b, b'O', b'B'] => Key::Down,
        [b'l'] | [0x1b, b'[', b'C'] | [0x1b, b'O', b'C'] => Key::Right,
        [b'h'] | [0x1b, b'[', b'D'] | [0x1b, b'O', b'D'] => Key::Left,
        [b'b'] | [0x1b, b'[', b'5', b'~'] => Key::PageUp,
        [b' '] | [b'f'] | [0x1b, b'[', b'6', b'~'] => Key::PageDown,
        [b'g'] | [0x1b, b'[', b'H'] | [0x1b, b'O', b'H'] | [0x1b, b'[', b'1', b'~'] => Key::First,
        [b'G'] | [0x1b, b'[', b'F'] | [0x1b, b'O', b'F'] | [0x1b, b'[', b'4', b'~'] => Key::Last,
        [b'n'] | [b'\t'] => Key::Next,
        [b'p'] | [b'N'] | [0x1b, b'[', b'Z'] => Key::Prev,
        _ => Key::Other,
    }
}

/// The keys in `bytes`, what a terminal sent since the last read, and
/// the bytes at its end that are the start of a key not all here yet.
///
/// A read is not a key press: a held key or a slow link delivers several
/// at once, and an escape sequence can arrive in two reads. Each key is
/// cut off and decoded on its own ([`decode`]). An Esc at the very end is
/// left over rather than taken for the Esc key, since it may be the first
/// byte of an arrow: the caller waits a moment for the rest.
fn keys(bytes: &[u8]) -> (Vec<Key>, &[u8]) {
    let mut keys = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let rest = &bytes[at..];
        let len = match rest {
            [0x1b] => break,
            // CSI: parameters, then one final byte.
            [0x1b, b'[', after @ ..] => {
                match after.iter().position(|b| (0x40..=0x7e).contains(b)) {
                    Some(end) => 2 + end + 1,
                    None => break,
                }
            }
            // SS3: one byte.
            [0x1b, b'O'] => break,
            [0x1b, b'O', ..] => 3,
            // Esc, then a key of its own.
            [0x1b, ..] => 1,
            // One character, however many bytes it is.
            [first, ..] => match first {
                0xf0..=0xff => 4,
                0xe0..=0xef => 3,
                0xc0..=0xdf => 2,
                _ => 1,
            }
            .min(rest.len()),
            [] => break,
        };
        keys.push(decode(&rest[..len]));
        at += len;
    }
    (keys, &bytes[at..])
}

/// How a wait for input ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wait {
    /// There is input to read.
    Ready,
    /// The time passed with none.
    TimedOut,
    /// A signal cut the wait short (the terminal was resized, a child
    /// exited): nothing is known yet.
    Interrupted,
}

/// Whether input arrives within `limit`, waiting with `wait` (which is
/// given the time left). A wait a signal cuts short is taken up again
/// for what is left of the time: read as the time having passed, it
/// would take the first byte of an arrow key for the Esc key by itself,
/// and close the page under a terminal being resized.
fn arrives_within(
    limit: std::time::Duration,
    mut wait: impl FnMut(std::time::Duration) -> std::io::Result<Wait>,
) -> std::io::Result<bool> {
    let deadline = std::time::Instant::now() + limit;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match wait(left)? {
            Wait::Ready => return Ok(true),
            Wait::TimedOut => return Ok(false),
            Wait::Interrupted if left.is_zero() => return Ok(false),
            Wait::Interrupted => {}
        }
    }
}

/// How far a sideways step moves a page.
const SIDEWAYS: usize = 8;

/// Where the table stands: the selected row and the first row on screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct View {
    selected: usize,
    top: usize,
}

impl View {
    /// How many rows a terminal `height` lines tall shows: all of it but
    /// the title, the column titles and the key line; one at least.
    fn visible(height: usize) -> usize {
        height.saturating_sub(3).max(1)
    }

    /// The view after `key` on a table of `rows` rows.
    fn after(self, key: Key, rows: usize, height: usize) -> View {
        let last = rows.saturating_sub(1);
        let page = View::visible(height);
        let selected = match key {
            Key::Up => self.selected.saturating_sub(1),
            Key::Down => (self.selected + 1).min(last),
            Key::PageUp => self.selected.saturating_sub(page),
            Key::PageDown => (self.selected + page).min(last),
            Key::First => 0,
            Key::Last => last,
            _ => self.selected,
        };
        View {
            selected,
            top: self.top,
        }
        .in_window(rows, height)
    }

    /// The view scrolled so the selected row is on screen, and so a
    /// terminal that grew shows as many rows as it now can.
    fn in_window(self, rows: usize, height: usize) -> View {
        let visible = View::visible(height);
        let selected = self.selected.min(rows.saturating_sub(1));
        let mut top = self.top.min(rows.saturating_sub(visible));
        if selected < top {
            top = selected;
        } else if selected >= top + visible {
            top = selected + 1 - visible;
        }
        View { selected, top }
    }
}

/// Where a page stands: its first line on screen and how far it is
/// shifted sideways.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Reading {
    top: usize,
    left: usize,
}

impl Reading {
    /// How many of a page's lines a terminal `height` lines tall shows:
    /// all of it but the title and the key line; one at least.
    fn visible(height: usize) -> usize {
        height.saturating_sub(2).max(1)
    }

    /// The furthest a page of `lines` lines scrolls: its last screenful.
    fn end(lines: usize, height: usize) -> usize {
        lines.saturating_sub(Reading::visible(height))
    }

    /// Where the page stands after `key`.
    fn after(self, key: Key, page: &Page, height: usize) -> Reading {
        let end = Reading::end(page.lines.len(), height);
        let screen = Reading::visible(height);
        let top = match key {
            Key::Up => self.top.saturating_sub(1),
            Key::Down => self.top + 1,
            Key::PageUp => self.top.saturating_sub(screen),
            Key::PageDown => self.top + screen,
            Key::First => 0,
            Key::Last => end,
            Key::Next => page
                .marks
                .iter()
                .map(|(line, _)| *line)
                .find(|line| *line > self.top)
                .unwrap_or(self.top),
            Key::Prev => page
                .marks
                .iter()
                .map(|(line, _)| *line)
                .rev()
                .find(|line| *line < self.top)
                .unwrap_or(0),
            _ => self.top,
        };
        let left = match key {
            Key::Right => self.left + SIDEWAYS,
            Key::Left => self.left.saturating_sub(SIDEWAYS),
            _ => self.left,
        };
        Reading {
            top: top.min(end),
            left,
        }
    }

    /// The mark the top of the screen is in: the last one at or above it.
    fn mark(self, page: &Page) -> Option<(usize, &str)> {
        page.marks
            .iter()
            .enumerate()
            .rev()
            .find(|(_, (line, _))| *line <= self.top)
            .map(|(index, (_, name))| (index, name.as_str()))
    }
}

/// `text` on one line of at most `max` characters, column spacing kept.
fn fit(text: &str, max: usize) -> String {
    const ELLIPSIS: &str = "...";
    if text.chars().count() <= max {
        return text.to_string();
    }
    if max <= ELLIPSIS.len() {
        return text.chars().take(max).collect();
    }
    let kept: String = text.chars().take(max - ELLIPSIS.len()).collect();
    format!("{}{ELLIPSIS}", kept.trim_end())
}

/// Columns between the tab stops of a page's lines.
const TAB_STOP: usize = 4;

/// The part of `line` that falls in columns `skip..skip + take`. Color
/// sequences are kept (they take no column) and closed at the end, so a
/// cut line never colors the one after it; any other escape sequence is
/// dropped, since it could move the cursor. Every character takes the
/// columns a terminal gives it, so a line takes exactly the columns it
/// is given: a tab runs to the next [`TAB_STOP`] (the indentation of
/// code is kept), a wide character takes its two columns (or shows as a
/// space where the window cuts it in half), one that takes none rides on
/// the one before it, and any other control character is a space.
fn window(line: &str, skip: usize, take: usize) -> String {
    let end = skip + take;
    let mut out = String::new();
    let mut column = 0usize;
    let mut colored = false;
    let mut chars = line.chars().peekable();
    // Blank columns `from..to`, where they fall in the window.
    let blank = |out: &mut String, from: usize, to: usize| {
        for _ in from.max(skip)..to.min(end) {
            out.push(' ');
        }
    };
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // A CSI sequence: `ESC [`, parameters, one final letter.
            let mut sequence = String::from(c);
            if chars.peek() == Some(&'[') {
                sequence.extend(chars.next());
                for next in chars.by_ref() {
                    sequence.push(next);
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            if sequence.len() > 2 && sequence.ends_with('m') {
                out.push_str(&sequence);
                colored = true;
            }
            continue;
        }
        let width = if c == '\t' {
            TAB_STOP - column % TAB_STOP
        } else if c.is_control() {
            1
        } else {
            console::measure_text_width(c.encode_utf8(&mut [0; 4]))
        };
        if width == 0 {
            // A combining mark: part of the character before it, when
            // that one is shown.
            if column > skip && column <= end {
                out.push(c);
            }
            continue;
        }
        if column >= end {
            break;
        }
        if c == '\t' || c.is_control() {
            blank(&mut out, column, column + width);
        } else if column >= skip && column + width <= end {
            out.push(c);
        } else {
            // Cut by an edge of the window: its columns that are inside.
            blank(&mut out, column, column + width);
        }
        column += width;
    }
    if colored {
        out.push_str("\x1b[0m");
    }
    out
}

/// The columns of `table` a line of `room` characters holds, with the
/// width of each, in order. Every column is as wide as its widest cell
/// (or its title), and a column that gives way and has nothing in any row
/// takes no room. When they do not all fit, the columns that give way are
/// left out, most willing first; if the rest still do not fit, the widest
/// of them is cut.
fn layout(table: &Table, room: usize) -> Vec<(usize, usize)> {
    let mut shown: Vec<(usize, usize)> = table
        .columns
        .iter()
        .enumerate()
        .filter(|(index, column)| {
            column.gives_way == 0
                || table
                    .rows
                    .iter()
                    .any(|row| row.get(*index).is_some_and(|cell| !cell.text.is_empty()))
        })
        .map(|(index, column)| {
            let cells = table
                .rows
                .iter()
                .filter_map(|row| row.get(index))
                .map(|cell| cell.text.chars().count())
                .max()
                .unwrap_or(0);
            (index, cells.max(column.title.chars().count()))
        })
        .collect();
    // Two columns for the selection mark, two between columns.
    let total = |shown: &[(usize, usize)]| {
        2 + shown.iter().map(|(_, width)| width).sum::<usize>() + 2 * shown.len().saturating_sub(1)
    };
    while total(&shown) > room {
        let most_willing = shown
            .iter()
            .enumerate()
            .filter(|(_, (index, _))| table.columns[*index].gives_way > 0)
            .max_by_key(|(_, (index, _))| table.columns[*index].gives_way)
            .map(|(position, _)| position);
        match most_willing {
            Some(position) => {
                shown.remove(position);
            }
            None => break,
        }
    }
    let over = total(&shown).saturating_sub(room);
    if over > 0 {
        if let Some(widest) = shown.iter_mut().max_by_key(|(_, width)| *width) {
            widest.1 = widest.1.saturating_sub(over).max(1);
        }
    }
    shown
}

/// One row of the table in `columns`. `strong` marks the selected row.
fn row_line(row: &[Cell], columns: &[(usize, usize)], strong: bool, style: Style) -> String {
    let mut line = String::new();
    let mut gap = 0usize;
    for (index, width) in columns {
        let cell = row.get(*index).cloned().unwrap_or_default();
        let text = fit(&cell.text, *width);
        let used = text.chars().count();
        if !text.is_empty() {
            // The padding owed since the last cell that had text: a row
            // never ends in spaces.
            line.push_str(&" ".repeat(gap));
            gap = 0;
            let code = match (strong, cell.paint) {
                (true, Some(paint)) => format!("1;{paint}"),
                (true, None) => "1".to_string(),
                (false, Some(paint)) => paint.to_string(),
                (false, None) => String::new(),
            };
            if code.is_empty() {
                line.push_str(&text);
            } else {
                line.push_str(&super::paint(&text, &code, style.color));
            }
        }
        gap += width - used + 2;
    }
    line
}

/// The column titles of `table` in `columns`, dimmed.
fn title_line(table: &Table, columns: &[(usize, usize)], style: Style) -> String {
    let titles: Vec<Cell> = table
        .columns
        .iter()
        .map(|column| Cell::plain(column.title))
        .collect();
    super::dim(
        &row_line(&titles, columns, false, Style::PLAIN),
        style.color,
    )
}

/// The table's column titles and rows as lines of at most `room`
/// characters, for printing once the browser is left (or where there is
/// none): the titles, then a line per row, each indented by two.
pub(crate) fn table_lines(table: &Table, room: usize, style: Style) -> Vec<String> {
    let columns = layout(table, room);
    let mut lines = vec![format!("  {}", title_line(table, &columns, style))];
    lines.extend(
        table
            .rows
            .iter()
            .map(|row| format!("  {}", row_line(row, &columns, false, style))),
    );
    lines
}

/// What the browser shows.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Screen {
    Table,
    /// Row `.0` was opened and its page is on its way.
    Waiting(usize),
    /// Row `.0`'s page.
    Page(usize, Page, Reading),
    /// Row `.0` has no page to show: why.
    NoPage(usize, String),
}

/// What a key press leaves the loop to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Nothing changed.
    Stay,
    Redraw,
    /// Ask the caller for row `.0`'s page.
    Open(usize),
    Leave,
}

/// Everything that decides what is on screen.
#[derive(Debug, Clone, PartialEq, Eq)]
struct State {
    table: Table,
    note: String,
    view: View,
    screen: Screen,
    /// A browser of one page (`show`): going back from it leaves.
    only_page: bool,
    /// The activity mark's frame.
    turn: usize,
    width: usize,
    height: usize,
}

impl State {
    fn of_table(table: Table, width: usize, height: usize) -> State {
        State {
            table,
            note: String::new(),
            view: View::default(),
            screen: Screen::Table,
            only_page: false,
            turn: 0,
            width,
            height,
        }
    }

    fn of_page(page: Page, width: usize, height: usize) -> State {
        State {
            table: Table {
                title: String::new(),
                columns: Vec::new(),
                rows: Vec::new(),
            },
            note: String::new(),
            view: View::default(),
            screen: Screen::Page(0, page, Reading::default()),
            only_page: true,
            turn: 0,
            width,
            height,
        }
    }

    /// Something is on its way: the activity mark is turning.
    fn waiting(&self) -> bool {
        !self.note.is_empty() || matches!(self.screen, Screen::Waiting(_))
    }

    /// Take in what the caller learned. A page that arrives for a row the
    /// user has left is dropped: they asked for something else since.
    fn apply(&mut self, update: Update) {
        match update {
            Update::Row(row, cells) => {
                if let Some(slot) = self.table.rows.get_mut(row) {
                    *slot = cells;
                }
            }
            Update::Note(note) => self.note = note,
            Update::Page(row, page) => {
                if self.screen == Screen::Waiting(row) {
                    self.screen = match page {
                        Ok(page) => Screen::Page(row, page, Reading::default()),
                        Err(why) => Screen::NoPage(row, why),
                    };
                }
            }
        }
    }

    /// The terminal is now `width` by `height`.
    fn resize(&mut self, width: usize, height: usize) {
        self.width = width;
        self.height = height;
        self.view = self.view.in_window(self.table.rows.len(), height);
        if let Screen::Page(_, page, reading) = &mut self.screen {
            reading.top = reading.top.min(Reading::end(page.lines.len(), height));
        }
    }

    fn key(&mut self, key: Key) -> Step {
        match &mut self.screen {
            Screen::Table => match key {
                Key::Back => Step::Leave,
                Key::Open if !self.table.rows.is_empty() => {
                    self.screen = Screen::Waiting(self.view.selected);
                    Step::Open(self.view.selected)
                }
                _ => {
                    let moved = self.view.after(key, self.table.rows.len(), self.height);
                    if moved == self.view {
                        Step::Stay
                    } else {
                        self.view = moved;
                        Step::Redraw
                    }
                }
            },
            Screen::Page(_, page, reading) => match key {
                Key::Back if self.only_page => Step::Leave,
                Key::Back => {
                    self.screen = Screen::Table;
                    Step::Redraw
                }
                _ => {
                    let moved = reading.after(key, page, self.height);
                    if moved == *reading {
                        Step::Stay
                    } else {
                        *reading = moved;
                        Step::Redraw
                    }
                }
            },
            Screen::Waiting(_) | Screen::NoPage(..) => match key {
                Key::Back | Key::Open => {
                    self.screen = Screen::Table;
                    Step::Redraw
                }
                _ => Step::Stay,
            },
        }
    }

    /// The lines of the frame: never more than the terminal has, and none
    /// reaching its last column, so the terminal neither scrolls nor
    /// wraps.
    fn frame(&self, style: Style) -> Vec<String> {
        let room = self.width.saturating_sub(1).max(1);
        let height = self.height.max(1);
        let glyphs = style.glyphs;
        let (mut lines, keys, at): (Vec<String>, &str, String) = match &self.screen {
            Screen::Table => {
                let columns = layout(&self.table, room);
                let mut title = super::bold(&fit(&self.table.title, room), style.color);
                // What is loading goes beside the title where there is
                // room for some of it.
                let left = room.saturating_sub(self.table.title.chars().count() + 5);
                if !self.note.is_empty() && left > 3 {
                    title.push_str(&format!(
                        "   {} {}",
                        super::status::activity_mark(self.turn, style),
                        super::dim(&fit(&self.note, left), style.color)
                    ));
                }
                // On a terminal too narrow even for the columns that stay,
                // a line is cut where the terminal ends.
                let mut lines = vec![
                    title,
                    window(
                        &format!("  {}", title_line(&self.table, &columns, style)),
                        0,
                        room,
                    ),
                ];
                let mark = if glyphs { "❯" } else { ">" };
                for (index, row) in self
                    .table
                    .rows
                    .iter()
                    .enumerate()
                    .skip(self.view.top)
                    .take(View::visible(height))
                {
                    let selected = index == self.view.selected;
                    let text = row_line(row, &columns, selected, style);
                    let line = if selected {
                        format!("{} {text}", super::paint(mark, "36", style.color))
                    } else {
                        format!("  {text}")
                    };
                    lines.push(window(&line, 0, room));
                }
                let keys = if glyphs {
                    "↑↓ move   PgUp/PgDn page   Enter open   q quit"
                } else {
                    "Up/Down move   PgUp/PgDn page   Enter open   q quit"
                };
                let at = format!("{}/{}", self.view.selected + 1, self.table.rows.len());
                (lines, keys, at)
            }
            Screen::Page(_, page, reading) => {
                let mut lines = vec![super::bold(&fit(&page.title, room), style.color)];
                lines.extend(
                    page.lines
                        .iter()
                        .skip(reading.top)
                        .take(Reading::visible(height))
                        .map(|line| window(line, reading.left, room)),
                );
                let keys = match (glyphs, page.marks.len() > 1) {
                    (true, true) => "↑↓ scroll   PgUp/PgDn page   n/p file   ←→ shift   q back",
                    (true, false) => "↑↓ scroll   PgUp/PgDn page   ←→ shift   q back",
                    (false, true) => "Up/Down scroll   PgUp/PgDn page   n/p file   q back",
                    (false, false) => "Up/Down scroll   PgUp/PgDn page   q back",
                };
                let last = (reading.top + Reading::visible(height)).min(page.lines.len());
                let mut at = format!("{last}/{}", page.lines.len());
                if let Some((index, name)) = reading.mark(page) {
                    at = format!("file {}/{} {name}   {at}", index + 1, page.marks.len());
                }
                (lines, keys, at)
            }
            Screen::Waiting(row) => {
                let lines = vec![format!(
                    "{} {}",
                    super::status::activity_mark(self.turn, style),
                    fit(
                        &format!("Reading {}", self.row_name(*row)),
                        room.saturating_sub(2)
                    )
                )];
                (lines, "q back", String::new())
            }
            Screen::NoPage(row, why) => {
                let mut lines = vec![
                    super::bold(&fit(&self.row_name(*row), room), style.color),
                    String::new(),
                ];
                lines.extend(why.lines().map(|line| window(line, 0, room)));
                (lines, "q back", String::new())
            }
        };
        if height >= 2 {
            // The position always shows; the keys give way on a narrow
            // terminal, and then the name of the file before the position.
            let line = if keys.chars().count() + 3 + at.chars().count() <= room {
                format!("{keys}   {at}").trim_end().to_string()
            } else if at.is_empty() {
                fit(keys, room)
            } else if at.chars().count() <= room {
                at
            } else {
                let tail: Vec<char> = at.chars().collect();
                tail[tail.len() - room..].iter().collect()
            };
            lines.truncate(height - 1);
            // The key line sits on the last line of the screen.
            while lines.len() + 1 < height {
                lines.push(String::new());
            }
            lines.push(super::dim(&line, style.color));
        }
        lines.truncate(height);
        lines
    }

    /// What row `row` is called on the screens that stand in for its
    /// page: its first two cells that say anything.
    fn row_name(&self, row: usize) -> String {
        self.table
            .rows
            .get(row)
            .map(|cells| {
                cells
                    .iter()
                    .map(|cell| cell.text.as_str())
                    .filter(|text| !text.is_empty())
                    .take(2)
                    .collect::<Vec<_>>()
                    .join("  ")
            })
            .unwrap_or_default()
    }
}

/// Show `table` full-screen until the user leaves it. `updates` carries
/// what the caller learns meanwhile; `open(row)` is called when a row is
/// opened, and its page is expected as an [`Update::Page`].
///
/// `Ok` is the table as it stood when the user left (every row update
/// applied). `Err` hands the table back untouched: the terminal could not
/// be set up for a full-screen browser (or this is not Unix), and nothing
/// was drawn.
pub(crate) fn run(
    table: Table,
    updates: Receiver<Update>,
    open: impl FnMut(usize),
) -> Result<Table, Table> {
    #[cfg(unix)]
    {
        screen::run(table, updates, open)
    }
    #[cfg(not(unix))]
    {
        let _ = (updates, open);
        Err(table)
    }
}

/// Show `page` full-screen until the user leaves it. `false`: the
/// terminal could not be set up (or this is not Unix) and nothing was
/// drawn.
pub(crate) fn read(page: Page) -> bool {
    #[cfg(unix)]
    {
        screen::read(page)
    }
    #[cfg(not(unix))]
    {
        let _ = page;
        false
    }
}

#[cfg(unix)]
mod screen {
    //! The terminal side: the alternate screen, unbuffered keys, and the
    //! loop that redraws on a key, an update or a size change.

    use std::io::Write;
    use std::sync::mpsc::{Receiver, TryRecvError};
    use std::time::Duration;

    use super::{arrives_within, decode, keys, Key, Page, State, Step, Table, Update, Wait};

    /// Enter the alternate screen and hide the cursor; leave and show.
    const ENTER: &str = "\x1b[?1049h\x1b[?25l";
    const LEAVE: &str = "\x1b[?25h\x1b[?1049l";

    /// How long a wait for a key lasts before the browser looks at the
    /// terminal's size and at what the caller sent, and turns its mark.
    const TICK: Duration = Duration::from_millis(100);

    /// The terminal as the browser found it, put back on drop: its input
    /// settings, the main screen and the cursor.
    struct Restore {
        original: libc::termios,
    }

    impl Restore {
        /// Take keys one at a time, unechoed, and the signal keys as plain
        /// bytes: Ctrl-C then leaves through this guard, where a signal
        /// would kill the process with the terminal still changed. `None`
        /// when stdin's settings cannot be read or set.
        fn install() -> Option<Restore> {
            // SAFETY: `termios` is plain data that `tcgetattr` fills; both
            // calls take a valid descriptor and a valid pointer, and report
            // failure by their return value.
            unsafe {
                let mut original: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(libc::STDIN_FILENO, &mut original) != 0 {
                    return None;
                }
                let mut raw = original;
                raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
                raw.c_cc[libc::VMIN] = 1;
                raw.c_cc[libc::VTIME] = 0;
                if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, &raw) != 0 {
                    return None;
                }
                let mut err = std::io::stderr().lock();
                let _ = err.write_all(ENTER.as_bytes());
                let _ = err.flush();
                Some(Restore { original })
            }
        }
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            let mut err = std::io::stderr().lock();
            let _ = err.write_all(LEAVE.as_bytes());
            let _ = err.flush();
            // SAFETY: restores the settings `install` read from the same
            // descriptor.
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, &self.original);
            }
        }
    }

    /// The terminal's size as `(columns, lines)`.
    fn size() -> (usize, usize) {
        let (lines, columns) = console::Term::stderr().size();
        (usize::from(columns).max(1), usize::from(lines).max(1))
    }

    /// How long a key that is not all here is waited for: the rest of an
    /// escape sequence follows its first byte at once, so an Esc with
    /// nothing after it for this long is the Esc key.
    const REST_OF_KEY: Duration = Duration::from_millis(40);

    /// Wait up to `wait` for stdin to have bytes to read. `Err` when it
    /// cannot be waited on.
    fn wait_readable(wait: Duration) -> std::io::Result<Wait> {
        // `select`, not `poll`: macOS's `poll` does not report terminal
        // devices reliably.
        // SAFETY: `fd_set` is plain data the FD_* macros initialise and
        // fill; stdin is below FD_SETSIZE; `select` gets valid pointers
        // and reports failure by its return value.
        let ready = unsafe {
            let mut readable: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut readable);
            libc::FD_SET(libc::STDIN_FILENO, &mut readable);
            let mut wait = libc::timeval {
                tv_sec: 0,
                tv_usec: wait.as_micros() as libc::suseconds_t,
            };
            libc::select(
                libc::STDIN_FILENO + 1,
                &mut readable,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut wait,
            )
        };
        if ready < 0 {
            let e = std::io::Error::last_os_error();
            return if e.kind() == std::io::ErrorKind::Interrupted {
                Ok(Wait::Interrupted)
            } else {
                Err(e)
            };
        }
        Ok(if ready > 0 {
            Wait::Ready
        } else {
            Wait::TimedOut
        })
    }

    /// Read what stdin has into `bytes`. `Err` when stdin is gone
    /// (closed, or no longer a terminal).
    fn read_into(bytes: &mut Vec<u8>) -> std::io::Result<()> {
        let mut chunk = [0u8; 64];
        // SAFETY: reads at most the buffer's length into it.
        let read =
            unsafe { libc::read(libc::STDIN_FILENO, chunk.as_mut_ptr().cast(), chunk.len()) };
        match read {
            n if n > 0 => {
                bytes.extend_from_slice(&chunk[..n as usize]);
                Ok(())
            }
            0 => Err(std::io::ErrorKind::UnexpectedEof.into()),
            _ => {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    /// The keys pressed within a [`TICK`], in order: none when no key
    /// came. `Err` when stdin is gone.
    fn next_keys() -> std::io::Result<Vec<Key>> {
        // A signal that cuts the tick short is the end of the tick: the
        // caller looks at the terminal's size again.
        if wait_readable(TICK)? != Wait::Ready {
            return Ok(Vec::new());
        }
        let mut bytes = Vec::new();
        read_into(&mut bytes)?;
        let mut pressed = Vec::new();
        loop {
            let (found, rest) = keys(&bytes);
            pressed.extend(found);
            if rest.is_empty() {
                return Ok(pressed);
            }
            // The start of a key: its rest is on its way, or it is the
            // Esc key by itself.
            let rest = rest.to_vec();
            if !arrives_within(REST_OF_KEY, wait_readable)? {
                pressed.push(decode(&rest));
                return Ok(pressed);
            }
            bytes = rest;
            read_into(&mut bytes)?;
        }
    }

    /// Write one frame over the whole screen, in a single write.
    fn draw(lines: &[String]) {
        // Home, each line followed by "erase to end of line", then "erase
        // below": the frame replaces whatever was there, at any size.
        let mut out = String::from("\x1b[H");
        for (index, line) in lines.iter().enumerate() {
            if index > 0 {
                out.push_str("\r\n");
            }
            out.push_str(line);
            out.push_str("\x1b[K");
        }
        out.push_str("\x1b[J");
        let mut err = std::io::stderr().lock();
        let _ = err.write_all(out.as_bytes());
        let _ = err.flush();
    }

    /// Run `state` on the terminal until the user leaves.
    fn browse(
        mut state: State,
        updates: Option<Receiver<Update>>,
        mut open: impl FnMut(usize),
    ) -> State {
        let style = crate::ui::Style::stderr();
        draw(&state.frame(style));
        loop {
            let mut redraw = false;
            if let Some(updates) = &updates {
                loop {
                    match updates.try_recv() {
                        Ok(update) => {
                            state.apply(update);
                            redraw = true;
                        }
                        Err(TryRecvError::Empty) => break,
                        // The caller is done sending: nothing is on its
                        // way any more.
                        Err(TryRecvError::Disconnected) => {
                            if !state.note.is_empty() {
                                state.note.clear();
                                redraw = true;
                            }
                            break;
                        }
                    }
                }
            }
            if redraw {
                draw(&state.frame(style));
                redraw = false;
            }
            match next_keys() {
                Ok(pressed) if !pressed.is_empty() => {
                    for key in pressed {
                        match state.key(key) {
                            Step::Leave => return state,
                            Step::Open(row) => {
                                open(row);
                                redraw = true;
                            }
                            Step::Redraw => redraw = true,
                            Step::Stay => {}
                        }
                    }
                }
                Ok(_) => {
                    let now = size();
                    if now != (state.width, state.height) {
                        state.resize(now.0, now.1);
                        redraw = true;
                    }
                    if state.waiting() {
                        state.turn = state.turn.wrapping_add(1);
                        redraw = true;
                    }
                }
                Err(_) => return state,
            }
            if redraw {
                draw(&state.frame(style));
            }
        }
    }

    pub(super) fn run(
        table: Table,
        updates: Receiver<Update>,
        open: impl FnMut(usize),
    ) -> Result<Table, Table> {
        let Some(_restore) = Restore::install() else {
            return Err(table);
        };
        let (width, height) = size();
        let state = State::of_table(table, width, height);
        Ok(browse(state, Some(updates), open).table)
    }

    pub(super) fn read(page: Page) -> bool {
        let Some(_restore) = Restore::install() else {
            return false;
        };
        let (width, height) = size();
        browse(State::of_page(page, width, height), None, |_| {});
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FANCY: Style = Style {
        color: true,
        glyphs: true,
    };

    fn columns() -> Vec<Column> {
        [
            ("SEVERITY", 0),
            ("PACKAGE", 0),
            ("FIXES", 1),
            ("TESTS", 2),
            ("CHANGE", 3),
            ("MODE", 4),
        ]
        .into_iter()
        .map(|(title, gives_way)| Column { title, gives_way })
        .collect()
    }

    fn table(rows: usize) -> Table {
        Table {
            title: format!("{rows} patches in this project"),
            columns: columns(),
            rows: (0..rows)
                .map(|i| {
                    vec![
                        Cell::painted("HIGH", Some("31")),
                        Cell::plain(format!("pkg-{i:02}@1.0.0")),
                        Cell::plain(format!("CVE-2026-{i:04}")),
                        Cell::plain(""),
                        Cell::plain(""),
                        Cell::plain("hosted"),
                    ]
                })
                .collect(),
        }
    }

    fn page(lines: usize) -> Page {
        Page {
            title: "pkg:npm/pkg-00@1.0.0  HIGH".to_string(),
            lines: (0..lines).map(|i| format!("line {i:03}")).collect(),
            marks: vec![(10, "a.js".to_string()), (40, "lib/b.js".to_string())],
        }
    }

    fn plain(lines: &[String]) -> Vec<String> {
        lines.iter().map(|l| crate::ui::strip_ansi(l)).collect()
    }

    #[test]
    fn keys_decode_to_what_they_ask() {
        for (bytes, key) in [
            (&b"\r"[..], Key::Open),
            (b"\n", Key::Open),
            (b"q", Key::Back),
            (b"\x1b", Key::Back),
            (b"\x03", Key::Back),
            (b"\x7f", Key::Back),
            (b"\x1b[A", Key::Up),
            (b"\x1bOA", Key::Up),
            (b"k", Key::Up),
            (b"\x1b[B", Key::Down),
            (b"j", Key::Down),
            (b"\x1b[C", Key::Right),
            (b"\x1b[D", Key::Left),
            (b"\x1b[5~", Key::PageUp),
            (b"\x1b[6~", Key::PageDown),
            (b" ", Key::PageDown),
            (b"\x1b[H", Key::First),
            (b"g", Key::First),
            (b"\x1b[F", Key::Last),
            (b"G", Key::Last),
            (b"n", Key::Next),
            (b"\t", Key::Next),
            (b"p", Key::Prev),
            (b"\x1b[Z", Key::Prev),
            (b"x", Key::Other),
            // A sequence the browser does not know is ignored, never read
            // as the Esc it begins with.
            (b"\x1b[1;5C", Key::Other),
        ] {
            assert_eq!(decode(bytes), key, "{bytes:?}");
        }
    }

    /// A read is not a key press. Several presses that arrive together
    /// are each a key, and the start of an escape sequence at the end of
    /// a read is left for the next one: it is never taken for the Esc
    /// key, which would close the page under a held arrow.
    #[test]
    fn a_read_is_cut_into_its_keys() {
        let all = |bytes: &'static [u8]| {
            let (found, rest) = keys(bytes);
            (found, rest.to_vec())
        };
        assert_eq!(
            all(b"\x1b[B\x1b[B\x1b[B"),
            (vec![Key::Down, Key::Down, Key::Down], vec![])
        );
        assert_eq!(
            all(b"jj\x1b[6~k\r"),
            (
                vec![Key::Down, Key::Down, Key::PageDown, Key::Up, Key::Open],
                vec![]
            )
        );
        assert_eq!(all(b"\x1bOA\x1bOB"), (vec![Key::Up, Key::Down], vec![]));
        // Split after the Esc, after `[`, inside the parameters, after `O`.
        assert_eq!(all(b"\x1b[B\x1b"), (vec![Key::Down], b"\x1b".to_vec()));
        assert_eq!(all(b"\x1b["), (vec![], b"\x1b[".to_vec()));
        assert_eq!(all(b"j\x1b[5"), (vec![Key::Down], b"\x1b[5".to_vec()));
        assert_eq!(all(b"\x1bO"), (vec![], b"\x1bO".to_vec()));
        // The rest arrives: the key is whole.
        assert_eq!(all(b"\x1b[5~"), (vec![Key::PageUp], vec![]));
        // Esc followed by a key of its own is Esc, then that key.
        assert_eq!(all(b"\x1bq"), (vec![Key::Back, Key::Back], vec![]));
        assert_eq!(all(b"\x1bj"), (vec![Key::Back, Key::Down], vec![]));
        // A sequence the browser does not know is one key it ignores, and
        // a character of several bytes is one key too.
        assert_eq!(all(b"\x1b[1;5Cj"), (vec![Key::Other, Key::Down], vec![]));
        assert_eq!(all("éj".as_bytes()), (vec![Key::Other, Key::Down], vec![]));
        assert_eq!(all(b""), (vec![], vec![]));
    }

    /// The wait for the rest of a key rides out a signal: an interrupted
    /// wait is taken up again for the time that is left, so a resize in
    /// the middle of an arrow key never turns its first byte into Esc.
    /// Only the time passing ends the wait with nothing.
    #[test]
    fn the_wait_for_the_rest_of_a_key_rides_out_signals() {
        use std::time::Duration;
        let limit = Duration::from_millis(40);
        let scripted = |script: &'static [Wait]| {
            let mut calls = 0;
            let result = arrives_within(limit, |left| {
                assert!(left <= limit);
                calls += 1;
                Ok(script[(calls - 1).min(script.len() - 1)])
            });
            (result.unwrap(), calls)
        };
        assert_eq!(scripted(&[Wait::Ready]), (true, 1));
        assert_eq!(scripted(&[Wait::TimedOut]), (false, 1));
        // Interrupted, then the rest arrives: the key is whole.
        assert_eq!(
            scripted(&[Wait::Interrupted, Wait::Interrupted, Wait::Ready]),
            (true, 3)
        );
        // Interrupted, then nothing in what was left of the time.
        assert_eq!(scripted(&[Wait::Interrupted, Wait::TimedOut]), (false, 2));
        // Signals without end stop at the limit, not never.
        let started = std::time::Instant::now();
        let ended = arrives_within(limit, |left| {
            std::thread::sleep(left.min(Duration::from_millis(5)));
            Ok(Wait::Interrupted)
        });
        assert!(!ended.unwrap());
        assert!(started.elapsed() >= limit);
        assert!(started.elapsed() < Duration::from_secs(5));
        // A wait that fails is the failure.
        assert!(arrives_within(limit, |_| Err(std::io::ErrorKind::Other.into())).is_err());
    }

    #[test]
    fn the_view_follows_the_selection_and_stops_at_the_ends() {
        // 10 lines: 7 rows in view.
        let start = View::default();
        assert_eq!(View::visible(10), 7);
        assert_eq!(start.after(Key::Up, 30, 10), start);
        let mut view = start;
        for _ in 0..6 {
            view = view.after(Key::Down, 30, 10);
        }
        assert_eq!(
            view,
            View {
                selected: 6,
                top: 0
            }
        );
        // One more scrolls.
        let view = view.after(Key::Down, 30, 10);
        assert_eq!(
            view,
            View {
                selected: 7,
                top: 1
            }
        );
        let paged = view.after(Key::PageDown, 30, 10);
        assert_eq!(
            paged,
            View {
                selected: 14,
                top: 8
            }
        );
        let last = paged.after(Key::Last, 30, 10);
        assert_eq!(
            last,
            View {
                selected: 29,
                top: 23
            }
        );
        assert_eq!(last.after(Key::Down, 30, 10), last);
        assert_eq!(last.after(Key::PageDown, 30, 10), last);
        assert_eq!(last.after(Key::First, 30, 10), View::default());
        // A table shorter than the screen never scrolls.
        assert_eq!(
            start.after(Key::Last, 3, 10),
            View {
                selected: 2,
                top: 0
            }
        );
    }

    /// The reported need: the browser must survive a resize. A smaller
    /// terminal keeps the selected row in view; a larger one fills with
    /// rows again instead of leaving the old window at the bottom.
    #[test]
    fn a_resize_keeps_the_selection_in_view_and_fills_the_screen() {
        let at_end = View {
            selected: 29,
            top: 23,
        };
        // Shrunk to 6 lines (3 rows): the selection stays on screen.
        assert_eq!(
            at_end.in_window(30, 6),
            View {
                selected: 29,
                top: 27
            }
        );
        // Grown to 40 lines: every row fits, so the table starts at the top.
        assert_eq!(
            at_end.in_window(30, 40),
            View {
                selected: 29,
                top: 0
            }
        );
        // In the middle, shrinking moves the window only as far as needed.
        let middle = View {
            selected: 12,
            top: 8,
        };
        assert_eq!(
            middle.in_window(30, 6),
            View {
                selected: 12,
                top: 10
            }
        );
        // One-line and zero-line terminals still show the selected row.
        assert_eq!(middle.in_window(30, 1).top, 12);
        assert_eq!(middle.in_window(30, 0).top, 12);
        // The page a reader is in is held to its last screenful.
        let mut state = State::of_page(page(100), 80, 12);
        state.key(Key::Last);
        assert!(matches!(&state.screen, Screen::Page(_, _, reading) if reading.top == 90));
        state.resize(80, 40);
        assert!(matches!(&state.screen, Screen::Page(_, _, reading) if reading.top == 62));
    }

    #[test]
    fn a_table_frame_fits_the_terminal_at_any_size() {
        let state = |rows: usize, width: usize, height: usize| {
            let mut state = State::of_table(table(rows), width, height);
            state.key(Key::Down);
            state
        };
        assert_eq!(
            state(30, 80, 8).frame(Style::PLAIN),
            [
                "30 patches in this project",
                "  SEVERITY  PACKAGE       FIXES          MODE",
                "  HIGH      pkg-00@1.0.0  CVE-2026-0000  hosted",
                "> HIGH      pkg-01@1.0.0  CVE-2026-0001  hosted",
                "  HIGH      pkg-02@1.0.0  CVE-2026-0002  hosted",
                "  HIGH      pkg-03@1.0.0  CVE-2026-0003  hosted",
                "  HIGH      pkg-04@1.0.0  CVE-2026-0004  hosted",
                "Up/Down move   PgUp/PgDn page   Enter open   q quit   2/30",
            ]
        );
        // Every size: never more lines than the terminal has, and no line
        // reaches the last column.
        for width in [1, 2, 5, 20, 39, 40, 41, 80, 200] {
            for height in [0, 1, 2, 3, 4, 10, 50] {
                for style in [Style::PLAIN, FANCY] {
                    let mut state = State::of_table(table(30), width, height);
                    for _ in 0..17 {
                        state.key(Key::Down);
                    }
                    let lines = plain(&state.frame(style));
                    assert!(lines.len() <= height.max(1), "{width}x{height}: {lines:?}");
                    for line in &lines {
                        assert!(
                            line.chars().count() <= width.saturating_sub(1).max(1),
                            "{width}x{height}: {line:?}"
                        );
                    }
                    assert!(
                        lines.iter().any(|l| l.contains("pkg-17")) || width < 30 || height < 4,
                        "{width}x{height}: {lines:?}"
                    );
                }
            }
        }
        // A narrow terminal gives up the columns that give way, most
        // willing first, then cuts what is left; the position stays.
        assert_eq!(
            state(30, 44, 6).frame(Style::PLAIN),
            [
                "30 patches in this project",
                "  SEVERITY  PACKAGE       FIXES",
                "  HIGH      pkg-00@1.0.0  CVE-2026-0000",
                "> HIGH      pkg-01@1.0.0  CVE-2026-0001",
                "  HIGH      pkg-02@1.0.0  CVE-2026-0002",
                "2/30",
            ]
        );
        assert_eq!(
            state(30, 22, 5).frame(Style::PLAIN),
            [
                "30 patches in this...",
                "  SEVERITY  PACKAGE",
                "  HIGH      pkg-00...",
                "> HIGH      pkg-01...",
                "2/30",
            ]
        );
        // A short table leaves the key line on the last line.
        let short = state(2, 80, 7).frame(Style::PLAIN);
        assert_eq!(short.len(), 7);
        assert_eq!(short[4..6], ["", ""]);
        assert!(short[6].ends_with("2/2"));
        // Glyph terminals mark the row with an arrow, name the arrows and
        // paint the cells: the selected row in bold.
        let fancy = state(30, 80, 8).frame(FANCY);
        assert!(
            fancy[3].starts_with("\x1b[36m❯\x1b[0m \x1b[1;31mHIGH\x1b[0m"),
            "{fancy:?}"
        );
        assert!(fancy[2].starts_with("  \x1b[31mHIGH\x1b[0m"), "{fancy:?}");
        assert!(plain(&fancy)[7].starts_with("↑↓ move"), "{fancy:?}");
    }

    /// The table goes up before everything about its rows is known: what
    /// the caller learns later fills in where the rows stand, the note
    /// says what is still loading, and columns appear as they get content.
    #[test]
    fn updates_fill_the_rows_in_and_say_what_is_loading() {
        let mut state = State::of_table(table(3), 100, 8);
        assert!(!state.waiting());
        state.apply(Update::Note("loading details 0/3".to_string()));
        assert!(state.waiting());
        assert_eq!(
            state.frame(Style::PLAIN)[0],
            "3 patches in this project   | loading details 0/3"
        );
        let mut cells = state.table.rows[1].clone();
        cells[3] = Cell::painted("106/106", Some("32"));
        cells[4] = Cell::plain("+26 -22");
        state.apply(Update::Row(1, cells));
        state.apply(Update::Note(String::new()));
        assert!(!state.waiting());
        assert_eq!(
            state.frame(Style::PLAIN)[..5],
            [
                "3 patches in this project",
                "  SEVERITY  PACKAGE       FIXES          TESTS    CHANGE   MODE",
                "> HIGH      pkg-00@1.0.0  CVE-2026-0000                    hosted",
                "  HIGH      pkg-01@1.0.0  CVE-2026-0001  106/106  +26 -22  hosted",
                "  HIGH      pkg-02@1.0.0  CVE-2026-0002                    hosted",
            ]
        );
        // A row that is not there is ignored.
        state.apply(Update::Row(9, Vec::new()));
        assert_eq!(state.table.rows.len(), 3);
        // The same rows print as plain lines once the browser is left.
        assert_eq!(
            table_lines(&state.table, 100, Style::PLAIN)[..2],
            [
                "  SEVERITY  PACKAGE       FIXES          TESTS    CHANGE   MODE",
                "  HIGH      pkg-00@1.0.0  CVE-2026-0000                    hosted",
            ]
        );
    }

    /// Opening a row asks for its page and waits for it; the page takes
    /// the screen when it arrives, scrolls, steps between its files, and
    /// goes back to the table where the user left it.
    #[test]
    fn a_row_opens_into_a_page_that_scrolls_and_steps_between_files() {
        let mut state = State::of_table(table(5), 60, 8);
        state.key(Key::Down);
        assert_eq!(state.key(Key::Open), Step::Open(1));
        assert!(state.waiting());
        assert_eq!(
            state.frame(Style::PLAIN),
            [
                "| Reading HIGH  pkg-01@1.0.0",
                "",
                "",
                "",
                "",
                "",
                "",
                "q back",
            ]
        );
        // A page for another row is not what was asked for.
        state.apply(Update::Page(3, Ok(page(60))));
        assert_eq!(state.screen, Screen::Waiting(1));
        state.apply(Update::Page(1, Ok(page(60))));
        assert_eq!(
            state.frame(Style::PLAIN),
            [
                "pkg:npm/pkg-00@1.0.0  HIGH",
                "line 000",
                "line 001",
                "line 002",
                "line 003",
                "line 004",
                "line 005",
                "Up/Down scroll   PgUp/PgDn page   n/p file   q back   6/60",
            ]
        );
        // `n` goes to the next file, and the key line names it (the keys
        // give way to it at this width).
        assert_eq!(state.key(Key::Next), Step::Redraw);
        let frame = state.frame(Style::PLAIN);
        assert_eq!(frame[1], "line 010");
        assert_eq!(frame[7], "file 1/2 a.js   16/60");
        state.key(Key::Next);
        assert_eq!(state.frame(Style::PLAIN)[1], "line 040");
        assert_eq!(state.key(Key::Next), Step::Stay, "no file after the last");
        state.key(Key::Prev);
        assert_eq!(state.frame(Style::PLAIN)[1], "line 010");
        // Scrolling stops at the last screenful.
        state.key(Key::Last);
        let frame = state.frame(Style::PLAIN);
        assert_eq!(frame[1], "line 054");
        assert_eq!(frame[6], "line 059");
        assert_eq!(state.key(Key::Down), Step::Stay);
        assert_eq!(state.key(Key::PageDown), Step::Stay);
        // A wide terminal shows the keys too.
        state.resize(120, 8);
        assert_eq!(
            state.frame(Style::PLAIN)[7],
            "Up/Down scroll   PgUp/PgDn page   n/p file   q back   file 2/2 lib/b.js   60/60"
        );
        // Back to the table, on the row that was opened.
        assert_eq!(state.key(Key::Back), Step::Redraw);
        assert_eq!(state.screen, Screen::Table);
        assert_eq!(state.view.selected, 1);
        assert_eq!(state.key(Key::Back), Step::Leave);
    }

    #[test]
    fn a_row_without_a_page_says_why_and_goes_back() {
        let mut state = State::of_table(table(2), 60, 6);
        state.key(Key::Open);
        state.apply(Update::Page(
            0,
            Err("the patch service could not be reached".to_string()),
        ));
        assert_eq!(
            state.frame(Style::PLAIN),
            [
                "HIGH  pkg-00@1.0.0",
                "",
                "the patch service could not be reached",
                "",
                "",
                "q back",
            ]
        );
        assert!(!state.waiting());
        assert_eq!(state.key(Key::Down), Step::Stay);
        assert_eq!(state.key(Key::Back), Step::Redraw);
        assert_eq!(state.screen, Screen::Table);
        // Leaving while the page is on its way drops it when it comes.
        state.key(Key::Open);
        state.key(Key::Back);
        state.apply(Update::Page(0, Ok(page(5))));
        assert_eq!(state.screen, Screen::Table);
    }

    /// `show` is a browser of one page: going back from it leaves.
    #[test]
    fn a_lone_page_leaves_on_back() {
        let mut state = State::of_page(page(5), 40, 6);
        assert_eq!(
            state.frame(Style::PLAIN),
            [
                "pkg:npm/pkg-00@1.0.0  HIGH",
                "line 000",
                "line 001",
                "line 002",
                "line 003",
                "4/5",
            ]
        );
        assert_eq!(state.key(Key::Down), Step::Redraw);
        assert_eq!(
            state.key(Key::Down),
            Step::Stay,
            "the last line is on screen"
        );
        assert_eq!(state.key(Key::Back), Step::Leave);
    }

    /// A page's lines are cut to the terminal, never wrapped: color
    /// sequences pass and are closed, anything that could move the cursor
    /// is dropped, and a character that is not one column wide is shown as
    /// one that is.
    #[test]
    fn a_window_of_a_line_takes_exactly_its_columns() {
        assert_eq!(window("abcdefghij", 0, 4), "abcd");
        assert_eq!(window("abcdefghij", 8, 4), "ij");
        assert_eq!(window("abcdefghij", 20, 4), "");
        assert_eq!(
            window("\x1b[32m+added line\x1b[0m", 0, 6),
            "\x1b[32m+added\x1b[0m"
        );
        assert_eq!(
            window("\x1b[32m+added line\x1b[0m", 7, 4),
            "\x1b[32mline\x1b[0m\x1b[0m"
        );
        assert_eq!(window("a\x07c", 0, 9), "a c");
        assert_eq!(window("a\x1b[2Jb\x1b[Hc", 0, 9), "abc");
        // A tab runs to the next stop, so code keeps its indentation,
        // wherever the window starts.
        assert_eq!(window("\tif x {", 0, 12), "    if x {");
        assert_eq!(window("+\t\treturn", 0, 20), "+       return");
        assert_eq!(window("ab\tc", 0, 9), "ab  c");
        assert_eq!(window("\t\tx", 6, 9), "  x");
        assert_eq!(window("\tx", 0, 2), "  ");
        // A wide character takes its two columns, and shows as a space
        // where an edge of the window cuts it in half.
        assert_eq!(window("日本語", 0, 9), "日本語");
        assert_eq!(window("日本語", 0, 4), "日本");
        assert_eq!(window("日本語", 0, 3), "日 ");
        assert_eq!(window("日本語", 1, 4), " 本 ");
        assert_eq!(window("a日b", 0, 4), "a日b");
        // One that takes no column rides on the one before it.
        assert_eq!(window("e\u{301}x", 0, 2), "e\u{301}x");
        assert_eq!(window("e\u{301}x", 1, 2), "x");
        // Shifted sideways, a page shows the rest of its long lines.
        let mut state = State::of_page(
            Page {
                title: "t".to_string(),
                lines: vec!["0123456789abcdefghij".to_string()],
                marks: Vec::new(),
            },
            12,
            4,
        );
        assert_eq!(state.frame(Style::PLAIN)[1], "0123456789a");
        state.key(Key::Right);
        assert_eq!(state.frame(Style::PLAIN)[1], "89abcdefghi");
        state.key(Key::Left);
        assert_eq!(state.key(Key::Left), Step::Stay);
    }

    #[test]
    fn the_layout_drops_willing_columns_then_cuts_the_widest() {
        let table = table(3);
        let widths = |room: usize| -> Vec<(&str, usize)> {
            layout(&table, room)
                .into_iter()
                .map(|(index, width)| (table.columns[index].title, width))
                .collect()
        };
        // TESTS and CHANGE have nothing in them yet: they take no room.
        assert_eq!(
            widths(200),
            [("SEVERITY", 8), ("PACKAGE", 12), ("FIXES", 13), ("MODE", 6)]
        );
        assert_eq!(
            widths(40),
            [("SEVERITY", 8), ("PACKAGE", 12), ("FIXES", 13)]
        );
        assert_eq!(widths(30), [("SEVERITY", 8), ("PACKAGE", 12)]);
        assert_eq!(widths(20), [("SEVERITY", 8), ("PACKAGE", 8)]);
        assert_eq!(widths(4), [("SEVERITY", 8), ("PACKAGE", 1)]);
    }
}
