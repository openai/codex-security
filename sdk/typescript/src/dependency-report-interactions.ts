// All evidence lives in the document. The script only selects what is visible.
export const reportInteractions = String.raw`
(() => {
  const all = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const byId = id => document.getElementById(id);
  const scroll = element => element?.scrollIntoView({ block: 'nearest' });
  const plainClick = e => !e.ctrlKey && !e.metaKey && !e.shiftKey && !e.altKey && !(e.button > 0);
  const setHash = (id, replace = false) => {
    const url = new URL(location.href);
    url.hash = id;
    if (url.href === location.href) return;
    if (replace || history.state?.inspector) history.replaceState(history.state, '', url);
    else history.pushState(null, '', url);
  };

  function inspect(inspector) {
    const frames = all('[data-frame]', inspector);
    if (!frames.length) return;
    const first = selector => inspector.querySelector(selector);
    const range = first('[data-range]');
    const expand = first('[data-expand]');
    const follows = all('[data-follow]', inspector);
    const outside = all('[data-in-range="false"]', inspector);
    const prev = first('[data-prev]');
    const next = first('[data-next]');
    const position = first('[data-position]');
    const jump = first('[data-jump]');
    const sink = first('[data-role="sink"]') || first('[data-role="query_sink"]') || first('[data-role="call_site"]');
    const matched = frames.filter(frame => frame.dataset.inRange !== 'false');
    const initial = matched.find(frame => frame.open) || matched[0] || frames[0];
    let full = !range || !matched.length;
    let active = initial;
    let expanded = false;
    const folded = new Set();
    const visible = () => full ? frames : matched;
    const adjacent = offset => visible()[visible().indexOf(active) + offset];
    const header = frame => frame.querySelector('summary');

    function select(frame, open = true) {
      active = frame;
      if (frame.dataset.inRange === 'false') full = true;
      for (const row of outside) row.hidden = !full;
      if (expanded && !open) folded.add(active);
      else folded.delete(active);
      for (const item of frames) {
        item.open = expanded ? !item.hidden && !folded.has(item) : item === active && open;
        if (item === active) header(item).setAttribute('aria-current', 'step');
        else header(item).removeAttribute('aria-current');
      }
      if (expand) {
        expand.textContent = expanded ? 'Collapse others' : 'Expand all';
        expand.setAttribute('aria-pressed', String(expanded));
      }
      if (range) {
        range.textContent = full ? 'Show matched path' : 'Show full stack';
        range.setAttribute('aria-pressed', String(full));
      }
      const at = visible().indexOf(active);
      if (prev) prev.disabled = at === 0;
      const last = at === visible().length - 1;
      if (next) next.disabled = last;
      for (const button of follows) button.hidden = visible().at(-1)?.contains(button) || false;
      if (position) position.textContent = (at + 1) + ' / ' + visible().length;
    }
    function visit(frame, keyboard = false) {
      if (!frame) return;
      select(frame);
      setHash(frame.id, keyboard);
      if (keyboard) header(frame).focus({ preventScroll: true });
      scroll(header(frame));
    }
    expand?.addEventListener('click', () => {
      expanded = !expanded;
      folded.clear();
      select(active);
    });
    range?.addEventListener('click', () => {
      full = !full;
      if (!full && !matched.includes(active)) {
        select(initial);
        setHash(active.id, true);
      } else select(active, active.open);
    });
    for (const button of follows) button.addEventListener('click', () => {
      const list = visible();
      visit(list[list.indexOf(button.closest('[data-frame]')) + 1]);
      header(active).focus({ preventScroll: true });
    });
    jump?.addEventListener('click', () => visit(sink));
    prev?.addEventListener('click', () => visit(adjacent(-1)));
    next?.addEventListener('click', () => visit(adjacent(1)));
    inspector.addEventListener('click', e => {
      const frame = e.target.closest('[data-frame] > summary')?.parentElement;
      if (!frame || !plainClick(e) || e.target.closest('a,button')) return;
      e.preventDefault();
      if (frame.open) {
        select(frame, false);
        setHash(frame.id);
      } else visit(frame);
    });
    inspector.addEventListener('keydown', e => {
      const frame = e.target.closest('[data-frame] > summary')?.parentElement;
      if (!frame || !plainClick(e)) return;
      const list = visible();
      const at = list.indexOf(frame);
      const move = {ArrowUp: at - 1, ArrowDown: at + 1, Home: 0, End: list.length - 1};
      if (Object.hasOwn(move, e.key)) {
        e.preventDefault();
        visit(list[move[e.key]], true);
      }
    });
    select(initial);
    return frame => select(frame ?? initial);
  }

  const search = document.querySelector('[data-search]');
  const verdict = document.querySelector('[data-verdict-filter]');
  const empty = all('[data-empty], [data-no-results]');
  const count = document.querySelector('[data-count]');
  const rail = document.querySelector('.rail-disclosure');
  const compact = matchMedia('(max-width: 720px)');
  const groups = all('.queue-group');
  const sections = all('[data-section]');
  for (const node of all('[data-js]')) node.hidden = false;
  const entries = all('[data-entry]').map(link => {
    const panel = byId(link.dataset.entry);
    const inspector = panel.querySelector('[data-inspector]');
    return {
      link, panel, section: panel.closest('[data-section]'),
      terms: (link.textContent + ' ' + (link.dataset.searchText || '')).toLowerCase(),
      reveal: inspector && inspect(inspector),
    };
  });
  let active;
  const workspace = document.querySelector('.workspace');
  const focusButtons = all('[data-focus]');
  let focused;
  function updateFocus() {
    const previous = focused;
    focused = active && history.state?.inspector === active.panel.id ? active : undefined;
    workspace?.classList.toggle('is-focused', !!focused);
    for (const button of focusButtons) {
      const selected = Boolean(focused?.panel.contains(button));
      button.textContent = selected ? 'Exit focus' : 'Focus';
      button.setAttribute('aria-pressed', String(selected));
      button.setAttribute('aria-label', selected ? 'Exit focused view' : 'Focus on call path');
    }
    if (previous && !focused && previous === active) {
      // Fragment navigation can reset keyboard focus after popstate returns.
      const url = location.href;
      const before = document.activeElement;
      setTimeout(() => {
        if (active !== previous || focused || location.href !== url) return;
        if (document.activeElement === before || document.activeElement === document.body)
          previous.panel.querySelector('[data-focus]')?.focus({ preventScroll: true });
      }, 0);
    }
  }
  for (const button of focusButtons) button.addEventListener('click', () => {
    if (focused) history.back();
    else {
      history.pushState({ inspector: active.panel.id }, '', location.href);
      updateFocus();
      scroll(button.closest('[data-inspector]')?.querySelector('.inspector-head'));
    }
  });
  document.addEventListener('keydown', event => {
    if (focused && event.key === 'Escape') {
      event.preventDefault();
      history.back();
    }
  });
  function clear() {
    if (search) search.value = '';
    if (verdict) verdict.value = '';
  }

  function draw(requested) {
    const words = (search?.value || '').toLowerCase().trim().split(/\s+/);
    let matches = entries.filter(item =>
      (!verdict?.value || item.link.dataset.verdict === verdict.value) &&
      words.every(word => item.terms.includes(word))
    );
    // A deep link takes precedence over an incompatible local filter.
    if (requested && !matches.includes(requested)) {
      clear();
      matches = entries;
    }
    const visible = new Set(matches);
    active = requested || (visible.has(active) ? active : matches[0]);
    for (const item of entries) {
      item.link.hidden = !visible.has(item);
      item.panel.hidden = item !== active;
      if (item === active) item.link.setAttribute('aria-current', 'true');
      else item.link.removeAttribute('aria-current');
    }
    updateFocus();
    for (const section of sections) section.hidden = section !== active?.section;
    for (const group of groups) group.hidden = !group.querySelector('[data-entry]:not([hidden])');
    for (const element of empty) element.hidden = !entries.length || matches.length > 0;
    if (count) count.textContent = String(matches.length);
  }
  for (const entry of entries) entry.link.addEventListener('click', e => {
    if (!plainClick(e)) return;
    e.preventDefault();
    draw(entry);
    entry.reveal?.();
    setHash(entry.panel.id);
    if (rail && compact.matches) rail.open = false;
    entry.panel.tabIndex = -1;
    entry.panel.focus({ preventScroll: true });
    scroll(entry.section?.querySelector('.advisory-head'));
  });
  function filter() {
    const before = active;
    draw();
    if (active !== before) {
      active?.reveal?.();
      setHash(active?.panel.id || '', true);
    }
  }
  search?.addEventListener('input', filter);
  verdict?.addEventListener('change', filter);
  for (const reset of all('[data-reset]')) reset.addEventListener('click', () => {
    clear();
    filter();
    search?.focus();
  });

  function navigate() {
    const target = byId(new URL(location.href).hash.slice(1));
    const panel = target?.closest('[data-finding]');
    const section = target?.closest('[data-section]');
    const item = panel
      ? entries.find(entry => entry.panel === panel)
      : entries.find(entry => entry.section === section);
    draw(item || entries[0]);
    active?.reveal?.(target?.closest('[data-frame]'));
    for (let node = target; node; node = node.parentElement) {
      if (node.tagName === 'DETAILS') node.open = true;
    }
    if (target && target !== panel && target !== section) scroll(target);
  }
  addEventListener('popstate', navigate);
  addEventListener('hashchange', navigate);
  if (rail) {
    const resize = () => { rail.open = !compact.matches; };
    resize();
    compact.addEventListener('change', resize);
  }
  const printable = '[data-section], [data-finding], [data-in-range]';
  let printState;
  addEventListener('beforeprint', () => {
    if (printState) return;
    printState = {
      hidden: all(printable).filter(node => node.hidden),
      closed: all('details:not([open])')
    };
    workspace?.classList.remove('is-focused');
    for (const node of printState.hidden) node.hidden = false;
    for (const node of printState.closed) node.open = true;
  });
  addEventListener('afterprint', () => {
    if (!printState) return;
    for (const node of printState.hidden) node.hidden = true;
    for (const node of printState.closed) node.open = false;
    updateFocus();
    printState = undefined;
  });
  document.documentElement.classList.add('enhanced');
  navigate();
})();
`;
