(() => {
  'use strict';
  // Presentation only. Everything here reads the canonical GET form (the
  // route's input points) or the URL query and updates the DOM; nothing adds
  // a parameter, a named control or a link with a query string.
  const CATEGORY = { shoes: '슈즈 신발', bags: '가방 백', tech: '디지털 전자 음향', home: '홈 리빙 조명 인테리어' };
  const PAGE_SIZE = 8;
  const WISHLIST = ['105', '101', '108', '110', '104', '112'];
  const LISTING = ['/search', '/catalog', '/account/wishlist', '/compare'];
  const PAGED = ['/catalog', '/account/wishlist'];
  const products = Array.isArray(window.DEMOSHOP_PRODUCTS) ? window.DEMOSHOP_PRODUCTS : [];
  const byId = Object.fromEntries(products.map(p => [p.id, p]));
  const path = location.pathname;
  const query = new URLSearchParams(location.search);
  const applied = location.search !== '';
  const form = document.getElementById('input-points');
  const field = name => (form ? form.querySelector('[name="' + name + '"]') : null);
  const value = name => { const el = field(name); return el && !el.disabled ? el.value : ''; };
  const digits = text => /^\d+$/.test(text || '');
  const won = amount => amount.toLocaleString('ko-KR');
  const put = (selector, text) => document.querySelectorAll(selector).forEach(el => { el.textContent = text; });
  const show = (selector, visible) => document.querySelectorAll(selector).forEach(el => { el.hidden = !visible; });
  const itemHash = /^#item-(1\d\d)(?:-(\d{1,2}))?$/.exec(location.hash);

  // Header search: a bare control with no form or name, so the crawl surface
  // stays the canonical /search form. Enter or the magnifier navigates to
  // /search?q=..., which is that form's first input point.
  const searchInput = document.querySelector('[data-search-input]');
  const search = () => {
    const term = searchInput.value.trim();
    location.href = term ? '/search?q=' + encodeURIComponent(term) : '/search';
  };
  if (searchInput) {
    if (path === '/search' && query.get('q')) searchInput.value = query.get('q');
    searchInput.addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); search(); } });
    document.querySelectorAll('[data-search-go]').forEach(el => el.addEventListener('click', event => { event.preventDefault(); search(); }));
  }

  // Quick picks fill the text input next to them; the visitor still submits.
  const syncChips = () => document.querySelectorAll('.chip').forEach(chip => {
    const input = chip.closest('.input-point-field').querySelector('input, textarea, select');
    chip.setAttribute('aria-pressed', String(Boolean(input) && input.value === chip.dataset.chip));
  });
  document.addEventListener('click', event => {
    const chip = event.target.closest('.chip');
    if (!chip) return;
    const input = chip.closest('.input-point-field').querySelector('input, textarea, select');
    if (!input) return;
    input.value = chip.dataset.chip;
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.focus();
  });
  // The product page's `variant` options belong to the displayed product:
  // rebuild its chips (unnamed type=button, like the server-rendered ones).
  const offerVariants = p => {
    const input = field('variant');
    const chips = input && input.closest('.input-point-field').querySelector('.chips');
    if (!chips) return;
    chips.textContent = '';
    (p.variants || []).forEach(([value, label]) => {
      const chip = document.createElement('button');
      chip.type = 'button'; chip.className = 'chip'; chip.dataset.chip = value; chip.textContent = label;
      chips.appendChild(chip);
    });
  };

  // "적용된 조건": what the server answered to, read back from the form.
  const describeApplied = () => {
    const target = document.querySelector('[data-applied]');
    if (!target || !form) return;
    target.textContent = '';
    if (!applied) {
      const submit = form.querySelector('button[type=submit]');
      target.textContent = '기본값으로 조회한 응답입니다. 값을 바꾸고 ‘' + (submit ? submit.textContent : '적용') + '’을 누르면 갱신됩니다.';
      return;
    }
    const parts = [];
    form.querySelectorAll('.input-point-field').forEach(block => {
      const caption = block.querySelector('.field-caption label, .field-caption > span');
      const control = block.querySelector('input, textarea, select');
      if (!caption || !control || control.disabled) return;
      const b = document.createElement('b');
      b.textContent = control.value === '' ? '(비어 있음)' : control.value;
      parts.push([caption.textContent + ' ', b]);
    });
    parts.forEach(([label, b], index) => {
      if (index) target.append(' · ');
      target.append(label, b);
    });
  };

  // Product listings: filter, sort and page the server-rendered grid from the
  // URL query. The form keeps its seeds (they are the crawl baselines), so a
  // bare page shows the whole catalog and says the filter is not applied yet.
  const renderListing = () => {
    const grid = document.querySelector('.product-grid');
    if (!grid || !LISTING.includes(path)) return;
    const cards = Array.from(grid.querySelectorAll('.product-card[data-product]'));
    const hash = /^#category-(all|shoes|bags|tech|home)$/.exec(location.hash);
    const filters = applied ? Object.fromEntries(query.entries()) : {};
    let category = hash ? hash[1] : 'all';
    if (!hash && /^(shoes|bags|tech|home)$/.test(filters.category || '')) category = filters.category;
    const categoryField = field('category');
    if (categoryField) {
      // An explicit all-category browse has no category condition. This is
      // client-only: the bare crawl form retains its original seed/options.
      const supportsAll = Array.from(categoryField.options).some(option => option.value === 'all');
      const omit = hash !== null && category === 'all' && !supportsAll;
      categoryField.disabled = omit;
      categoryField.closest('.input-point-field').hidden = omit;
      if (!omit && (hash || applied)) categoryField.value = category;
      categoryField.form.action = path + (omit ? '#category-all' : '');
    }
    document.querySelectorAll('[data-filter]').forEach(el => el.setAttribute('aria-current', String(el.dataset.filter === category)));
    const term = path === '/search' ? (filters.q || '').trim().toLowerCase() : '';
    const brand = (filters.brand || '').trim().toLowerCase();
    const color = (filters.color || '').trim().toLowerCase();
    const size = /^[sml]$/.test(filters.size || '') ? filters.size : '';
    const min = digits(filters.min_price) ? Number(filters.min_price) : null;
    const max = digits(filters.max_price) ? Number(filters.max_price) : null;
    const ids = path === '/compare' ? (applied ? filters.ids : value('ids')) : '';
    const wanted = path === '/compare' ? (ids || '').split(',').map(id => id.trim()).filter(id => byId[id]) : null;
    const matches = card => {
      const p = byId[card.dataset.product];
      // Without the products script the page degrades to what the server
      // rendered: category tabs still work, the finer filters are skipped.
      if (!p) return category === 'all' || card.dataset.category === category;
      if (path === '/account/wishlist') return WISHLIST.includes(p.id);
      if (wanted) return wanted.includes(p.id);
      if (category !== 'all' && p.category !== category) return false;
      if (term && !(card.dataset.search + ' ' + CATEGORY[p.category]).includes(term)) return false;
      if (brand && !(p.brand_key.includes(brand) || p.brand.toLowerCase().includes(brand))) return false;
      if (color && !(p.color.includes(color) || p.color_label.includes(color))) return false;
      if (size && !p.sizes.includes(size)) return false;
      if (min !== null && p.price < min) return false;
      if (max !== null && p.price > max) return false;
      return true;
    };
    const sort = applied ? (filters.sort || '') : (path === '/compare' || path === '/account/wishlist' ? value('sort') : '');
    const order = {
      newest: (a, b) => a.rank - b.rank, recent: (a, b) => a.rank - b.rank, rating: (a, b) => a.rank - b.rank,
      price: (a, b) => a.price - b.price, price_asc: (a, b) => a.price - b.price, price_desc: (a, b) => b.price - a.price
    }[sort];
    let shown = cards.filter(matches);
    if (path === '/account/wishlist' && !order) shown.sort((a, b) => WISHLIST.indexOf(a.dataset.product) - WISHLIST.indexOf(b.dataset.product));
    if (wanted && !order) shown.sort((a, b) => wanted.indexOf(a.dataset.product) - wanted.indexOf(b.dataset.product));
    if (order && products.length) shown = shown.slice().sort((a, b) => order(byId[a.dataset.product], byId[b.dataset.product]));
    const pageSize = PAGED.includes(path) ? PAGE_SIZE : Infinity;
    const pages = Math.max(1, Math.ceil(shown.length / pageSize));
    const requested = applied && digits(filters.page) ? Number(filters.page) : 1;
    const page = Math.min(Math.max(requested, 1), Math.max(pages, requested));
    const visible = new Set(shown.slice((page - 1) * pageSize, page * pageSize));
    shown.forEach(card => grid.appendChild(card));
    cards.forEach(card => { card.hidden = !visible.has(card); });
    show('[data-search-empty]', visible.size === 0);
    const heading = document.querySelector('[data-search-heading]');
    const note = document.querySelector('[data-search-note]');
    if (heading && note && term) {
      heading.textContent = '‘' + filters.q.trim() + '’ 검색 결과';
      note.textContent = shown.length ? shown.length + '개의 상품을 찾았습니다.' : '일치하는 상품이 없습니다. 다른 검색어를 입력해 보세요.';
    }
    const state = document.querySelector('[data-filter-state]');
    if (state) {
      state.textContent = '';
      const b = document.createElement('b');
      if (applied) {
        b.textContent = '조건 적용됨';
        state.append(b, ' · ' + shown.length + '개 상품' + (pages > 1 ? ' · ' + page + ' / ' + pages + ' 페이지' : ''));
      } else if (path === '/compare' || path === '/account/wishlist') {
        b.textContent = '기본 조건';
        state.append(b, ' · ' + shown.length + '개 상품');
      } else {
        b.textContent = '조건 적용 전';
        state.append(b, ' · 전체 ' + shown.length + '개 상품 · 아래 값을 바꾸고 적용하면 이 조건으로 목록이 좁혀집니다.');
      }
    }
    const pager = document.querySelector('[data-pager]');
    if (pager) {
      // Always shown on paged routes: the pager is the visible face of `page`.
      pager.hidden = false;
      const list = pager.querySelector('[data-pager-pages]');
      list.textContent = '';
      for (let number = 1; number <= Math.max(pages, requested); number += 1) {
        const button = document.createElement('button');
        button.type = 'button'; button.textContent = String(number); button.dataset.pageGo = String(number);
        button.setAttribute('aria-current', String(number === page));
        list.appendChild(button);
      }
      pager.querySelector('[data-page-step="-1"]').disabled = page <= 1;
      pager.querySelector('[data-page-step="1"]').disabled = page >= pages;
      pager.dataset.page = String(page);
    }
    const compare = document.querySelector('[data-compare]');
    if (compare) {
      const chosen = shown.map(card => byId[card.dataset.product]).filter(Boolean);
      compare.hidden = chosen.length === 0;
      compare.textContent = '';
      if (chosen.length) {
        const table = document.createElement('table');
        const rows = [['상품', p => p.name], ['브랜드', p => p.brand], ['가격', p => won(p.price) + '원'], ['컬러', p => p.color_label], ['사이즈', p => (p.sizes.length ? p.sizes.join(' / ').toUpperCase() : '단일')], ['카테고리', p => CATEGORY[p.category].split(' ')[0]]];
        rows.forEach(([label, pick], index) => {
          const tr = document.createElement('tr');
          const th = document.createElement('th'); th.textContent = label; tr.appendChild(th);
          chosen.forEach(p => { const td = document.createElement('td'); td.textContent = pick(p); tr.appendChild(td); });
          (index === 0 ? table.createTHead() : table.tBodies[0] || table.createTBody()).appendChild(tr);
        });
        compare.appendChild(table);
      }
    }
  };
  // Paging navigates with the canonical `page` parameter merged into the
  // current query, so the other filters stay exactly as they were applied.
  const goPage = number => {
    const next = new URLSearchParams(location.search);
    next.set('page', String(number));
    location.href = path + '?' + next.toString();
  };
  document.addEventListener('click', event => {
    const go = event.target.closest('[data-page-go]');
    if (go) { goPage(Number(go.dataset.pageGo)); return; }
    const step = event.target.closest('[data-page-step]');
    if (step) goPage(Number(step.closest('[data-pager]').dataset.page) + Number(step.dataset.pageStep));
  });

  // Product page: `id` picks the product, `variant` is shown as the option,
  // `tab` opens a panel and `qty` (the canonical text input) drives the total.
  const paintProduct = p => {
    document.querySelectorAll('[data-product-image]').forEach(img => { img.src = p.image; img.alt = p.name; });
    put('[data-product-brand]', p.brand); put('[data-product-name]', p.name); put('[data-product-description]', p.blurb);
    put('[data-product-price]', won(p.price)); put('[data-product-color]', p.color_label);
    put('[data-product-sizes]', p.sizes.length ? p.sizes.join(' / ').toUpperCase() : '단일 사이즈');
    put('[data-product-category]', CATEGORY[p.category].split(' ')[0]); put('[data-product-id]', p.id);
  };
  const quantityOf = (raw, fallback) => (digits(raw) && Number(raw) >= 1 ? Number(raw) : fallback);
  if (path === '/product' && form) {
    // "함께 본 상품" links stay on this document and only change the
    // fragment, so the fragment is applied on load and on every change.
    const applyItemHash = () => {
      const item = /^#item-(1\d\d)(?:-(\d{1,2}))?$/.exec(location.hash);
      if (!item) return;
      if (field('id')) field('id').value = item[1];
      if (item[2] && field('qty')) field('qty').value = item[2];
    };
    applyItemHash();
    let shownProduct = null;
    const renderProduct = () => {
      const id = value('id');
      // Any id that is not a real catalog product (e.g. the crawl seed 1001)
      // falls back to the first product, so a bare /product never shows an
      // "등록되지 않은 상품" placeholder or a 0원 total during the demo.
      const p = byId[id] || products[0];
      paintProduct(p);
      if (p && p !== shownProduct) {
        // A new product brings its own options and starts on its own colour.
        // The server-rendered value is kept only for the seed product on a
        // bare page: it is the crawl baseline.
        const variant = field('variant');
        const options = (p.variants || []).map(([v]) => v);
        const preferred = [p.color + '-270', p.color + '-m', p.color].map(v => options.find(o => o === v)).find(Boolean) || options[0];
        if (variant && preferred && (shownProduct !== null || itemHash)) variant.value = preferred;
        offerVariants(p);
        syncChips();
        shownProduct = p;
      }
      const qty = quantityOf(value('qty'), 1);
      put('[data-qty-note]', digits(value('qty')) && Number(value('qty')) >= 1 ? qty + '개' : '수량은 1 이상의 숫자여야 합니다 · 1개로 계산');
      put('[data-variant]', value('variant') || '기본');
      put('[data-total]', won((p ? p.price : 0) * qty));
      const anchor = '#item-' + (p ? p.id : '101') + '-' + Math.min(qty, 99);
      document.querySelectorAll('[data-cart]').forEach(el => { el.href = '/cart' + anchor; });
      document.querySelectorAll('[data-checkout]').forEach(el => { el.href = '/checkout' + anchor; });
      const tab = /^(detail|spec|ship)$/.test(value('tab')) ? value('tab') : 'detail';
      document.querySelectorAll('[data-tab-panel]').forEach(el => { el.hidden = el.dataset.tabPanel !== tab; });
      document.querySelectorAll('[data-tab]').forEach(el => el.setAttribute('aria-selected', String(el.dataset.tab === tab)));
    };
    document.querySelectorAll('[data-tab]').forEach(el => el.addEventListener('click', () => {
      if (field('tab')) field('tab').value = el.dataset.tab;
      renderProduct();
    }));
    form.addEventListener('input', renderProduct);
    form.addEventListener('change', renderProduct);
    window.addEventListener('hashchange', () => { applyItemHash(); renderProduct(); window.scrollTo({ top: 0 }); });
    renderProduct();
  }

  // Cart: `qty`, `coupon` and `note` are reflected in the order summary.
  if (path === '/cart' && form && products.length) {
    const p = (itemHash && byId[itemHash[1]]) || products[0];
    if (itemHash && itemHash[2] && field('qty')) field('qty').value = itemHash[2];
    const renderCart = () => {
      paintProduct(p);
      const raw = value('qty');
      const qty = quantityOf(raw, 1);
      put('[data-qty-note]', digits(raw) && Number(raw) >= 1 ? '× ' + qty : '수량 확인 필요 · 1개로 계산');
      put('[data-item-id]', value('item_id') || '(비어 있음)');
      const coupon = value('coupon').trim();
      const valid = /^[A-Z0-9]{4,}$/.test(coupon);
      const subtotal = p.price * qty;
      const discount = valid ? Math.round(subtotal * 0.1) : 0;
      put('[data-coupon-note]', coupon === '' ? '쿠폰 없음' : (valid ? coupon + ' · 10%' : '형식이 올바르지 않은 코드'));
      put('[data-subtotal]', won(subtotal)); put('[data-discount]', won(discount)); put('[data-total]', won(subtotal - discount));
      put('[data-note-echo]', value('note') || '없음');
      document.querySelectorAll('[data-checkout]').forEach(el => { el.href = '/checkout#item-' + p.id + '-' + Math.min(qty, 99); });
    };
    form.addEventListener('input', renderCart);
    form.addEventListener('change', renderCart);
    renderCart();
  }

  // Checkout: shipping, payment, message and reference come from the form.
  if (path === '/checkout' && form && products.length) {
    const p = (itemHash && byId[itemHash[1]]) || products[0];
    const qty = itemHash && itemHash[2] ? Number(itemHash[2]) : 1;
    const renderCheckout = () => {
      paintProduct(p);
      put('[data-quantity-echo]', String(qty));
      const express = value('shipping') === 'express';
      const fee = express ? 3000 : 0;
      put('[data-shipping-fee]', express ? won(fee) + '원' : '무료');
      put('[data-shipping-note]', express ? '빠른 배송' : '일반 배송');
      put('[data-payment-echo]', { card: '신용 · 체크카드', transfer: '계좌이체', point: '적립금' }[value('payment')] || value('payment') || '(선택 없음)');
      put('[data-message-echo]', value('message') || '없음');
      put('[data-order-ref]', value('order_ref') || '(비어 있음)');
      put('[data-subtotal]', won(p.price * qty)); put('[data-total]', won(p.price * qty + fee));
    };
    form.addEventListener('input', renderCheckout);
    form.addEventListener('change', renderCheckout);
    renderCheckout();
  }
  document.querySelectorAll('[data-place-order]').forEach(el => el.addEventListener('click', () => {
    const result = document.querySelector('[data-order-success]');
    result.hidden = false; result.tabIndex = -1; result.focus();
    result.scrollIntoView({ block: 'center' }); el.disabled = true; el.textContent = '시연 완료';
  }));

  const focusInputs = () => {
    if (!form) return;
    form.scrollIntoView({ block: 'start' });
    const marker = form.querySelector('.input-point-field:not([hidden]) .input-marker');
    if (marker) marker.focus();
  };
  document.querySelectorAll('.surface-jump').forEach(link => link.addEventListener('click', event => { event.preventDefault(); focusInputs(); }));

  // Reveal mode: outlines every canonical control and tags the storefront
  // controls that feed one. Viewer preference, kept across pages in
  // localStorage; the inline head script restores it before first paint.
  const REVEAL_KEY = 'demoshop-reveal-inputs';
  const toggle = document.querySelector('[data-reveal-toggle]');
  const applyReveal = on => {
    document.documentElement.classList.toggle('reveal-inputs', on);
    if (toggle) {
      toggle.setAttribute('aria-pressed', String(on));
      toggle.querySelector('[data-reveal-label]').textContent = on ? '입력점 숨기기' : '입력점 표시';
    }
  };
  let revealed = false;
  try { revealed = localStorage.getItem(REVEAL_KEY) === '1'; } catch (error) { revealed = false; }
  applyReveal(revealed);
  if (toggle) toggle.addEventListener('click', () => {
    revealed = !revealed;
    try { localStorage.setItem(REVEAL_KEY, revealed ? '1' : '0'); } catch (error) { /* per-viewer convenience only */ }
    applyReveal(revealed);
  });

  if (form) form.addEventListener('input', syncChips);
  window.addEventListener('hashchange', renderListing);
  renderListing();
  describeApplied();
  syncChips();
  if (location.hash === '#input-points') focusInputs();
})();
