'use strict';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const S = { csrf: '', user: null, perms: [], cfg: {}, hotels: [], page: 1, pages: 1,
            selected: null, room: null, step: 1 };

const AMENITIES = ['Free WiFi','Pool','Spa','Fitness Center','Restaurant','Bar','Room Service',
                   'Parking','Airport Shuttle','Pet Friendly','Air Conditioning','Breakfast'];

/* ---------- api ---------- */
async function api(action, { method = 'GET', body = null, params = null } = {}) {
  let url = 'api.php?action=' + encodeURIComponent(action);
  if (params) for (const [k, v] of Object.entries(params))
    if (v !== '' && v !== null && v !== undefined) url += `&${encodeURIComponent(k)}=${encodeURIComponent(v)}`;
  const headers = { Accept: 'application/json' };
  if (method === 'POST') headers['X-CSRF-Token'] = S.csrf;
  if (body) headers['Content-Type'] = 'application/json';
  const res = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined, credentials: 'same-origin' });
  let data;
  try { data = await res.json(); }
  catch { throw new Error('Unexpected server response.'); }
  if (!res.ok) { const e = new Error(data.error || 'Request failed.'); e.fields = data.fields || null; e.code = data.code; throw e; }
  return data;
}

/* ---------- ui helpers ---------- */
function toast(msg, isErr = false) {
  const t = $('#toast'); t.textContent = msg; t.classList.toggle('err', isErr); t.hidden = false;
  clearTimeout(t._h); t._h = setTimeout(() => t.hidden = true, 4200);
}
function openModal(id) { const m = $(id); m.hidden = false; document.body.style.overflow = 'hidden';
  const f = m.querySelector('input,select,button'); if (f) setTimeout(() => f.focus(), 40); }
function closeModal(m) { m.hidden = true; document.body.style.overflow = ''; }
function showErr(form, msg, fields) {
  const box = form.querySelector('[data-err]'); if (!box) return;
  box.textContent = msg || 'Please fix the highlighted fields.'; box.hidden = false;
  $$('.field', form).forEach(f => f.classList.remove('bad'));
  if (fields) Object.keys(fields).forEach(k => {
    const map = { name:'rgName', email:'rgEmail', phone:'rgPhone', password:'rgPw', password_confirm:'rgPw2' };
    const el = $('#' + (map[k] || k)); if (el) el.closest('.field')?.classList.add('bad');
  });
}
function clearErr(form) { const b = form.querySelector('[data-err]'); if (b) b.hidden = true;
  $$('.field', form).forEach(f => f.classList.remove('bad')); }
function busy(btn, on, label) {
  if (on) { btn.dataset.label = btn.textContent; btn.textContent = 'Please wait…'; btn.disabled = true; }
  else { btn.textContent = btn.dataset.label || label || btn.textContent; btn.disabled = false; }
}
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
const money = n => (S.cfg.symbol || '$') + Number(n).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const stars = n => '★'.repeat(n) + '☆'.repeat(5 - n);
const pad = n => String(n).padStart(2, '0');
const iso = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const nights = (a, b) => Math.round((new Date(b) - new Date(a)) / 86400000);

/* ---------- session ---------- */
function paintAuth() {
  const in_ = !!S.user;
  $('#btnSignIn').hidden = in_; $('#btnRegister').hidden = in_;
  $('#userChip').hidden = !in_; $('#navBookings').hidden = !in_; $('#navProfile').hidden = !in_;
  if (in_) $('#userName').textContent = S.user.name;
  const needsVerify = in_ && S.user.type === 'customer' && !S.user.email_verified_at;
  $('#verifyBanner').hidden = !needsVerify;
}
function setTab(modal, name) {
  $$('.tab', modal).forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  $$('.pane', modal).forEach(p => {
    const isForm = p.tagName === 'FORM';
    const id = p.id || '';
    const match =
      (name === 'signin' && id === 'formSignIn') ||
      (name === 'register' && id === 'formRegister') ||
      (name === 'forgot' && id === 'formForgot') ||
      (name === 'verify' && id === 'paneVerify') ||
      (name === 'profile' && id === 'formProfile') ||
      (name === 'security' && id === 'formPassword') ||
      (name === 'bookings' && id === 'paneBookings');
    if (isForm || id) p.hidden = !match;
  });
}

/* ---------- search ---------- */
function filterParams(extra = {}) {
  const p = {
    destination: $('#fDest').value.trim(),
    check_in: $('#fIn').value, check_out: $('#fOut').value,
    guests: $('#fGuests').value, rooms: $('#fRooms').value,
    min_price: $('#fMinP').value, max_price: $('#fMaxP').value,
    min_stars: ($$('input[name=stars]').find(r => r.checked) || {}).value || '',
    amenities: $$('#amenityBox input:checked').map(c => c.value).join(','),
    available: $('#fAvailable').checked ? '1' : '0',
    sort: $('#fSort').value, page: S.page, ...extra
  };
  return p;
}
async function runSearch() {
  const err = $('#searchError'); err.hidden = true;
  const ci = $('#fIn').value, co = $('#fOut').value;
  if (ci && co && nights(ci, co) < 1) { err.textContent = 'Check-out must be after check-in.'; err.hidden = false; return; }
  $('#loading').hidden = false; $('#empty').hidden = true; $('#grid').innerHTML = '';
  try {
    const d = await api('search', { params: filterParams() });
    S.hotels = d.hotels; S.page = d.page; S.pages = d.pages;
    $('#resultsTitle').textContent = d.total ? `${d.total} stay${d.total > 1 ? 's' : ''} found` : 'Search results';
    renderGrid();
    $('#loading').hidden = true;
    $('#empty').hidden = d.total > 0;
    renderPager();
  } catch (e) { $('#loading').hidden = true; toast(e.message, true); }
}
function renderGrid() {
  $('#grid').innerHTML = S.hotels.map(h => `
    <article class="card">
      <div class="card-img">
        <img src="${esc(h.image)}" alt="${esc(h.name)}" loading="lazy">
        <span class="badge ${h.available_rooms > 3 ? 'ok' : 'warn'}">${h.available_rooms} room${h.available_rooms === 1 ? '' : 's'} left</span>
      </div>
      <div class="card-body">
        <p class="loc">${esc(h.city)}, ${esc(h.country)}</p>
        <h3>${esc(h.name)}</h3>
        <p class="rating"><span class="stars">${stars(h.star_rating)}</span> · ${h.rating.toFixed(1)} (${h.review_count})</p>
        <ul class="chips">${h.amenities.slice(0, 4).map(a => `<li>${esc(a)}</li>`).join('')}${h.amenities.length > 4 ? `<li>+${h.amenities.length - 4}</li>` : ''}</ul>
        <div class="price-row">
          <span class="price">${money(h.from_price)}<small>per night</small></span>
          <button class="btn primary" data-hotel="${h.id}">View &amp; book</button>
        </div>
      </div>
    </article>`).join('');
}
function renderPager() {
  const p = $('#pager');
  if (S.pages <= 1) { p.hidden = true; return; }
  let html = `<button ${S.page === 1 ? 'disabled' : ''} data-p="${S.page - 1}">‹</button>`;
  for (let i = 1; i <= S.pages; i++)
    html += `<button data-p="${i}" aria-current="${i === S.page}">${i}</button>`;
  html += `<button ${S.page === S.pages ? 'disabled' : ''} data-p="${S.page + 1}">›</button>`;
  p.innerHTML = html; p.hidden = false;
}

/* ---------- hotel modal ---------- */
async function openHotel(id) {
  openModal('#mHotel');
  $('#hmName').textContent = 'Loading…'; $('#hmDesc').textContent = '';
  try {
    const d = await api('hotel', { params: { id, check_in: $('#fIn').value, check_out: $('#fOut').value } });
    const h = d.hotel; S.selected = h; S.nights = d.nights;
    $('#hmName').textContent = h.name;
    $('#hmLoc').textContent = `${h.address ? h.address + ', ' : ''}${h.city}, ${h.country} — ${h.location_text}`;
    $('#hmRating').innerHTML = `<span class="stars">${stars(h.star_rating)}</span> · ${h.rating.toFixed(1)} / 5 from ${h.review_count} reviews`;
    $('#hmFrom').textContent = money(Math.min(...h.room_types.map(r => r.price_per_night)));
    $('#hmDesc').textContent = h.description;
    $('#hmAmen').innerHTML = h.amenities.map(a => `<li>${esc(a)}</li>`).join('') || '<li class="muted">None listed</li>';
    $('#hmPolicies').innerHTML = Object.entries(h.policies).map(([k, v]) =>
      `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');
    $('#hmRevCount').textContent = `${h.review_count} verified stays`;
    const img = $('#hmImg');
    img.src = h.images[0].url; img.alt = h.name;
    $('#hmThumbs').innerHTML = h.images.map((im, i) =>
      `<button type="button" class="${i === 0 ? 'on' : ''}" data-src="${esc(im.url)}" aria-label="Photo ${i + 1}">
         <img src="${esc(im.url)}" alt=""></button>`).join('');
    $('#hmRooms').innerHTML = h.room_types.map(r => `
      <div class="room ${r.free_rooms > 0 ? 'free' : 'out'}">
        <div>
          <strong>${esc(r.name)}</strong>
          <p>Up to ${r.max_guests} guests · ${r.free_rooms > 0 ? r.free_rooms + ' available' : 'Sold out for these dates'}</p>
          <p>${esc(r.description)}</p>
        </div>
        <div style="text-align:right">
          <div class="price">${money(r.price_per_night)}<small>per night</small></div>
          <button class="btn primary" data-room="${r.id}" ${r.free_rooms > 0 ? '' : 'disabled'} style="margin-top:.4rem">Select</button>
        </div>
      </div>`).join('');
  } catch (e) { toast(e.message, true); closeModal($('#mHotel')); }
}

/* ---------- booking flow ---------- */
function setStep(n) {
  S.step = n;
  $$('#bkSteps li').forEach(li => {
    const s = +li.dataset.s;
    li.classList.toggle('on', s === n);
    li.classList.toggle('done', s < n);
  });
  $$('#mBooking .pane').forEach(p => { p.hidden = +p.dataset.pane !== n; });
}
function openBooking(roomId) {
  if (!S.user) { toast('Sign in to book.', true); openAuth('signin'); return; }
  if (S.user.type === 'customer' && !S.user.email_verified_at) {
    toast('Verify your email before booking.', true); openAuth('verify'); return;
  }
  const room = S.selected.room_types.find(r => r.id === roomId);
  if (!room) return;
  S.room = room;
  closeModal($('#mHotel')); openModal('#mBooking');
  $('#bkIn').value = $('#fIn').value; $('#bkOut').value = $('#fOut').value;
  $('#bkRooms').value = $('#fRooms').value; $('#bkGuests').value = $('#fGuests').value;
  $('#bkRoomInfo').textContent = `${room.name} — ${money(room.price_per_night)}/night, up to ${room.max_guests} guests per room.`;
  if (S.user) { $('#bkName').value = S.user.name || ''; $('#bkEmail').value = S.user.email || ''; $('#bkPhone').value = S.user.phone || ''; }
  $('#bkTitle').textContent = 'Book ' + S.selected.name;
  setStep(1);
}
function bookingTotals() {
  const ci = $('#bkIn').value, co = $('#bkOut').value;
  const n = nights(ci, co), rooms = Math.max(1, +$('#bkRooms').value || 1);
  const sub = S.room.price_per_night * n * rooms;
  const tax = sub * (S.cfg.tax_rate || 0);
  const fee = S.cfg.service_fee || 0;
  return { n, rooms, guests: +$('#bkGuests').value || 1, sub, tax, fee, total: sub + tax + fee, ci, co };
}
function renderSummary() {
  const t = bookingTotals();
  $('#bkSummary').innerHTML = `
    <div class="row"><span>Hotel</span><strong>${esc(S.selected.name)}</strong></div>
    <div class="row"><span>Room</span><strong>${esc(S.room.name)}</strong></div>
    <div class="row"><span>Dates</span><strong>${esc(t.ci)} → ${esc(t.co)} (${t.n} night${t.n === 1 ? '' : 's'})</strong></div>
    <div class="row"><span>Rooms / guests</span><strong>${t.rooms} / ${t.guests}</strong></div>
    <div class="row"><span class="muted">Subtotal</span><span>${money(t.sub)}</span></div>
    <div class="row"><span class="muted">Taxes (${Math.round((S.cfg.tax_rate || 0) * 100)}%)</span><span>${money(t.tax)}</span></div>
    <div class="row"><span class="muted">Service fee</span><span>${money(t.fee)}</span></div>
    <div class="row total"><span>Total</span><span>${money(t.total)}</span></div>`;
}
async function confirmBooking(btn) {
  const t = bookingTotals();
  const method = ($$('input[name=pay]').find(r => r.checked) || {}).value;
  const body = {
    hotel_id: S.selected.id, room_type_id: S.room.id,
    check_in: t.ci, check_out: t.co, rooms: t.rooms, guests: t.guests,
    guest_name: $('#bkName').value.trim(), guest_email: $('#bkEmail').value.trim(),
    guest_phone: $('#bkPhone').value.trim(), special_requests: $('#bkNotes').value.trim(),
    payment_method: method
  };
  const err = $('#mBooking .pane[data-pane="3"] [data-err]'); err.hidden = true;
  busy(btn, true);
  try {
    const d = await api('create_booking', { method: 'POST', body });
    $('#bkRef').textContent = d.booking.reference;
    $('#bkDone').innerHTML = $('#bkSummary').innerHTML;
    setStep(4);
    toast('Booking confirmed — reference ' + d.booking.reference);
  } catch (e) {
    err.textContent = e.message; err.hidden = false;
    if (e.code === 'unverified' || e.code === 'inactive') { closeModal($('#mBooking')); openAuth('verify'); }
    if (e.code === 'sold_out') openHotel(S.selected.id);
  } finally { busy(btn, false); }
}

/* ---------- auth ---------- */
function openAuth(tab = 'signin') { openModal('#mAuth'); setTab($('#mAuth'), tab); }

async function loadMyBookings() {
  const box = $('#myBookings'); $('#bkLoading').hidden = false; box.innerHTML = '';
  try {
    const d = await api('my_bookings');
    $('#bkLoading').hidden = true;
    if (!d.bookings.length) {
      box.innerHTML = `<div class="state slim"><p><strong>No bookings yet.</strong></p>
        <p class="muted">Find a stay and your reservations will appear here.</p></div>`;
      return;
    }
    box.innerHTML = d.bookings.map(b => `
      <article class="bk-item">
        <header><strong class="ref">${esc(b.reference)}</strong>
          <span class="pill ${esc(b.status)}">${esc(b.status)}</span></header>
        <dl>
          <div><dt>Hotel</dt><dd>${esc(b.hotel_name)}</dd></div>
          <div><dt>Location</dt><dd>${esc(b.hotel_city)}</dd></div>
          <div><dt>Room</dt><dd>${esc(b.room_name)}</dd></div>
          <div><dt>Check-in</dt><dd>${esc(b.check_in)}</dd></div>
          <div><dt>Check-out</dt><dd>${esc(b.check_out)}</dd></div>
          <div><dt>Nights / rooms</dt><dd>${b.nights} / ${b.rooms}</dd></div>
          <div><dt>Payment</dt><dd>${esc(b.payment_method)} · ${esc(b.payment_status)}</dd></div>
          <div><dt>Total</dt><dd>${money(b.total)}</dd></div>
        </dl>
      </article>`).join('');
  } catch (e) { $('#bkLoading').hidden = true; toast(e.message, true); }
}
function fillProfile() {
  const u = S.user; if (!u) return;
  $('#pfName').value = u.name || ''; $('#pfPhone').value = u.phone || '';
  $('#pfCountry').value = u.country || ''; $('#pfCity').value = u.city || '';
  $('#pfDob').value = u.date_of_birth || ''; $('#pfAddr').value = u.address || '';
  $('#pfPrefs').value = u.preferences || '';
}
function openDash(tab = 'profile') { openModal('#mDash'); setTab($('#mDash'), tab); fillProfile(); if (tab === 'bookings') loadMyBookings(); }

/* ---------- events ---------- */
function initFilters() {
  const today = new Date(), t2 = new Date(); t2.setDate(today.getDate() + 2);
  $('#fIn').min = iso(today); $('#fOut').min = iso(t2);
  $('#fIn').value = iso(today); $('#fOut').value = iso(t2);
  $('#amenityBox').insertAdjacentHTML('beforeend',
    AMENITIES.map(a => `<label><input type="checkbox" value="${a}"> ${a}</label>`).join(''));
  $('#fIn').addEventListener('change', () => { $('#fOut').min = $('#fIn').value; });
}

document.addEventListener('click', e => {
  const t = e.target;
  if (t.closest('[data-close]')) { const m = t.closest('.modal'); if (m) closeModal(m); return; }
  if (t.classList.contains('modal')) { closeModal(t); return; }
  const tab = t.closest('.tab'); if (tab) { setTab(tab.closest('.modal'), tab.dataset.tab); return; }
  const hotelBtn = t.closest('[data-hotel]'); if (hotelBtn) { openHotel(+hotelBtn.dataset.hotel); return; }
  const roomBtn = t.closest('[data-room]'); if (roomBtn) { openBooking(+roomBtn.dataset.room); return; }
  const thumb = t.closest('.thumbs button'); if (thumb) {
    $('#hmImg').src = thumb.dataset.src;
    $$('.thumbs button').forEach(b => b.classList.toggle('on', b === thumb)); return; }
  const pg = t.closest('#pager button'); if (pg && !pg.disabled) { S.page = +pg.dataset.p; runSearch();
    window.scrollTo({ top: $('#main').offsetTop - 70, behavior: 'smooth' }); return; }
});

$('#searchForm').addEventListener('submit', e => { e.preventDefault(); S.page = 1; runSearch(); });
$('#btnApply').addEventListener('click', () => { S.page = 1; runSearch(); });
$('#fSort').addEventListener('change', () => { S.page = 1; runSearch(); });
function resetFilters() {
  $('#fDest').value = ''; $('#fMinP').value = ''; $('#fMaxP').value = '';
  $$('input[name=stars]')[0].checked = true;
  $$('#amenityBox input').forEach(c => c.checked = false);
  $('#fAvailable').checked = false; S.page = 1; runSearch();
}
$('#btnReset').addEventListener('click', resetFilters);
$('#btnClear').addEventListener('click', resetFilters);

$('#btnSignIn').addEventListener('click', () => openAuth('signin'));
$('#btnRegister').addEventListener('click', () => openAuth('register'));
$('#navProfile').addEventListener('click', () => openDash('profile'));
$('#navBookings').addEventListener('click', () => openDash('bookings'));
$('#btnSignOut').addEventListener('click', async () => {
  try { await api('logout', { method: 'POST', body: {} }); } catch {}
  S.user = null; S.perms = []; paintAuth(); toast('Signed out.'); runSearch();
});

/* auth forms */
$('#formSignIn').addEventListener('submit', async e => {
  e.preventDefault(); clearErr(e.target); const btn = e.target.querySelector('button');
  busy(btn, true);
  try {
    const d = await api('login', { method: 'POST',
      body: { identifier: $('#liId').value.trim(), password: $('#liPw').value } });
    S.user = d.user; S.perms = d.perms || []; paintAuth();
    closeModal($('#mAuth')); toast(d.message);
    if (S.user.type === 'admin') location.href = 'admin.html';
    else { runSearch(); if (!S.user.email_verified_at) openAuth('verify'); }
  } catch (err) { showErr(e.target, err.message, err.fields); }
  finally { busy(btn, false); }
});

$('#formRegister').addEventListener('submit', async e => {
  e.preventDefault(); clearErr(e.target); const btn = e.target.querySelector('button'); busy(btn, true);
  try {
    const d = await api('register', { method: 'POST', body: {
      name: $('#rgName').value.trim(), email: $('#rgEmail').value.trim(), phone: $('#rgPhone').value.trim(),
      password: $('#rgPw').value, password_confirm: $('#rgPw2').value } });
    toast(d.message);
    if (d.dev_link) { $('#devLinkBox').hidden = false;
      $('#devLinkBox').innerHTML = `Local dev link: <a href="${esc(d.dev_link)}">${esc(d.dev_link)}</a>`;
      $('#vfToken').value = new URL(d.dev_link).searchParams.get('verify') || ''; }
    setTab($('#mAuth'), 'verify');
  } catch (err) { showErr(e.target, err.message, err.fields); }
  finally { busy(btn, false); }
});

$('#btnVerify').addEventListener('click', async () => {
  const box = $('#paneVerify [data-err]'); box.hidden = true;
  const raw = $('#vfToken').value.trim();
  const token = raw.includes('verify=') ? new URL(raw).searchParams.get('verify') : raw.split('/').pop();
  try {
    const d = await api('verify_email', { method: 'POST', body: { token } });
    toast(d.message); await api('me').then(m => { S.user = m.user; S.perms = m.perms; });
    paintAuth(); closeModal($('#mAuth')); runSearch();
  } catch (e) { box.textContent = e.message; box.hidden = false; }
});
$('#btnResend').addEventListener('click', async () => {
  if (!S.user) { toast('Sign in first, then resend.', true); return; }
  try { const d = await api('resend_verification', { method: 'POST', body: {} });
    toast(d.message);
    if (d.dev_link) { $('#devLinkBox').hidden = false; $('#devLinkBox').textContent = 'Local dev link: ' + d.dev_link; }
  } catch (e) { toast(e.message, true); }
});
$('#bannerResend').addEventListener('click', () => $('#btnResend').click());

$('#formForgot').addEventListener('submit', async e => {
  e.preventDefault(); clearErr(e.target); const btn = e.target.querySelector('button'); busy(btn, true);
  try {
    const d = await api('forgot_password', { method: 'POST', body: { email: $('#fgEmail').value.trim() } });
    toast(d.message);
    if (d.dev_link) { $('#resetBox').hidden = false; $('#rsToken').value = new URL(d.dev_link).hash.replace('#reset=', ''); }
  } catch (err) { showErr(e.target, err.message); }
  finally { busy(btn, false); }
});
$('#btnResetPw').addEventListener('click', async () => {
  const box = $('#formForgot [data-err]'); box.hidden = true;
  try {
    const d = await api('reset_password', { method: 'POST', body: {
      token: $('#rsToken').value.trim(), password: $('#rsPw').value, password_confirm: $('#rsPw2').value } });
    toast(d.message); setTab($('#mAuth'), 'signin');
  } catch (e) { box.textContent = e.message; box.hidden = false; }
});

/* dashboard forms */
$('#formProfile').addEventListener('submit', async e => {
  e.preventDefault(); clearErr(e.target); const btn = e.target.querySelector('button'); busy(btn, true);
  try {
    const d = await api('update_profile', { method: 'POST', body: {
      name: $('#pfName').value, phone: $('#pfPhone').value, country: $('#pfCountry').value,
      city: $('#pfCity').value, address: $('#pfAddr').value, date_of_birth: $('#pfDob').value,
      preferences: $('#pfPrefs').value } });
    S.user = d.user; paintAuth(); toast(d.message);
  } catch (err) { showErr(e.target, err.message, err.fields); }
  finally { busy(btn, false); }
});
$('#formPassword').addEventListener('submit', async e => {
  e.preventDefault(); clearErr(e.target); const btn = e.target.querySelector('button'); busy(btn, true);
  try {
    const d = await api('change_password', { method: 'POST', body: {
      current_password: $('#pwCur').value, new_password: $('#pwNew').value, confirm_password: $('#pwCfm').value } });
    e.target.reset(); toast(d.message);
  } catch (err) { showErr(e.target, err.message, err.fields); }
  finally { busy(btn, false); }
});

/* booking steps */
$('#bkNext1').addEventListener('click', () => {
  const box = $('#mBooking .pane[data-pane="1"] [data-err]'); box.hidden = true;
  const ci = $('#bkIn').value, co = $('#bkOut').value;
  if (!ci || !co || nights(ci, co) < 1) { box.textContent = 'Check-out must be after check-in.'; box.hidden = false; return; }
  if (nights(ci, co) > 365) { box.textContent = 'Maximum stay is 365 nights.'; box.hidden = false; return; }
  setStep(2);
});
$('#bkBack2').addEventListener('click', () => setStep(1));
$('#bkForm2').addEventListener('submit', e => {
  e.preventDefault(); clearErr(e.target);
  const n = $('#bkName').value.trim(), em = $('#bkEmail').value.trim(), ph = $('#bkPhone').value.trim();
  if (n.length < 2 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em) || !/^[0-9+\-\s()]{7,20}$/.test(ph)) {
    showErr(e.target, 'Enter a valid name, email and phone number.'); return;
  }
  renderSummary(); setStep(3);
});
$('#bkBack3').addEventListener('click', () => setStep(2));
$('#bkConfirm').addEventListener('click', e => confirmBooking(e.currentTarget));
$('#bkViewMine').addEventListener('click', () => { closeModal($('#mBooking')); openDash('bookings'); });
$$('input[name=pay]').forEach(r => r.addEventListener('change', () => {
  $('#cardDemo').style.display = $('input[name=pay]:checked').value === 'card' ? '' : 'none';
}));

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { const open = $$('.modal').filter(m => !m.hidden).pop(); if (open) closeModal(open); }
});

/* ---------- boot ---------- */
(async function boot() {
  $('#year').textContent = new Date().getFullYear();
  initFilters();
  try {
    const b = await api('bootstrap');
    S.csrf = b.csrf; S.user = b.user; S.perms = b.perms || []; S.cfg = b.config || {};
    paintAuth();
  } catch (e) { toast('Could not reach the server.', true); }

  const v = new URLSearchParams(location.search).get('verify');
  if (v) { openAuth('verify'); $('#vfToken').value = v; $('#btnVerify').click(); history.replaceState({}, '', location.pathname); }
  const r = (location.hash.match(/reset=(\w+)/) || [])[1];
  if (r) { openAuth('forgot'); $('#resetBox').hidden = false; $('#rsToken').value = r; }

  await runSearch();
})();
