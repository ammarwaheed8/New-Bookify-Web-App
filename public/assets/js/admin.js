'use strict';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));

const S = { csrf:'', user:null, perms:new Set(), cfg:{}, roles:[], permissions:[], staff:[],
            current:'dashboard', auditPage:1 };

async function api(action, { method='GET', body=null, params=null } = {}) {
  let url = 'api.php?action=' + encodeURIComponent(action);
  if (params) for (const [k,v] of Object.entries(params))
    if (v !== '' && v != null) url += `&${encodeURIComponent(k)}=${encodeURIComponent(v)}`;
  const h = { Accept:'application/json' };
  if (method === 'POST') h['X-CSRF-Token'] = S.csrf;
  if (body) h['Content-Type'] = 'application/json';
  const res = await fetch(url, { method, headers:h, body: body?JSON.stringify(body):undefined, credentials:'same-origin' });
  let d; try { d = await res.json(); } catch { throw new Error('Unexpected server response.'); }
  if (!res.ok) {
    if (res.status === 401) showLogin();
    const e = new Error(d.error || 'Request failed.'); e.fields = d.fields; e.status = res.status; throw e;
  }
  return d;
}
const can = p => S.perms.has(p);
const money = n => (S.cfg.symbol || '$') + Number(n).toLocaleString(undefined, { minimumFractionDigits:2, maximumFractionDigits:2 });

function toast(m, err=false){ const t=$('#toast'); t.textContent=m; t.classList.toggle('err',err);
  t.hidden=false; clearTimeout(t._h); t._h=setTimeout(()=>t.hidden=true,4000); }
function showErr(form, msg, fields){
  const b = form.querySelector('[data-err]'); if(b){ b.textContent = msg || 'Fix the highlighted fields.'; b.hidden=false; }
  $$('.field',form).forEach(f=>f.classList.remove('bad'));
  if(fields) Object.keys(fields).forEach(k=>{ const el = $('#'+k); if(el) el.closest('.field')?.classList.add('bad'); });
}
function clearErr(form){ const b=form.querySelector('[data-err]'); if(b) b.hidden=true;
  $$('.field',form).forEach(f=>f.classList.remove('bad')); }
function busy(btn,on){ if(on){ btn.dataset.l=btn.textContent; btn.textContent='Please wait…'; btn.disabled=true; }
  else { btn.textContent=btn.dataset.l||btn.textContent; btn.disabled=false; } }
function openModal(id){ const m=$(id); m.hidden=false; document.body.style.overflow='hidden';
  setTimeout(()=>m.querySelector('input,select,button')?.focus(),40); }
function closeModal(m){ m.hidden=true; document.body.style.overflow=''; }
function confirmAsk(msg){
  return new Promise(res => {
    $('#cfMsg').textContent = msg; $('#mConfirm').hidden=false;
    const done = v => { $('#mConfirm').hidden=true; $('#cfYes').onclick=null; $('#cfNo').onclick=null; res(v); };
    $('#cfYes').onclick = () => done(true); $('#cfNo').onclick = () => done(false);
  });
}

/* ---------- nav ---------- */
const NAV = [
  { id:'dashboard', label:'Dashboard', perm:'dashboard.view', icon:'▦' },
  { id:'hotels',    label:'Hotels',    perm:'hotels.view',    icon:'⌂' },
  { id:'bookings',  label:'Bookings',  perm:'bookings.view',  icon:'✎' },
  { id:'users',     label:'Customers', perm:'users.view',     icon:'☺' },
  { id:'staff',     label:'Staff & roles', perm:'admins.view', icon:'⚙' },
  { id:'audit',     label:'Audit log', perm:'audit.view',     icon:'≡' },
];
function buildNav(){
  $('#sideNav').innerHTML = NAV.filter(n => can(n.perm))
    .map((n,i) => `<button data-nav="${n.id}" class="${i===0?'on':''}" type="button">${n.icon} ${n.label}</button>`).join('');
  const first = NAV.find(n => can(n.perm));
  if (first) go(first.id); else $('#sideNav').innerHTML = '<p class="muted small">No permissions granted.</p>';
}
function go(id){
  S.current = id;
  $$('#sideNav button').forEach(b => b.classList.toggle('on', b.dataset.nav === id));
  $$('.view').forEach(v => v.hidden = v.dataset.view !== id);
  ({ dashboard:loadDashboard, hotels:loadHotels, bookings:loadBookings,
     users:loadUsers, staff:loadStaff, audit:loadAudit }[id] || (()=>{}))();
}
document.addEventListener('click', e => {
  const n = e.target.closest('[data-nav]'); if (n) go(n.dataset.nav);
  if (e.target.closest('[data-close]')) { const m = e.target.closest('.modal'); if (m) closeModal(m); }
  else if (e.target.classList.contains('modal')) closeModal(e.target);
  const permBtn = e.target.closest('[data-perm]');
  if (permBtn && !can(permBtn.dataset.perm)) { e.preventDefault(); toast('Permission denied.', true); }
});

/* ---------- dashboard ---------- */
async function loadDashboard(){
  try {
    const d = await api('dashboard');
    const s = d.stats;
    const cards = [
      ['Total customers', s.total_users, ''],['Active', s.active_users, 'ok'],
      ['Blocked', s.blocked_users, 'warn'],['Pending users', s.pending_users, 'warn'],
      ['Hotels', s.hotels, ''],['Bookings', s.bookings, ''],
      ['Pending approvals', s.pending_approvals, 'warn'],
      ['Revenue (all time)', money(s.revenue), 'ok'],
      ['Revenue (this month)', money(s.revenue_month), 'ok'],
    ];
    $('#metrics').innerHTML = cards.map(([l,v,c]) =>
      `<div class="metric ${c}"><div class="num">${esc(v)}</div><div class="lbl">${esc(l)}</div></div>`).join('');
    $('#recentTable tbody').innerHTML = d.recent.map(b => `
      <tr><td><code>${esc(b.reference)}</code></td><td>${esc(b.user_name)}</td><td>${esc(b.hotel_name)}</td>
      <td>${esc(b.check_in)} → ${esc(b.check_out)}</td><td>${money(b.total)}</td>
      <td><span class="pill ${esc(b.status)}">${esc(b.status)}</span></td></tr>`).join('')
      || '<tr><td colspan="6" class="muted">No bookings yet.</td></tr>';
  } catch (e) { toast(e.message, true); }
}

/* ---------- hotels ---------- */
async function loadHotels(){
  if (!can('hotels.view')) return;
  try {
    const d = await api('admin_hotels');
    $('#hotelTable tbody').innerHTML = d.hotels.map(h => `
      <tr>
        <td class="name-cell">${h.image?`<img class="thumb" src="${esc(h.image)}" alt="">`:''}
            <div><strong>${esc(h.name)}</strong><br><span class="muted small">${esc(h.slug)}</span></div></td>
        <td>${esc(h.city)}, ${esc(h.country)}</td>
        <td>${'★'.repeat(h.star_rating)}</td>
        <td>${h.room_count}</td>
        <td>${money(h.min_price || h.base_price)}</td>
        <td><span class="pill ${esc(h.status)}">${esc(h.status)}</span></td>
        <td class="t-actions">
          <button class="btn ghost sm" data-h-edit="${h.id}" ${can('hotels.update')?'':'disabled'}>Edit</button>
          <button class="btn ghost sm" data-h-pub="${h.id}" ${can('hotels.publish')?'':'disabled'}>
            ${h.status==='published'?'Unpublish':'Publish'}</button>
          <button class="btn danger sm" data-h-del="${h.id}" ${can('hotels.delete')?'':'disabled'}>Delete</button>
        </td>
      </tr>`).join('') || '<tr><td colspan="7" class="muted">No hotels yet.</td></tr>';
  } catch (e) { toast(e.message, true); }
}
function roomRow(r = {}){
  const div = document.createElement('div');
  div.className = 'room-row';
  div.innerHTML = `
    <div class="field"><label>Name</label><input data-r="name" value="${esc(r.name||'')}"></div>
    <div class="field"><label>Description</label><input data-r="description" value="${esc(r.description||'')}"></div>
    <div class="field"><label>Guests</label><input data-r="max_guests" type="number" min="1" value="${r.max_guests||2}"></div>
    <div class="field"><label>Rooms</label><input data-r="total_rooms" type="number" min="1" value="${r.total_rooms||10}"></div>
    <div class="field"><label>Price/night</label><input data-r="price_per_night" type="number" min="0" step="0.01" value="${r.price_per_night||0}"></div>
    <button class="btn ghost sm" type="button" data-rm>Remove</button>`;
  div.querySelector('[data-rm]').onclick = () => div.remove();
  if (r.id) div.dataset.id = r.id;
  return div;
}
async function openHotelEditor(id){
  $('#formHotel').reset(); clearErr($('#formHotel')); $('#roomRows').innerHTML = '';
  if (id) {
    const d = await api('admin_hotels');
    const h = d.hotels.find(x => x.id === id); if (!h) return;
    $('#heTitle').textContent = 'Edit hotel — ' + h.name;
    $('#heId').value = h.id; $('#heName').value = h.name; $('#heCity').value = h.city;
    $('#heCountry').value = h.country; $('#heAddr').value = h.address;
    $('#heStars').value = h.star_rating; $('#heRating').value = h.rating;
    $('#heLoc').value = h.location_text; $('#heDesc').value = h.description;
    $('#heAmen').value = (JSON.parse(h.amenities||'[]')).join('\n');
    $('#heStatus').value = h.status;
    const pol = JSON.parse(h.policies || '{}');
    $('#heCin').value = pol.checkin || '15:00'; $('#heCout').value = pol.checkout || '11:00';
    $('#heCancel').value = pol.cancellation || '';
    const full = await api('hotel', { params:{ id } });
    $('#heImages').value = full.hotel.images.map(i => i.url).join('\n');
    full.hotel.room_types.forEach(r => $('#roomRows').appendChild(roomRow(r)));
  } else {
    $('#heTitle').textContent = 'New hotel'; $('#heId').value = '';
    $('#roomRows').appendChild(roomRow({ name:'Standard Room', total_rooms:10, price_per_night:120 }));
  }
  openModal('#mHotelEdit');
}
$('#btnNewHotel').addEventListener('click', () => openHotelEditor(0));
$('#btnAddRoom').addEventListener('click', () => $('#roomRows').appendChild(roomRow()));

$('#formHotel').addEventListener('submit', async e => {
  e.preventDefault(); clearErr(e.target);
  const btn = e.target.querySelector('button[type=submit]'); busy(btn, true);
  const rooms = $$('#roomRows .room-row').map(row => {
    const o = { name:'', description:'', max_guests:2, total_rooms:10, price_per_night:0 };
    $$('[data-r]', row).forEach(i => { o[i.dataset.r] = i.type === 'number' ? +i.value : i.value; });
    if (row.dataset.id) o.id = +row.dataset.id;
    return o;
  });
  const body = {
    id: +$('#heId').value || 0,
    name: $('#heName').value.trim(), city: $('#heCity').value.trim(), country: $('#heCountry').value.trim(),
    address: $('#heAddr').value.trim(), star_rating: +$('#heStars').value, rating: +$('#heRating').value,
    location_text: $('#heLoc').value.trim(), description: $('#heDesc').value.trim(),
    amenities: $('#heAmen').value.split('\n').map(s => s.trim()).filter(Boolean),
    images: $('#heImages').value.split('\n').map(s => s.trim()).filter(Boolean),
    status: $('#heStatus').value, room_types: rooms,
    policies: { checkin: $('#heCin').value, checkout: $('#heCout').value,
                cancellation: $('#heCancel').value, children: 'Children of all ages welcome.',
                pets: 'Pets not allowed unless stated otherwise.' }
  };
  try {
    const d = await api('save_hotel', { method:'POST', body });
    toast(d.message); closeModal($('#mHotelEdit')); loadHotels();
  } catch (err) { showErr(e.target, err.message, err.fields); }
  finally { busy(btn, false); }
});

$('#hotelTable').addEventListener('click', async e => {
  const ed = e.target.closest('[data-h-edit]'); if (ed) return openHotelEditor(+ed.dataset.hEdit);
  const pb = e.target.closest('[data-h-pub]');
  if (pb) { try { const d = await api('toggle_hotel', { method:'POST', body:{ id:+pb.dataset.hPub } });
      toast(d.message); loadHotels(); } catch (er) { toast(er.message, true); } }
  const dl = e.target.closest('[data-h-del]');
  if (dl) {
    const name = dl.closest('tr').querySelector('strong').textContent;
    if (await confirmAsk(`Delete "${name}"? This cannot be undone.`)) {
      try { const d = await api('delete_hotel', { method:'POST', body:{ id:+dl.dataset.hDel } });
        toast(d.message); loadHotels(); } catch (er) { toast(er.message, true); }
    }
  }
});

/* ---------- bookings ---------- */
async function loadBookings(){
  try {
    const d = await api('admin_bookings', { params:{ status:$('#bkFilter').value } });
    $('#bookingTable tbody').innerHTML = d.bookings.map(b => `
      <tr>
        <td><code>${esc(b.reference)}</code></td>
        <td>${esc(b.user_name)}<br><span class="muted small">${esc(b.user_email)}</span></td>
        <td>${esc(b.hotel_name)}<br><span class="muted small">${esc(b.room_name)}</span></td>
        <td>${esc(b.check_in)} → ${esc(b.check_out)}<br><span class="muted small">${b.nights}n · ${b.rooms} rm · ${b.guests} guests</span></td>
        <td>${money(b.total)}</td>
        <td><span class="muted small">${esc(b.payment_method)} · ${esc(b.payment_status)}</span></td>
        <td>
          ${can('bookings.update')
            ? `<select data-b-status="${b.id}">
                 ${['pending','confirmed','completed','cancelled','rejected']
                   .map(s => `<option ${s===b.status?'selected':''}>${s}</option>`).join('')}
               </select>`
            : `<span class="pill ${esc(b.status)}">${esc(b.status)}</span>`}
        </td>
      </tr>`).join('') || '<tr><td colspan="7" class="muted">No bookings.</td></tr>';
  } catch (e) { toast(e.message, true); }
}
$('#bkFilter').addEventListener('change', loadBookings);
$('#bookingTable').addEventListener('change', async e => {
  const sel = e.target.closest('[data-b-status]'); if (!sel) return;
  const id = +sel.dataset.bStatus, status = sel.value;
  if (['cancelled','rejected'].includes(status) &&
      !await confirmAsk(`Mark booking as ${status}? This may trigger a refund record.`)) return loadBookings();
  try { const d = await api('update_booking', { method:'POST', body:{ id, status } });
    toast(d.message); loadBookings(); loadDashboard(); }
  catch (er) { toast(er.message, true); loadBookings(); }
});

/* ---------- customers ---------- */
async function loadUsers(){
  if (!can('users.view')) return;
  try {
    const d = await api('admin_users', { params:{ q:$('#uSearch').value.trim(), status:$('#uFilter').value } });
    $('#userTable tbody').innerHTML = d.users.map(u => `
      <tr>
        <td><strong>${esc(u.name)}</strong></td>
        <td>${esc(u.email)}</td>
        <td>${esc(u.phone)}</td>
        <td>${u.email_verified_at ? '<span class="dot"></span>Yes' : '<span class="dot off"></span>No'}</td>
        <td><span class="pill ${esc(u.status)}">${esc(u.status)}</span></td>
        <td class="muted small">${esc((u.created_at||'').slice(0,10))}</td>
        <td class="t-actions">
          <button class="btn ghost sm" data-u-edit="${u.id}" ${can('users.update')?'':'disabled'}>Edit</button>
          ${u.status!=='active' ? `<button class="btn ghost sm" data-u-act="${u.id}" ${can('users.approve')?'':'disabled'}>Activate</button>` : ''}
          ${u.status!=='blocked' ? `<button class="btn ghost sm" data-u-blk="${u.id}" ${can('users.approve')?'':'disabled'}>Block</button>` : ''}
          <button class="btn danger sm" data-u-del="${u.id}" ${can('users.delete')?'':'disabled'}>Delete</button>
        </td>
      </tr>`).join('') || '<tr><td colspan="7" class="muted">No customers match.</td></tr>';
  } catch (e) { toast(e.message, true); }
}
let uTimer; $('#uSearch').addEventListener('input', () => { clearTimeout(uTimer); uTimer = setTimeout(loadUsers, 300); });
$('#uFilter').addEventListener('change', loadUsers);

function openUserEditor(u){
  clearErr($('#formUser'));
  $('#ueTitle').textContent = u ? 'Edit customer' : 'New customer';
  $('#ueId').value = u ? u.id : '';
  $('#ueName').value = u ? u.name : ''; $('#ueEmail').value = u ? u.email : '';
  $('#uePhone').value = u ? u.phone : ''; $('#ueStatus').value = u ? u.status : 'active';
  $('#uePwWrap').hidden = !!u;
  openModal('#mUserEdit');
}
$('#btnNewUser').addEventListener('click', () => openUserEditor(null));
$('#formUser').addEventListener('submit', async e => {
  e.preventDefault(); clearErr(e.target);
  const btn = e.target.querySelector('button[type=submit]'); busy(btn, true);
  const body = { id:+$('#ueId').value||0, name:$('#ueName').value.trim(), email:$('#ueEmail').value.trim(),
                 phone:$('#uePhone').value.trim(), status:$('#ueStatus').value };
  if (!body.id) body.password = $('#uePw').value;
  try { const d = await api('save_user', { method:'POST', body });
    toast(d.message); closeModal($('#mUserEdit')); loadUsers(); }
  catch (er) { showErr(e.target, er.message, er.fields); }
  finally { busy(btn, false); }
});
$('#userTable').addEventListener('click', async e => {
  const ed = e.target.closest('[data-u-edit]');
  if (ed) { try { const d = await api('admin_users'); openUserEditor(d.users.find(u => u.id === +ed.dataset.uEdit)); }
            catch (er) { toast(er.message, true); } return; }
  const act = e.target.closest('[data-u-act]'), blk = e.target.closest('[data-u-blk]'), del = e.target.closest('[data-u-del]');
  if (act) try { const d = await api('update_user_status', { method:'POST', body:{ id:+act.dataset.uAct, status:'active' }});
    toast(d.message); loadUsers(); } catch (er) { toast(er.message, true); }
  if (blk) {
    if (!await confirmAsk('Block this customer? They will not be able to sign in or book.')) return;
    try { const d = await api('update_user_status', { method:'POST', body:{ id:+blk.dataset.uBlk, status:'blocked' }});
      toast(d.message); loadUsers(); } catch (er) { toast(er.message, true); }
  }
  if (del) {
    if (!await confirmAsk('Delete this customer permanently?')) return;
    try { const d = await api('delete_user', { method:'POST', body:{ id:+del.dataset.uDel }});
      toast(d.message); loadUsers(); } catch (er) { toast(er.message, true); }
  }
});

/* ---------- staff & roles ---------- */
async function loadStaff(){
  if (!can('admins.view')) return;
  try {
    const d = await api('admin_staff');
    S.roles = d.roles;
    $('#staffTable tbody').innerHTML = d.staff.map(s => `
      <tr>
        <td><strong>${esc(s.name)}</strong></td>
        <td>${esc(s.username)}</td>
        <td>${esc(s.email)}</td>
        <td>${s.roles.map(r => `<span class="pill confirmed">${esc(r)}</span>`).join(' ') ||
             '<span class="pill draft">none</span>'}
            ${s.permissions.length ? `<br><span class="muted small">+${s.permissions.length} direct perms</span>` : ''}</td>
        <td><span class="pill ${esc(s.status)}">${esc(s.status)}</span></td>
        <td class="t-actions">
          <button class="btn ghost sm" data-s-edit="${s.id}" ${can('admins.update')?'':'disabled'}>Edit</button>
          <button class="btn danger sm" data-s-del="${s.id}" ${can('admins.delete')?'':'disabled'}>Delete</button>
        </td>
      </tr>`).join('');

    const rd = await api('roles');
    S.permissions = rd.permissions;
    $('#roleTable tbody').innerHTML = rd.roles.map(r => `
      <tr>
        <td><strong>${esc(r.name)}</strong></td>
        <td class="muted">${esc(r.description)}</td>
        <td>${r.user_count}</td>
        <td class="muted small">${r.permissions.length ? esc(r.permissions.join(', ')) : '—'}</td>
        <td class="t-actions">
          <button class="btn ghost sm" data-r-edit="${r.id}" ${can('roles.manage')?'':'disabled'}>Edit</button>
          <button class="btn danger sm" data-r-del="${r.id}" ${can('roles.manage')&&r.name!=='super_admin'?'':'disabled'}>Delete</button>
        </td>
      </tr>`).join('');
  } catch (e) { toast(e.message, true); }
}
async function openStaffEditor(s){
  clearErr($('#formStaff'));
  const d = await api('admin_staff'); S.roles = d.roles;
  const rd = await api('roles'); S.permissions = rd.permissions;
  $('#seTitle').textContent = s ? 'Edit staff — ' + s.name : 'New staff account';
  $('#seId').value = s ? s.id : '';
  $('#seName').value = s ? s.name : ''; $('#seUser').value = s ? s.username : '';
  $('#seEmail').value = s ? s.email : ''; $('#sePhone').value = s ? s.phone : '';
  $('#sePw').value = ''; $('#sePw').closest('.field').hidden = !!s;
  $('#seStatus').value = s ? s.status : 'active';
  $('#seRoles').innerHTML = d.roles.map(r =>
    `<label><input type="checkbox" value="${esc(r.name)}" ${s && s.roles.includes(r.name) ? 'checked':''}> ${esc(r.name)}
     <span class="muted small">— ${esc(r.description)}</span></label>`).join('');
  $('#sePerms').innerHTML = `<div class="perm-grid">` + rd.permissions.map(p =>
    `<label><input type="checkbox" value="${esc(p.code)}" ${s && s.permissions.includes(p.code) ? 'checked':''}> ${esc(p.code)}</label>`).join('') + `</div>`;
  openModal('#mStaffEdit');
}
$('#btnNewStaff').addEventListener('click', () => openStaffEditor(null));
$('#formStaff').addEventListener('submit', async e => {
  e.preventDefault(); clearErr(e.target);
  const btn = e.target.querySelector('button[type=submit]'); busy(btn, true);
  const body = { id:+$('#seId').value||0, name:$('#seName').value.trim(), username:$('#seUser').value.trim(),
    email:$('#seEmail').value.trim(), phone:$('#sePhone').value.trim(), status:$('#seStatus').value,
    roles:$$('#seRoles input:checked').map(i=>i.value),
    permissions:$$('#sePerms input:checked').map(i=>i.value) };
  if ($('#sePw').value) body.password = $('#sePw').value;
  try { const d = await api('save_staff', { method:'POST', body });
    toast(d.message); closeModal($('#mStaffEdit')); loadStaff(); }
  catch (er) { showErr(e.target, er.message, er.fields); }
  finally { busy(btn, false); }
});
$('#staffTable').addEventListener('click', async e => {
  const ed = e.target.closest('[data-s-edit]');
  if (ed) { try { const d = await api('admin_staff');
      openStaffEditor(d.staff.find(s => s.id === +ed.dataset.sEdit)); } catch (er) { toast(er.message,true); } return; }
  const del = e.target.closest('[data-s-del]');
  if (del && await confirmAsk('Delete this staff account?')) {
    try { const d = await api('delete_staff', { method:'POST', body:{ id:+del.dataset.sDel } });
      toast(d.message); loadStaff(); } catch (er) { toast(er.message, true); }
  }
});
async function openRoleEditor(r){
  clearErr($('#formRole'));
  const d = await api('roles'); S.permissions = d.permissions;
  $('#reTitle').textContent = r ? 'Edit role — ' + r.name : 'New role';
  $('#reId').value = r ? r.id : ''; $('#reName').value = r ? r.name : ''; $('#reDesc').value = r ? r.description : '';
  $('#reName').disabled = r && r.name === 'super_admin';
  $('#rePerms').innerHTML = `<div class="perm-grid">` + d.permissions.map(p =>
    `<label><input type="checkbox" value="${esc(p.code)}" ${r && r.permissions.includes(p.code)?'checked':''}> ${esc(p.code)}</label>`).join('') + `</div>`;
  openModal('#mRoleEdit');
}
$('#formRole').addEventListener('submit', async e => {
  e.preventDefault(); clearErr(e.target);
  const btn = e.target.querySelector('button[type=submit]'); busy(btn, true);
  try { const d = await api('save_role', { method:'POST', body:{
      id:+$('#reId').value||0, name:$('#reName').value.trim(), description:$('#reDesc').value.trim(),
      permissions:$$('#rePerms input:checked').map(i=>i.value) } });
    toast(d.message); closeModal($('#mRoleEdit')); loadStaff(); }
  catch (er) { showErr(e.target, er.message, er.fields); }
  finally { busy(btn, false); }
});
$('#roleTable').addEventListener('click', async e => {
  const ed = e.target.closest('[data-r-edit]');
  if (ed) { try { const d = await api('roles'); openRoleEditor(d.roles.find(r => r.id === +ed.dataset.rEdit)); }
    catch (er) { toast(er.message,true); } return; }
  const del = e.target.closest('[data-r-del]');
  if (del && await confirmAsk('Delete this role?')) {
    try { const d = await api('delete_role', { method:'POST', body:{ id:+del.dataset.rDel } });
      toast(d.message); loadStaff(); } catch (er) { toast(er.message, true); }
  }
});

/* ---------- audit ---------- */
async function loadAudit(){
  try {
    const d = await api('audit', { params:{ page:S.auditPage } });
    $('#auditCount').textContent = `${d.total} entries`;
    $('#auditTable tbody').innerHTML = d.entries.map(a => `
      <tr><td class="muted small">${esc(a.created_at)}</td><td>${esc(a.actor_name)}</td>
      <td><code>${esc(a.action)}</code></td><td>${esc(a.entity)} #${a.entity_id ?? '—'}</td>
      <td class="muted small">${esc(a.details)}</td><td class="muted small">${esc(a.ip)}</td></tr>`).join('')
      || '<tr><td colspan="6" class="muted">No activity yet.</td></tr>';
    let html = `<button ${d.page===1?'disabled':''} data-ap="${d.page-1}">‹</button>`;
    for (let i=1;i<=d.pages;i++) html += `<button data-ap="${i}" aria-current="${i===d.page}">${i}</button>`;
    html += `<button ${d.page===d.pages?'disabled':''} data-ap="${d.page+1}">›</button>`;
    $('#auditPager').innerHTML = d.pages>1 ? html : '';
    $('#auditPager').onclick = ev => { const b = ev.target.closest('[data-ap]');
      if (b && !b.disabled) { S.auditPage = +b.dataset.ap; loadAudit(); } };
  } catch (e) { toast(e.message, true); }
}

/* ---------- auth ---------- */
function showLogin(){ $('#appView').hidden = true; $('#loginView').hidden = false; }
function showApp(){
  $('#loginView').hidden = true; $('#appView').hidden = false;
  $('#who').textContent = `${S.user.name} · admin`; buildNav();
}
$('#formAdminLogin').addEventListener('submit', async e => {
  e.preventDefault(); clearErr(e.target);
  const btn = e.target.querySelector('button[type=submit]'); busy(btn, true);
  try {
    const b = await api('bootstrap');
    S.csrf = b.csrf;
    const d = await api('login', { method:'POST',
      body:{ identifier:$('#adId').value.trim(), password:$('#adPw').value } });
    if (d.user.type !== 'admin' || d.user.status !== 'active') throw new Error('This account has no admin access.');
    S.user = d.user; S.perms = new Set(d.perms || []);
    const cfg = await api('bootstrap'); S.cfg = cfg.config || {};
    toast('Signed in.'); showApp();
  } catch (er) { showErr(e.target, er.message); }
  finally { busy(btn, false); }
});
$('#btnAdminOut').addEventListener('click', async () => {
  try { await api('logout', { method:'POST', body:{} }); } catch {}
  location.reload();
});

/* ---------- boot ---------- */
(async function boot(){
  try {
    const b = await api('bootstrap');
    S.csrf = b.csrf; S.cfg = b.config || {};
    if (b.user && b.user.type === 'admin' && b.user.status === 'active') {
      S.user = b.user; S.perms = new Set(b.perms || []);
      if (!S.perms.has('dashboard.view')) { showLogin(); toast('Your account has no admin permissions.', true); }
      else showApp();
    } else showLogin();
  } catch { showLogin(); }
})();
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { const open = $$('.modal').filter(m => !m.hidden).pop(); if (open) closeModal(open); }
});
