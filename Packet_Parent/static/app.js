'use strict';
const $ = (selector) => document.querySelector(selector);
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const icon = (name) => `<svg aria-hidden="true"><use href="#i-${name}"/></svg>`;
const colors = {Education:'#8fa878',Entertainment:'#d4ba82',Gaming:'#b4a4cb',Social:'#8aadb8',Unknown:'#d3d8cc'};
const titles = {overview:['Your family, connected.','A clearer picture of your family’s internet activity.','Overview'],activity:['Every connection, in context.','Explore the network activity observed in your captures.','Internet activity'],alerts:['A moment to check in.','Understand which family rules matched observed activity.','Alerts'],rules:['Boundaries that fit your family.','Set domain, category, schedule, and internet-time rules.','Family rules'],devices:['Meet your connected devices.','Give each observed device a name and a family member.','Devices'],captures:['From packets to perspective.','Import a network capture to start understanding activity.','Capture library'],settings:['Make it work for your family.','Tune how internet activity is grouped and measured.','Settings']};
let monitorLoaded = false, followToday = true;
let state = null, view = 'overview', authenticated = false, setupDone = false, refreshBusy = false, refreshPending = false, toastTimer;

async function api(path, options = {}) {
  let response;
  try { response = await fetch('/api' + path, {...options, signal: AbortSignal.timeout(30000), headers: {'X-PacketParent':'1', ...(options.body instanceof ArrayBuffer ? {} : {'Content-Type':'application/json'}), ...options.headers}}); } catch (error) { throw new Error('Dashboard connection lost. Restart Start PacketParent.bat and refresh this page.'); }
  const data = await response.json().catch(() => ({detail: 'The dashboard server returned an error. Check its terminal.'}));
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith('/auth/')) { authenticated = false; await initAuth(); }
    throw new Error(data.detail || 'The request could not be completed.');
  }
  return data;
}
function toast(message, error = false) {
  clearTimeout(toastTimer); const node = $('#toast'); node.textContent = message;
  node.className = 'toast' + (error ? ' error-toast' : '');
  toastTimer = setTimeout(() => node.classList.add('hidden'), error ? 8000 : 4200);
}
function duration(seconds, markup = false) {
  const minutes = Math.floor(Math.max(0, seconds) / 60), hours = Math.floor(minutes / 60);
  if (seconds > 0 && seconds < 60) return markup ? '&lt;1 <small>min</small>' : '<1 min';
  return markup ? (hours ? `${hours}<small>h</small> ${minutes % 60}<small>m</small>` : `${minutes}<small> min</small>`) : (hours ? `${hours}h ${minutes % 60}m` : `${minutes} min`);
}
function clock(timestamp) {
  if (timestamp === null || timestamp === undefined) return '—';
  return new Date((timestamp + (state?.settings.utc_offset || 0) * 60) * 1000).toLocaleTimeString('en', {timeZone:'UTC',hour:'2-digit',minute:'2-digit',hour12:false});
}
function fullDate(timestamp) { if (timestamp == null) return 'No matching activity'; return new Date((timestamp + state.settings.utc_offset * 60) * 1000).toLocaleString('en', {timeZone:'UTC',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',hour12:false}); }
function deviceName(ip) { return state?.devices.find(d => d.ip === ip)?.name || ip; }
function deviceOptions(selected = '') { return `<option value="">All devices</option>` + state.devices.map(d => `<option value="${esc(d.ip)}" ${d.ip === selected ? 'selected' : ''}>${esc(d.name)}</option>`).join(''); }
function timezoneLabel() { const offset = state.settings.utc_offset; return `UTC${offset < 0 ? '−' : '+'}${String(Math.floor(Math.abs(offset)/60)).padStart(2,'0')}:${String(Math.abs(offset)%60).padStart(2,'0')}`; }
function categoryBadge(value) { return `<span class="badge ${esc(value)}">${esc(value)}</span>`; }
function empty(title, text, buttons = '') { return `<div class="empty">${icon('activity')}<h2>${title}</h2><p>${text}</p>${buttons ? `<div class="empty-actions">${buttons}</div>` : ''}</div>`; }
function importButtons() { return `<button class="button primary" data-action="upload">${icon('upload')}Import PCAP</button><button class="button" data-action="demo">Explore sample family</button>`; }

async function initAuth() {
  const result = await api('/auth/status');
  setupDone = result.setup; authenticated = result.authenticated;
  $('#auth-screen').classList.toggle('hidden', authenticated);
  $('#auth-title').textContent = setupDone ? 'Welcome back.' : 'Welcome to PacketParent.';
  $('#auth-description').textContent = setupDone ? 'Sign in to your local parent dashboard.' : 'Create a parent password to get started.';
  $('#auth-submit').innerHTML = (setupDone ? 'Open parent space' : 'Create parent space') + ' <span>→</span>';
  $('#confirm-field').classList.toggle('hidden', setupDone);
  $('#auth-confirm').required = !setupDone;
  $('#auth-password').autocomplete = setupDone ? 'current-password' : 'new-password';
  if (authenticated) await refresh(true);
}
$('#auth-form').addEventListener('submit', async event => {
  event.preventDefault(); $('#auth-error').classList.add('hidden');
  const password = $('#auth-password').value;
  if (!setupDone && password !== $('#auth-confirm').value) { $('#auth-error').textContent = 'The passwords do not match.'; $('#auth-error').classList.remove('hidden'); return; }
  $('#auth-submit').disabled = true;
  try {
    await api(setupDone ? '/auth/login' : '/auth/setup', {method:'POST',body:JSON.stringify({password,utc_offset:-new Date().getTimezoneOffset()})});
    authenticated = true; setupDone = true; $('#auth-screen').classList.add('hidden'); $('#auth-form').reset(); await refresh(true);
  } catch(error) { $('#auth-error').textContent = error.message; $('#auth-error').classList.remove('hidden'); }
  finally { $('#auth-submit').disabled = false; }
});
$('#logout').addEventListener('click', async () => { try { await api('/auth/logout', {method:'POST'}); authenticated = false; await initAuth(); } catch(e) { toast(e.message,true); } });

async function refresh(force = false) {
  if (!authenticated) return;
  if (refreshBusy) { if (force) refreshPending = true; return; }
  refreshBusy = true;
  try {
    const requestedDay = $('#date-filter').value, requestedDevice = $('#device-filter').value;
    const source = $('#source-filter').value;
    const query = new URLSearchParams({day:source === 'live' && followToday ? '' : requestedDay,device:requestedDevice,source});
    const result = await api('/dashboard?' + query);
    if (source !== $('#source-filter').value || requestedDay !== $('#date-filter').value || requestedDevice !== $('#device-filter').value) { refreshPending = true; return; }
    state = result;
    const previous = $('#device-filter').value;
    $('#device-filter').innerHTML = deviceOptions(previous);
    $('#date-filter').value = state.day;
    $('#timezone-label').textContent = timezoneLabel();
    $('#nav-alert-count').textContent = state.summary.unacknowledged;
    $('#sample-banner').classList.toggle('hidden', !state.captures.some(c => c.demo));
    $('#refresh-note').innerHTML = '<span class="status-dot"></span>Updated just now · refreshes every 5s';
    $('#connection-error').classList.add('hidden');
    renderMonitor();
    if (!monitorLoaded) await loadMonitor();
    if (force || ['overview','activity','alerts','captures'].includes(view) || (view === 'devices' && !document.activeElement?.closest('[data-device]'))) render();
  } catch(error) { $('#refresh-note').textContent = 'Disconnected · displayed data may be stale'; $('#connection-error').textContent = error.message; $('#connection-error').classList.remove('hidden'); if (force) toast(error.message,true); }
  finally { refreshBusy = false; if (refreshPending) { refreshPending = false; queueMicrotask(() => refresh(true)); } }
}
function changeView(next) {
  view = next;
  document.querySelectorAll('.view').forEach(el => el.classList.toggle('hidden', el.id !== 'view-' + next));
  document.querySelectorAll('[data-view]').forEach(el => { el.classList.toggle('selected', el.dataset.view === next); el.setAttribute('aria-current', el.dataset.view === next ? 'page' : 'false'); });
  $('#page-heading').textContent = titles[next][0]; $('#page-description').textContent = titles[next][1]; $('#breadcrumb-view').textContent = titles[next][2];
  if (state) render();
}
document.querySelectorAll('[data-view]').forEach(el => el.addEventListener('click', () => changeView(el.dataset.view)));
$('#device-filter').addEventListener('change', () => refresh(true));
$('#date-filter').addEventListener('change', () => { followToday = $('#date-filter').value === state?.today; refresh(true); });
$('#source-filter').addEventListener('change', () => { followToday = true; $('#date-filter').value = ''; $('#device-filter').value = ''; refresh(true); });
$('#activity-search').addEventListener('input', renderActivity);

function metrics() {
  const s = state.summary;
  const items = [ ['Estimated internet-active time',duration(s.seconds,true),'Combined device time · overlapping apps merged','clock',true], ['Domains observed',s.domains.toLocaleString(),`${s.observations.toLocaleString()} network observations`,'globe'],['Open alerts',s.unacknowledged,'Rule matches awaiting your review','bell'],['Registered devices',state.devices.length,state.source === 'live' ? 'This PC keeps one identity across IP changes' : 'In the selected activity source','device'] ];
  return `<div class="metrics">${items.map(([name,value,sub,i,featured]) => `<div class="metric ${featured?'featured':''}"><div class="metric-top"><span>${name}</span>${icon(i)}</div><div class="metric-value">${value}</div><div class="metric-sub">${sub}</div></div>`).join('')}</div>`;
}
function activityTable(rows, limit = 0) {
  const selected = limit ? rows.slice(0,limit) : rows.slice(0,500);
  if (!selected.length) return empty('No activity in this view.','Choose another date or device, or import a capture to see observations.');
  return `<div class="table-wrap"><table><thead><tr><th>DOMAIN / CONNECTION</th><th>DEVICE</th><th>CATEGORY</th><th>LAST SEEN</th><th>OBSERVATIONS</th></tr></thead><tbody>${selected.map(r => `<tr><td><div class="domain-cell"><span class="site-icon">${esc(r.domain[0])}</span><span>${esc(r.domain)}<small>${esc(r.evidence)}</small></span></div></td><td>${esc(deviceName(r.device_ip))}</td><td>${categoryBadge(r.category)}</td><td>${clock(r.last)}</td><td>${r.count.toLocaleString()}</td></tr>`).join('')}</tbody></table></div>`;
}
function renderOverview() {
  const node = $('#view-overview');
  if (!state.captures.length) { node.innerHTML = metrics() + empty('Ready to observe this PC.','Choose your Wi-Fi or Ethernet adapter above and click Start monitoring. Browse for a little while; completed captures usually appear within 15 seconds. Opening Wireshark alone does not update this dashboard.',importButtons()) + `<div class="callout"><b>How it works</b> · Import a capture → extract network metadata → store observations in SQLite → review your dashboard.</div>`; return; }
  const maximum = Math.max(3600,...state.hourly), total = Object.values(state.categories).reduce((a,b)=>a+b,0);
  let position = 0; const gradient = Object.entries(state.categories).map(([name,value]) => { const old=position; position += value/(total||1)*100; return `${colors[name]} ${old}% ${position}%`; }).join(',');
  const recent = state.alerts.filter(a=>!a.acknowledged).slice(0,2);
  node.innerHTML = metrics() + `<div class="main-grid"><div class="card card-pad"><div class="card-head"><div><h2>A day on the internet</h2><p>Estimated active minutes by hour · ${timezoneLabel()}</p></div><span class="legend-small"><i></i>Internet activity</span></div><div class="chart" role="img" aria-label="Hourly estimated internet-active time">${state.hourly.map((s,h)=>`<div class="bar-slot" title="${String(h).padStart(2,'0')}:00 — ${duration(s)} across selected devices"><div class="bar ${s?'':'is-empty'}" style="height:${Math.max(2,s/maximum*100)}%"></div></div>`).join('')}</div><div class="chart-labels"><span>00:00</span><span>04:00</span><span>08:00</span><span>12:00</span><span>16:00</span><span>20:00</span><span>23:00</span></div><div class="chart-note">A ${state.settings.idle_seconds}-second quiet period separates sessions. No idle tail is added.</div></div>
  <div class="card card-pad"><div class="card-head"><div><h2>What’s in the mix?</h2><p>Share of network observations, not time</p></div></div><div class="category-content"><div class="donut" style="background:${total?`conic-gradient(${gradient})`:'#edf1e8'}"><div class="donut-label">${Object.keys(state.categories).length}<small>CATEGORIES</small></div></div><div class="category-legend">${Object.entries(state.categories).sort((a,b)=>b[1]-a[1]).map(([name,value])=>`<div class="category-row"><i style="background:${colors[name]}"></i>${name}<strong>${Math.round(value/(total||1)*100)}%</strong></div>`).join('') || '<p class="form-hint">No observations for this date.</p>'}</div></div><div class="chart-note">Categories use a small local domain list. Unmatched domains stay Unknown.</div></div></div>
  <div class="card table-card"><div class="card-head"><div><h2>Recent internet activity</h2><p>A little context behind the connections</p></div><button class="button subtle" data-action="view" data-target="activity">View all ${icon('arrow')}</button></div>${activityTable(state.activity,5)}<div class="table-footer">Observed traffic does not confirm that a page was actively viewed. Encrypted content stays private.</div></div>
  <div class="bottom-grid"><div class="card card-pad"><div class="card-head"><div><h2>Worth a check-in</h2><p>Recent rule matches</p></div><button class="button subtle" data-action="view" data-target="alerts">All alerts ${icon('arrow')}</button></div>${recent.map(a=>`<div class="alert-preview"><div class="alert-symbol">${icon('bell')}</div><div class="alert-copy"><b>${esc(a.title)}</b><p>${esc(deviceName(a.device_ip))} · ${esc(a.domain || 'Daily usage')}</p><small>${clock(a.timestamp)} · ${esc(a.evidence)}</small></div></div>`).join('') || '<p class="form-hint">No open alerts for the selected date and device.</p>'}</div><div class="card card-pad insight-card"><div class="eyebrow">THE BIGGER PICTURE</div><h2>Good habits begin<br>with understanding.</h2><p>Use these observations to start a conversation. Internet time is an estimate; background traffic and buffered content can affect it.</p><button class="button subtle" data-action="view" data-target="rules">Review your family rules ${icon('arrow')}</button></div></div>`;
}
function renderActivity() {
  if (!state) return;
  const query = $('#activity-search').value.toLowerCase();
  const rows = state.activity.filter(r => `${r.domain} ${deviceName(r.device_ip)} ${r.category}`.toLowerCase().includes(query));
  $('#activity-content').innerHTML = `<div class="card">${activityTable(rows)}<div class="table-footer">${rows.length} grouped entries${rows.length>500?' · showing first 500':''}. Each entry groups a device, destination, and evidence type.</div></div><div class="callout"><b>Read the evidence:</b> DNS query = requested domain. TLS server name / HTTP Host = visible hostname. DNS-to-IP inference = estimated association that may be ambiguous on shared servers. IP connection = no domain identified. ${state.summary.unknown.toLocaleString()} observations have no visible domain.</div><div class="section-head"><div><h2>Internet activity sessions</h2><p>Payload traffic only. Known background exclusions apply.</p></div></div><div class="card table-wrap"><table><thead><tr><th>DEVICE</th><th>START</th><th>END</th><th>ESTIMATED TIME</th></tr></thead><tbody>${state.sessions.slice(0,100).map(s=>`<tr><td>${esc(deviceName(s.device_ip))}</td><td>${clock(s.start)}</td><td>${clock(s.end)}</td><td>${duration(s.seconds)}</td></tr>`).join('') || '<tr><td colspan="4">No payload activity sessions.</td></tr>'}</tbody></table></div>`;
}
function renderAlerts() {
  $('#view-alerts').innerHTML = `<div class="section-head"><div><h2>${state.summary.unacknowledged} open ${state.summary.unacknowledged===1?'alert':'alerts'}</h2><p>Repeated matches are grouped by rule, device, destination, and day.</p></div><button class="button" data-action="view" data-target="rules">Manage rules</button></div>` + (state.alerts.length ? `<div class="alert-list">${state.alerts.map(a=>`<article class="card alert-card ${a.acknowledged?'acknowledged':''}"><span class="alert-symbol">${icon('bell')}</span><div class="alert-copy"><b>${esc(a.title)}</b><p>${esc(a.reason)}</p><p>${esc(deviceName(a.device_ip))} · ${clock(a.timestamp)}${a.last_seen!==a.timestamp?'–'+clock(a.last_seen):''} · ${a.count.toLocaleString()} ${a.count===1?'match':'matches'}</p><span class="evidence">Evidence: ${esc(a.evidence)}</span></div>${a.acknowledged?'<span class="badge success">Reviewed</span>':`<button class="button" data-action="ack" data-id="${esc(a.id)}">Mark reviewed</button>`}</article>`).join('')}</div>` : empty('Nothing needs a check-in.','No rules matched the selected activity. Missing capture coverage is not evidence that a device was offline.'));
}
function ruleDescription(r) {
  if (r.kind === 'hours') return `Flag payload activity outside <b>${esc(r.start)}–${esc(r.end)}</b>.`;
  if (r.kind === 'budget') return `Flag estimated internet time above <b>${r.minutes} minutes per day</b>, per device.`;
  return `Flag <b>${esc(r.target)}</b> ${r.kind==='domain'?'and its subdomains':'activity'}${r.start?` between <b>${esc(r.start)}–${esc(r.end)}</b>`:' at any time'}.`;
}
function renderRules() {
  $('#view-rules').innerHTML = `<div class="section-head"><div><h2>Your family rules</h2><p>Rules generate alerts. They do not block connections. Times use ${timezoneLabel()}.</p></div><button class="button primary" data-action="new-rule">+ Create rule</button></div>` + (state.rules.length ? `<div class="rule-grid">${state.rules.map(r=>`<article class="card rule-card"><div class="card-head"><div><span class="badge ${r.enabled?'success':''}">${r.enabled?'Enabled':'Paused'} · ${esc(r.kind==='budget'?'Daily limit':r.kind)}</span><h2 style="margin-top:13px">${esc(r.name)}</h2></div><button class="switch ${r.enabled?'on':''}" data-action="toggle-rule" data-id="${r.id}" aria-label="${r.enabled?'Pause':'Enable'} ${esc(r.name)}" aria-pressed="${!!r.enabled}"><i></i></button></div><p>${ruleDescription(r)}</p><p>${icon('device')} ${esc(r.device_ip?deviceName(r.device_ip):'All devices')}</p><div class="rule-actions"><button class="text-button" data-action="edit-rule" data-id="${r.id}">Edit rule ↗</button><button class="text-button danger" data-action="delete-rule" data-id="${r.id}">Delete</button></div></article>`).join('')}</div>` : empty('Start with one simple boundary.','Create a domain restriction, study-hours rule, or daily internet-time limit.')) + `<div class="callout">Saving a rule re-evaluates existing captures too, so you can explore how a policy would affect the recorded activity.</div>`;
}
function renderDevices() {
  $('#view-devices').innerHTML = `<div class="section-head"><div><h2>${state.devices.length} registered devices</h2><p>Live monitoring identifies this PC across changes to its network address.</p></div></div>` + (state.devices.length ? `<div class="device-grid">${state.devices.map(d=>`<form class="card device-card" data-device="${esc(d.ip)}"><div class="device-icon">${icon('device')}</div><h2>${esc(d.name)}</h2><p>${esc(d.is_local ? 'This PC · ' + (d.addresses.join(', ') || 'Awaiting traffic') : d.ip)} · Last observed ${d.last_seen?fullDate(d.last_seen):'—'}<br>${d.observations.toLocaleString()} observations · ${duration(state.device_seconds[d.ip]||0)} in the current view</p><label class="field">Device name<input name="name" value="${esc(d.name)}" required maxlength="80"></label><label class="field">Family member<input name="child" value="${esc(d.child)}" maxlength="60" placeholder="Family member’s name"></label><button class="button" type="submit">Save device</button></form>`).join('')}</div>` : empty('No devices yet.','Import traffic captured on the monitored device or on a gateway carrying its traffic.',importButtons())) + `<div class="callout">This PC’s live history uses a persistent identity. Nearby devices’ discovery broadcasts are excluded. Imported gateway captures still identify devices by local IP address.</div>`;
}
function renderCaptures() {
  $('#view-captures').innerHTML = `<div class="upload-zone" id="drop-zone">${icon('upload')}<h2>Bring your network activity into focus.</h2><p>Drop a PCAP or PCAPNG here, or choose a file.<br>Up to 25 MB · Ethernet, raw IP, loopback, and Linux cooked captures</p><div class="empty-actions">${importButtons()}<a class="button" href="/api/demo/download">Download sample PCAP</a></div></div><div class="section-head"><div><h2>Capture library</h2><p>Showing the latest 30 imports. Re-importing identical packets does not double-count usage.</p></div></div><div class="card">${state.captures.map(c=>`<div class="capture-item">${icon('activity')}<div><b>${esc(c.name)}</b><p>${fullDate(c.first)}–${clock(c.last)} · ${c.stats.packets.toLocaleString()} packets · ${c.stats.inserted.toLocaleString()} new observations<br>Imported ${fullDate(c.imported)}${c.stats.duplicates?' · '+c.stats.duplicates+' duplicate observations skipped':''}${c.stats.malformed_packets?' · '+c.stats.malformed_packets+' malformed packets skipped':''}${c.stats.unsupported_link?' · '+c.stats.unsupported_link+' unsupported link packets skipped':''}</p></div><span class="badge ${c.demo?'warning':'success'}">${c.demo?'Synthetic demo':c.source==='live'?'This PC':'Imported'}</span></div>`).join('') || '<div class="card-pad"><p class="form-hint">Your imported captures will appear here.</p></div>'}</div><div class="callout"><b>Automatic ingestion: ${state.watcher.running?'watching the local inbox':'not running'}.</b> This watches completed files; it does not mean a capture sensor is recording.<br>To connect live traffic, install Wireshark/TShark and run <code>python capture.py --list</code>, then <code>python capture.py --interface 1</code> using your chosen interface. The helper writes finished segments to <code>data/inbox</code>.${state.watcher.last_import?'<br>Last inbox import: '+fullDate(state.watcher.last_import):''}${state.watcher.error?'<br><b>Inbox error:</b> '+esc(state.watcher.error):''}</div>`;
  const zone = $('#drop-zone');
  zone.addEventListener('dragover', event => { event.preventDefault(); zone.classList.add('drag'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag'));
  zone.addEventListener('drop', event => { event.preventDefault(); zone.classList.remove('drag'); if(event.dataTransfer.files[0]) upload(event.dataTransfer.files[0]); });
}
function renderSettings() {
  $('#view-settings').innerHTML = `<form class="card settings-card" id="settings-form"><h2>Internet-time estimation</h2><p class="form-hint">Count elapsed time between payload observations in each session. Isolated packets count as zero duration. Simultaneous apps on one device are merged.</p><div class="form-row"><label class="field">Session inactivity threshold (seconds)<input name="idle_seconds" type="number" min="30" max="600" value="${state.settings.idle_seconds}" required><small>A longer threshold bridges more quiet gaps.</small></label><label class="field">Local UTC offset (minutes)<input name="utc_offset" type="number" min="-720" max="840" value="${state.settings.utc_offset}" required><small>India: 330. UTC: 0. Fixed offset; adjust manually for daylight saving.</small></label></div><label class="field">Background domains excluded from time<textarea name="ignored_domains" rows="5">${esc(state.settings.ignored_domains.join('\n'))}</textarea><small>One domain per line. Subdomains are included. These observations remain in the activity log; only time estimation and permitted-hours rules exclude them.</small></label><button class="button primary" type="submit">Save settings</button></form><div class="callout"><b>What the estimate means:</b> a connection is evidence of network activity, not human attention. Background services can inflate time; buffering and quiet reading can reduce it. DNS lookups, empty TCP packets, common local service traffic, and configured background domains do not extend sessions.<br><b>Data stays local:</b> uploaded raw files are parsed in memory. Only metadata is stored in SQLite. Captures created by the optional helper remain in <code>data/inbox</code> until you remove them.</div>`;
}
function render() { ({overview:renderOverview,activity:renderActivity,alerts:renderAlerts,rules:renderRules,devices:renderDevices,captures:renderCaptures,settings:renderSettings}[view])(); }

function ruleFields() {
  const kind = $('#rule-kind').value;
  $('#target-domain-field').classList.toggle('hidden',kind!=='domain'); $('#target-category-field').classList.toggle('hidden',kind!=='category');
  $('#rule-time-fields').classList.toggle('hidden',kind==='budget'); $('#budget-field').classList.toggle('hidden',kind!=='budget');
  $('#start-label').textContent = kind==='hours'?'Internet allowed from':'Active from (optional)'; $('#end-label').textContent = kind==='hours'?'Internet allowed until':'Until (optional)';
  $('#time-help').textContent = kind==='hours'?'Activity outside this window triggers an alert. Overnight windows are supported.':'Leave both blank to apply all day. Times use your configured UTC offset.';
}
function openRule(id = null) {
  const form = $('#rule-form'); form.reset(); $('#rule-error').classList.add('hidden');
  const rule = state.rules.find(r=>r.id===Number(id)); form.elements.id.value = rule?.id || '';
  $('#rule-device').innerHTML = deviceOptions(rule?.device_ip || '');
  if (rule) { for(const key of ['name','kind','start','end','minutes']) form.elements[key].value=rule[key]; form.elements[rule.kind==='category'?'category':'domain'].value=rule.target; }
  $('#rule-dialog-title').textContent = rule?'Edit family rule':'Create a family rule'; ruleFields(); $('#rule-dialog').showModal();
}
$('#rule-kind').addEventListener('change',ruleFields);
$('#close-rule').addEventListener('click',()=>$('#rule-dialog').close()); $('#cancel-rule').addEventListener('click',()=>$('#rule-dialog').close());
$('#rule-form').addEventListener('submit', async event => {
  event.preventDefault(); const form=event.currentTarget, data=Object.fromEntries(new FormData(form));
  const existing=state.rules.find(r=>r.id===Number(data.id));
  const payload={name:data.name,kind:data.kind,target:data.kind==='category'?data.category:data.domain,start:data.start,end:data.end,minutes:Number(data.minutes),device_ip:data.device_ip,enabled:existing?.enabled ?? 1};
  const submit=form.querySelector('[type=submit]'); submit.disabled=true;
  try { await api('/rules'+(data.id?'/'+data.id:''),{method:data.id?'PUT':'POST',body:JSON.stringify(payload)}); $('#rule-dialog').close(); await refresh(true); toast('Rule saved. Existing captures were re-evaluated.'); }
  catch(error){$('#rule-error').textContent=error.message;$('#rule-error').classList.remove('hidden');}
  finally{submit.disabled=false;}
});

$('#upload-top').addEventListener('click',()=>$('#file-input').click());
$('#file-input').addEventListener('change',async event=>{if(event.target.files[0]) await upload(event.target.files[0]);event.target.value='';});
async function upload(file) {
  if(file.size>25*1024*1024){toast('Choose a capture smaller than 25 MB.',true);return;}
  $('#upload-top').disabled=true;toast('Parsing capture and evaluating family rules…');
  try { const result=await api('/captures?source='+($('#source-filter').value === 'live' ? 'live' : 'import')+'&name='+encodeURIComponent(file.name),{method:'POST',body:await file.arrayBuffer(),headers:{'Content-Type':'application/octet-stream'}});if ($('#source-filter').value === 'demo') $('#source-filter').value = 'import'; $('#date-filter').value='';await refresh(true);toast(result.message); }
  catch(error){toast(error.message,true);}finally{$('#upload-top').disabled=false;}
}
document.addEventListener('click',async event=>{
  const button=event.target.closest('[data-action]');if(!button)return;
  const {action,id,target}=button.dataset;
  try {
    if(action==='view') {changeView(target);return;}
    if(action==='upload') {$('#file-input').click();return;}
    if(action==='new-rule'||action==='edit-rule') {openRule(id);return;}
    button.disabled=true;
    if(action==='demo'){toast('Building and parsing a synthetic family capture…');const result=await api('/demo',{method:'POST'});$('#source-filter').value='demo';$('#date-filter').value='';$('#device-filter').value='';await refresh(true);toast(result.message);}
    if(action==='ack'){await api(`/alerts/${id}/acknowledge`,{method:'POST'});await refresh(true);toast('Alert marked as reviewed.');}
    if(action==='toggle-rule'){const rule=state.rules.find(r=>r.id===Number(id));await api('/rules/'+id,{method:'PUT',body:JSON.stringify({...rule,enabled:rule.enabled?0:1})});await refresh(true);}
    if(action==='delete-rule'){if(confirm('Delete this rule and its generated alerts?')){await api('/rules/'+id,{method:'DELETE'});await refresh(true);toast('Rule deleted.');}}
  }catch(error){toast(error.message,true);}finally{button.disabled=false;}
});
document.addEventListener('submit',async event=>{
  const form=event.target;
  if(!form.dataset.device && form.id!=='settings-form')return;
  event.preventDefault();const data=Object.fromEntries(new FormData(form)),button=form.querySelector('[type=submit]');button.disabled=true;
  try {
    if(form.dataset.device){await api('/devices/'+encodeURIComponent(form.dataset.device),{method:'PUT',body:JSON.stringify(data)});toast('Device details saved.');}
    else{await api('/settings',{method:'PUT',body:JSON.stringify({idle_seconds:Number(data.idle_seconds),utc_offset:Number(data.utc_offset),ignored_domains:data.ignored_domains.split(/\r?\n/).map(s=>s.trim()).filter(Boolean)})});toast('Settings saved. Usage and alerts were recalculated.');}
    await refresh(true);
  }catch(error){toast(error.message,true);}finally{button.disabled=false;}
});
setInterval(()=>{if(authenticated && !document.hidden && !$('#rule-dialog').open) refresh();},5000);
initAuth().catch(error=>toast('Could not connect to PacketParent: '+error.message,true));

async function loadMonitor() {
  const result = await api('/monitor');
  const selector = $('#monitor-interface'), previous = selector.value;
  selector.innerHTML = result.interfaces.map(i => `<option value="${esc(i.name)}">${esc(i.label)}</option>`).join('') || '<option value="">No capture adapters found</option>';
  selector.value = result.interfaces.find(i => i.name === previous)?.name || result.interfaces.find(i => /wi-?fi|ethernet/i.test(i.label) && !/virtual|vEthernet/i.test(i.label))?.name || result.interfaces[0]?.name || '';
  monitorLoaded = true;
  if (!result.interfaces.length) $('#monitor-detail').textContent = result.error || 'Install Wireshark with TShark and Npcap, then reload this page.';
}
function renderMonitor() {
  const m = state.monitor || {}, running = ['starting','recording'].includes(m.state);
  $('#monitor-title').textContent = running ? 'This PC · monitoring on ' + (m.interface || 'selected adapter') : 'This PC · monitoring ' + (m.state || 'stopped');
  $('#monitor-detail').textContent = m.error || state.watcher.error || (running ? 'Completed segments arrive about every 10–15 seconds. Viewing ' + (state.source === 'live' ? state.day + ' · live history.' : 'a separate source; choose This PC · live to see new traffic.') : 'Start monitoring here to update the dashboard. Opening Wireshark alone does not send captures.');
  $('#monitor-start').classList.toggle('hidden', running);
  $('#monitor-stop').classList.toggle('hidden', !running);
  $('#monitor-interface').disabled = running;
}
$('#monitor-start').addEventListener('click', async () => {
  const button = $('#monitor-start'); button.disabled = true;
  try { await api('/monitor/start', {method:'POST',body:JSON.stringify({interface:$('#monitor-interface').value})}); $('#source-filter').value='live'; $('#date-filter').value=''; $('#device-filter').value=''; followToday=true; toast('Starting capture. The first update can take about 15 seconds.'); await refresh(true); }
  catch(error) { toast(error.message,true); } finally { button.disabled=false; }
});
$('#monitor-stop').addEventListener('click', async () => {
  try { await api('/monitor/stop', {method:'POST'}); toast('Stopping monitoring…'); await refresh(true); } catch(error) { toast(error.message,true); }
});
