'use strict';
// UI text in Vietnamese (default) and English. Both backends send their messages
// (notes, errors, log lines) in English; translateBackend() maps the known ones.
(() => {
  const STRINGS = {
    vi: {
      langSwitch: 'EN',
      langSwitchAria: 'Switch to English',
      subtitle: 'Tìm nguyên nhân trang web bị chặn và cách vượt qua.',
      checkTitle: 'Kiểm tra kết nối',
      checkBtn: 'Kiểm tra',
      summaryIdle: 'Bấm Kiểm tra để xem chế độ nào hợp với mạng của bạn.',
      editHosts: 'Sửa danh sách trang',
      hostsAria: 'Tên miền, mỗi dòng một tên',
      saveHosts: 'Lưu danh sách',
      tabDns: 'DNS',
      tabOptimize: 'Tối ưu',
      recommended: 'Nên dùng',
      dnsIntro: 'Đổi DNS sang máy chủ công cộng (có DNS-over-HTTPS trên Windows 11). Khắc phục kiểu chặn bằng DNS. Không cần giữ app chạy; bấm Hoàn tác để trả lại DNS cũ.',
      providerAria: 'Nhà cung cấp DNS',
      dnsReading: 'Đang đọc DNS hiện tại…',
      undo: 'Hoàn tác',
      apply: 'Áp dụng',
      dnsHint: 'Mỗi lần đổi, máy có thể hỏi quyền quản trị viên.',
      optIntro: 'Chạy một proxy ngay trên máy, tách gói TLS ClientHello để bộ lọc không đọc được tên trang. Khắc phục kiểu chặn theo tên miền (SNI). Giữ app mở trong lúc chạy.',
      status: 'Trạng thái',
      split: 'Cách tách',
      traffic: 'Lưu lượng',
      off: 'Tắt',
      findSplit: 'Tìm cách tách tốt nhất',
      start: 'Bật',
      stop: 'Tắt',
      optHint: 'Áp dụng cho các app dùng cài đặt proxy của hệ thống (trình duyệt, trang cửa hàng và cộng đồng của Steam). App bỏ qua cài đặt này thì không được áp dụng.',

      'kind.ok': 'Ổn',
      'kind.dns': 'Chặn DNS',
      'kind.sni': 'Chặn SNI',
      'kind.ip': 'Chặn IP',
      'kind.run': 'Đang kiểm tra…',
      checking: 'Đang kiểm tra…',
      'sum.null': 'Tất cả trang đều vào được. Không cần sửa gì.',
      'sum.dns': 'Bị chặn bằng DNS. Hãy dùng chế độ DNS.',
      'sum.sni': 'Bị chặn theo tên miền (SNI). Hãy dùng chế độ Tối ưu.',
      'sum.mixed': 'Một số trang bị chặn theo tên miền (SNI). Hãy dùng chế độ Tối ưu.',
      'sum.ip': 'Bị chặn theo địa chỉ IP. Cần VPN hoặc đường hầm, app này chưa có.',
      'net.null': 'Mạng của bạn không chặn các trang này.',
      'net.dns': 'Mạng của bạn chặn bằng DNS.',
      'net.sni': 'Mạng của bạn chặn theo tên miền (SNI).',
      'net.mixed': 'Mạng của bạn chặn một số trang theo tên miền (SNI).',
      'net.ip': 'Mạng của bạn chặn theo địa chỉ IP.',
      'opt.all': 'Tối ưu đang bật và vào được cả {total} trang.',
      'opt.none': 'Tối ưu đang bật nhưng chưa vào được trang nào. Hãy thử "Tìm cách tách tốt nhất".',
      'opt.some': 'Tối ưu đang bật; vào được {working}/{total} trang.',
      'badge.optOk': 'Tối ưu ✓',
      'badge.optBad': 'Tối ưu ✗',
      worksWith: '{host}: vào được bằng cách {how}',

      'split.none': 'chưa có',
      'split.mid': 'giữa tên miền',
      'split.after1': 'sau 1 byte',
      'split.afterN': 'sau {n} byte',
      'split.tcp': 'tách TCP {where}',
      'split.record': 'tách bản ghi {where}',

      'dns.using': 'Đang dùng {provider}.',
      'dns.usingOn': 'Đang dùng {provider} trên {adapter}.',
      'dns.default': 'Mặc định của mạng: {servers}',
      'dns.defaultOn': 'Mặc định của mạng trên {adapter}: {servers}',
      'dns.automatic': 'tự động',
      'opt.on': 'Bật · 127.0.0.1:{port}',
      stats: '{c} kết nối, {f} ClientHello đã tách, {e} lỗi',

      hostsSaved: 'Đã lưu danh sách trang.',
      'dns.switching': 'Đang đổi DNS sang {provider}… hãy xác nhận trên hộp thoại của hệ thống.',
      'dns.changed': 'Đã đổi DNS. Bấm Kiểm tra lại để xác nhận.',
      'dns.restoring': 'Đang trả lại DNS cũ… hãy xác nhận trên hộp thoại của hệ thống.',
      'dns.restored': 'Đã trả lại DNS cũ.',
      'opt.started': 'Đã bật Tối ưu. Hãy mở lại các app đang chạy.',
      'opt.stopped': 'Đã tắt Tối ưu.',
      'measure.trying': 'Đang thử từng cách tách gói bắt tay…',
      'measure.best': 'Cách tách tốt nhất: {how}',
      'measure.none': 'Không cách tách nào vượt qua được. Có thể mạng chặn theo địa chỉ IP.',

      'note.ok': 'Vào được bình thường',
      'note.dnsWrong': 'DNS của máy trả về sai địa chỉ',
      'note.dnsNone': 'Cả DNS của máy lẫn DoH đều không trả về địa chỉ dùng được',
      'note.ipUnreachable': 'Không kết nối được tới địa chỉ này',
      'note.sni': 'Bị chặn theo tên miền; tách ClientHello thì vào được',
      'note.ipFrag': 'Bắt tay vẫn thất bại kể cả khi đã tách gói',
      'err.uac': 'Bạn đã từ chối quyền quản trị viên.',
      'err.port': 'Cổng {port} đang bị app khác dùng.',
      'err.noHosts': 'Hãy thêm ít nhất một tên miền.',
      'err.noAdapter': 'Không tìm thấy card mạng đang hoạt động.',
      'err.nothingToRestore': 'Không có gì để hoàn tác.',
      'err.otherAdapter': 'DNS đã được đổi trên một card mạng khác. Hãy Hoàn tác trước rồi áp dụng lại.',
      'err.resolve': 'Không phân giải được {host}.',
      'log.optOn': 'Đã bật Tối ưu: {addr}',
      'log.optOff': 'Đã tắt Tối ưu, cài đặt proxy đã được trả lại.',
      'log.error': 'Lỗi: {msg}',
    },
    en: {
      langSwitch: 'VI',
      langSwitchAria: 'Chuyển sang tiếng Việt',
      subtitle: 'Find out what is blocking a site, then work around it.',
      checkTitle: 'Connection check',
      checkBtn: 'Check',
      summaryIdle: 'Run a check to see which mode fits your network.',
      editHosts: 'Edit hosts',
      hostsAria: 'Host names, one per line',
      saveHosts: 'Save hosts',
      tabDns: 'DNS',
      tabOptimize: 'Optimize',
      recommended: 'Recommended',
      dnsIntro: 'Changes your DNS to a public resolver (with DNS-over-HTTPS on Windows 11). Fixes blocking by DNS. Nothing keeps running; Undo puts your old DNS back.',
      providerAria: 'DNS provider',
      dnsReading: 'Reading current DNS…',
      undo: 'Undo',
      apply: 'Apply',
      dnsHint: 'May ask for administrator permission each time.',
      optIntro: 'Runs a local proxy that splits the TLS ClientHello so filters cannot read the site name. Fixes blocking by host name (SNI). Keep the app open while it runs.',
      status: 'Status',
      split: 'Split',
      traffic: 'Traffic',
      off: 'Off',
      findSplit: 'Find best split',
      start: 'Start',
      stop: 'Stop',
      optHint: "Covers apps that use the system proxy setting (browsers, Steam's store and community pages). Apps that ignore it are not covered.",

      'kind.ok': 'OK',
      'kind.dns': 'DNS block',
      'kind.sni': 'SNI block',
      'kind.ip': 'IP block',
      'kind.run': 'Checking…',
      checking: 'Checking…',
      'sum.null': 'All hosts reachable. No fix needed.',
      'sum.dns': 'Blocked by DNS. Use DNS mode.',
      'sum.sni': 'Blocked by host name (SNI). Use Optimize.',
      'sum.mixed': 'Blocked by host name on some hosts. Use Optimize.',
      'sum.ip': 'Blocked by address. That needs a VPN or tunnel, which this app does not include.',
      'net.null': 'Your network does not block these sites.',
      'net.dns': 'Your network blocks by DNS.',
      'net.sni': 'Your network blocks by host name (SNI).',
      'net.mixed': 'Your network blocks some sites by host name (SNI).',
      'net.ip': 'Your network blocks by address.',
      'opt.all': 'Optimize is on and gets through to all {total} sites.',
      'opt.none': 'Optimize is on, but no site gets through it. Try "Find best split".',
      'opt.some': 'Optimize is on; {working} of {total} sites get through it.',
      'badge.optOk': 'Optimize ✓',
      'badge.optBad': 'Optimize ✗',
      worksWith: '{host}: works with {how}',

      'split.none': 'none',
      'split.mid': 'mid host name',
      'split.after1': 'after 1 byte',
      'split.afterN': 'after {n} bytes',
      'split.tcp': 'TCP split {where}',
      'split.record': 'record split {where}',

      'dns.using': 'Using {provider}.',
      'dns.usingOn': 'Using {provider} on {adapter}.',
      'dns.default': 'Network default: {servers}',
      'dns.defaultOn': 'Network default on {adapter}: {servers}',
      'dns.automatic': 'automatic',
      'opt.on': 'On · 127.0.0.1:{port}',
      stats: '{c} connections, {f} ClientHellos split, {e} errors',

      hostsSaved: 'Hosts saved.',
      'dns.switching': 'Switching DNS to {provider}… approve the system prompt.',
      'dns.changed': 'DNS changed. Run the check again to confirm.',
      'dns.restoring': 'Restoring your previous DNS… approve the system prompt.',
      'dns.restored': 'Previous DNS restored.',
      'opt.started': 'Optimize is on. Restart apps that were already open.',
      'opt.stopped': 'Optimize is off.',
      'measure.trying': 'Trying each way of splitting the handshake…',
      'measure.best': 'Best split: {how}',
      'measure.none': 'No split got through. The block may be by address.',

      'note.ok': 'Reachable normally',
      'note.dnsWrong': 'System DNS returns a wrong address',
      'note.dnsNone': 'No usable DNS answer from the system or DoH',
      'note.ipUnreachable': 'Address is unreachable',
      'note.sni': 'Blocked by host name; splitting the ClientHello works',
      'note.ipFrag': 'Handshake fails even when fragmented',
      'err.uac': 'Administrator permission was declined.',
      'err.port': 'Port {port} is already in use.',
      'err.noHosts': 'Add at least one host name.',
      'err.noAdapter': 'No active network adapter found.',
      'err.nothingToRestore': 'Nothing to restore.',
      'err.otherAdapter': 'DNS was changed on a different network adapter. Undo it first, then apply again.',
      'err.resolve': 'Could not resolve {host}.',
      'log.optOn': 'Optimize on: {addr}',
      'log.optOff': 'Optimize off, system proxy restored.',
      'log.error': 'Error: {msg}',
    },
  };

  // English messages from the backends (Rust and Node send the same texts).
  const BACKEND = [
    [/^Reachable normally$/, 'note.ok'],
    [/^System DNS returns a wrong address$/, 'note.dnsWrong'],
    [/^No usable DNS answer/, 'note.dnsNone'],
    [/^Address is unreachable$/, 'note.ipUnreachable'],
    [/^Blocked by host name; splitting/, 'note.sni'],
    [/^Handshake fails even when fragmented$/, 'note.ipFrag'],
    [/^Administrator permission was declined$/, 'err.uac'],
    [/^Port (?<port>\d+) is already in use$/, 'err.port'],
    [/^Add at least one host name$/, 'err.noHosts'],
    [/^No active network adapter found$/, 'err.noAdapter'],
    [/^Nothing to restore$/, 'err.nothingToRestore'],
    [/^DNS was changed on a different network adapter/, 'err.otherAdapter'],
    [/^Could not resolve (?<host>.+)$/, 'err.resolve'],
    [/^Optimize on: (?<addr>[^,]+)/, 'log.optOn'],
    [/^Optimize off/, 'log.optOff'],
    [/^error: (?<msg>[\s\S]*)$/, 'log.error'],
  ];

  const KEY = 'fugawrap.lang';
  let lang = 'vi';
  try {
    const saved = localStorage.getItem(KEY);
    if (saved && STRINGS[saved]) lang = saved;
  } catch { /* storage unavailable: keep the default */ }

  function t(key, params = {}) {
    const s = STRINGS[lang][key] ?? STRINGS.en[key] ?? key;
    return s.replace(/\{(\w+)\}/g, (_, k) => String(params[k] ?? ''));
  }

  function translateBackend(text) {
    if (!text) return text;
    for (const [re, key] of BACKEND) {
      const m = re.exec(text);
      if (m) return t(key, m.groups || {});
    }
    return text;
  }

  // Fill every element marked with data-i18n (text) or data-i18n-aria (aria-label).
  function apply() {
    document.documentElement.lang = lang;
    document.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = t(el.dataset.i18n); });
    document.querySelectorAll('[data-i18n-aria]').forEach((el) => { el.setAttribute('aria-label', t(el.dataset.i18nAria)); });
  }

  function setLang(next) {
    if (!STRINGS[next]) return;
    lang = next;
    try { localStorage.setItem(KEY, next); } catch { /* not remembered, still switches */ }
    apply();
  }

  window.i18n = { t, translateBackend, apply, setLang, get lang() { return lang; } };
})();
