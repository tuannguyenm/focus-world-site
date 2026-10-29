const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PROOF = /^[0-9a-f]{64}$/;

export function readPublicConfig(value) {
  if (!value || typeof value.supabaseUrl !== 'string' || typeof value.anonKey !== 'string') return null;
  if (!value.supabaseUrl || !value.anonKey) return null;
  const url = new URL(value.supabaseUrl);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) throw new Error('invalid_configuration');
  if (url.username || url.password || url.search || url.hash) throw new Error('invalid_configuration');
  if (!value.anonKey.startsWith('sb_publishable_')) {
    try {
      const claims = JSON.parse(atob(value.anonKey.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
      if (claims.role !== 'anon') throw new Error('private_key');
    } catch { throw new Error('invalid_public_key'); }
  }
  return {supabaseUrl: url.href.replace(/\/$/, ''), anonKey: value.anonKey};
}

// This capability can only retry/check this particular deletion. It contains
// no sign-in tokens and is removed after a confirmed terminal response.
export function createDeletionClient({storage, apiUrl, anonKey, fetchImpl = fetch, cryptoImpl = crypto}) {
  const key = `focus-world:delete-account:${apiUrl}`;
  function load() {
    const raw = storage.getItem(key);
    if (!raw) return null;
    let value;
    try { value = JSON.parse(raw); } catch { throw new Error('invalid_saved_request'); }
    if (value.version !== 1 || !UUID.test(value.deletion_id) || !PROOF.test(value.recovery_token) || !UUID.test(value.owner_uid)) {
      throw new Error('invalid_saved_request');
    }
    return value;
  }
  function prepare(owner) {
    const existing = load();
    if (existing) {
      if (owner && owner.uid !== existing.owner_uid) throw new Error('owner_mismatch');
      return existing;
    }
    if (!owner || !UUID.test(owner.uid)) throw new Error('owner_required');
    const bytes = new Uint8Array(32);
    cryptoImpl.getRandomValues(bytes);
    const value = {version: 1, deletion_id: cryptoImpl.randomUUID(), owner_uid: owner.uid, email: owner.email || null,
      recovery_token: Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')};
    storage.setItem(key, JSON.stringify(value));
    // A write that cannot be read back is not durable enough to send.
    const stored = load();
    if (!stored || stored.deletion_id !== value.deletion_id || stored.recovery_token !== value.recovery_token) {
      throw new Error('request_not_saved');
    }
    return stored;
  }
  async function send(accessToken, ownerUid) {
    const job = load();
    if (!job) throw new Error('request_not_saved');
    if (accessToken && ownerUid !== job.owner_uid) throw new Error('owner_mismatch');
    const abort = new AbortController();
    const timeout = setTimeout(() => abort.abort(), 20000);
    try {
      const response = await fetchImpl(`${apiUrl}/functions/v1/delete-account`, {
        method: 'POST', signal: abort.signal,
        headers: {'Content-Type': 'application/json', ...(anonKey ? {apikey: anonKey} : {}),
          ...(accessToken ? {Authorization: `Bearer ${accessToken}`} : {})},
        body: JSON.stringify({deletion_id: job.deletion_id, recovery_token: job.recovery_token}),
      });
      if (!response.ok) throw new Error(`request_failed_${response.status}`);
      const result = await response.json();
      if (result.deletion_id !== job.deletion_id || !['pending', 'done'].includes(result.status)) {
        throw new Error('invalid_response');
      }
      if (result.status === 'done') storage.removeItem(key);
      return result;
    } finally { clearTimeout(timeout); }
  }
  return {load, prepare, send};
}

async function mount() {
  const elements = Object.fromEntries(['status', 'sign-in', 'google', 'confirm', 'email', 'consent', 'delete',
    'different-account', 'recovery', 'retry', 'done', 'explanation', 'sign-in-note'].map(id => [id, document.getElementById(id)]));
  function status(text, error = false) {
    elements.status.textContent = text;
    elements.status.classList.toggle('error', error);
  }
  function screen(name) {
    for (const id of ['sign-in', 'confirm', 'recovery', 'done']) elements[id].hidden = id !== name;
    elements.explanation.hidden = name === 'done';
  }
  let config;
  try { config = readPublicConfig(JSON.parse(document.getElementById('focus-world-config').textContent)); }
  catch { status('Trang chưa sẵn sàng. Bạn vẫn có thể xoá tài khoản trong app.', true); return; }
  if (!config) { status('Trang xoá tài khoản đang được chuẩn bị. Bạn vẫn có thể xoá tài khoản trong app.'); return; }
  let deletion;
  try {
    deletion = createDeletionClient({storage: window.localStorage, apiUrl: config.supabaseUrl, anonKey: config.anonKey});
    deletion.load();
  } catch { status('Trình duyệt không thể đọc yêu cầu đã lưu. Hãy sử dụng app để quản lý tài khoản.', true); return; }

  let client = null;
  let session = null;
  let busy = false;
  async function runDeletion() {
    if (busy) return;
    busy = true;
    elements.retry.disabled = true;
    elements.delete.disabled = true;
    screen('recovery');
    status('Đang xác nhận với Focus World…');
    try {
      const job = deletion.load();
      const authenticated = session?.user.id === job.owner_uid ? session : null;
      const result = await deletion.send(authenticated?.access_token, authenticated?.user.id);
      if (result.status === 'done') {
        session = null;
        screen('done');
        status('Yêu cầu đã hoàn tất.');
        // Auth may already be gone; clear the browser session locally regardless.
        if (client) void client.auth.signOut({scope: 'local'}).catch(() => {});
      } else status('Yêu cầu đang được xử lý. Bạn có thể kiểm tra lại sau ít phút.');
    } catch (error) {
      if (error.message === 'request_failed_401' && client) {
        const job = deletion.load();
        elements['sign-in'].hidden = false;
        elements.google.disabled = false;
        elements['sign-in-note'].textContent = job.email
          ? `Đăng nhập lại bằng ${job.email} để tiếp tục yêu cầu đã lưu.`
          : 'Đăng nhập lại bằng đúng tài khoản Google đã yêu cầu xoá để tiếp tục.';
        status('Cần xác nhận lại danh tính để tiếp tục. Yêu cầu đã lưu vẫn được giữ nguyên.', true);
      } else status('Chưa xác nhận được kết quả. Yêu cầu vẫn được giữ để kiểm tra lại; không cần gửi một yêu cầu mới.', true);
    } finally { busy = false; elements.retry.disabled = false; }
  }
  elements.retry.addEventListener('click', () => { void runDeletion(); });
  const recovering = deletion.load();
  if (recovering) {
    screen('recovery');
    status('Đã tìm thấy yêu cầu xoá trước đó. Kiểm tra lại để xác nhận kết quả.');
  }

  try {
    const {createClient} = await import('https://esm.sh/@supabase/supabase-js@2.117.3');
    client = createClient(config.supabaseUrl, config.anonKey, {auth: {flowType: 'pkce',
      detectSessionInUrl: true, persistSession: true, autoRefreshToken: true,
      storage: window.sessionStorage, storageKey: 'focus-world:deletion-auth'}});
    const {data, error} = await client.auth.getSession();
    if (error) throw error;
    session = data.session;
    if (session) {
      const {data: identity, error: identityError} = await client.auth.getUser();
      if (identityError) {
        await client.auth.signOut({scope: 'local'});
        session = null;
      } else if (!identity.user?.identities?.some(item => item.provider === 'google')) {
        await client.auth.signOut({scope: 'local'});
        session = null;
      } else elements.email.textContent = identity.user.email || 'Tài khoản Google đã xác thực';
    }
    if (recovering) {
      screen('recovery');
      if (session && session.user.id !== recovering.owner_uid) {
        await client.auth.signOut({scope: 'local'});
        session = null;
        elements['sign-in'].hidden = false;
        elements['sign-in-note'].textContent = recovering.email
          ? `Hãy đăng nhập bằng ${recovering.email}, tài khoản đã yêu cầu xoá.`
          : 'Hãy đăng nhập lại bằng đúng tài khoản đã yêu cầu xoá.';
        status('Tài khoản vừa đăng nhập khác với tài khoản trong yêu cầu. Chưa gửi yêu cầu xoá.', true);
      } else status('Kiểm tra lại để xác nhận kết quả của yêu cầu đã lưu.');
    } else {
      screen(session ? 'confirm' : 'sign-in');
      status(session ? 'Chỉ xoá khi bạn xác nhận bên trên.' : 'Việc đăng nhập chưa xoá dữ liệu.');
    }
    elements.google.addEventListener('click', async () => {
      elements.google.disabled = true;
      status('Đang mở Google…');
      const redirectTo = `${location.origin}${location.pathname}`;
      try {
        const {error: signInError} = await client.auth.signInWithOAuth({provider: 'google',
          options: {redirectTo, queryParams: {prompt: 'select_account'}}});
        if (signInError) throw signInError;
      } catch { status('Chưa thể đăng nhập Google. Vui lòng thử lại.', true); elements.google.disabled = false; }
    });
    elements['different-account'].addEventListener('click', async () => {
      await client.auth.signOut({scope: 'local'});
      session = null;
      elements.consent.checked = false;
      screen('sign-in');
      status('Đăng nhập bằng tài khoản bạn muốn xoá.');
    });
    elements.consent.addEventListener('change', () => { elements.delete.disabled = !elements.consent.checked || busy; });
    elements.confirm.addEventListener('submit', async event => {
      event.preventDefault();
      if (!elements.consent.checked || busy || !session) return;
      try {
        // Refresh before the irreversible request, then persist the retry proof.
        const confirmedUid = session.user.id;
        const {data: current, error: refreshError} = await client.auth.getSession();
        if (refreshError || !current.session || current.session.user.id !== confirmedUid) throw new Error('session_missing');
        session = current.session;
        deletion.prepare({uid: session.user.id, email: session.user.email});
      } catch { status('Chưa thể lưu yêu cầu an toàn. Tài khoản chưa bị xoá; hãy thử lại.', true); return; }
      await runDeletion();
    });
  } catch {
    status(recovering
      ? 'Chưa thể kết nối dịch vụ đăng nhập. Bạn vẫn có thể kiểm tra yêu cầu đã lưu.'
      : 'Chưa thể kết nối dịch vụ đăng nhập. Vui lòng tải lại trang để thử lại.', true);
  }
}

if (typeof document !== 'undefined') void mount();
