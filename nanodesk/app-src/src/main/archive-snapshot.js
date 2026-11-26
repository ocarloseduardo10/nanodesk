/**
 * NanoDesk — Arquivar página (1.9.0) — snapshot DENTRO da página
 * ------------------------------------------------------------------
 * `installArchive` é uma função AUTOCONTIDA (sem variáveis externas): o processo principal a
 * injeta como texto (`SNAPSHOT_SOURCE`) em cada frame via webFrameMain.executeJavaScript, e os
 * testes a executam em jsdom. Protocolo em 3 tempos:
 *
 *   __ndArchive.settle(opts)   rola a página para disparar conteúdo "lazy";
 *   __ndArchive.prepare(opts)  clona o DOM num documento INERTE (nada é requisitado), troca
 *                              cada recurso/estilo por marcadores e devolve a LISTA do que o
 *                              processo principal precisa buscar (pela sessão da aba);
 *   __ndArchive.matches(scope, selectors)  oráculo de CSS (quais seletores casam algo);
 *   __ndArchive.put({resources,styles,frames})  recebe dados em partes (evita um JSON gigante);
 *   __ndArchive.finalize(meta) preenche os marcadores e devolve o HTML final do frame.
 *
 * Privacidade por construção: nunca grava senhas, campos ocultos, tokens CSRF, scripts,
 * valores de input[type=file] nem <noscript>; remove on*, <base>, <meta refresh>, pings e
 * pré-carregamentos. Código ORIGINAL (MIT).
 */
'use strict';

function installArchive(win, ns) {
  // ns = nome aleatório da propriedade (gerado pelo processo principal a cada captura): uma página
  // não consegue pré-instalar um objeto falso nem adivinhar o nome.
  var NS = String(ns || '__ndArchive');
  if (win[NS] && win[NS].v === 1) return;
  var doc0 = win.document;
  var HTMLNS = 'http://www.w3.org/1999/xhtml';
  var MAX_DEPTH = 4;
  var S = null;

  function reset(opts) {
    var o = opts || {};
    S = {
      n: 0,
      prefix: String(o.idPrefix || ''),
      opts: {
        removeHidden: !!o.removeHidden,
        selectionOnly: !!o.selectionOnly,
        keepFormValues: o.keepFormValues !== false,
        keepNoScript: !!o.keepNoScript,
        maxBlobBytes: Number(o.maxBlobBytes) || 25 * 1024 * 1024,
        maxResources: Number(o.maxResources) || 4000
      },
      inert: doc0.implementation.createHTMLDocument(''),
      resources: [], styles: [], iframes: [], roots: {}, fixups: [], pending: [],
      got: { resources: {}, styles: {}, frames: {} },
      rootClone: null, frameRoots: [], sel: null, elements: 0
    };
  }

  function uid(kind) { S.n += 1; return S.prefix + kind + S.n; }
  function abs(u, base) { try { return new URL(String(u), base).href; } catch (e) { return null; } }
  function lower(s) { return String(s || '').toLowerCase(); }

  /* ---------------- blob: → data: (só dá para ler dentro da página) ---------------- */
  function blobToData(url, c, attr) {
    S.pending.push(win.fetch(url).then(function (r) { return r.blob(); }).then(function (b) {
      if (b.size > S.opts.maxBlobBytes) return;
      return new Promise(function (resolve) {
        var fr = new win.FileReader();
        fr.onload = function () { c.setAttribute(attr, String(fr.result)); resolve(); };
        fr.onerror = function () { resolve(); };
        fr.readAsDataURL(b);
      });
    }).catch(function () { /* blob revogado: segue sem a imagem */ }));
  }

  /* ---------------- recursos referenciados em atributos ---------------- */
  function addRes(c, attr, url, kind, ctx) {
    c.removeAttribute(attr);
    if (!url) return;
    var u = abs(url, ctx.base);
    if (!u) return;
    if (/^data:/i.test(u)) { c.setAttribute(attr, u); return; }
    if (/^blob:/i.test(u)) { blobToData(u, c, attr); return; }
    if (!/^https?:/i.test(u)) return;
    if (S.resources.length >= S.opts.maxResources) return;
    var id = uid('r');
    S.resources.push({ id: id, url: u, kind: kind, base: ctx.base });
    S.fixups.push({ t: 'res', c: c, attr: attr, id: id });
  }

  /* ---------------- estilos ---------------- */
  function sheetText(sheet) {
    try {
      var rules = sheet.cssRules;
      var out = [];
      for (var i = 0; i < rules.length; i++) out.push(rules[i].cssText);
      return out.join('\n');
    } catch (e) { return null; }
  }

  function addStyle(ctx, info) {
    var id = uid('s');
    var st = S.inert.createElement('style');
    if (info.media) st.setAttribute('media', info.media);
    S.styles.push({ id: id, scope: ctx.scope, kind: info.kind, text: info.text == null ? null : String(info.text), href: info.href || null, base: info.base || ctx.base, media: info.media || '' });
    S.fixups.push({ t: 'style', c: st, id: id });
    return st;
  }

  function handleInlineStyle(c, ctx) {
    if (!c.hasAttribute('style')) return;
    var v = c.getAttribute('style');
    if (/url\s*\(|image-set\s*\(/i.test(v)) {
      var id = uid('i');
      S.styles.push({ id: id, scope: ctx.scope, kind: 'inline', text: v, href: null, base: ctx.base, media: '' });
      S.fixups.push({ t: 'inline', c: c, id: id });
      c.removeAttribute('style');
    }
  }

  /* ---------------- imagens ---------------- */
  var LAZY_ATTRS = ['data-src', 'data-lazy-src', 'data-original', 'data-lazy', 'data-url', 'data-hi-res-src', 'data-actualsrc', 'data-full-src'];

  function pickImageUrl(el) {
    var u = el.currentSrc || el.getAttribute('src') || '';
    var tiny = !u || (/^data:image\//i.test(u) && u.length < 300) || (el.complete && el.naturalWidth <= 1 && el.naturalHeight <= 1);
    if (tiny) {
      for (var i = 0; i < LAZY_ATTRS.length; i++) {
        var v = el.getAttribute(LAZY_ATTRS[i]);
        if (v && !/^\s*$/.test(v)) return v;
      }
      var ds = el.getAttribute('data-srcset') || el.getAttribute('data-lazy-srcset');
      if (ds) { var parts = ds.split(',').map(function (x) { return x.trim().split(/\s+/)[0]; }).filter(Boolean); if (parts.length) return parts[parts.length - 1]; }
    }
    return u;
  }

  /* ---------------- formulários ---------------- */
  function handleFormControl(el, c, tag) {
    var type = lower(el.getAttribute('type') || (tag === 'input' ? 'text' : ''));
    if (tag === 'input') {
      if (type === 'password' || type === 'hidden' || type === 'file') { c.removeAttribute('value'); return; }
      if (type === 'checkbox' || type === 'radio') {
        if (el.checked) c.setAttribute('checked', ''); else c.removeAttribute('checked');
        return;
      }
      if (type === 'image') return;
      if (S.opts.keepFormValues && el.value != null && el.value !== '') c.setAttribute('value', String(el.value)); else c.removeAttribute('value');
    } else if (tag === 'textarea') {
      c.textContent = S.opts.keepFormValues ? String(el.value || '') : '';
    } else if (tag === 'option') {
      if (el.selected) c.setAttribute('selected', ''); else c.removeAttribute('selected');
    }
  }

  /* ---------------- atributos comuns ---------------- */
  var URL_ATTR = /^(xlink:)?href$|^(form)?action$|^src$|^data$|^background$|^poster$|^formaction$|^longdesc$|^cite$|^manifest$|^codebase$/i;
  function isJsUrl(v) { return String(v).replace(/[\u0000-\u0020]/g, '').toLowerCase().indexOf('javascript:') === 0 || /^[\s\u0000-\u0020]*(vbscript|livescript):/i.test(String(v)); }
  var DROP_ATTRS = { nonce: 1, integrity: 1, crossorigin: 1, ping: 1, autofocus: 1, srcset: 1, sizes: 1, loading: 1, fetchpriority: 1, decoding: 1, imagesrcset: 1, imagesizes: 1, blocking: 1 };

  function cleanAttributes(el, c, tag, ctx) {
    var names = [];
    for (var i = 0; i < c.attributes.length; i++) names.push(c.attributes[i].name);
    for (var k = 0; k < names.length; k++) {
      var n = names[k];
      var ln = lower(n);
      if (ln.indexOf('on') === 0 || DROP_ATTRS[ln]) { c.removeAttribute(n); continue; }
      if (URL_ATTR.test(ln) && isJsUrl(c.getAttribute(n))) { if (ln === 'href' && (tag === 'a' || tag === 'area')) c.setAttribute(n, '#'); else c.removeAttribute(n); continue; }
      if (ln === 'href' && (tag === 'a' || tag === 'area')) {
        var h = c.getAttribute(n);
        if (/^\s*javascript:/i.test(h)) c.setAttribute(n, '#');
        else if (h && h.charAt(0) !== '#') { var ab = abs(h, ctx.base); if (ab && !/^javascript:/i.test(ab)) c.setAttribute(n, ab); }
        continue;
      }
      if (ln === 'action' && tag === 'form') { var a = abs(c.getAttribute(n), ctx.base); if (a) c.setAttribute(n, a); }
    }
    if (tag === 'a' && lower(c.getAttribute('target')) === '_blank') c.setAttribute('rel', 'noopener noreferrer');
  }

  /* ---------------- tags removidas por completo ---------------- */
  var DROP_TAGS = { script: 1, template: 1, object: 1, embed: 1, applet: 1, portal: 1, base: 1, frame: 1, frameset: 1, param: 1, slot: 0 };
  var HEAD_SAFE = { html: 1, head: 1, body: 1, meta: 1, link: 1, style: 1, title: 1, option: 1, optgroup: 1, source: 1, track: 1 };

  function isHidden(el, tag, ctx) {
    if (!S.opts.removeHidden || HEAD_SAFE[tag] || !ctx.win) return false;
    if (el.namespaceURI !== HTMLNS) return false;
    if (el.hidden) return true;
    try {
      var cs = ctx.win.getComputedStyle(el);
      if (cs.display === 'none') return true;
      if (cs.visibility === 'hidden' && el.children.length === 0) return true;
    } catch (e) { /* sem estilo computado: mantém */ }
    return false;
  }

  /* ---------------- clonagem ---------------- */
  function cloneEl(el, ctx) {
    var ns = el.namespaceURI;
    var tag = lower(el.localName);
    var isHtml = ns === HTMLNS;
    S.elements += 1;

    if (!isHtml && (tag === 'script' || tag === 'set' || tag === 'handler' || tag === 'listener')) return null;   // SVG/MathML: script, <set>, handlers
    if (!isHtml && tag === 'animate' && /href/i.test(el.getAttribute('attributeName') || '')) return null;
    if (isHtml) {
      if (DROP_TAGS[tag]) return null;
      if (tag === 'noscript' && !S.opts.keepNoScript) return null;
      if (tag === 'link') return cloneLink(el, ctx);
      if (tag === 'meta') return cloneMeta(el, ctx);
      if (tag === 'style') return cloneStyle(el, ctx);
      if (tag === 'canvas') return cloneCanvas(el, ctx);
      if (tag === 'iframe') return cloneIframe(el, ctx);
      if (tag === 'picture') return clonePicture(el, ctx);
      if (tag === 'source' || tag === 'track') return null;
    }
    if (isHidden(el, tag, ctx)) return null;

    var c = S.inert.importNode(el, false);
    cleanAttributes(el, c, tag, ctx);

    if (isHtml) {
      if (tag === 'img') { handleImg(el, c, ctx); }
      else if (tag === 'video') { handleVideo(el, c, ctx); cloneInto(el, c, ctx, true); handleInlineStyle(c, ctx); return c; }
      else if (tag === 'audio') { c.removeAttribute('src'); c.removeAttribute('autoplay'); c.setAttribute('controls', ''); handleInlineStyle(c, ctx); return c; }
      else if (tag === 'input' || tag === 'textarea' || tag === 'option') {
        handleFormControl(el, c, tag);
        if (tag === 'input' && lower(el.getAttribute('type')) === 'image') addRes(c, 'src', el.getAttribute('src'), 'image', ctx);
      }
      else if (tag === 'details') { if (el.open) c.setAttribute('open', ''); else c.removeAttribute('open'); }
      else if (tag === 'body' || tag === 'table' || tag === 'td' || tag === 'th' || tag === 'tr') {
        if (c.hasAttribute('background')) addRes(c, 'background', c.getAttribute('background'), 'image', ctx);
      }
      if (tag === 'textarea') { handleInlineStyle(c, ctx); return c; }
    } else if (tag === 'image' || tag === 'feimage') {
      var hv = el.getAttribute('href'); var xv = el.getAttributeNS ? el.getAttributeNS('http://www.w3.org/1999/xlink', 'href') : null;
      if (hv != null) addRes(c, 'href', hv, 'image', ctx);
      if (xv) { c.removeAttributeNS('http://www.w3.org/1999/xlink', 'href'); addRes(c, 'xlink:href', xv, 'image', ctx); }
    } else if (tag === 'use') {
      var uh = el.getAttribute('href') || (el.getAttributeNS ? el.getAttributeNS('http://www.w3.org/1999/xlink', 'href') : '');
      if (uh && uh.charAt(0) !== '#') { c.removeAttribute('href'); try { c.removeAttributeNS('http://www.w3.org/1999/xlink', 'href'); } catch (e) { /* ignorado */ } }
    }

    handleInlineStyle(c, ctx);
    cloneInto(el, c, ctx, false);
    return c;
  }

  function cloneInto(el, c, ctx, skipMedia) {
    var tag = lower(el.localName);
    if (el.shadowRoot) {
      var tpl = S.inert.createElement('template');
      tpl.setAttribute('shadowrootmode', 'open');
      var scope = uid('sh');
      S.roots[scope] = el.shadowRoot;
      var sctx = { doc: ctx.doc, win: ctx.win, base: ctx.base, scope: scope, depth: ctx.depth, sel: ctx.sel };
      try {
        var adopted = el.shadowRoot.adoptedStyleSheets || [];
        for (var a = 0; a < adopted.length; a++) {
          var t = sheetText(adopted[a]);
          if (t) tpl.content.appendChild(addStyle(sctx, { kind: 'adopted', text: t }));
        }
      } catch (e) { /* ignorado */ }
      for (var s = el.shadowRoot.firstChild; s; s = s.nextSibling) {
        if (s.nodeType === 1) { var k = cloneEl(s, sctx); if (k) tpl.content.appendChild(k); }
        else if (s.nodeType === 3) tpl.content.appendChild(S.inert.createTextNode(s.data));
      }
      c.appendChild(tpl);
    }
    if (tag === 'textarea') return;
    for (var n = el.firstChild; n; n = n.nextSibling) {
      if (n.nodeType === 1) {
        var nt = lower(n.localName);
        if (skipMedia && (nt === 'source' || nt === 'track')) continue;
        if (ctx.sel && ctx.inBody && !ctx.sel.intersects(n)) continue;
        var kid = cloneEl(n, ctx);
        if (kid) c.appendChild(kid);
      } else if (n.nodeType === 3) {
        if (ctx.sel && ctx.inBody && !ctx.sel.intersects(n)) continue;
        c.appendChild(S.inert.createTextNode(n.data));
      }
    }
  }

  function handleImg(el, c, ctx) {
    var u = pickImageUrl(el);
    c.removeAttribute('data-srcset'); c.removeAttribute('data-lazy-srcset');
    for (var li = 0; li < LAZY_ATTRS.length; li++) c.removeAttribute(LAZY_ATTRS[li]);   // sem função sem scripts; só deixariam URLs de origem
    addRes(c, 'src', u, 'image', ctx);
  }

  function clonePicture(el, ctx) {
    var c = S.inert.importNode(el, false);
    cleanAttributes(el, c, 'picture', ctx);
    for (var n = el.firstChild; n; n = n.nextSibling) {
      if (n.nodeType === 1 && lower(n.localName) === 'img') { var k = cloneEl(n, ctx); if (k) c.appendChild(k); }
    }
    return c;
  }

  function handleVideo(el, c, ctx) {
    c.removeAttribute('src'); c.removeAttribute('autoplay'); c.removeAttribute('preload'); c.removeAttribute('loop');
    c.setAttribute('controls', '');
    var poster = el.getAttribute('poster');
    if (poster) { addRes(c, 'poster', poster, 'image', ctx); return; }
    try {
      if (el.videoWidth > 0 && el.readyState >= 2) {
        var cv = el.ownerDocument.createElement('canvas');
        cv.width = el.videoWidth; cv.height = el.videoHeight;
        cv.getContext('2d').drawImage(el, 0, 0);
        c.setAttribute('poster', cv.toDataURL('image/jpeg', 0.85));
      }
    } catch (e) { /* vídeo "tainted" (CORS): sem quadro */ }
  }

  function cloneCanvas(el, ctx) {
    var data = '';
    try { data = el.toDataURL('image/png'); } catch (e) { return null; }   // canvas "tainted": omite
    if (typeof data !== 'string' || data.indexOf('data:image/') !== 0 || data.length < 30) return null;
    var img = S.inert.createElement('img');
    ['id', 'class', 'style', 'width', 'height', 'title', 'role', 'aria-label'].forEach(function (a) { if (el.hasAttribute(a)) img.setAttribute(a, el.getAttribute(a)); });
    img.setAttribute('src', data);
    handleInlineStyle(img, ctx);
    return img;
  }

  function cloneLink(el, ctx) {
    var rel = lower(el.getAttribute('rel')).split(/\s+/);
    var href = el.getAttribute('href');
    if (rel.indexOf('stylesheet') >= 0 && rel.indexOf('alternate') < 0) {
      var abHref = abs(href, ctx.base);
      if (!abHref || el.disabled) return null;
      var text = el.sheet ? sheetText(el.sheet) : null;
      return addStyle(ctx, { kind: 'link', href: abHref, base: abHref, text: text, media: el.getAttribute('media') || '' });
    }
    if (rel.indexOf('icon') >= 0 || rel.indexOf('apple-touch-icon') >= 0 || rel.indexOf('shortcut') >= 0) {
      var c = S.inert.createElement('link');
      c.setAttribute('rel', el.getAttribute('rel'));
      if (el.getAttribute('type')) c.setAttribute('type', el.getAttribute('type'));
      if (el.getAttribute('sizes')) c.setAttribute('sizes', el.getAttribute('sizes'));
      addRes(c, 'href', href, 'image', ctx);
      return c;
    }
    if (rel.indexOf('canonical') >= 0) {
      var cn = S.inert.createElement('link');
      cn.setAttribute('rel', 'canonical');
      var cu = abs(href, ctx.base);
      if (cu) cn.setAttribute('href', cu);
      return cn;
    }
    return null;   // preload/prefetch/preconnect/modulepreload/manifest/alternate/...
  }

  function cloneMeta(el, ctx) {
    var he = lower(el.getAttribute('http-equiv'));
    if (he) return null;
    if (el.hasAttribute('charset')) return null;
    var nm = lower(el.getAttribute('name'));
    if (/csrf|xsrf|token|nonce|authenticity/.test(nm)) return null;
    var c = S.inert.importNode(el, false);
    cleanAttributes(el, c, 'meta', ctx);
    return c;
  }

  function cloneStyle(el, ctx) {
    var type = lower(el.getAttribute('type'));
    if (type && type !== 'text/css') return null;
    var text = el.sheet ? sheetText(el.sheet) : null;
    if (text == null || (text === '' && el.textContent)) text = el.textContent || '';
    if (el.sheet && el.sheet.disabled) return null;
    return addStyle(ctx, { kind: 'style', text: text, media: el.getAttribute('media') || '' });
  }

  function cloneIframe(el, ctx) {
    var token = uid('f');
    var c = S.inert.importNode(el, false);
    cleanAttributes(el, c, 'iframe', ctx);
    ['src', 'srcdoc', 'allow', 'allowfullscreen', 'csp', 'credentialless', 'loading'].forEach(function (a) { c.removeAttribute(a); });
    c.setAttribute('sandbox', '');
    c.setAttribute('referrerpolicy', 'no-referrer');
    var src = el.getAttribute('src');
    var idoc = null;
    try { idoc = el.contentDocument; } catch (e) { idoc = null; }
    if (idoc && idoc.documentElement && ctx.depth < MAX_DEPTH && (el.hasAttribute('srcdoc') || (idoc.URL && idoc.URL !== 'about:blank') || (idoc.body && idoc.body.childNodes.length > 0))) {
      var sub = processDocument(idoc, ctx.depth + 1);
      S.frameRoots.push({ token: token, doc: idoc, root: sub });
      S.fixups.push({ t: 'frame-local', c: c, token: token });
    } else {
      var abSrc = src ? abs(src, ctx.base) : null;
      if (abSrc && /^https?:/i.test(abSrc) && ctx.depth < MAX_DEPTH) {
        S.iframes.push({ token: token, src: abSrc, name: el.getAttribute('name') || '' });
        S.fixups.push({ t: 'frame-remote', c: c, token: token });
      }
    }
    handleInlineStyle(c, ctx);
    return c;
  }

  /* ---------------- documento ---------------- */
  function processDocument(doc, depth) {
    var scope = uid('d');
    S.roots[scope] = doc;
    var win2 = doc.defaultView;
    var ctx = { doc: doc, win: win2, base: doc.baseURI || doc.URL, scope: scope, depth: depth, sel: null, inBody: false };
    if (depth === 0 && S.opts.selectionOnly) {
      try {
        var sel = win.getSelection();
        if (sel && sel.rangeCount > 0 && !sel.isCollapsed) {
          var rs = [];
          for (var ri = 0; ri < sel.rangeCount; ri++) rs.push(sel.getRangeAt(ri));
          S.sel = { intersects: function (node) { for (var q = 0; q < rs.length; q++) { try { if (rs[q].intersectsNode(node)) return true; } catch (e) { return true; } } return false; } };
        }
      } catch (e) { S.sel = null; }
    }
    var html = doc.documentElement;
    var c = S.inert.importNode(html, false);
    cleanAttributes(html, c, 'html', ctx);
    for (var n = html.firstChild; n; n = n.nextSibling) {
      if (n.nodeType !== 1) continue;
      var tn = lower(n.localName);
      var cctx = ctx;
      if (tn === 'body' && S.sel && depth === 0) cctx = { doc: ctx.doc, win: ctx.win, base: ctx.base, scope: ctx.scope, depth: ctx.depth, sel: S.sel, inBody: true };
      var k = cloneEl(n, cctx);
      if (k) c.appendChild(k);
    }
    var head = null;
    for (var m = c.firstChild; m; m = m.nextSibling) if (lower(m.localName) === 'head') { head = m; break; }
    if (!head) { head = S.inert.createElement('head'); c.insertBefore(head, c.firstChild); }
    try {
      var ad = doc.adoptedStyleSheets || [];
      for (var i = 0; i < ad.length; i++) {
        var t = sheetText(ad[i]);
        if (t) head.appendChild(addStyle(ctx, { kind: 'adopted', text: t }));
      }
    } catch (e) { /* ignorado */ }
    return c;
  }

  function doctypeOf(doc) {
    var d = doc.doctype;
    if (!d) return '';
    var s = '<!DOCTYPE ' + d.name;
    if (d.publicId) s += ' PUBLIC "' + d.publicId + '"' + (d.systemId ? ' "' + d.systemId + '"' : '');
    else if (d.systemId) s += ' SYSTEM "' + d.systemId + '"';
    return s + '>';
  }

  /* ---------------- API ---------------- */
  function sleep(ms) { return new Promise(function (r) { win.setTimeout(r, ms); }); }

  function settle(opts) {
    var o = opts || {};
    var maxMs = Number(o.maxMs) || 6000;
    var t0 = Date.now();
    var el = doc0.scrollingElement || doc0.documentElement;
    var sx = win.scrollX || 0; var sy = win.scrollY || 0;
    return (async function () {
      try {
        var lazies = doc0.querySelectorAll('img[loading="lazy"]');
        for (var i = 0; i < lazies.length; i++) { try { lazies[i].loading = 'eager'; } catch (e) { /* ignorado */ } }
        var y = 0; var guard = 0;
        while (Date.now() - t0 < maxMs && guard++ < 250) {
          var h = el.scrollHeight; var vh = win.innerHeight || 800;
          if (y > h) break;
          try { win.scrollTo(0, y); win.dispatchEvent(new win.Event('scroll')); } catch (e) { /* ignorado */ }
          await sleep(110);
          y += Math.max(200, Math.floor(vh * 0.8));
        }
        try { win.scrollTo(0, el.scrollHeight); } catch (e) { /* ignorado */ }
        await sleep(150);
        var pend = Array.prototype.slice.call(doc0.images).filter(function (im) { return !im.complete; }).slice(0, 80);
        if (pend.length) {
          await Promise.race([
            Promise.all(pend.map(function (im) { return new Promise(function (r) { im.addEventListener('load', r, { once: true }); im.addEventListener('error', r, { once: true }); }); })),
            sleep(Math.max(300, maxMs - (Date.now() - t0)))
          ]);
        }
      } finally {
        try { win.scrollTo(sx, sy); } catch (e) { /* ignorado */ }
      }
      return { ms: Date.now() - t0, height: el.scrollHeight };
    })();
  }

  function prepare(opts) {
    reset(opts);
    return (async function () {
      S.rootClone = processDocument(doc0, 0);
      if (S.pending.length) await Promise.all(S.pending);
      return {
        url: doc0.URL, title: doc0.title || '', lang: doc0.documentElement.getAttribute('lang') || '',
        resources: S.resources, styles: S.styles, iframes: S.iframes, elements: S.elements,
        selection: !!S.sel
      };
    })();
  }

  function matches(scope, selectors) {
    var root = S.roots[scope] || doc0;
    var out = [];
    for (var i = 0; i < selectors.length; i++) {
      var s = selectors[i];
      try { out.push(!!root.querySelector(s)); } catch (e) { out.push(true); }
    }
    return out;
  }

  function put(chunk) {
    var c = chunk || {};
    ['resources', 'styles', 'frames'].forEach(function (k) {
      var src = c[k]; if (!src) return;
      for (var id in src) if (Object.prototype.hasOwnProperty.call(src, id)) S.got[k][id] = src[id];
    });
    return true;
  }

  function safeCss(t) { return String(t == null ? '' : t).replace(/<\/(style)/gi, '<\\/$1').replace(/<!--/g, '<\\!--'); }

  function head(c) {
    for (var m = c.firstChild; m; m = m.nextSibling) if (lower(m.localName) === 'head') return m;
    return null;
  }

  function serialize(rootClone, doc) {
    var dt = doctypeOf(doc);
    return (dt ? dt + '\n' : '') + rootClone.outerHTML;
  }

  function finalize(meta) {
    var m = meta || {};
    var G = S.got;
    // 1) frames locais (mesma origem): finalizados dentro da própria página
    // frameRoots é registrado do mais PROFUNDO para o mais raso: iterar para frente
    for (var i = 0; i < S.frameRoots.length; i++) {
      var fr = S.frameRoots[i];
      applyFixups();
      G.frames[fr.token] = serialize(fr.root, fr.doc);
    }
    applyFixups();
    // 2) cabeçalho de segurança/privacidade do documento principal
    var root = S.rootClone;
    var hd = head(root);
    if (hd) {
      var first = hd.firstChild;
      var add = function (tag, attrs) {
        var e = S.inert.createElement(tag);
        for (var k in attrs) if (Object.prototype.hasOwnProperty.call(attrs, k)) e.setAttribute(k, attrs[k]);
        hd.insertBefore(e, first);
      };
      var items = [];
      items.push(['meta', { charset: 'utf-8' }]);
      if (m.csp) items.push(['meta', { 'http-equiv': 'Content-Security-Policy', content: String(m.csp) }]);
      items.push(['meta', { name: 'referrer', content: 'no-referrer' }]);
      if (m.sourceUrl) items.push(['meta', { name: 'nanodesk:source', content: String(m.sourceUrl) }]);
      if (m.savedAt) items.push(['meta', { name: 'nanodesk:saved', content: String(m.savedAt) }]);
      for (var j = items.length - 1; j >= 0; j--) add(items[j][0], items[j][1]);
    }
    var html = serialize(root, doc0);
    return html;
  }

  var applied = false;
  function applyFixups() {
    var G = S.got;
    for (var i = 0; i < S.fixups.length; i++) {
      var f = S.fixups[i];
      if (f.done) continue;
      if (f.t === 'res') {
        var v = G.resources[f.id];
        if (v) { f.c.setAttribute(f.attr, v); f.done = true; } else if (G.resources.__final) f.done = true;
      } else if (f.t === 'style') {
        var css = G.styles[f.id];
        if (css != null) { f.c.textContent = safeCss(css); f.done = true; } else if (G.styles.__final) f.done = true;
      } else if (f.t === 'inline') {
        var st = G.styles[f.id];
        if (st != null) { if (st) f.c.setAttribute('style', st); f.done = true; } else if (G.styles.__final) f.done = true;
      } else if (f.t === 'frame-local' || f.t === 'frame-remote') {
        var h = G.frames[f.token];
        if (h) { f.c.setAttribute('srcdoc', h); f.done = true; }
      }
    }
    applied = true;
  }

  function dispose() { try { delete win[NS]; } catch (e) { win[NS] = undefined; } S = null; return true; }

  win[NS] = {
    v: 1, settle: settle, prepare: prepare, matches: matches, put: put, finalize: finalize, dispose: dispose,
    // para depuração/teste (não expõe dados da página)
    _applied: function () { return applied; }
  };
}

/** Código a injetar no frame, instalando a API em window[ns]. */
function snapshotSource(ns) { return '(' + installArchive.toString() + ')(window,' + JSON.stringify(String(ns)) + ');'; }
const SNAPSHOT_SOURCE = snapshotSource('__ndArchive');

module.exports = { installArchive, snapshotSource, SNAPSHOT_SOURCE };
