/**
 * NanoDesk — Teclado virtual embaralhado (1.9.1)
 * ------------------------------------------------------------------
 * Contramedida contra keyloggers que só registram TECLAS (e contra quem grava as posições
 * dos cliques): a senha-mestra pode ser digitada com o mouse, e a posição de cada tecla é
 * EMBARALHADA de novo a cada clique (aleatoriedade criptográfica). Nenhum evento de teclado
 * físico é gerado.
 * LIMITE HONESTO: não protege contra malware que grava a TELA (ou lê a memória do app).
 * Código ORIGINAL (MIT).
 */
(function (root) {
  'use strict';

  var LOWER = 'abcdefghijklmnopqrstuvwxyz'.split('');
  var UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
  var DIGITS = '0123456789'.split('');
  var SYMBOLS = '!@#$%&*()-_=+[]{};:,.?/\\|~^<>\'"`'.split('');
  var ACC_LOWER = 'çáàâãéêíóôõú'.split('');
  var ACC_UPPER = 'ÇÁÀÂÃÉÊÍÓÔÕÚ'.split('');

  /** Inteiro uniforme em [0, n) sem viés (rejeição) — usa crypto quando disponível. */
  function randInt(n, cryptoObj) {
    var c = cryptoObj || (root.crypto && root.crypto.getRandomValues ? root.crypto : null);
    if (!c) throw new Error('Sem fonte de aleatoriedade criptográfica.');
    var limit = Math.floor(0x100000000 / n) * n;
    var buf = new Uint32Array(1);
    do { c.getRandomValues(buf); } while (buf[0] >= limit);
    return buf[0] % n;
  }

  /** Fisher–Yates com aleatoriedade criptográfica (não altera o array original). */
  function shuffle(arr, cryptoObj) {
    var a = arr.slice();
    for (var i = a.length - 1; i > 0; i--) {
      var j = randInt(i + 1, cryptoObj);
      var t = a[i]; a[i] = a[j]; a[j] = t;
    }
    return a;
  }

  /** Teclas do layout atual, em ordem embaralhada. */
  function layout(shift, cryptoObj) {
    var keys = (shift ? UPPER.concat(ACC_UPPER) : LOWER.concat(ACC_LOWER)).concat(DIGITS, SYMBOLS);
    return shuffle(keys, cryptoObj);
  }

  /** Insere texto no campo na posição do cursor e avisa quem escuta (input). */
  function insertAt(input, ch) {
    var s = input.selectionStart, e = input.selectionEnd;
    if (typeof s !== 'number') { input.value += ch; }
    else { input.setRangeText(ch, s, e, 'end'); }
    input.dispatchEvent(new Event('input', { bubbles: true }));
  }
  function backspace(input) {
    var s = input.selectionStart, e = input.selectionEnd;
    if (typeof s !== 'number') { input.value = input.value.slice(0, -1); }
    else if (s !== e) { input.setRangeText('', s, e, 'end'); }
    else if (s > 0) { input.setRangeText('', s - 1, s, 'end'); }
    input.dispatchEvent(new Event('input', { bubbles: true }));
  }

  /**
   * Liga o teclado virtual a um ou mais campos de senha.
   * @param {{inputs: HTMLInputElement[], host: HTMLElement, toggle: HTMLElement}} o
   */
  function attach(o) {
    var inputs = o.inputs, host = o.host, toggle = o.toggle;
    var doc = host.ownerDocument;
    var current = inputs[0];
    var shift = false;
    var open = false;
    inputs.forEach(function (i) { i.addEventListener('focus', function () { current = i; }); });

    function render() {
      host.innerHTML = '';
      if (!open) return;
      var panel = doc.createElement('div');
      panel.className = 'vkb';
      panel.setAttribute('role', 'group');
      panel.setAttribute('aria-label', 'Teclado virtual embaralhado');
      var note = doc.createElement('div');
      note.className = 'vkb-note';
      note.textContent = 'Clique nas teclas: as posições mudam a cada clique.';
      panel.appendChild(note);
      var grid = doc.createElement('div');
      grid.className = 'vkb-grid';
      layout(shift).forEach(function (k) {
        var b = doc.createElement('button');
        b.type = 'button'; b.className = 'vkb-key'; b.textContent = k; b.tabIndex = -1;
        b.addEventListener('mousedown', function (ev) { ev.preventDefault(); });   // não tira o foco do campo
        b.addEventListener('click', function () { insertAt(current, k); render(); });
        grid.appendChild(b);
      });
      panel.appendChild(grid);
      var bar = doc.createElement('div');
      bar.className = 'vkb-bar';
      [['⇧ ' + (shift ? 'minúsculas' : 'MAIÚSCULAS'), function () { shift = !shift; render(); }],
       ['⌫ Apagar', function () { backspace(current); render(); }],
       ['Fechar', function () { open = false; render(); }]].forEach(function (d) {
        var b = doc.createElement('button');
        b.type = 'button'; b.className = 'btn'; b.textContent = d[0]; b.tabIndex = -1;
        b.addEventListener('mousedown', function (ev) { ev.preventDefault(); });
        b.addEventListener('click', d[1]);
        bar.appendChild(b);
      });
      panel.appendChild(bar);
      host.appendChild(panel);
    }
    toggle.addEventListener('click', function () { open = !open; render(); try { current.focus(); } catch (e) { /* ignorado */ } });
    return { close: function () { open = false; render(); } };
  }

  var api = { layout: layout, shuffle: shuffle, randInt: randInt, attach: attach, _sets: { LOWER: LOWER, UPPER: UPPER, DIGITS: DIGITS, SYMBOLS: SYMBOLS } };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.NDVKeyboard = api;
})(typeof window !== 'undefined' ? window : globalThis);
