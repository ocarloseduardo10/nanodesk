/**
 * NanoDesk — PDF Reader Enhancement (1.8.7)
 * Brave-style PDF viewer: dark mode, settings panel, progress bar, fullscreen.
 */
'use strict';
(function () {
  if (window.__nanodeskPdfEnhance) return;
  window.__nanodeskPdfEnhance = 1;
  var darkMode = false, settingsPanel = null;
  var CSS = `
#toolbarContainer{background:#1a1b2e!important;border-bottom:1px solid rgba(124,92,255,.2)!important;box-shadow:0 2px 8px rgba(0,0,0,.15)!important}
#toolbarViewer,#toolbarViewerRight,#toolbarViewerLeft{background:transparent!important}
.toolbarButton{border-radius:8px!important;transition:background .15s,transform .1s!important}
.toolbarButton:hover{background:rgba(124,92,255,.15)!important}
.toolbarButton:active{transform:scale(.95)!important}
#viewerContainer{background:#2a2b3c!important;transition:background .3s!important}
.pdfViewer .page{border:none!important;box-shadow:0 4px 12px rgba(0,0,0,.3)!important;border-radius:4px!important;margin:10px auto!important}
#viewerContainer.nd-pdf-dark{background:#1a1a2e!important;filter:invert(.92) hue-rotate(180deg)!important}
#viewerContainer.nd-pdf-dark .page{background:#fff!important;filter:invert(1) hue-rotate(180deg)!important}
#nd-pdf-settings{position:fixed;top:42px;right:0;width:280px;bottom:0;background:#1a1b2e;border-left:1px solid rgba(124,92,255,.2);z-index:50;padding:20px;overflow-y:auto;display:none;color:#e8eaf0;font:13px system-ui,sans-serif}
#nd-pdf-settings.nd-visible{display:block}
#nd-pdf-settings h3{margin:0 0 16px;font-size:16px;color:#7c5cff}
.nd-setting-group{margin-bottom:20px}
.nd-setting-label{display:block;margin-bottom:6px;color:#aab2c5;font-size:12px}
.nd-btn-group{display:flex;gap:6px}
.nd-btn{flex:1;padding:8px;border-radius:8px;border:1px solid rgba(255,255,255,.1);background:#232535;color:#e8eaf0;font-size:12px;cursor:pointer;text-align:center;transition:background .15s}
.nd-btn:hover{background:#2d3045}
.nd-btn.nd-active{background:#7c5cff;border-color:#7c5cff;color:#fff}
.nd-toggle{display:flex;align-items:center;justify-content:space-between;padding:10px 0}
.nd-switch{position:relative;width:40px;height:22px;background:#3a3b4e;border-radius:11px;cursor:pointer;transition:background .2s}
.nd-switch.nd-on{background:#7c5cff}
.nd-switch::after{content:'';position:absolute;top:2px;left:2px;width:18px;height:18px;background:#fff;border-radius:50%;transition:transform .2s}
.nd-switch.nd-on::after{transform:translateX(18px)}
#nd-pdf-progress{position:fixed;bottom:0;left:0;right:0;height:3px;background:rgba(255,255,255,.05);z-index:60}
#nd-pdf-progress-bar{height:100%;background:linear-gradient(90deg,#7c5cff,#9c7cff);width:0%;transition:width .2s;border-radius:0 2px 2px 0}
#nd-settings-btn{position:absolute;right:8px;top:8px;width:32px;height:32px;border-radius:8px;border:1px solid rgba(255,255,255,.1);background:#232535;color:#e8eaf0;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:16px;z-index:40;transition:background .15s}
#nd-settings-btn:hover{background:#2d3045}`;
  function init(){
    var s=document.createElement('style');s.id='nd-pdf-modern';s.textContent=CSS;document.head.appendChild(s);
    var btn=document.createElement('button');btn.id='nd-settings-btn';btn.innerHTML='&#9881;';btn.title='Configurações do PDF';btn.addEventListener('click',function(){settingsPanel.classList.toggle('nd-visible')});
    var tb=document.getElementById('toolbarViewerRight')||document.getElementById('toolbarViewer');if(tb)tb.appendChild(btn);else document.body.appendChild(btn);
    settingsPanel=document.createElement('div');settingsPanel.id='nd-pdf-settings';
    settingsPanel.innerHTML='<h3>Configurações do PDF</h3>'+
      '<div class="nd-setting-group"><div class="nd-toggle"><span>Modo escuro (inverter cores)</span><div class="nd-switch" id="nd-dark-toggle"></div></div></div>'+
      '<div class="nd-setting-group"><label class="nd-setting-label">Zoom</label><div class="nd-btn-group"><button class="nd-btn" id="nd-zoom-out">\u2212</button><button class="nd-btn" id="nd-zoom-reset">100%</button><button class="nd-btn" id="nd-zoom-in">+</button></div></div>'+
      '<div class="nd-setting-group"><label class="nd-setting-label">Ajuste</label><div class="nd-btn-group"><button class="nd-btn" id="nd-fit-width">Largura</button><button class="nd-btn" id="nd-fit-page">P\u00e1gina</button><button class="nd-btn nd-active" id="nd-fit-auto">Auto</button></div></div>'+
      '<div class="nd-setting-group"><label class="nd-setting-label">Rota\u00e7\u00e3o</label><div class="nd-btn-group"><button class="nd-btn" id="nd-rot-left">\u21ba</button><button class="nd-btn" id="nd-rot-right">\u21bb</button></div></div>'+
      '<div class="nd-setting-group"><button class="nd-btn" id="nd-fullscreen" style="width:100%">Tela cheia (F)</button></div>'+
      '<div style="margin-top:20px;padding:12px;background:#12141f;border-radius:8px;font-size:11px;color:#666">Atalhos: D = modo escuro \u00b7 F = tela cheia \u00b7 +/\u2212 = zoom \u00b7 \u2190/\u2192 = p\u00e1ginas</div>';
    document.body.appendChild(settingsPanel);
    document.getElementById('nd-dark-toggle').addEventListener('click',function(){darkMode=!darkMode;var v=document.getElementById('viewerContainer');if(v)v.classList.toggle('nd-pdf-dark',darkMode);this.classList.toggle('nd-on',darkMode)});
    document.getElementById('nd-zoom-out').addEventListener('click',function(){PDFViewerApplication.pdfViewer.decreaseScale()});
    document.getElementById('nd-zoom-in').addEventListener('click',function(){PDFViewerApplication.pdfViewer.increaseScale()});
    document.getElementById('nd-zoom-reset').addEventListener('click',function(){PDFViewerApplication.pdfViewer.currentScaleValue='1.0'});
    document.getElementById('nd-fit-width').addEventListener('click',function(){PDFViewerApplication.pdfViewer.currentScaleValue='page-width';['nd-fit-width','nd-fit-page','nd-fit-auto'].forEach(function(i){document.getElementById(i).classList.toggle('nd-active',i==='nd-fit-width')})});
    document.getElementById('nd-fit-page').addEventListener('click',function(){PDFViewerApplication.pdfViewer.currentScaleValue='page-fit';['nd-fit-width','nd-fit-page','nd-fit-auto'].forEach(function(i){document.getElementById(i).classList.toggle('nd-active',i==='nd-fit-page')})});
    document.getElementById('nd-fit-auto').addEventListener('click',function(){PDFViewerApplication.pdfViewer.currentScaleValue='auto';['nd-fit-width','nd-fit-page','nd-fit-auto'].forEach(function(i){document.getElementById(i).classList.toggle('nd-active',i==='nd-fit-auto')})});
    document.getElementById('nd-rot-left').addEventListener('click',function(){PDFViewerApplication.pdfViewer.pagesRotation-=90});
    document.getElementById('nd-rot-right').addEventListener('click',function(){PDFViewerApplication.pdfViewer.pagesRotation+=90});
    document.getElementById('nd-fullscreen').addEventListener('click',function(){if(!document.fullscreenElement)document.documentElement.requestFullscreen().catch(function(){});else document.exitFullscreen().catch(function(){})});
    var bar=document.createElement('div');bar.id='nd-pdf-progress';bar.innerHTML='<div id="nd-pdf-progress-bar"></div>';document.body.appendChild(bar);
    var vc=document.getElementById('viewerContainer');if(vc)vc.addEventListener('scroll',function(){var pct=(vc.scrollTop+vc.clientHeight)/vc.scrollHeight;var b=document.getElementById('nd-pdf-progress-bar');if(b)b.style.width=Math.min(100,Math.max(0,pct*100))+'%'});
    document.addEventListener('keydown',function(e){if(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA')return;switch(e.key){case'd':case'D':document.getElementById('nd-dark-toggle').click();e.preventDefault();break;case'f':case'F':if(!document.fullscreenElement)document.documentElement.requestFullscreen().catch(function(){});else document.exitFullscreen().catch(function(){});e.preventDefault();break;case'Escape':if(settingsPanel.classList.contains('nd-visible'))settingsPanel.classList.remove('nd-visible');break}});
    try{window.__nanodeskPdfEnhanceReady=1}catch(_){}
  }
  if(document.readyState==='complete'||document.readyState==='interactive')setTimeout(init,500);else document.addEventListener('DOMContentLoaded',function(){setTimeout(init,500)});
})();
