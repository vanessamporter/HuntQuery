'use strict';
(function(){
  const $=id=>document.getElementById(id);
  const defaultTargets=['arkime','dql','wireshark'];
  const targetDescriptions={arkime:'Session and PCAP hunting',dql:'Malcolm / OpenSearch DQL',lucene:'Malcolm legacy / advanced Lucene',splunk:'Splunk SPL with CIM-style fields',wireshark:'Packet display filters',zeek:'Zeek JSON log filtering with jq',suricata:'Suricata EVE JSON filtering with jq',securityonion:'Security Onion Hunt / SOC search'};
  let copyStatusTimer;

  function el(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=text;return n;}
  function renderTargets(){
    const box=$('targets');
    for(const [id,label] of Object.entries(NQT.TARGETS)){
      const lab=el('label','target-option');
      const cb=document.createElement('input');cb.type='checkbox';cb.value=id;cb.checked=defaultTargets.includes(id);cb.className='target-checkbox';
      const text=el('span','target-option-text');text.append(el('span','target-option-name',label),el('span','target-option-desc',targetDescriptions[id]||''));
      lab.append(cb,text);box.appendChild(lab);
    }
    updateTargetPicker();
  }
  function selectedTargets(){return [...document.querySelectorAll('.target-checkbox:checked')].map(x=>x.value);}
  function updateTargetPicker(){
    const selected=selectedTargets();const labels=selected.map(id=>NQT.TARGETS[id]);
    let buttonText='Choose tools';
    if(selected.length===Object.keys(NQT.TARGETS).length)buttonText='All tools selected';
    else if(selected.length===1)buttonText=labels[0];
    else if(selected.length>1&&selected.length<=3)buttonText=labels.join(', ');
    else if(selected.length>3)buttonText=`${selected.length} tools selected`;
    $('targetTriggerText').textContent=buttonText;
    $('targetSummary').textContent=selected.length?`Selected: ${labels.join(', ')}`:'No tools selected';
  }
  function setTargetMenu(open){$('targetMenu').classList.toggle('hidden',!open);$('targetTrigger').setAttribute('aria-expanded',String(open));}
  function toggleTargetMenu(){setTargetMenu($('targetTrigger').getAttribute('aria-expanded')!=='true');}
  function clearChildren(node){while(node.firstChild)node.removeChild(node.firstChild);}
  function showErrors(errors){const box=$('inputError');clearChildren(box);if(!errors.length){box.classList.add('hidden');return;}box.classList.remove('hidden');for(const e of errors)box.appendChild(el('div','',`✕ ${e}`));}
  function renderInterpretation(parsed){
    const box=$('explain');clearChildren(box);
    if(parsed.sourceTarget)box.appendChild(el('div','good',`Detected input: ${NQT.TARGETS[parsed.sourceTarget]}.`));
    if(!parsed.conds.length){box.appendChild(el('div','',parsed.sourceTarget?'No supported fields could be translated.':'No supported fields were recognized.'));return;}
    box.appendChild(el('strong','','Recognized:'));
    const ul=el('ul','clean');for(const c of parsed.conds)ul.appendChild(el('li','',NQT.describe(c)));box.appendChild(ul);
    if(parsed.unrecognizedTerms&&parsed.unrecognizedTerms.length){
      box.appendChild(el('strong','','Not recognized:'));
      box.appendChild(el('div','warn',parsed.unrecognizedTerms.join(', ')));
    }
  }
  function renderStatus(parsed,targets){const box=$('status');clearChildren(box);const warnings=new Set();for(const t of targets)for(const w of NQT.warningsFor(parsed,t))warnings.add(w);if(!warnings.size){box.appendChild(el('div','good','✓ Query built from known field mappings.'));return;}for(const w of warnings)box.appendChild(el('div','warn',`⚠ ${w}`));}
  function copyText(text){
    if(navigator.clipboard&&window.isSecureContext)return navigator.clipboard.writeText(text);
    const ta=document.createElement('textarea');ta.value=text;ta.setAttribute('readonly','');ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();
    try{const ok=document.execCommand('copy');return ok?Promise.resolve():Promise.reject(new Error('Copy failed'));}catch(e){return Promise.reject(e);}finally{ta.remove();}
  }
  function renderOutputs(parsed,outputs,targets){
    const box=$('outputs');clearChildren(box);
    for(const t of targets){
      const card=el('div','output-card');const head=el('div','output-head');head.appendChild(el('strong','',NQT.TARGETS[t]));
      const btn=el('button','btn smallbtn','Copy');btn.type='button';btn.dataset.copyTarget=t;head.appendChild(btn);
      const out=el('div','output',outputs[t]||'No query generated for this target.');out.dataset.outputTarget=t;card.append(head,out);box.appendChild(card);
    }
  }
  function run(){
    showErrors([]);
    $('timeSection').classList.add('hidden');
    const targets=selectedTargets();
    if(!targets.length){showErrors(['No output tool is selected. Open the Output targets dropdown and choose at least one tool, such as Arkime or Wireshark.']);clearChildren($('outputs'));return;}
    const result=NQT.translate($('plain').value,targets);showErrors(result.parsed.errors||[]);
    if(result.parsed.errors&&result.parsed.errors.length){clearChildren($('outputs'));renderInterpretation(result.parsed);renderStatus(result.parsed,targets);return;}
    renderOutputs(result.parsed,result.outputs,targets);renderInterpretation(result.parsed);renderStatus(result.parsed,targets);
    if(result.parsed.time){$('timeSection').classList.remove('hidden');$('time').textContent=result.parsed.time.label;}else $('timeSection').classList.add('hidden');
  }
  function submitTranslation(){
    setTargetMenu(false);
    try{run();}
    catch(error){
      clearChildren($('outputs'));
      $('timeSection').classList.add('hidden');
      showErrors(['Translation could not be completed because of an unexpected error. Refresh the page and try again.']);
      console.error('HuntQuery translation failed:',error);
    }
  }
  function showCopyStatus(message,temporary=false){clearTimeout(copyStatusTimer);$('copyStatus').textContent=message;if(temporary)copyStatusTimer=setTimeout(()=>{$('copyStatus').textContent='';},1400);}
  function copyOne(target){const node=document.querySelector(`[data-output-target="${target}"]`);if(!node)return;copyText(node.textContent).then(()=>showCopyStatus(`Copied ${NQT.TARGETS[target]}`,true)).catch(()=>showCopyStatus('Copy failed. Select the query text manually.'));}
  function copyAll(){const nodes=[...document.querySelectorAll('[data-output-target]')];if(!nodes.length)return;const text=nodes.map(n=>`${NQT.TARGETS[n.dataset.outputTarget]}\n${n.textContent}`).join('\n\n');copyText(text).then(()=>showCopyStatus('Copied all queries',true)).catch(()=>showCopyStatus('Copy failed. Select the query text manually.'));}
  function updateClearButton(){$('clearInline').classList.toggle('hidden',!$('plain').value);}
  function clearInput(){$('plain').value='';clearChildren($('outputs'));$('explain').textContent='Nothing parsed yet.';clearChildren($('status'));showErrors([]);$('timeSection').classList.add('hidden');showCopyStatus('');updateClearButton();$('plain').focus();}

  renderTargets();
  $('translationForm').addEventListener('submit',e=>{e.preventDefault();submitTranslation();});$('copyAll').addEventListener('click',copyAll);$('clear').addEventListener('click',clearInput);$('clearInline').addEventListener('click',clearInput);
  $('targetTrigger').addEventListener('click',toggleTargetMenu);
  $('targets').addEventListener('change',e=>{if(e.target.classList.contains('target-checkbox'))updateTargetPicker();});
  $('selectAll').addEventListener('click',()=>{document.querySelectorAll('.target-checkbox').forEach(x=>x.checked=true);updateTargetPicker();});
  $('clearTargets').addEventListener('click',()=>{document.querySelectorAll('.target-checkbox').forEach(x=>x.checked=false);updateTargetPicker();});
  document.addEventListener('click',e=>{if(!$('targetPicker').contains(e.target))setTargetMenu(false);});
  document.addEventListener('keydown',e=>{if(e.key==='Escape'){if(document.activeElement===$('plain')&&$('plain').value)clearInput();else setTargetMenu(false);}});
  $('plain').addEventListener('input',updateClearButton);
  $('plain').addEventListener('keydown',e=>{if((e.key==='Enter'||e.code==='NumpadEnter')&&!e.shiftKey&&!e.isComposing){e.preventDefault();submitTranslation();}});
  $('outputs').addEventListener('click',e=>{const b=e.target.closest('[data-copy-target]');if(b)copyOne(b.dataset.copyTarget);});
  document.querySelectorAll('.examples button').forEach(b=>b.addEventListener('click',()=>{$('plain').value=b.textContent.trim();updateClearButton();$('plain').focus();}));
  updateClearButton();
})();
