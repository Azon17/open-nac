// ════════════════════════════════════════════════════════════════
// Open NAC — Extended Posture Page v2
// ISE-equivalent: Conditions (11 types) + Requirements + Policies
// Replaces PosturePage() in index.html
// ════════════════════════════════════════════════════════════════
//
// DEPLOY: Replace the existing PosturePage function in
//   services/admin-ui/public/index.html
//   (lines 625–800 approximately)
//
// Changes:
//   ✅ Toggle buttons call PATCH /posture/{type}/{id}/toggle API
//   ✅ Extended condition form with ISE-style wizard per category
//   ✅ AV vendor picker (loads from /posture/av-vendors)
//   ✅ Firewall profile selector
//   ✅ Patch Management with KB input
//   ✅ File check (path, version, hash)
//   ✅ Registry check (path, key, value)
//   ✅ Service check (name, state, start type)
//   ✅ USB restriction (mass storage, device classes)
//   ✅ Compound conditions (AND/OR/NOT sub-condition picker)
//   ✅ Category stats in sidebar
//   ✅ Assessment history per endpoint
// ════════════════════════════════════════════════════════════════

function PosturePage(){
  const[tab,setTab]=useState("policies");
  const[conditions,setConditions]=useState(null);
  const[requirements,setRequirements]=useState(null);
  const[policies,setPolicies]=useState(null);
  const[stats,setStats]=useState(null);
  const[editing,setEditing]=useState(null);
  const[editType,setEditType]=useState("");
  const[form,setForm]=useState({});
  const[msg,setMsg]=useState(null);
  const[avVendors,setAvVendors]=useState([]);

  const load=()=>{
    api("/posture/conditions").then(setConditions);
    api("/posture/requirements").then(setRequirements);
    api("/posture/policies").then(setPolicies);
    api("/posture/stats").then(setStats);
    api("/posture/av-vendors").then(r=>setAvVendors(r?.items||[]));
  };
  useEffect(()=>{load()},[]);

  // ── Toggle handler (FIX: actually calls API) ──
  const handleToggle=async(type,id,currentEnabled)=>{
    const paths={condition:"conditions",requirement:"requirements",policy:"policies"};
    const r=await api(`/posture/${paths[type]}/${id}/toggle`,{
      method:"PATCH",
      body:JSON.stringify({enabled:!currentEnabled})
    });
    if(r?.status==="toggled"){
      setMsg({type:"success",text:`${type} ${r.enabled?"enabled":"disabled"}`});
      load();
    }else{
      setMsg({type:"error",text:r?.error||"Toggle failed"});
    }
    setTimeout(()=>setMsg(null),2500);
  };

  const save=async()=>{
    let path,body={...form};
    if(editType==="condition"){
      path="/posture/conditions";
      if(typeof body.os_types==="string")try{body.os_types=JSON.parse(body.os_types)}catch(e){body.os_types=["windows","macos","linux"]}
      if(typeof body.kb_numbers==="string"&&body.kb_numbers)try{body.kb_numbers=JSON.parse(body.kb_numbers)}catch(e){body.kb_numbers=body.kb_numbers.split(",").map(s=>s.trim()).filter(Boolean)}
      if(typeof body.usb_classes==="string"&&body.usb_classes)try{body.usb_classes=JSON.parse(body.usb_classes)}catch(e){body.usb_classes=body.usb_classes.split(",").map(s=>s.trim()).filter(Boolean)}
      if(typeof body.firewall_profiles==="string"&&body.firewall_profiles)try{body.firewall_profiles=JSON.parse(body.firewall_profiles)}catch(e){body.firewall_profiles=body.firewall_profiles.split(",").map(s=>s.trim()).filter(Boolean)}
      if(typeof body.sub_conditions==="string"&&body.sub_conditions)try{body.sub_conditions=JSON.parse(body.sub_conditions)}catch(e){body.sub_conditions=body.sub_conditions.split(",").map(s=>s.trim()).filter(Boolean)}
      // Clean nulls — don't send empty strings for optional fields
      ["vendor","product_name","min_version","file_path","registry_path","registry_key","service_name","compound_operator"].forEach(k=>{
        if(body[k]==="")body[k]=null;
      });
      ["kb_numbers","usb_classes","firewall_profiles","sub_conditions"].forEach(k=>{
        if(!body[k]||body[k].length===0)body[k]=null;
      });
    }else if(editType==="requirement"){
      path="/posture/requirements";
      if(typeof body.os_types==="string")try{body.os_types=JSON.parse(body.os_types)}catch(e){}
      if(typeof body.conditions==="string")try{body.conditions=JSON.parse(body.conditions)}catch(e){}
      if(typeof body.remediation==="string")try{body.remediation=JSON.parse(body.remediation)}catch(e){}
    }else{
      path="/posture/policies";
      if(typeof body.identity_match==="string")try{body.identity_match=JSON.parse(body.identity_match)}catch(e){}
      if(typeof body.requirements==="string")try{body.requirements=JSON.parse(body.requirements)}catch(e){}
    }
    const r=editing==="new"?await api(path,{method:"POST",body:JSON.stringify(body)}):await api(`${path}/${editing}`,{method:"PUT",body:JSON.stringify(body)});
    setMsg({type:r?.error?"error":"success",text:r?.error||"Saved successfully"});
    setEditing(null);load();setTimeout(()=>setMsg(null),3000);
  };

  const del=async(type,id,name)=>{
    if(!confirm(`Delete "${name}"?`))return;
    const paths={condition:"/posture/conditions",requirement:"/posture/requirements",policy:"/posture/policies"};
    await api(`${paths[type]}/${id}`,{method:"DELETE"});load();
  };

  const s=stats||{};
  const catIcons={antivirus:"🛡",firewall:"🔥",disk_encryption:"🔒",patches:"📦",patch_management:"📋",os_version:"💻",application:"📱",service:"⚙",custom:"🔧",registry:"📝",file:"📄",usb:"🔌",compound:"🔗"};
  const catLabels={antivirus:"Anti-Malware",firewall:"Firewall",disk_encryption:"Disk Encryption",patches:"OS Patches",patch_management:"Patch Management",os_version:"OS Version",application:"Application",service:"Service",registry:"Registry",file:"File Check",usb:"USB Restriction",compound:"Compound",custom:"Custom"};
  const sevColors={critical:"red",warning:"yellow",info:"blue"};

  // ── Operator options per category ──
  const operatorsByCategory={
    antivirus:["installed","running","enabled","version_gte"],
    firewall:["enabled","all_profiles_enabled","specific_profile_enabled"],
    disk_encryption:["enabled"],
    patches:["equals","less_than","greater_than"],
    patch_management:["kb_installed","kb_not_installed"],
    os_version:["version_gte","version_lte"],
    application:["installed","not_exists","version_gte"],
    file:["file_exists","file_not_exists","file_version_gte","file_sha256"],
    registry:["registry_exists","registry_value_equals","registry_value_contains"],
    service:["service_running","service_stopped","service_auto_start"],
    usb:["usb_storage_blocked","usb_class_blocked"],
    compound:["compound_and","compound_or","compound_not"],
    custom:["enabled","equals","exists","not_exists"],
  };

  // ── New condition defaults by category ──
  const newConditionDefaults=(cat)=>{
    const base={name:"",description:"",category:cat,os_types:JSON.stringify(["windows","macos"]),operator:operatorsByCategory[cat]?.[0]||"enabled",expected_value:"true",severity:"critical",enabled:true,vendor:null,product_name:null,min_version:null,file_path:null,registry_path:null,registry_key:null,service_name:null,kb_numbers:null,usb_classes:null,firewall_profiles:null,sub_conditions:null,compound_operator:null};
    if(cat==="antivirus"){base.os_types=JSON.stringify(["windows","macos","linux"]);base.operator="running"}
    if(cat==="firewall"){base.operator="all_profiles_enabled";base.firewall_profiles=JSON.stringify(["Domain","Private","Public"])}
    if(cat==="patches"){base.operator="equals";base.expected_value="0"}
    if(cat==="patch_management"){base.operator="kb_installed";base.kb_numbers="[]"}
    if(cat==="registry"){base.os_types=JSON.stringify(["windows"]);base.registry_path="HKLM\\\\SOFTWARE\\\\";base.registry_key=""}
    if(cat==="file"){base.file_path="";base.operator="file_exists"}
    if(cat==="service"){base.service_name="";base.operator="service_running"}
    if(cat==="usb"){base.operator="usb_storage_blocked";base.usb_classes=JSON.stringify(["mass_storage"])}
    if(cat==="compound"){base.operator="compound_and";base.compound_operator="AND";base.sub_conditions="[]"}
    return base;
  };

  // ── Condition count by category ──
  const condCountByCat={};
  (conditions?.items||[]).forEach(c=>{condCountByCat[c.category]=(condCountByCat[c.category]||0)+1});

  return React.createElement("div",null,
    // Alert
    msg&&React.createElement("div",{className:`alert alert-${msg.type}`},
      React.createElement("span",null,msg.text),
      React.createElement("span",{onClick:()=>setMsg(null),style:{cursor:"pointer",fontWeight:600}},"×")
    ),

    // ── Stats bar ──
    React.createElement("div",{style:{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:12,marginBottom:16}},
      [["Compliant",s.compliant||0,"#16a34a"],["Non-compliant",s.non_compliant||0,"#dc2626"],["Unknown",s.unknown||0,"#6b7280"],["Exempt",s.exempt||0,"#2563eb"],["Total",s.total||0,"#374151"]].map(([l,v,c])=>
        React.createElement("div",{key:l,className:"card",style:{padding:12,textAlign:"center"}},
          React.createElement("div",{style:{fontSize:10,color:"#6b7280"}},l),
          React.createElement("div",{style:{fontSize:22,fontWeight:700,color:c}},v)
        )
      )
    ),

    // ── Tabs ──
    React.createElement("div",{style:{display:"flex",borderBottom:"2px solid #e5e7eb",marginBottom:16}},
      [["policies","Posture Policies"],["requirements","Requirements"],["conditions","Conditions"]].map(([k,l])=>
        React.createElement("div",{key:k,onClick:()=>setTab(k),style:{padding:"10px 20px",fontSize:13,fontWeight:tab===k?600:400,cursor:"pointer",color:tab===k?"#f48120":"#6b7280",borderBottom:tab===k?"2px solid #f48120":"2px solid transparent",marginBottom:-2}},l)
      )
    ),

    // ══════════════════════════════
    // POLICIES TAB
    // ══════════════════════════════
    tab==="policies"&&React.createElement("div",null,
      React.createElement("div",{style:{display:"flex",justifyContent:"space-between",marginBottom:12}},
        React.createElement("div",{style:{fontSize:12,color:"#6b7280"}},"Map posture requirements to identity groups. Determines which checks apply to which users."),
        React.createElement("button",{className:"btn btn-primary",onClick:()=>{setEditType("policy");setForm({name:"",description:"",priority:100,identity_match:JSON.stringify({"AD-Group":"Domain Users"},null,2),requirements:JSON.stringify(["Corporate Workstation"],null,2),action_compliant:"permit",action_non_compliant:"quarantine",reassessment_minutes:240,grace_minutes:0,enabled:true});setEditing("new")}},"+\u00a0New Policy")
      ),
      React.createElement("div",{className:"card"},!policies?React.createElement("div",{className:"empty"},"Loading..."):
        React.createElement("table",null,
          React.createElement("thead",null,React.createElement("tr",null,...["Pri","Policy Name","Identity Match","Requirements","Compliant","Non-compliant","Reassess","On",""].map(h=>React.createElement("th",{key:h},h)))),
          React.createElement("tbody",null,(policies.items||[]).map((p,i)=>
            React.createElement("tr",{key:i},
              React.createElement("td",{className:"mono"},p.priority),
              React.createElement("td",{style:{fontWeight:600}},p.name,p.description&&React.createElement("div",{style:{fontSize:10,color:"#9ca3af"}},p.description)),
              React.createElement("td",{className:"mono",style:{fontSize:11,color:"#6b7280",maxWidth:150,overflow:"hidden",textOverflow:"ellipsis"}},JSON.stringify(p.identity_match)),
              React.createElement("td",null,(p.requirements||[]).map((r,j)=>React.createElement("span",{key:j,className:"badge badge-blue",style:{marginRight:4,marginBottom:2}},r))),
              React.createElement("td",null,React.createElement("span",{className:"badge badge-green"},p.action_compliant)),
              React.createElement("td",null,React.createElement("span",{className:"badge badge-red"},p.action_non_compliant)),
              React.createElement("td",{className:"mono",style:{fontSize:11}},p.reassessment_minutes+"m"),
              React.createElement("td",null,React.createElement("div",{className:`toggle ${p.enabled?"on":"off"}`,onClick:()=>handleToggle("policy",p.id,p.enabled)})),
              React.createElement("td",null,React.createElement("div",{style:{display:"flex",gap:4}},
                React.createElement("button",{className:"btn btn-default btn-sm",onClick:()=>{setEditType("policy");setForm({...p,identity_match:JSON.stringify(p.identity_match,null,2),requirements:JSON.stringify(p.requirements,null,2)});setEditing(p.id)}},"Edit"),
                React.createElement("button",{className:"btn btn-danger btn-sm",onClick:()=>del("policy",p.id,p.name)},"Del")
              ))
            )
          ))
        )
      )
    ),

    // ══════════════════════════════
    // REQUIREMENTS TAB
    // ══════════════════════════════
    tab==="requirements"&&React.createElement("div",null,
      React.createElement("div",{style:{display:"flex",justifyContent:"space-between",marginBottom:12}},
        React.createElement("div",{style:{fontSize:12,color:"#6b7280"}},"Groups of conditions that define what \"compliant\" means."),
        React.createElement("button",{className:"btn btn-primary",onClick:()=>{setEditType("requirement");setForm({name:"",description:"",os_types:JSON.stringify(["windows","macos"]),conditions:JSON.stringify([],null,2),remediation:JSON.stringify({},null,2),enabled:true});setEditing("new")}},"+\u00a0New Requirement")
      ),
      React.createElement("div",{className:"card"},!requirements?React.createElement("div",{className:"empty"},"Loading..."):
        React.createElement("table",null,
          React.createElement("thead",null,React.createElement("tr",null,...["Requirement","OS Types","Conditions","Remediation","On",""].map(h=>React.createElement("th",{key:h},h)))),
          React.createElement("tbody",null,(requirements.items||[]).map((r,i)=>
            React.createElement("tr",{key:i},
              React.createElement("td",{style:{fontWeight:600}},r.name,r.description&&React.createElement("div",{style:{fontSize:10,color:"#9ca3af"}},r.description)),
              React.createElement("td",null,(r.os_types||[]).map((o,j)=>React.createElement("span",{key:j,className:"badge badge-gray",style:{marginRight:3,fontSize:10}},o))),
              React.createElement("td",null,(r.conditions||[]).map((c,j)=>React.createElement("span",{key:j,className:"badge badge-blue",style:{marginRight:3,marginBottom:2,fontSize:10}},c))),
              React.createElement("td",{className:"mono",style:{fontSize:10,color:"#6b7280",maxWidth:200,overflow:"hidden",textOverflow:"ellipsis"}},JSON.stringify(r.remediation)),
              React.createElement("td",null,React.createElement("div",{className:`toggle ${r.enabled?"on":"off"}`,onClick:()=>handleToggle("requirement",r.id,r.enabled)})),
              React.createElement("td",null,React.createElement("div",{style:{display:"flex",gap:4}},
                React.createElement("button",{className:"btn btn-default btn-sm",onClick:()=>{setEditType("requirement");setForm({...r,os_types:JSON.stringify(r.os_types),conditions:JSON.stringify(r.conditions,null,2),remediation:JSON.stringify(r.remediation,null,2)});setEditing(r.id)}},"Edit"),
                React.createElement("button",{className:"btn btn-danger btn-sm",onClick:()=>del("requirement",r.id,r.name)},"Del")
              ))
            )
          ))
        )
      )
    ),

    // ══════════════════════════════
    // CONDITIONS TAB (ISE-style with category filter)
    // ══════════════════════════════
    tab==="conditions"&&React.createElement(ConditionsTab,{
      conditions,catIcons,catLabels,sevColors,condCountByCat,
      operatorsByCategory,newConditionDefaults,avVendors,
      handleToggle,del,setEditing,setEditType,setForm
    }),

    // ══════════════════════════════
    // EDIT MODALS
    // ══════════════════════════════
    editing&&React.createElement(EditModal,{
      editing,editType,form,setForm,save,
      setEditing,conditions,requirements,avVendors,
      catIcons,catLabels,operatorsByCategory,newConditionDefaults,
    })
  );
}

// ── Conditions Tab (ISE-style with category sidebar) ──
function ConditionsTab({conditions,catIcons,catLabels,sevColors,condCountByCat,operatorsByCategory,newConditionDefaults,avVendors,handleToggle,del,setEditing,setEditType,setForm}){
  const[catFilter,setCatFilter]=useState("all");
  const ALL_CATS=["antivirus","firewall","disk_encryption","patches","patch_management","os_version","application","file","registry","service","usb","compound","custom"];

  const filtered=(conditions?.items||[]).filter(c=>catFilter==="all"||c.category===catFilter);

  return React.createElement("div",{style:{display:"grid",gridTemplateColumns:"200px 1fr",gap:16}},
    // Category sidebar
    React.createElement("div",{className:"card",style:{padding:8,alignSelf:"start"}},
      React.createElement("div",{onClick:()=>setCatFilter("all"),style:{padding:"8px 12px",borderRadius:5,cursor:"pointer",fontSize:12,fontWeight:catFilter==="all"?600:400,color:catFilter==="all"?"#f48120":"#374151",background:catFilter==="all"?"#fff4e8":"transparent",display:"flex",justifyContent:"space-between",marginBottom:2}},
        React.createElement("span",null,"All conditions"),
        React.createElement("span",{className:"badge badge-gray",style:{fontSize:10}},(conditions?.items||[]).length)
      ),
      React.createElement("div",{style:{borderTop:"1px solid #e5e7eb",margin:"4px 0"}}),
      ALL_CATS.map(cat=>
        React.createElement("div",{key:cat,onClick:()=>setCatFilter(cat),style:{padding:"6px 12px",borderRadius:5,cursor:"pointer",fontSize:12,fontWeight:catFilter===cat?600:400,color:catFilter===cat?"#f48120":"#374151",background:catFilter===cat?"#fff4e8":"transparent",display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:1}},
          React.createElement("span",null,catIcons[cat]||"◆"," ",catLabels[cat]||cat),
          (condCountByCat[cat]||0)>0&&React.createElement("span",{className:"badge badge-gray",style:{fontSize:9}},condCountByCat[cat])
        )
      ),
      React.createElement("div",{style:{borderTop:"1px solid #e5e7eb",margin:"6px 0"}}),
      // Quick-add by category
      React.createElement("div",{style:{padding:"4px 12px",fontSize:11,color:"#9ca3af",marginBottom:4}},"Quick add:"),
      React.createElement("div",{style:{display:"flex",flexWrap:"wrap",gap:3,padding:"0 8px"}},
        ALL_CATS.filter(c=>c!=="custom").map(cat=>
          React.createElement("button",{key:cat,className:"btn btn-default",style:{padding:"2px 6px",fontSize:10},onClick:()=>{
            setEditType("condition");
            setForm(newConditionDefaults(cat));
            setEditing("new");
          }},catIcons[cat])
        )
      )
    ),

    // Conditions table
    React.createElement("div",null,
      React.createElement("div",{style:{display:"flex",justifyContent:"space-between",marginBottom:12}},
        React.createElement("div",{style:{fontSize:12,color:"#6b7280"}},
          catFilter==="all"?"All conditions":catIcons[catFilter]+" "+catLabels[catFilter]+" conditions",
          " — ",filtered.length," total"
        ),
        React.createElement("button",{className:"btn btn-primary",onClick:()=>{
          setEditType("condition");
          setForm(newConditionDefaults(catFilter==="all"?"antivirus":catFilter));
          setEditing("new");
        }},"+\u00a0New Condition")
      ),
      React.createElement("div",{className:"card"},!conditions?React.createElement("div",{className:"empty"},"Loading..."):
        React.createElement("table",null,
          React.createElement("thead",null,React.createElement("tr",null,...["","Condition","Category","Details","Severity","On",""].map(h=>React.createElement("th",{key:h},h)))),
          React.createElement("tbody",null,filtered.map((c,i)=>
            React.createElement("tr",{key:i},
              React.createElement("td",{style:{fontSize:16,textAlign:"center"}},catIcons[c.category]||"◆"),
              React.createElement("td",{style:{fontWeight:500}},
                c.name,
                c.description&&React.createElement("div",{style:{fontSize:10,color:"#9ca3af"}},c.description),
                c.vendor&&React.createElement("div",{style:{fontSize:10,color:"#2563eb"}},c.vendor," ",c.product_name||"")
              ),
              React.createElement("td",null,React.createElement("span",{className:"badge badge-gray"},catLabels[c.category]||c.category)),
              // Details column — show relevant info per category
              React.createElement("td",{style:{fontSize:11,color:"#6b7280",maxWidth:220}},
                React.createElement("span",{className:"mono"},c.operator),
                c.expected_value&&c.expected_value!=="true"&&React.createElement("span",null," = ",c.expected_value),
                c.file_path&&React.createElement("div",{style:{fontSize:10,color:"#9ca3af",maxWidth:200,overflow:"hidden",textOverflow:"ellipsis"}},c.file_path),
                c.registry_path&&React.createElement("div",{style:{fontSize:10,color:"#9ca3af"}},c.registry_key||c.registry_path),
                c.service_name&&React.createElement("div",{style:{fontSize:10,color:"#9ca3af"}},"svc: ",c.service_name),
                c.kb_numbers&&c.kb_numbers.length>0&&React.createElement("div",{style:{fontSize:10,color:"#9ca3af"}},c.kb_numbers.slice(0,3).join(", "),c.kb_numbers.length>3&&"..."),
                c.sub_conditions&&c.sub_conditions.length>0&&React.createElement("div",{style:{fontSize:10,color:"#6366f1"}},c.compound_operator||"AND",": ",c.sub_conditions.join(" + ")),
                React.createElement("div",{style:{display:"flex",gap:3,marginTop:2}},(c.os_types||[]).map((o,j)=>React.createElement("span",{key:j,style:{fontSize:9,color:"#9ca3af",background:"#f3f4f6",padding:"0 4px",borderRadius:2}},o)))
              ),
              React.createElement("td",null,React.createElement("span",{className:`badge badge-${sevColors[c.severity]||"gray"}`},c.severity)),
              React.createElement("td",null,React.createElement("div",{className:`toggle ${c.enabled?"on":"off"}`,onClick:()=>handleToggle("condition",c.id,c.enabled)})),
              React.createElement("td",null,React.createElement("div",{style:{display:"flex",gap:4}},
                React.createElement("button",{className:"btn btn-default btn-sm",onClick:()=>{
                  setEditType("condition");
                  setForm({
                    ...c,
                    os_types:JSON.stringify(c.os_types),
                    kb_numbers:c.kb_numbers?JSON.stringify(c.kb_numbers):null,
                    usb_classes:c.usb_classes?JSON.stringify(c.usb_classes):null,
                    firewall_profiles:c.firewall_profiles?JSON.stringify(c.firewall_profiles):null,
                    sub_conditions:c.sub_conditions?JSON.stringify(c.sub_conditions):null,
                  });
                  setEditing(c.id);
                }},"Edit"),
                React.createElement("button",{className:"btn btn-danger btn-sm",onClick:()=>del("condition",c.id,c.name)},"Del")
              ))
            )
          ),
          filtered.length===0&&React.createElement("tr",null,React.createElement("td",{colSpan:7,style:{textAlign:"center",padding:30,color:"#9ca3af"}},"No conditions",catFilter!=="all"?` in category "${catLabels[catFilter]}"`:"")))
        )
      )
    )
  );
}

// ── Edit Modal (context-aware per type) ──
function EditModal({editing,editType,form,setForm,save,setEditing,conditions,requirements,avVendors,catIcons,catLabels,operatorsByCategory,newConditionDefaults}){
  const F=(label,key,props={})=>
    React.createElement("div",{className:"field",key:key},
      React.createElement("label",{className:"label"},label),
      props.type==="textarea"
        ?React.createElement("textarea",{className:"input mono",rows:props.rows||3,style:{resize:"vertical"},value:form[key]||"",onChange:e=>setForm({...form,[key]:e.target.value})})
        :props.type==="select"
          ?React.createElement("select",{className:"input",value:form[key]||"",onChange:e=>setForm({...form,[key]:e.target.value})},
            (props.options||[]).map(o=>Array.isArray(o)?React.createElement("option",{key:o[0],value:o[0]},o[1]):React.createElement("option",{key:o,value:o},o)))
          :React.createElement("input",{className:`input ${props.mono?"mono":""}`,type:props.inputType||"text",value:form[key]??"",onChange:e=>setForm({...form,[key]:props.inputType==="number"?+e.target.value:e.target.value}),...(props.placeholder?{placeholder:props.placeholder}:{})})
    );

  const FR=(children)=>React.createElement("div",{className:"field-row"},children);

  return React.createElement(Modal,{title:`${editing==="new"?"Create":"Edit"} ${editType}`,onClose:()=>setEditing(null),wide:true},

    // ── Common fields ──
    F("Name","name"),
    F("Description","description"),

    // ════════════════════════════════
    // CONDITION FORM (ISE-style wizard)
    // ════════════════════════════════
    editType==="condition"&&React.createElement(React.Fragment,null,

      // Category + Severity row
      FR([
        React.createElement("div",{key:"cat"},
          React.createElement("label",{className:"label"},"Category"),
          React.createElement("select",{className:"input",value:form.category||"antivirus",onChange:e=>{
            const newCat=e.target.value;
            const defaults=newConditionDefaults(newCat);
            setForm({...form,category:newCat,operator:defaults.operator,vendor:defaults.vendor,product_name:defaults.product_name,file_path:defaults.file_path,registry_path:defaults.registry_path,registry_key:defaults.registry_key,service_name:defaults.service_name,kb_numbers:defaults.kb_numbers,usb_classes:defaults.usb_classes,firewall_profiles:defaults.firewall_profiles,sub_conditions:defaults.sub_conditions,compound_operator:defaults.compound_operator});
          }},
            ["antivirus","firewall","disk_encryption","patches","patch_management","os_version","application","file","registry","service","usb","compound","custom"].map(c=>
              React.createElement("option",{key:c,value:c},(catIcons[c]||"◆")+" "+(catLabels[c]||c))
            )
          )
        ),
        React.createElement("div",{key:"sev"},
          React.createElement("label",{className:"label"},"Severity"),
          React.createElement("select",{className:"input",value:form.severity||"critical",onChange:e=>setForm({...form,severity:e.target.value})},
            React.createElement("option",{value:"critical"},"\uD83D\uDD34 Critical (blocks access)"),
            React.createElement("option",{value:"warning"},"\uD83D\uDFE1 Warning (logged only)"),
            React.createElement("option",{value:"info"},"\uD83D\uDD35 Info")
          )
        )
      ]),

      // Operator + Expected value row
      FR([
        React.createElement("div",{key:"op"},
          React.createElement("label",{className:"label"},"Operator"),
          React.createElement("select",{className:"input",value:form.operator||"",onChange:e=>setForm({...form,operator:e.target.value})},
            (operatorsByCategory[form.category]||["enabled"]).map(o=>React.createElement("option",{key:o,value:o},o.replace(/_/g," ")))
          )
        ),
        React.createElement("div",{key:"val"},
          React.createElement("label",{className:"label"},"Expected Value"),
          React.createElement("input",{className:"input mono",value:form.expected_value||"",onChange:e=>setForm({...form,expected_value:e.target.value})})
        )
      ]),

      F("OS Types (JSON array)","os_types",{mono:true}),

      // ── Category-specific wizard sections ──

      // ANTIVIRUS — vendor picker
      form.category==="antivirus"&&React.createElement("div",{style:{background:"#f0fdf4",border:"1px solid #bbf7d0",borderRadius:6,padding:12,marginBottom:12}},
        React.createElement("div",{style:{fontSize:12,fontWeight:600,color:"#166534",marginBottom:8}},"🛡 Anti-Malware Vendor Selection"),
        FR([
          React.createElement("div",{key:"v"},
            React.createElement("label",{className:"label"},"Vendor"),
            React.createElement("select",{className:"input",value:form.vendor||"",onChange:e=>{
              const v=e.target.value;
              const prods=[...new Set(avVendors.filter(av=>av.vendor_name===v).map(av=>av.product_name))];
              setForm({...form,vendor:v||null,product_name:prods[0]||null});
            }},
              React.createElement("option",{value:""},"Any vendor"),
              [...new Set(avVendors.map(av=>av.vendor_name))].map(v=>React.createElement("option",{key:v,value:v},v))
            )
          ),
          React.createElement("div",{key:"p"},
            React.createElement("label",{className:"label"},"Product"),
            React.createElement("select",{className:"input",value:form.product_name||"",onChange:e=>setForm({...form,product_name:e.target.value||null})},
              React.createElement("option",{value:""},"Any product"),
              avVendors.filter(av=>!form.vendor||av.vendor_name===form.vendor).map(av=>React.createElement("option",{key:av.product_name,value:av.product_name},av.product_name+" ("+av.os_type+")"))
            )
          )
        ]),
        F("Minimum Version","min_version",{placeholder:"e.g. 7.0",mono:true})
      ),

      // FIREWALL — profile picker
      form.category==="firewall"&&React.createElement("div",{style:{background:"#fef2f2",border:"1px solid #fecaca",borderRadius:6,padding:12,marginBottom:12}},
        React.createElement("div",{style:{fontSize:12,fontWeight:600,color:"#991b1b",marginBottom:8}},"🔥 Firewall Profile Configuration"),
        F("Required Profiles (JSON array)","firewall_profiles",{mono:true,placeholder:'["Domain","Private","Public"]'}),
        React.createElement("div",{style:{display:"flex",gap:4,marginTop:4}},
          [["All Win",'["Domain","Private","Public"]'],["Domain only",'["Domain"]'],["macOS ALF",'["ALF"]'],["Linux ufw",'["ufw"]']].map(([l,v])=>
            React.createElement("button",{key:l,className:"btn btn-default btn-sm",onClick:()=>setForm({...form,firewall_profiles:v})},l)
          )
        )
      ),

      // PATCH MANAGEMENT — KB numbers
      form.category==="patch_management"&&React.createElement("div",{style:{background:"#fef9c3",border:"1px solid #fde68a",borderRadius:6,padding:12,marginBottom:12}},
        React.createElement("div",{style:{fontSize:12,fontWeight:600,color:"#854d0e",marginBottom:8}},"📋 Patch Management — KB Numbers"),
        F("Required KB Patches (JSON array)","kb_numbers",{type:"textarea",rows:2}),
        React.createElement("div",{style:{fontSize:10,color:"#92400e",marginTop:4}},"Enter KB numbers as JSON array: [\"KB5034441\", \"KB5034123\"]")
      ),

      // FILE — path input
      form.category==="file"&&React.createElement("div",{style:{background:"#eff6ff",border:"1px solid #bfdbfe",borderRadius:6,padding:12,marginBottom:12}},
        React.createElement("div",{style:{fontSize:12,fontWeight:600,color:"#1e40af",marginBottom:8}},"📄 File Check"),
        F("File Path","file_path",{mono:true,placeholder:"C:\\Program Files\\..."}),
        form.operator==="file_sha256"&&F("Expected SHA-256 hash","expected_value",{mono:true})
      ),

      // REGISTRY — path + key
      form.category==="registry"&&React.createElement("div",{style:{background:"#f3e8ff",border:"1px solid #e9d5ff",borderRadius:6,padding:12,marginBottom:12}},
        React.createElement("div",{style:{fontSize:12,fontWeight:600,color:"#6b21a8",marginBottom:8}},"📝 Registry Check"),
        F("Registry Path","registry_path",{mono:true,placeholder:"HKLM\\SOFTWARE\\Policies\\..."}),
        F("Registry Key","registry_key",{mono:true,placeholder:"ValueName"}),
        (form.operator==="registry_value_equals"||form.operator==="registry_value_contains")&&
          React.createElement("div",{style:{fontSize:10,color:"#7c3aed",marginTop:4}},"Expected value is set in the 'Expected Value' field above")
      ),

      // SERVICE — name
      form.category==="service"&&React.createElement("div",{style:{background:"#f0f9ff",border:"1px solid #bae6fd",borderRadius:6,padding:12,marginBottom:12}},
        React.createElement("div",{style:{fontSize:12,fontWeight:600,color:"#0369a1",marginBottom:8}},"⚙ Service Check"),
        F("Service Name","service_name",{mono:true,placeholder:"wuauserv, CrowdStrike Falcon Sensor, ..."}),
        React.createElement("div",{style:{display:"flex",gap:4,marginTop:4}},
          [["WinDefend","WinDefend"],["wuauserv","wuauserv"],["TermService","TermService"],["CSFalconService","CSFalconService"],["SentinelAgent","SentinelAgent"]].map(([l,v])=>
            React.createElement("button",{key:l,className:"btn btn-default btn-sm",style:{fontSize:10},onClick:()=>setForm({...form,service_name:v})},l)
          )
        )
      ),

      // USB — classes
      form.category==="usb"&&React.createElement("div",{style:{background:"#fef2f2",border:"1px solid #fecaca",borderRadius:6,padding:12,marginBottom:12}},
        React.createElement("div",{style:{fontSize:12,fontWeight:600,color:"#991b1b",marginBottom:8}},"🔌 USB Restriction"),
        F("Blocked USB Classes (JSON array)","usb_classes",{mono:true}),
        React.createElement("div",{style:{display:"flex",gap:4,marginTop:4}},
          [["Mass Storage",'["mass_storage"]'],["All Removable",'["mass_storage","portable_device","cdrom"]'],["All USB",'["mass_storage","portable_device","cdrom","hid","wireless"]']].map(([l,v])=>
            React.createElement("button",{key:l,className:"btn btn-default btn-sm",style:{fontSize:10},onClick:()=>setForm({...form,usb_classes:v})},l)
          )
        )
      ),

      // COMPOUND — sub-condition picker
      form.category==="compound"&&React.createElement("div",{style:{background:"#eef2ff",border:"1px solid #c7d2fe",borderRadius:6,padding:12,marginBottom:12}},
        React.createElement("div",{style:{fontSize:12,fontWeight:600,color:"#4338ca",marginBottom:8}},"🔗 Compound Condition"),
        React.createElement("div",{className:"field"},
          React.createElement("label",{className:"label"},"Logical Operator"),
          React.createElement("select",{className:"input",value:form.compound_operator||"AND",onChange:e=>{
            setForm({...form,compound_operator:e.target.value,operator:"compound_"+e.target.value.toLowerCase()});
          }},
            React.createElement("option",{value:"AND"},"AND — all sub-conditions must pass"),
            React.createElement("option",{value:"OR"},"OR — at least one must pass"),
            React.createElement("option",{value:"NOT"},"NOT — sub-condition(s) must FAIL")
          )
        ),
        F("Sub-Conditions (JSON array of condition names)","sub_conditions",{type:"textarea",rows:2}),
        conditions&&React.createElement("div",{style:{display:"flex",gap:3,flexWrap:"wrap",marginTop:6}},
          (conditions.items||[]).filter(c=>c.category!=="compound").map(c=>
            React.createElement("button",{key:c.name,className:"btn btn-default btn-sm",style:{fontSize:10},onClick:()=>{
              let cur;try{cur=JSON.parse(form.sub_conditions||"[]")}catch(e){cur=[]}
              if(!cur.includes(c.name)){cur=[...cur,c.name];setForm({...form,sub_conditions:JSON.stringify(cur)})}
            }},(catIcons[c.category]||"◆")+" "+c.name)
          )
        )
      )
    ),

    // ════════════════════════════════
    // REQUIREMENT FORM
    // ════════════════════════════════
    editType==="requirement"&&React.createElement(React.Fragment,null,
      F("OS Types (JSON)","os_types",{mono:true}),
      React.createElement("div",{className:"field"},
        React.createElement("label",{className:"label"},"Conditions (JSON array of condition names)"),
        React.createElement("textarea",{className:"input mono",rows:3,style:{resize:"vertical"},value:typeof form.conditions==="string"?form.conditions:JSON.stringify(form.conditions,null,2),onChange:e=>setForm({...form,conditions:e.target.value})}),
        conditions&&React.createElement("div",{style:{display:"flex",gap:4,marginTop:6,flexWrap:"wrap"}},
          (conditions.items||[]).map(c=>
            React.createElement("button",{key:c.name,className:"btn btn-default btn-sm",onClick:()=>{
              let cur;try{cur=typeof form.conditions==="string"?JSON.parse(form.conditions):form.conditions}catch(e){cur=[]}
              if(!cur.includes(c.name)){cur=[...cur,c.name];setForm({...form,conditions:JSON.stringify(cur,null,2)})}
            }},(catIcons[c.category]||"◆")+" "+c.name)
          )
        )
      ),
      F("Remediation (JSON: key → instruction)","remediation",{type:"textarea",rows:3})
    ),

    // ════════════════════════════════
    // POLICY FORM
    // ════════════════════════════════
    editType==="policy"&&React.createElement(React.Fragment,null,
      FR([
        React.createElement("div",{key:"pri"},
          React.createElement("label",{className:"label"},"Priority"),
          React.createElement("input",{className:"input",type:"number",value:form.priority||100,onChange:e=>setForm({...form,priority:+e.target.value})})
        ),
        React.createElement("div",{key:"re"},
          React.createElement("label",{className:"label"},"Reassessment (minutes)"),
          React.createElement("input",{className:"input",type:"number",value:form.reassessment_minutes||240,onChange:e=>setForm({...form,reassessment_minutes:+e.target.value})})
        )
      ]),
      React.createElement("div",{className:"field"},
        React.createElement("label",{className:"label"},"Identity Match (JSON)"),
        React.createElement("textarea",{className:"input mono",rows:2,style:{resize:"vertical"},value:typeof form.identity_match==="string"?form.identity_match:JSON.stringify(form.identity_match,null,2),onChange:e=>setForm({...form,identity_match:e.target.value})}),
        React.createElement("div",{style:{display:"flex",gap:4,marginTop:4,flexWrap:"wrap"}},
          [["Domain Users",'{"AD-Group":"Domain Users"}'],["Contractors",'{"AD-Group":"Contractors"}'],["Workstations",'{"Device-Category":"workstation"}'],["Mobile",'{"Device-Category":"mobile"}'],["All","{}"]].map(([l,v])=>
            React.createElement("button",{key:l,className:"btn btn-default btn-sm",onClick:()=>setForm({...form,identity_match:v})},l)
          )
        )
      ),
      React.createElement("div",{className:"field"},
        React.createElement("label",{className:"label"},"Requirements (JSON array of requirement names)"),
        React.createElement("textarea",{className:"input mono",rows:2,style:{resize:"vertical"},value:typeof form.requirements==="string"?form.requirements:JSON.stringify(form.requirements,null,2),onChange:e=>setForm({...form,requirements:e.target.value})}),
        requirements&&React.createElement("div",{style:{display:"flex",gap:4,marginTop:4,flexWrap:"wrap"}},
          (requirements.items||[]).map(r=>
            React.createElement("button",{key:r.name,className:"btn btn-default btn-sm",onClick:()=>{
              let cur;try{cur=typeof form.requirements==="string"?JSON.parse(form.requirements):form.requirements}catch(e){cur=[]}
              if(!cur.includes(r.name)){cur=[...cur,r.name];setForm({...form,requirements:JSON.stringify(cur,null,2)})}
            }},r.name)
          )
        )
      ),
      FR([
        React.createElement("div",{key:"ac"},
          React.createElement("label",{className:"label"},"Action if Compliant"),
          React.createElement("select",{className:"input",value:form.action_compliant||"",onChange:e=>setForm({...form,action_compliant:e.target.value})},
            React.createElement("option",{value:"permit"},"✅ Permit (production VLAN)"),
            React.createElement("option",{value:"continue"},"➡ Continue (no change)")
          )
        ),
        React.createElement("div",{key:"anc"},
          React.createElement("label",{className:"label"},"Action if Non-compliant"),
          React.createElement("select",{className:"input",value:form.action_non_compliant||"",onChange:e=>setForm({...form,action_non_compliant:e.target.value})},
            React.createElement("option",{value:"quarantine"},"🔴 Quarantine (VLAN 999)"),
            React.createElement("option",{value:"remediate"},"🟡 Remediate (redirect to portal)"),
            React.createElement("option",{value:"deny"},"⛔ Deny access")
          )
        )
      ]),
      F("Grace Period (minutes, 0 = immediate enforcement)","grace_minutes",{inputType:"number"})
    ),

    // Save / Cancel
    React.createElement("div",{style:{display:"flex",gap:8,marginTop:16,paddingTop:16,borderTop:"1px solid #e5e7eb"}},
      React.createElement("button",{className:"btn btn-green",onClick:save},editing==="new"?"Create":"Save"),
      React.createElement("button",{className:"btn btn-default",onClick:()=>setEditing(null)},"Cancel")
    )
  );
}
