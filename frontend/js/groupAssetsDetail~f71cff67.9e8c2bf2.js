(window.webpackJsonp=window.webpackJsonp||[]).push([["groupAssetsDetail~f71cff67"],{"0a069":function(t,e,n){"use strict";var a=n("6489");n.n(a).a},"0e9d":function(t,e,n){"use strict";n("99af"),n("4160"),n("caad"),n("a15b"),n("d81d"),n("fb6a"),n("b0c0"),n("cca6"),n("b64b"),n("d3b7"),n("a79d"),n("ac1f"),n("1276"),n("159b");var a=n("5530"),r=n("90d8");e.a={data:function(){return{tableConfig:[],currentIndex:0,currentKey:+new Date,targetName:"",currentComponent:{columns:[],total:0,dataList:[],searchGroup:[],params:{page:1,size:10}},downloadMethod:{site:r.u,domain:r.p,url:r.v,ip:r.t,asset_domain:r.q,asset_ip:r.r,asset_site:r.s},isLoading:!1,imgVisible:!1,imgSrc:"",originalQuery:{}}},watch:{$route:function(t,e){this.checkParams()}},computed:{page_num:function(){return this.currentComponent.total%this.currentComponent.params.size>0?parseInt(this.currentComponent.total/this.currentComponent.params.size)+1:this.currentComponent.total/this.currentComponent.params.size}},mounted:function(){if(this.$route.query.targetName){var t=this.$route.query.targetName;this.targetName=(t.length>30?this.$route.query.targetName.slice(0,30)+"...":this.$route.query.targetName)+"相关资产"}},methods:{initTabs:function(t){this.currentKey=(new Date).getTime(),this.currentIndex=t,this.resetParams(t),this.initData(t),this.originalQuery=Object(a.a)({},this.$route.query)},operateCallback:function(t){"reset"===t&&this.initData(this.currentIndex)},changeTabs:function(t){var e=arguments.length>1&&void 0!==arguments[1]&&arguments[1];if(this.currentIndex=t,this.currentKey=(new Date).getTime(),!e)return this.$route.query.page=1,this.$route.query.size=10,void this.$router.push({query:Object(a.a)(Object(a.a)({},this.$route.query),{},{tabIndex:this.currentIndex,ts:(new Date).getTime()})});this.initParams(t),this.initData(t)},resetParams:function(t){this.currentComponent={columns:this.tableConfig[t].columns,total:this.tableConfig[t].total,tableList:this.tableConfig[t].tableList,searchGroup:this.tableConfig[t].searchGroup,params:{page:1,size:10}},this.tableConfig[t].params={page:1,size:10}},clearFilter:function(){this.currentComponent.params={page:1,size:10},this.tableConfig[this.currentIndex].params={page:1,size:10},this.initData(this.currentIndex)},exportData:function(t){var e=Object(a.a)({},this.currentComponent.params);e.size=1e4,this.$route.query.task_id&&(e.task_id=this.$route.query.task_id),this.$route.query.scope_id&&(e.scope_id=this.$route.query.scope_id),["site","domain","url","ip","asset_site","asset_domain","asset_ip"].includes(t)&&this.downloadMethod[t](Object(a.a)({},e)).then((function(t){var e=t.headers["content-disposition"].split("filename=")[1];if("download"in document.createElement("a")){var n=document.createElement("a");n.setAttribute("href","data:text/plain;charset=utf-8,"+encodeURIComponent(t.data)),n.setAttribute("download",e),n.style.display="none",document.body.appendChild(n),n.click(),document.body.removeChild(n)}else navigator.msSaveBlob(t,e)}))},initParams:function(t){this.currentComponent={columns:this.tableConfig[t].columns,total:this.tableConfig[t].total,tableList:this.tableConfig[t].tableList,searchGroup:this.tableConfig[t].searchGroup,params:Object(a.a)({},Object.assign(this.tableConfig[t].params,this.currentComponent.params))}},changeContent:function(t,e){this.tableConfig[this.currentIndex].params[t]=e+"",this.currentComponent.params[t]=e,this.$route.query[t]=e},searchContent:function(t,e){for(var n in this.tableConfig[this.currentIndex].params.page=1,this.currentComponent.params.page=1,this.tableConfig[this.currentIndex].params.size=10,this.currentComponent.params.size=10,this.tableConfig[this.currentIndex].params[t]=e+"",this.$route.query[t]=e,this.$route.query)this.$route.query[n]||delete this.$route.query[n];this.$route.query.page=1,this.$route.query.size=10,this.$router.push({query:Object(a.a)(Object(a.a)({},this.$route.query),{},{ts:(new Date).getTime()})})},checkParams:function(){for(var t in this.currentComponent.params={page:1,size:10},9===this.currentIndex&&(this.currentComponent.params.order=""),this.tableConfig[this.currentIndex].params={page:1,size:10},this.$route.query)["page","size"].includes(t)&&(this.$route.query[t]=parseInt(this.$route.query[t])),this.currentComponent.params[t]=this.$route.query[t],Object.assign(this.tableConfig[this.currentIndex].params,this.currentComponent.params);this.changeTabs(parseInt(this.$route.query.tabIndex)||0,!0)},initData:function(t){var e=this,n={};Object.keys(this.tableConfig[t].params).forEach((function(a){void 0!==e.tableConfig[t].params[a]&&e.tableConfig[t].params[a]&&(n[a]=e.tableConfig[t].params[a])})),n.update_date&&delete n.update_date,this.$route.query.task_id&&(n.task_id=this.$route.query.task_id),this.$route.query.scope_id&&(n.scope_id=this.$route.query.scope_id),this.isLoading=!0,this.tableConfig[t].api(Object(a.a)({},n)).then((function(t){t.items.forEach((function(t,n){t.key=t._id,t.index=(e.currentComponent.params.page-1)*e.currentComponent.params.size+n+1,t.currentTab=e.tabList[e.currentIndex],e.transformItem(t),Object.keys(t).forEach((function(e){t[e]||(t[e]="-")}))})),e.currentComponent.tableList=t.items,e.currentComponent.total=t.total,document.querySelector("#contentWrap").scrollTop=0})).finally((function(){setTimeout((function(){e.isLoading=!1}),200)}))},transformItem:function(t){switch(this.currentIndex){case 0:this.transformSite(t);break;case 2:this.transformIp(t);break;case 3:this.transformSSL(t);break;case 4:this.transformServe(t);break;case 5:this.transformFile(t)}},transformIp:function(t){t.os_name=void 0===t.os_info||"{}"===JSON.stringify(t.os_info)?"-":t.os_info.name,t.port=t.port_info&&t.port_info.length?t.port_info.map((function(t){return t.port_id})).join(", "):"-",t.geo_asn=void 0===t.geo_asn||"{}"===JSON.stringify(t.geo_asn)?"-":t.geo_asn.organization,t.geo_city="{}"===(void 0===t.geo_city&&JSON.stringify(t.geo_city))?"-":!(void 0===t.geo_city||void 0===t.geo_city.city)&&t.geo_city.country_name+" / "+t.geo_city.region_name},transformSSL:function(t){t.ipInfo="".concat(t.ip,":").concat(t.port),t.detailInfo={subjectName:t.cert&&t.cert.subject_dn?t.cert.subject_dn:"-",serialName:t.cert&&t.cert.serial_number?t.cert.serial_number:"-",issuerName:t.cert&&t.cert.issuer&&t.cert.issuer.common_name?t.cert.issuer.common_name:"-",rangeTime:t.cert&&t.cert.validity?"".concat(t.cert.validity.start," 至 ").concat(t.cert.validity.end):"-",useName:t.cert&&t.cert.extensions&&t.cert.extensions.subjectAltName?t.cert.extensions.subjectAltName:"-",endTime:t.cert&&t.cert.validity&&t.cert.validity.end?t.cert.validity.end:"-",sha256:t.cert&&t.cert.fingerprint&&t.cert.fingerprint.sha256?t.cert.fingerprint.sha256:"-",sha1:t.cert&&t.cert.fingerprint&&t.cert.fingerprint.sha1?t.cert.fingerprint.sha1:"-",md5:t.cert&&t.cert.fingerprint&&t.cert.fingerprint.md5?t.cert.fingerprint.md5:"-"}},transformSite:function(t){t.hash=t.favicon&&t.favicon.hash},transformServe:function(t){t.protsArr=[],t.productArr=[],t.service_info&&t.service_info.length&&t.service_info.forEach((function(e){t.protsArr.push(e.ip+":"+e.port_id),t.productArr.push({name:e.product?e.product:"-",version:e.version})}))},transformFile:function(t){t.content_length=t.content_length?t.content_length:"0"},checkProductRepeat:function(t,e,n){if(!t)return!0;var a=!1;return n.forEach((function(e){e.name===t&&(a=!0)})),a},turnPageCallback:function(t,e){this.tableConfig[this.currentIndex].params.page=this.tableConfig[this.currentIndex].params.size===e?t:1,this.tableConfig[this.currentIndex].params.size=e,this.currentComponent.params.page=this.tableConfig[this.currentIndex].params.size===e?t:1,this.currentComponent.params.size=e,this.$route.query.size&&this.$route.query.size!==e?this.$route.query.page=1:this.$route.query.page=this.currentComponent.params.page,this.$route.query.size=this.currentComponent.params.size,this.$router.push({query:Object(a.a)(Object(a.a)({},this.$route.query),{},{ts:(new Date).getTime()})})}}}},"0fd1":function(t,e,n){"use strict";n.r(e);var a={props:{text:{type:[Array,Object]},record:{type:Object}}},r=n("2877"),i=Object(r.a)(a,(function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{},[t.text.length?n("div",t._l(t.text,(function(e,a){return n("p",{key:a},[t._v(" "+t._s(e.name))])})),0):n("div",[t._v("-")])])}),[],!1,null,"3cbdd361",null);e.default=i.exports},"1b26":function(t,e,n){"use strict";n.d(e,"e",(function(){return r})),n.d(e,"g",(function(){return i})),n.d(e,"a",(function(){return s})),n.d(e,"c",(function(){return o})),n.d(e,"b",(function(){return c})),n.d(e,"d",(function(){return u})),n.d(e,"f",(function(){return l}));var a=n("e20a"),r=function(t){return a.a.get("/policy/",{params:t})},i=function(t){return a.a.post("/task/policy/",t)},s=function(t){return a.a.post("/policy/add/",t)},o=function(t){return a.a.post("/policy/edit/",t)},c=function(t){return a.a.post("/policy/delete/",t)},u=function(){return a.a.get("/poc/?plugin_type=poc&size=10000")},l=function(){return a.a.get("/poc/?plugin_type=brute&size=10000")}},"1b78":function(t,e,n){"use strict";n.r(e),n("a9e3");var a={props:{text:{type:Number},record:{type:Object}},methods:{watchTask:function(t){this.$router.push({name:"taskList",query:{searchId:t}})}}},r=n("2877"),i=Object(r.a)(a,(function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",[n("a",{staticStyle:{color:"#00c5dc"},attrs:{href:"javascript:void(0)"},on:{click:function(e){return t.watchTask(t.record.task_id)}}},[t._v(t._s(t.text))])])}),[],!1,null,"317077e8",null);e.default=i.exports},"1bdf":function(t,e,n){"use strict";n.r(e);var a=n("2877"),r=Object(a.a)({},(function(t,e){return(0,e._c)("a",{staticClass:"ftColor",attrs:{href:"/groupAssetsManagement/groupAssetsDetail?scope_id="+e.props.record._id+"&targetName="+e.props.record.name,title:e.props.text}},[e._v(e._s(e.props.text.length>26?e.props.text.slice(0,26)+"...":e.props.text))])}),[],!0,null,null,null);e.default=r.exports},2692:function(t,e,n){"use strict";var a=n("2736");n.n(a).a},2736:function(t,e,n){},2805:function(t,e,n){},"2e61":function(t,e,n){"use strict";n.r(e);var a=n("90d8"),r={props:{text:{type:String},record:{type:Object}},data:function(){return{tagContent:""}},methods:{addTagOption:function(){var t=this;Object(a.f)({_id:this.record._id,tag:this.tagContent}).then((function(e){200===e.code&&(t.$message.success("添加成功"),t.tagContent="",t.resetTable())}))},deleteItem:function(t){var e=this;Object(a.l)({_id:this.record._id,tag:t}).then((function(t){200===t.code&&(e.tagContent="",e.$message.success("删除成功"),e.resetTable())}))},resetTable:function(){this.$emit("operateCallback","reset")}}},i=(n("6006"),n("2877")),s=Object(i.a)(r,(function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"site-header"},[n("a",{staticStyle:{color:"#00c5dc"},attrs:{href:t.text,target:"_blank"}},[t.record.favicon&&t.record.favicon.data&&t.record.favicon.url.includes("svg")?n("img",{staticClass:"site-img",attrs:{src:"data:image/svg+xml;base64,"+t.record.favicon.data,alt:""}}):t.record.favicon&&t.record.favicon.data?n("img",{staticClass:"site-img",attrs:{src:"data:image/png;base64,"+t.record.favicon.data,alt:""}}):t._e(),t._v(" "+t._s(t.text))]),t.record.favicon&&t.record.favicon.hash?n("p",{staticClass:"site-word"},[t._v(" Favicon Hash: "+t._s(t.record.favicon.hash)+" ")]):t._e(),n("div",{staticClass:"mt5"},[t._l(t.record.tag,(function(e,a){return n("a-tag",{key:a,attrs:{closable:""},on:{close:function(n){return t.deleteItem(e)}}},[t._v(t._s(e))])})),n("a-popconfirm",{attrs:{placement:"top"},on:{confirm:t.addTagOption}},[n("template",{staticClass:"no-padding",slot:"title"},[n("a-input",{attrs:{placeholder:"请输入标签名称"},model:{value:t.tagContent,callback:function(e){t.tagContent=e},expression:"tagContent"}})],1),n("i",{attrs:{slot:"icon"},slot:"icon"}),n("span",{staticClass:"add-tag"},[t._v("添加标签")])],2)],2)])}),[],!1,null,null,null);e.default=s.exports},3633:function(t,e,n){"use strict";var a=n("ae06");n.n(a).a},"4a84":function(t,e,n){},"4ec0":function(t,e,n){"use strict";n.r(e);var a={props:{text:{type:String},record:{type:Object}},methods:{deleteTaskOption:function(t){this.$emit("operateCallback","deleteAssetsGourp",t)},addMonitorTask:function(t){this.$emit("operateCallback","addMonitor",t)},addScopeAssets:function(t){this.$emit("operateCallback","addScopeAssets",t)},addMonitorTaskSite:function(t){this.$emit("operateCallback","addMonitorTaskSite",t)}}},r=(n("3633"),n("2877")),i=Object(r.a)(a,(function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("span",{},[n("a-button",{staticClass:"operate-link",on:{click:function(e){return t.addScopeAssets(t.record)}}},[t._v("添加资产分组范围")]),n("a-button",{staticClass:"operate-link",on:{click:function(e){return t.addMonitorTask(t.record)}}},[t._v("添加监控任务")]),n("p"),n("a-button",{staticClass:"operate-link",on:{click:function(e){return t.addMonitorTaskSite(t.record)}}},[t._v("添加站点监控任务")]),n("a-popconfirm",{attrs:{"ok-text":"确认","cancel-text":"取消"},on:{confirm:function(e){return t.deleteTaskOption(t.record._id)}}},[n("template",{slot:"title"},[n("p",[t._v("删除后不可恢复，确认删除吗？")])]),n("a-button",{staticClass:"operate-link"},[t._v("删除")])],2)],1)}),[],!1,null,"35418253",null);e.default=i.exports},"56d4":function(t,e,n){"use strict";n.r(e),n("a15b"),n("d81d"),n("b0c0"),n("d3b7"),n("a79d");var a=n("5530"),r=n("bc6a"),i=n("0e9d"),s=n("1b26"),o={props:["type"],data:function(){return{form:this.$form.createForm(this),submitFLag:!1,policyList:[]}},methods:{subForm:function(){var t=this;this.form.validateFields((function(e,n){e||t.$emit("addAssetsSubmit",n)}))},handleCancel:function(){this.$emit("closeModal")}},mounted:function(){var t=this;Object(s.e)({size:1e3}).then((function(e){t.policyList=e.items.map((function(t){return{id:t._id,name:t.name}}))}))}},c=(n("7bcb"),n("2877")),u=Object(c.a)(o,(function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("a-modal",{attrs:{title:t.type?"添加子域名":"添加站点",visible:!0},on:{ok:t.subForm,cancel:t.handleCancel}},[n("a-form",{attrs:{form:t.form,"label-col":{span:5},"wrapper-col":{span:18}}},[n("a-form-item",{attrs:{label:t.type?"子域名":"站点"}},[t.type?n("a-textarea",{directives:[{name:"decorator",rawName:"v-decorator",value:["value",{rules:[{required:!0,message:"请输入域名!"}]}],expression:"[\n          'value',\n          {\n            rules: [{ required: true, message:'请输入域名!' }]\n          },\n        ]"}],staticStyle:{height:"100px"},attrs:{placeholder:"请输入域名，多个域名请用空格或者换行隔开。"}}):n("a-input",{directives:[{name:"decorator",rawName:"v-decorator",value:["value",{rules:[{required:!0,message:"请输入站点!"}]}],expression:"[\n          'value',\n          {\n            rules: [{ required: true, message: '请输入站点!' }]\n          },\n        ]"}],attrs:{placeholder:"请输入站点"}}),t.type?n("div",{staticClass:"tip"},[t._v("会对子域名自动下发侦察任务, 获取子域名关联的ip、站点等信息。示例: live.freebuf.com")]):n("div",{staticClass:"tip"},[t._v("会对站点进行探测, 获取标题、headers, finger等信息。示例: https://www.freebuf.com/")])],1),t.type?n("a-form-item",{attrs:{label:"策略"}},[n("a-select",{directives:[{name:"decorator",rawName:"v-decorator",value:["policy_id"],expression:"['policy_id']"}],attrs:{allowClear:"","aria-label":"policy_id",placeholder:"请选择策略"}},t._l(t.policyList,(function(e,a){return n("a-select-option",{key:a,attrs:{value:e.id}},[t._v(t._s(e.name))])})),1)],1):t._e()],1)],1)}),[],!1,null,"6872e0e2",null).exports,l=n("90d8"),d=n("d550"),p=n("8b4c"),m={mixins:[i.a],components:{addAssets:u,policyTask:p.a,batchDelete:d.a},data:function(){return{tabList:["站点","域名","IP"],exportKeysArr:["asset_site","asset_domain","asset_ip"],selectedRowKeys:[],isAddAssets:!1,policyTaskModal:!1,resultId:"",resultTotal:0,isSaveResult:!1}},mounted:function(){this.tableConfig=r.b,this.initTabs(0),this.initParams(0)},methods:{transformItem:function(t){switch(this.currentIndex){case 0:this.transformSiteData(t);break;case 2:this.transformIpData(t)}},transformIpData:function(t){t.port=t.port_info&&t.port_info.length?t.port_info.map((function(t){return t.port_id})).join(", "):"",t._osName=t.os_info&&t.os_info.name?t.os_info.name:"",t.geo_asn=void 0===t.geo_asn||"{}"===JSON.stringify(t.geo_asn)?"-":t.geo_asn.organization,t.geo_city="{}"===(void 0===t.geo_city&&JSON.stringify(t.geo_city))?"-":!(void 0===t.geo_city||void 0===t.geo_city.city)&&t.geo_city.country_name+" / "+t.geo_city.region_name},transformSiteData:function(t){t._faviconHash=t.favicon&&t.favicon.hash?t.favicon.hash:"",t._fingerName=t.finger?t.finger:[]},selectRowCallback:function(t){this.selectedRowKeys=t},checkDate:function(t,e){e.length||(this.currentComponent.params.update_date__dlt="",this.currentComponent.params.update_date__dgt="",this.tableConfig[this.currentIndex].params.update_date__dlt="",this.tableConfig[this.currentIndex].params.update_date__dgt="",this.tableConfig[this.currentIndex].params.update_date=[],this.initData(this.currentIndex))},getFilterTime:function(t,e){this.currentComponent.params.update_date__dgt=e[0],this.currentComponent.params.update_date__dlt=e[1],this.tableConfig[this.currentIndex].params.update_date__dgt=e[0],this.tableConfig[this.currentIndex].params.update_date__dlt=e[1],this.tableConfig[this.currentIndex].params.update_date=e,this.initData(this.currentIndex)},initParams:function(t){this.currentComponent={columns:this.tableConfig[t].columns,total:this.tableConfig[t].total,tableList:this.tableConfig[t].tableList,searchGroup:this.tableConfig[t].searchGroup,params:Object(a.a)({},this.tableConfig[t].params),deleteAPI:this.tableConfig[t].deleteAPI,addAPI:this.tableConfig[t].addAPI}},deleteSelectData:function(){var t=this;this.currentComponent.deleteAPI({_id:this.selectedRowKeys}).then((function(e){200===e.code&&(t.$message.success("删除成功"),t.initData(t.currentIndex),t.selectedRowKeys=[])}))},addDetailAssets:function(t){var e=this,n={scope_id:this.$route.query.scope_id};0===this.currentIndex?n.site=t.value:(n.domain=t.value,n.policy_id=t.policy_id),this.currentComponent.addAPI(Object(a.a)({},n)).then((function(t){200===t.code&&(e.isAddAssets=!1,e.$message.success("添加成功"),e.changeTabs(e.currentIndex))}))},saveResult:function(){var t=this,e=Object(a.a)({},this.currentComponent.params);e.scope_id=this.$route.query.scope_id,delete e.ts,delete e.size,delete e.page,delete e.update_date,delete e.update_date__dgt,delete e.update_date__dlt,this.isSaveResult=!0,Object(l.A)(Object(a.a)({},e)).then((function(e){200===e.code&&(t.policyTaskModal=!0,t.resultId=e.data.result_set_id,t.resultTotal=e.data.result_total)})).finally((function(){t.isSaveResult=!1}))}}},f=(n("2692"),Object(c.a)(m,(function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"table-wrap"},[t.targetName?n("div",{staticClass:"top-info"},[n("h2",[t._v(t._s(t.targetName))])]):t._e(),n("a-tabs",{attrs:{type:"card",tabBarGutter:8},on:{change:t.changeTabs},model:{value:t.currentIndex,callback:function(e){t.currentIndex=e},expression:"currentIndex"}},t._l(t.tabList,(function(t,e){return n("a-tab-pane",{key:e,attrs:{tab:t}})})),1),n("div",{staticClass:"search-wrap"},[2===t.currentIndex?n("span",{staticClass:"item"},[n("span",{staticClass:"label"},[t._v("IP类别：")]),n("a-select",{staticStyle:{width:"260px"},attrs:{allowClear:"",placeholder:"请选择IP类型进行搜索"},on:{change:function(e){return t.searchContent("ip_type",t.currentComponent.params.ip_type)}},model:{value:t.currentComponent.params.ip_type,callback:function(e){t.$set(t.currentComponent.params,"ip_type",e)},expression:"currentComponent.params['ip_type']"}},[n("a-select-option",{attrs:{value:"PRIVATE"}},[t._v("内网")]),n("a-select-option",{attrs:{value:"PUBLIC"}},[t._v("公网")])],1)],1):t._e(),t._l(t.currentComponent.searchGroup,(function(e,a){return n("span",{key:a,staticClass:"item"},[n("span",{staticClass:"label"},[t._v(t._s(e.label+"："))]),"input"===e.filterType?n("a-input-search",{key:t.currentKey+a,staticStyle:{width:"260px"},attrs:{allowClear:"",placeholder:"请输入"+e.label+"进行搜索"},on:{change:function(n){return t.changeContent(e.value,t.currentComponent.params[e.value])},search:function(n){return t.searchContent(e.value,n)}},model:{value:t.currentComponent.params[e.value],callback:function(n){t.$set(t.currentComponent.params,e.value,n)},expression:"currentComponent.params[item.value]"}}):t._e(),"date"===e.filterType?n("a-range-picker",{staticStyle:{width:"400px"},attrs:{"show-time":"",valueFormat:"YYYY-MM-DD HH:mm:ss"},on:{change:function(e){return t.checkDate(a,e)},ok:function(e){return t.getFilterTime(a,e)}},model:{value:t.currentComponent.params[e.value],callback:function(n){t.$set(t.currentComponent.params,e.value,n)},expression:"currentComponent.params[item.value]"}}):t._e()],1)})),n("span",{staticClass:"item"},[n("a-button",{on:{click:t.clearFilter}},[t._v("清除")]),t.currentComponent.total&&t.exportKeysArr[t.currentIndex]?n("a-button",{staticClass:"ml16",attrs:{type:"primary"},on:{click:function(e){return t.exportData(t.exportKeysArr[t.currentIndex])}}},[t._v("导出"+t._s("IP"===t.tabList[t.currentIndex]?" IP 端口":t.tabList[t.currentIndex]))]):t._e(),0===t.currentIndex?n("a-button",{staticClass:"ml16",attrs:{type:"primary",loading:t.isSaveResult},on:{click:function(e){return t.saveResult(t.exportKeysArr[t.currentIndex])}}},[t._v("风险任务下发")]):t._e()],1)],2),n("batch-delete",{attrs:{selectedRowKeys:t.selectedRowKeys},on:{deleteCallback:t.deleteSelectData}},[n("a-button",{directives:[{name:"show",rawName:"v-show",value:[0,1].includes(t.currentIndex),expression:"[0, 1].includes(currentIndex)"}],staticClass:"add-assets",attrs:{type:"primary"},on:{click:function(e){t.isAddAssets=!0}}},[t._v(" "+t._s(t.currentIndex?"添加子域名":"添加站点")+" ")])],1),n("table-component",{attrs:{columns:t.currentComponent.columns,selectedRowKeys:t.selectedRowKeys,isLoading:t.isLoading,tableList:t.currentComponent.tableList,pagination:!1,isSelect:!0,scroll:{x:1500},total:t.currentComponent.total,params:t.currentComponent.params},on:{selectRowCallback:t.selectRowCallback,operateCallback:t.operateCallback,turnPageCallback:t.turnPageCallback}}),t.isAddAssets?n("add-assets",{attrs:{type:t.currentIndex},on:{addAssetsSubmit:t.addDetailAssets,closeModal:function(e){t.isAddAssets=!1}}}):t._e(),t.policyTaskModal?n("policy-task",{attrs:{resultId:t.resultId,resultTotal:t.resultTotal},on:{closeModal:function(e){t.policyTaskModal=!1}}}):t._e()],1)}),[],!1,null,"72eface8",null));e.default=f.exports},6006:function(t,e,n){"use strict";var a=n("4a84");n.n(a).a},6489:function(t,e,n){},6609:function(t,e,n){"use strict";n.r(e);var a={props:{text:{type:String},record:{type:Object}}},r=n("2877"),i=Object(r.a)(a,(function(){var t=this.$createElement,e=this._self._c||t;return e("div",{staticClass:"scroll-x"},[this.text?e("pre",[this._v(this._s(this.text))]):e("div",[this._v("-")])])}),[],!1,null,"2d7fad56",null);e.default=i.exports},"677a":function(t,e,n){"use strict";var a=n("e978");n.n(a).a},"7bcb":function(t,e,n){"use strict";var a=n("938d");n.n(a).a},8631:function(t,e,n){"use strict";n("c975"),n("d3b7"),n("380f");var a=n("f64c"),r=n("bc3a"),i=n.n(r),s=n("a18c"),o=i.a.create({baseURL:"/api",timeout:12e3});o.interceptors.request.use((function(t){t.headers["Content-Type"]="application/json; charset=UTF-8";var e=localStorage.getItem("token");return e&&(t.headers.token=e),t}),(function(t){return Promise.reject(t)})),o.interceptors.response.use((function(t){var e=t;return void 0!==e.code&&200!==e.code?[401,403,404].indexOf(e.code)>-1?void s.a.push({name:"login"}):(a.a.error(e.message),Promise.reject(new Error(e.message||"Error"))):e}),(function(t){return a.a.error(t.message),Promise.reject(t)})),e.a=o},"8b4c":function(t,e,n){"use strict";n("4de4"),n("caad"),n("b0c0"),n("a9e3"),n("d3b7"),n("a79d"),n("ac1f"),n("2532"),n("1276");var a=n("5530"),r=n("1b26"),i={name:"policyTask",props:{resultId:{type:String,default:""},resultTotal:{type:Number,default:0}},data:function(){return{isLoading:!1,form:this.$form.createForm(this),policyData:[],nameString:void 0,isEmpty:!1}},mounted:function(){var t=this;Object(r.e)({size:1e3}).then((function(e){200===e.code&&(t.policyData=e.items.filter((function(t){return t.name+=" (PoC : ".concat(t.policy.poc_config.length,")"),t.policy.poc_config.length})))}))},methods:{handleSubmit:function(){var t=this;this.form.validateFields((function(e,n){if(t.nameString||(t.isEmpty=!0),!e){t.isLoading=!0;var i=n.policy_id.split(","),s={name:t.nameString,task_tag:"risk_cruising",target:"",policy_id:i[0],result_set_id:t.resultId};Object(r.g)(Object(a.a)({},s)).then((function(e){200===e.code&&(t.$message.success("下发成功"),t.closeModal())})).finally((function(){t.isLoading=!1}))}}))},changeTaskName:function(t){this.nameString&&!this.nameString.includes("风险巡航任务-")||(this.nameString="风险巡航任务-".concat(t.split(",")[1]))},closeModal:function(){this.$emit("closeModal")}}},s=(n("677a"),n("2877")),o=Object(s.a)(i,(function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("a-modal",{attrs:{visible:!0,title:"添加风险巡航任务",confirmLoading:t.isLoading},on:{ok:t.handleSubmit,cancel:t.closeModal}},[n("a-form",{attrs:{form:t.form,"label-col":{span:5},"wrapper-col":{span:18}}},[n("a-form-item",{attrs:{label:"策略名称"}},[n("a-select",{directives:[{name:"decorator",rawName:"v-decorator",value:["policy_id",{rules:[{required:!0,message:"请选择策略名称!"}]}],expression:"[\n          'policy_id',\n          { rules: [{ required: true, message: '请选择策略名称!' }] },\n        ]"}],attrs:{"show-search":"",optionFilterProp:"label",allowClear:"",placeholder:"请选择策略名称"},on:{change:t.changeTaskName}},t._l(t.policyData,(function(e,a){return n("a-select-option",{key:a,attrs:{value:e._id+","+e.name,label:e.name}},[t._v(t._s(e.name))])})),1)],1),n("a-form-item",{staticClass:"required",class:t.isEmpty?"has-error":"",attrs:{label:"任务名称"}},[n("a-input",{attrs:{allowClear:"",placeholder:"请输入任务名称"},on:{change:function(e){t.isEmpty=!1}},model:{value:t.nameString,callback:function(e){t.nameString=e},expression:"nameString"}}),t.isEmpty?n("span",{staticClass:"errorTip"},[t._v("请输入策略名称!")]):t._e()],1),n("a-form-item",{attrs:{label:"目标"}},[n("span",{staticClass:"total-num"},[t._v("选择目标数 "+t._s(t.resultTotal))])])],1)],1)}),[],!1,null,"0b912255",null);e.a=o.exports},"90d8":function(t,e,n){"use strict";n.d(e,"z",(function(){return i})),n.d(e,"d",(function(){return s})),n.d(e,"c",(function(){return o})),n.d(e,"k",(function(){return c})),n.d(e,"j",(function(){return u})),n.d(e,"w",(function(){return l})),n.d(e,"x",(function(){return d})),n.d(e,"y",(function(){return p})),n.d(e,"i",(function(){return m})),n.d(e,"h",(function(){return f})),n.d(e,"g",(function(){return h})),n.d(e,"b",(function(){return _})),n.d(e,"a",(function(){return g})),n.d(e,"u",(function(){return b})),n.d(e,"p",(function(){return v})),n.d(e,"v",(function(){return y})),n.d(e,"t",(function(){return x})),n.d(e,"s",(function(){return C})),n.d(e,"q",(function(){return I})),n.d(e,"r",(function(){return k})),n.d(e,"m",(function(){return w})),n.d(e,"n",(function(){return T})),n.d(e,"o",(function(){return $})),n.d(e,"A",(function(){return S})),n.d(e,"l",(function(){return j})),n.d(e,"f",(function(){return O})),n.d(e,"e",(function(){return A}));var a=n("e20a"),r=n("8631"),i=function(t){return a.a.get("/asset_scope/",{params:t})},s=function(t){return a.a.post("/asset_scope/",t)},o=function(t){return a.a.post("/asset_scope/add/",t)},c=function(t){return a.a.get("/asset_scope/delete/",{params:t})},u=function(t){return a.a.post("/asset_scope/delete/",t)},l=function(t){return a.a.get("/asset_domain/",{params:t})},d=function(t){return a.a.get("/asset_ip/",{params:t})},p=function(t){return a.a.get("/asset_site/",{params:t})},m=function(t){return a.a.post("/asset_site/delete/",t)},f=function(t){return a.a.post("/asset_ip/delete/",t)},h=function(t){return a.a.post("/asset_domain/delete/",t)},_=function(t){return a.a.post("/asset_site/",t)},g=function(t){return a.a.post("/asset_domain/",t)},b=function(t){return r.a.get("/site/export/",{params:t})},v=function(t){return r.a.get("/domain/export/",{params:t})},y=function(t){return r.a.get("/url/export/",{params:t})},x=function(t){return r.a.get("/ip/export/",{params:t})},C=function(t){return r.a.get("/asset_site/export/",{params:t})},I=function(t){return r.a.get("/asset_domain/export/",{params:t})},k=function(t){return r.a.get("/asset_ip/export/",{params:t})},w=function(t){return r.a.post("/batch_export/asset_domain/",t)},T=function(t){return r.a.post("/batch_export/asset_ip/",t)},$=function(t){return r.a.post("/batch_export/asset_site/",t)},S=function(t){return a.a.get("/asset_site/save_result_set/",{params:t})},j=function(t){return a.a.post("/asset_site/delete_tag/",t)},O=function(t){return a.a.post("/asset_site/add_tag/",t)},A=function(t){return a.a.post("/scheduler/add/site_monitor/",t)}},9348:function(t,e,n){var a={"./arrTip.vue":"e286","./dataIndex.vue":"1b78","./finger.vue":"0fd1","./headers.vue":"6609","./name.vue":"1bdf","./operate.vue":"4ec0","./site.vue":"2e61","./tag.vue":"c09b"};function r(t){var e=i(t);return n(e)}function i(t){if(!n.o(a,t)){var e=new Error("Cannot find module '"+t+"'");throw e.code="MODULE_NOT_FOUND",e}return a[t]}r.keys=function(){return Object.keys(a)},r.resolve=i,t.exports=r,r.id="9348"},"938d":function(t,e,n){},ae06:function(t,e,n){},bc6a:function(t,e,n){"use strict";n.d(e,"c",(function(){return o})),n.d(e,"a",(function(){return c})),n.d(e,"b",(function(){return u})),n("b0c0");var a=n("90d8"),r=(n("4160"),n("e260"),n("d3b7"),n("ac1f"),n("466d"),n("159b"),n("ddb0"),n("9348")),i={};r.keys().forEach((function(t){i[t.match(/(\.\/)(\w*)/)[2]]=r(t).default}));var s=i,o=[{name:"资产组名称",key:"name"},{name:"资产范围",key:"scope"},{name:"资产范围ID",key:"_id"}],c=[{title:"资产组名称",dataIndex:"title",fixed:"left",sorter:!0,scopedSlots:{customRender:"name",component:s.name}},{title:"资产范围",dataIndex:"scope_array",scopedSlots:{customRender:"scope_array",component:s.tag}},{title:"资产范围ID",dataIndex:"_id",scopedSlots:{customRender:"_id",component:s.name}},{width:400,title:"操作",dataIndex:"operate",scopedSlots:{customRender:"operate",component:s.operate}}],u=[{columns:[{width:80,title:"序号",dataIndex:"index",scopedSlots:{customRender:"dataIndex",component:s.dataIndex}},{width:300,title:"站点",dataIndex:"site",scopedSlots:{customRender:"site",component:s.site}},{width:300,title:"标题",dataIndex:"title"},{width:400,title:"headers",dataIndex:"headers",scopedSlots:{customRender:"headers",component:s.headers}},{width:200,title:"finger",dataIndex:"_fingerName",scopedSlots:{customRender:"finger",component:s.finger}},{width:300,title:"更新时间",dataIndex:"update_date"}],api:a.y,addAPI:a.b,deleteAPI:a.i,searchGroup:[{label:"站点",value:"site",filterType:"input"},{label:"主机名",value:"hostname",filterType:"input"},{label:"标题",value:"title",filterType:"input"},{label:"Web Server",value:"http_server",filterType:"input"},{label:"状态码",value:"status",filterType:"input"},{label:"标头",value:"headers",filterType:"input"},{label:"指 纹",value:"finger.name",filterType:"input"},{label:"favicon hash",value:"favicon.hash",filterType:"input"},{label:"标签",value:"tag",filterType:"input"},{label:"更新时间",value:"update_date",filterType:"date"}],total:0,params:{page:1,size:10}},{columns:[{width:100,title:"序号",dataIndex:"index",scopedSlots:{customRender:"dataIndex",component:s.dataIndex}},{width:300,title:"域名",dataIndex:"domain"},{width:100,title:"解析类型",dataIndex:"type"},{width:150,title:"记录值",dataIndex:"record",scopedSlots:{customRender:"record",component:s.arrTip}},{width:120,title:"关联IP",dataIndex:"ips",scopedSlots:{customRender:"ips",component:s.arrTip}},{width:100,title:"来源",dataIndex:"source"},{width:300,title:"更新时间",dataIndex:"update_date"}],total:0,api:a.w,addAPI:a.a,deleteAPI:a.g,searchGroup:[{label:"域名",value:"domain",filterType:"input"},{label:"记录值",value:"record",filterType:"input"},{label:"类型",value:"type",filterType:"input"},{type:"number",label:"IP",value:"ips",filterType:"input"},{label:"来源",value:"source",filterType:"input"},{label:"更新时间",value:"update_date",filterType:"date"}],params:{page:1,size:10}},{columns:[{width:100,title:"序号",dataIndex:"index",scopedSlots:{customRender:"dataIndex",component:s.dataIndex}},{width:200,title:"IP",dataIndex:"ip"},{width:250,title:"操作系统",dataIndex:"_osName"},{width:320,title:"开放端口",dataIndex:"port"},{width:300,title:"关联域名",dataIndex:"domain",scopedSlots:{customRender:"domain",component:s.arrTip}},{width:200,title:"Geo",dataIndex:"geo_city"},{width:300,title:"AS",dataIndex:"geo_asn"},{width:300,title:"更新时间",dataIndex:"update_date"}],total:0,api:a.x,addAPI:"",deleteAPI:a.h,searchGroup:[{type:"number",label:"IP",value:"ip",filterType:"input"},{type:"number",label:"端口",value:"port_info.port_id",filterType:"input"},{label:"操作系统",value:"os_info.name",filterType:"input"},{label:"域名",value:"domain",filterType:"input"},{label:"CDN",value:"cdn_name",filterType:"input"},{label:"更新时间",value:"update_date",filterType:"date"}],params:{page:1,size:10}}]},c09b:function(t,e,n){"use strict";n.r(e);var a={props:{text:{type:Array||String,default:function(){return[]}},record:{type:Object}},data:function(){return{open:!1}},methods:{toggle:function(){this.open=!this.open;try{var t=document.createEvent("Event");t.initEvent("resize",!0,!0),window.dispatchEvent(t)}catch(t){}},deleteAssets:function(t,e){this.$emit("operateCallback","deleteTag",t,e)},onCopy:function(t){this.$message.success("内容已复制到剪切板！")},onError:function(t){this.$message.error("抱歉，复制失败！")}}},r=(n("0a069"),n("2877")),i=Object(r.a)(a,(function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{class:{close:!t.open&&t.text.length>4}},[t.text.length?n("div",{staticClass:"taglist"},[t._l(t.text,(function(e,a){return n("div",{key:a,staticClass:"tag-wrap"},[n("a-tag",{attrs:{visible:!0,closable:""},on:{close:function(n){return t.deleteAssets(t.record._id,e)}}},[t._v(" "+t._s(e)+" ")])],1)})),n("div",{staticClass:"btns"},[t.text.length>4?n("a-button",{attrs:{type:"link"},on:{click:t.toggle}},[t._v(t._s(t.open?"收起":"展开"))]):t._e(),n("a-button",{directives:[{name:"clipboard",rawName:"v-clipboard:copy",value:t.text+"",expression:"text+''",arg:"copy"},{name:"clipboard",rawName:"v-clipboard:success",value:t.onCopy,expression:"onCopy",arg:"success"},{name:"clipboard",rawName:"v-clipboard:error",value:t.onError,expression:"onError",arg:"error"}],attrs:{type:"link"}},[t._v("复制")])],1)],2):n("div",[t._v("-")])])}),[],!1,null,"abb17e16",null);e.default=i.exports},d550:function(t,e,n){"use strict";var a={name:"batchDelete",props:{selectedRowKeys:{type:Array,default:function(){return[]}}},methods:{deleteCallback:function(){this.$emit("deleteCallback")}}},r=(n("fb70"),n("2877")),i=Object(r.a)(a,(function(){var t=this.$createElement,e=this._self._c||t;return e("div",{staticClass:"option-btn inline-btn"},[this.selectedRowKeys.length?e("a-popconfirm",{attrs:{"ok-text":"确认","cancel-text":"取消"},on:{confirm:this.deleteCallback}},[e("template",{slot:"title"},[e("p",[this._v("确认删除所选数据吗？")])]),e("a-button",[this._v("批量删除")])],2):e("a-button",{attrs:{disabled:!0}},[this._v("批量删除")]),this._t("default")],2)}),[],!1,null,"4072efce",null);e.a=i.exports},e286:function(t,e,n){"use strict";n.r(e);var a=n("2877"),r=Object(a.a)({},(function(t,e){var n=e._c;return n("div",[void 0!==e.props.text&&e.props.text.length?n("div",[e.props.text.length>5?n("div",[n("a-tooltip",{attrs:{placement:"topLeft"}},[n("template",{slot:"title"},e._l(e.props.text,(function(t,a){return n("p",{key:a},[e._v(e._s(t))])})),0),e._l(e.props.text.slice(0,5),(function(t,a){return n("div",{key:a},[e._v(" "+e._s(4===a?t+"...":t)+" ")])}))],2)],1):n("div",e._l(e.props.text,(function(t,a){return n("p",{key:a},[e._v(e._s(t))])})),0)]):n("div",[e._v("-")])])}),[],!0,null,null,null);e.default=r.exports},e978:function(t,e,n){},fb70:function(t,e,n){"use strict";var a=n("2805");n.n(a).a}}]);