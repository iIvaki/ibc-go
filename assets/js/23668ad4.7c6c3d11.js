"use strict";(self.webpackChunkdocs=self.webpackChunkdocs||[]).push([[8063],{5098:(e,n,t)=>{t.r(n),t.d(n,{assets:()=>r,contentTitle:()=>s,default:()=>d,frontMatter:()=>a,metadata:()=>c,toc:()=>l});var i=t(85893),o=t(11151);const a={title:"Authentication Modules",sidebar_label:"Authentication Modules",sidebar_position:3,slug:"/apps/interchain-accounts/auth-modules"},s="Building an authentication module",c={id:"apps/interchain-accounts/auth-modules",title:"Authentication Modules",description:"Authentication modules enable application developers to perform custom logic when interacting with the Interchain Accounts controller sumbmodule's MsgServer.",source:"@site/versioned_docs/version-v9.0.x/02-apps/02-interchain-accounts/03-auth-modules.md",sourceDirName:"02-apps/02-interchain-accounts",slug:"/apps/interchain-accounts/auth-modules",permalink:"/v9/apps/interchain-accounts/auth-modules",draft:!1,unlisted:!1,tags:[],version:"v9.0.x",sidebarPosition:3,frontMatter:{title:"Authentication Modules",sidebar_label:"Authentication Modules",sidebar_position:3,slug:"/apps/interchain-accounts/auth-modules"},sidebar:"defaultSidebar",previous:{title:"Development Use Cases",permalink:"/v9/apps/interchain-accounts/development"},next:{title:"Integration",permalink:"/v9/apps/interchain-accounts/integration"}},r={},l=[{value:"Integration into <code>app.go</code> file",id:"integration-into-appgo-file",level:2}];function u(e){const n={a:"a",admonition:"admonition",code:"code",h1:"h1",h2:"h2",li:"li",p:"p",ul:"ul",...(0,o.a)(),...e.components};return(0,i.jsxs)(i.Fragment,{children:[(0,i.jsx)(n.h1,{id:"building-an-authentication-module",children:"Building an authentication module"}),"\n",(0,i.jsx)(n.admonition,{title:"Synopsis",type:"note",children:(0,i.jsxs)(n.p,{children:["Authentication modules enable application developers to perform custom logic when interacting with the Interchain Accounts controller sumbmodule's ",(0,i.jsx)(n.code,{children:"MsgServer"}),"."]})}),"\n",(0,i.jsx)(n.p,{children:"The controller submodule is used for account registration and packet sending. It executes only logic required of all controllers of interchain accounts. The type of authentication used to manage the interchain accounts remains unspecified. There may exist many different types of authentication which are desirable for different use cases. Thus the purpose of the authentication module is to wrap the controller submodule with custom authentication logic."}),"\n",(0,i.jsxs)(n.p,{children:["In ibc-go, authentication modules can communicate with the controller submodule by passing messages through ",(0,i.jsx)(n.code,{children:"baseapp"}),"'s ",(0,i.jsx)(n.code,{children:"MsgServiceRouter"}),". To implement an authentication module, the ",(0,i.jsx)(n.code,{children:"IBCModule"})," interface need not be fulfilled; it is only required to fulfill Cosmos SDK's ",(0,i.jsx)(n.code,{children:"AppModuleBasic"})," interface, just like any regular Cosmos SDK application module."]}),"\n",(0,i.jsx)(n.p,{children:"The authentication module must:"}),"\n",(0,i.jsxs)(n.ul,{children:["\n",(0,i.jsx)(n.li,{children:"Authenticate interchain account owners."}),"\n",(0,i.jsx)(n.li,{children:"Track the associated interchain account address for an owner."}),"\n",(0,i.jsx)(n.li,{children:"Send packets on behalf of an owner (after authentication)."}),"\n"]}),"\n",(0,i.jsxs)(n.h2,{id:"integration-into-appgo-file",children:["Integration into ",(0,i.jsx)(n.code,{children:"app.go"})," file"]}),"\n",(0,i.jsxs)(n.p,{children:["To integrate the authentication module into your chain, please follow the steps outlined in ",(0,i.jsxs)(n.a,{href:"/v9/apps/interchain-accounts/integration#example-integration",children:[(0,i.jsx)(n.code,{children:"app.go"})," integration"]}),"."]})]})}function d(e={}){const{wrapper:n}={...(0,o.a)(),...e.components};return n?(0,i.jsx)(n,{...e,children:(0,i.jsx)(u,{...e})}):u(e)}},11151:(e,n,t)=>{t.d(n,{Z:()=>c,a:()=>s});var i=t(67294);const o={},a=i.createContext(o);function s(e){const n=i.useContext(a);return i.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function c(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(o):e.components||o:s(e.components),i.createElement(a.Provider,{value:n},e.children)}}}]);