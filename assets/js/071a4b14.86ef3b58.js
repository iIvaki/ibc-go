"use strict";(self.webpackChunkdocs=self.webpackChunkdocs||[]).push([[88988],{56239:(e,n,t)=>{t.r(n),t.d(n,{assets:()=>r,contentTitle:()=>a,default:()=>u,frontMatter:()=>c,metadata:()=>s,toc:()=>l});var i=t(85893),o=t(11151);const c={title:"Overview",sidebar_label:"Overview",sidebar_position:1,slug:"/apps/interchain-accounts/overview"},a="Overview",s={id:"apps/interchain-accounts/overview",title:"Overview",description:"Learn about what the Interchain Accounts module is, and how to build custom modules that utilize Interchain Accounts functionality",source:"@site/versioned_docs/version-v4.6.x/02-apps/02-interchain-accounts/01-overview.md",sourceDirName:"02-apps/02-interchain-accounts",slug:"/apps/interchain-accounts/overview",permalink:"/v4/apps/interchain-accounts/overview",draft:!1,unlisted:!1,tags:[],version:"v4.6.x",sidebarPosition:1,frontMatter:{title:"Overview",sidebar_label:"Overview",sidebar_position:1,slug:"/apps/interchain-accounts/overview"},sidebar:"defaultSidebar",previous:{title:"Params",permalink:"/v4/apps/transfer/params"},next:{title:"Authentication Modules",permalink:"/v4/apps/interchain-accounts/auth-modules"}},r={},l=[{value:"What is the Interchain Accounts module?",id:"what-is-the-interchain-accounts-module",level:2},{value:"Concepts",id:"concepts",level:2},{value:"SDK Security Model",id:"sdk-security-model",level:2},{value:"Known Bugs",id:"known-bugs",level:2}];function h(e){const n={a:"a",admonition:"admonition",code:"code",h1:"h1",h2:"h2",li:"li",p:"p",ul:"ul",...(0,o.a)(),...e.components};return(0,i.jsxs)(i.Fragment,{children:[(0,i.jsx)(n.h1,{id:"overview",children:"Overview"}),"\n",(0,i.jsx)(n.admonition,{title:"Synopsis",type:"note",children:(0,i.jsx)(n.p,{children:"Learn about what the Interchain Accounts module is, and how to build custom modules that utilize Interchain Accounts functionality"})}),"\n",(0,i.jsx)(n.h2,{id:"what-is-the-interchain-accounts-module",children:"What is the Interchain Accounts module?"}),"\n",(0,i.jsx)(n.p,{children:"Interchain Accounts is the Cosmos SDK implementation of the ICS-27 protocol, which enables cross-chain account management built upon IBC. Chains using the Interchain Accounts module can programmatically create accounts on other chains and control these accounts via IBC transactions."}),"\n",(0,i.jsx)(n.p,{children:"Interchain Accounts exposes a simple-to-use API which means IBC application developers do not require an in-depth knowledge of the underlying low-level details of IBC or the ICS-27 protocol."}),"\n",(0,i.jsx)(n.p,{children:"Developers looking to build upon Interchain Accounts must write custom logic in their own IBC application module, called authentication modules."}),"\n",(0,i.jsxs)(n.ul,{children:["\n",(0,i.jsx)(n.li,{children:"How is an interchain account different than a regular account?"}),"\n"]}),"\n",(0,i.jsx)(n.p,{children:"Regular accounts use a private key to sign transactions on-chain. Interchain Accounts are instead controlled programmatically by separate chains via IBC transactions. Interchain Accounts are implemented as sub-accounts of the interchain accounts module account."}),"\n",(0,i.jsx)(n.h2,{id:"concepts",children:"Concepts"}),"\n",(0,i.jsxs)(n.p,{children:[(0,i.jsx)(n.code,{children:"Host Chain"}),": The chain where the interchain account is registered. The host chain listens for IBC packets from a controller chain which should contain instructions (e.g. cosmos SDK messages) for which the interchain account will execute."]}),"\n",(0,i.jsxs)(n.p,{children:[(0,i.jsx)(n.code,{children:"Controller Chain"}),": The chain registering and controlling an account on a host chain. The controller chain sends IBC packets to the host chain to control the account. A controller chain must have at least one interchain accounts authentication module in order to act as a controller chain."]}),"\n",(0,i.jsxs)(n.p,{children:[(0,i.jsx)(n.code,{children:"Authentication Module"}),": A custom IBC application module on the controller chain that uses the Interchain Accounts module API to build custom logic for the creation & management of interchain accounts. For a controller chain to utilize the interchain accounts module functionality, an authentication module is required."]}),"\n",(0,i.jsxs)(n.p,{children:[(0,i.jsx)(n.code,{children:"Interchain Account"}),": An account on a host chain. An interchain account has all the capabilities of a normal account. However, rather than signing transactions with a private key, a controller chain's authentication module will send IBC packets to the host chain which signals what transactions the interchain account should execute."]}),"\n",(0,i.jsx)(n.h2,{id:"sdk-security-model",children:"SDK Security Model"}),"\n",(0,i.jsx)(n.p,{children:"SDK modules on a chain are assumed to be trustworthy.  For example, there are no checks to prevent an untrustworthy module from accessing the bank keeper."}),"\n",(0,i.jsx)(n.p,{children:"The implementation of ICS27 on ibc-go uses this assumption in its security considerations. The implementation assumes the authentication module will not try to open channels on owner addresses it does not control."}),"\n",(0,i.jsx)(n.p,{children:"The implementation assumes other IBC application modules will not bind to ports within the ICS27 namespace."}),"\n",(0,i.jsx)(n.h2,{id:"known-bugs",children:"Known Bugs"}),"\n",(0,i.jsxs)(n.ul,{children:["\n",(0,i.jsxs)(n.li,{children:["Fee-enabled Interchain Accounts channels cannot be reopened in case of closure due to packet timeout. Regular channels (non fee-enabled) can be reopened. A fix for this bug has been implemented, but, since it is API breaking, it is only available from v5.x. See ",(0,i.jsx)(n.a,{href:"https://github.com/cosmos/ibc-go/pull/2302",children:"this PR"})," for more details."]}),"\n"]})]})}function u(e={}){const{wrapper:n}={...(0,o.a)(),...e.components};return n?(0,i.jsx)(n,{...e,children:(0,i.jsx)(h,{...e})}):h(e)}},11151:(e,n,t)=>{t.d(n,{Z:()=>s,a:()=>a});var i=t(67294);const o={},c=i.createContext(o);function a(e){const n=i.useContext(c);return i.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function s(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(o):e.components||o:a(e.components),i.createElement(c.Provider,{value:n},e.children)}}}]);