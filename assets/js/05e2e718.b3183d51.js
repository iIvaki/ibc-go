"use strict";(self.webpackChunkdocs=self.webpackChunkdocs||[]).push([[60263],{9191:(e,n,i)=>{i.r(n),i.d(n,{assets:()=>a,contentTitle:()=>c,default:()=>d,frontMatter:()=>o,metadata:()=>l,toc:()=>r});var t=i(85893),s=i(11151);const o={title:"Solomachine",sidebar_label:"Solomachine",sidebar_position:1,slug:"/ibc/light-clients/solomachine/solomachine"},c="solomachine",l={id:"light-clients/solomachine/solomachine",title:"Solomachine",description:"Abstract",source:"@site/versioned_docs/version-v7.8.x/03-light-clients/02-solomachine/01-solomachine.md",sourceDirName:"03-light-clients/02-solomachine",slug:"/ibc/light-clients/solomachine/solomachine",permalink:"/v7/ibc/light-clients/solomachine/solomachine",draft:!1,unlisted:!1,tags:[],version:"v7.8.x",sidebarPosition:1,frontMatter:{title:"Solomachine",sidebar_label:"Solomachine",sidebar_position:1,slug:"/ibc/light-clients/solomachine/solomachine"},sidebar:"defaultSidebar",previous:{title:"Setup",permalink:"/v7/ibc/light-clients/setup"},next:{title:"Concepts",permalink:"/v7/ibc/light-clients/solomachine/concepts"}},a={},r=[{value:"Abstract",id:"abstract",level:2},{value:"Contents",id:"contents",level:2}];function h(e){const n={a:"a",code:"code",h1:"h1",h2:"h2",li:"li",ol:"ol",p:"p",strong:"strong",...(0,s.a)(),...e.components};return(0,t.jsxs)(t.Fragment,{children:[(0,t.jsx)(n.h1,{id:"solomachine",children:(0,t.jsx)(n.code,{children:"solomachine"})}),"\n",(0,t.jsx)(n.h2,{id:"abstract",children:"Abstract"}),"\n",(0,t.jsxs)(n.p,{children:["This paper defines the implementation of the ICS06 protocol on the Cosmos SDK. For the general\nspecification please refer to the ",(0,t.jsx)(n.a,{href:"https://github.com/cosmos/ibc/tree/master/spec/client/ics-006-solo-machine-client",children:"ICS06 Specification"}),"."]}),"\n",(0,t.jsx)(n.p,{children:"This implementation of a solo machine light client supports single and multi-signature public\nkeys. The client is capable of handling public key updates by header and governance proposals.\nThe light client is capable of processing client misbehaviour. Proofs of the counterparty state\nare generated by the solo machine client by signing over the desired state with a certain sequence,\ndiversifier, and timestamp."}),"\n",(0,t.jsx)(n.h2,{id:"contents",children:"Contents"}),"\n",(0,t.jsxs)(n.ol,{children:["\n",(0,t.jsx)(n.li,{children:(0,t.jsx)(n.strong,{children:(0,t.jsx)(n.a,{href:"/v7/ibc/light-clients/solomachine/concepts",children:"Concepts"})})}),"\n",(0,t.jsx)(n.li,{children:(0,t.jsx)(n.strong,{children:(0,t.jsx)(n.a,{href:"/v7/ibc/light-clients/solomachine/state",children:"State"})})}),"\n",(0,t.jsx)(n.li,{children:(0,t.jsx)(n.strong,{children:(0,t.jsx)(n.a,{href:"/v7/ibc/light-clients/solomachine/state_transitions",children:"State Transitions"})})}),"\n"]})]})}function d(e={}){const{wrapper:n}={...(0,s.a)(),...e.components};return n?(0,t.jsx)(n,{...e,children:(0,t.jsx)(h,{...e})}):h(e)}},11151:(e,n,i)=>{i.d(n,{Z:()=>l,a:()=>c});var t=i(67294);const s={},o=t.createContext(s);function c(e){const n=t.useContext(o);return t.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function l(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(s):e.components||s:c(e.components),t.createElement(o.Provider,{value:n},e.children)}}}]);