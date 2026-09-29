"""Trusted, dependency-free navigation and presentation assets for v0.2."""

# Static dotted silhouette inspired by the CLI spider; no report data or assets.
SPIDER_MARK = (
    '<svg class="spider-mark" viewBox="0 0 44 60" aria-hidden="true" focusable="false">'
    '<g fill="none" stroke="currentColor" stroke-width="1.8" '
    'stroke-linecap="round" stroke-dasharray="0.1 3">'
    '<path d="M18 23 12 18 10 9 10 3 M26 23 32 18 34 9 34 3 '
    'M17 27 8 24 3 16 2 9 M27 27 36 24 41 16 42 9 '
    'M17 31 8 34 3 42 2 50 M27 31 36 34 41 42 42 50 '
    'M18 35 12 42 12 50 16 57 M26 35 32 42 32 50 28 57 '
    'M20 15 19 9 M24 15 25 9"/></g><g fill="currentColor">'
    + ''.join(
        f'<circle cx="{x}" cy="{y}" r="0.9"/>'
        for x in range(16, 29, 2)
        for y in range(15, 47, 2)
        if ((x - 22) / 4) ** 2 + ((y - 21) / 6) ** 2 <= 1
        or ((x - 22) / 5.5) ** 2 + ((y - 36) / 10) ** 2 <= 1
    )
    + '</g></svg>'
)

STYLE = """
:root{--paper:#f5f7fa;--ink:#192b3c;--muted:#627184;--accent:#087e8b;
 --line:#e1e8ed;--high:#b64d47;--medium:#987014;--low:#637588;
 --sqli:#b17a21;--xss:#7974c9;--bac:#208d91;--track:#eef2f6}
body{background:var(--paper);font-size:14px;word-break:keep-all}
a{color:inherit;text-decoration:none}button,input,select{font:inherit}
button,a,input,select,summary{-webkit-tap-highlight-color:transparent}
:focus-visible{outline:3px solid #0a98a6;outline-offset:4px}
summary:focus-visible{outline:3px solid #0a98a6!important;outline-offset:4px}
[hidden]{display:none!important}.skip-link{position:fixed;top:-70px;left:20px;z-index:50;
 background:white;padding:14px;border:2px solid var(--accent)}.skip-link:focus{top:10px}
.sidebar{position:fixed;inset:0 auto 0 0;width:224px;background:#102d3b;color:#b8ccd4;
 padding:32px 20px;display:flex;flex-direction:column;z-index:10}
.app-brand{display:flex;gap:11px;align-items:center;font-size:22px;font-weight:750;
 letter-spacing:-.7px;color:#f7ffff}.brand-mark{display:grid;place-items:center;width:44px;
 height:60px;flex-shrink:0;color:#ff667d}.spider-mark{display:block;width:44px;height:60px}
.sidebar small{font-size:10px;letter-spacing:2px;display:block;margin:9px 0 39px 55px}
.nav-label{font-size:10px;letter-spacing:1.8px;color:#89a8b6;margin:8px 12px 12px}
.sidebar nav a{display:flex;gap:13px;align-items:center;padding:13px 14px;border-radius:8px;
 margin:5px 0;font-weight:550;font-size:13px}.sidebar nav a:hover{background:#1b4050}
.sidebar nav a[aria-current=page]{background:#1e4856;color:#b9f4ee}
.nav-icon{font-size:19px;line-height:1;width:20px;text-align:center}
.sidebar-bottom{margin-top:auto;padding:18px 12px 0;border-top:1px solid #30505d;
 font-size:12px;line-height:1.8}.sidebar-bottom strong{color:#dcebee}
.workspace{margin-left:224px;min-width:0}.topbar{height:76px;background:#fff;border-bottom:1px
 solid var(--line);display:flex;justify-content:space-between;align-items:center;padding:0 38px;
 gap:16px}.crumb{font-size:12px;color:var(--muted)}.crumb b{color:var(--ink);font-weight:600}
.top-actions{display:flex;gap:15px;align-items:center}.snapshot-badge{font-size:11px;color:#267b75;
 background:#eef8f5;border:1px solid #d5eae4;border-radius:20px;padding:5px 10px}
.button{display:inline-flex;align-items:center;justify-content:center;gap:8px;background:white;
 border:1px solid #d4dfe5;padding:10px 15px;border-radius:7px;cursor:pointer;font-size:12px;
 font-weight:650;color:var(--ink)}.button:hover{background:#f0f6f7}.button.primary{background:#087e8b;
 color:white;border-color:#087e8b}.button.primary:hover{background:#076b77}
.main-content{max-width:1510px;margin:auto;padding:32px 38px 48px}
.report-page{display:none}.report-page.overview{display:block}
.main-content:has(.report-page:target)>.overview{display:none}
.main-content>.report-page:target{display:block}
.enhanced .main-content>.report-page{display:none}.enhanced .main-content>.report-page.active{display:block}
.page-heading{display:flex;justify-content:space-between;gap:22px;align-items:center;margin-bottom:24px}
.eyebrow{font-size:10px;font-weight:700;letter-spacing:2px;color:var(--accent);margin-bottom:8px}
h1.page-title{font-size:29px;font-weight:750;letter-spacing:-1.2px;margin:0 0 8px;line-height:1.35}
.subtitle{color:var(--muted);font-size:13px;line-height:1.8;margin:0;max-width:770px}
.target-chip{display:inline-flex;gap:8px;align-items:center;font-family:var(--mono);font-size:11px;
 color:#4e6778;background:white;border:1px solid var(--line);border-radius:6px;padding:8px 11px;
 margin-top:13px;max-width:100%;overflow-wrap:anywhere}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin-bottom:22px}
.metric{padding:20px 22px;background:white;border:1px solid var(--line);border-radius:10px;
 box-shadow:0 3px 7px #192b3c03}.metric-label{font-size:12px;color:var(--muted);display:flex;
 justify-content:space-between}.metric-label span{color:#96a8b5}.metric-value{font-size:32px;
 font-weight:700;letter-spacing:-1.4px;margin:10px 0 6px;line-height:1}.metric-value small{
 font-size:12px;letter-spacing:0;color:var(--muted);margin-left:6px;font-weight:500}
.metric-note{font-size:11px;color:var(--muted)}.metric.accent{border-top:3px solid #188c94;
 padding-top:18px}.metric.accent .metric-value{color:var(--accent)}
.panel{background:white;border:1px solid var(--line);border-radius:11px;min-width:0;overflow:hidden}
.panel-head{display:flex;justify-content:space-between;align-items:center;gap:14px;padding:20px 23px 16px}
.panel h2{font-size:15px;margin:0;letter-spacing:-.3px}.panel-desc{font-size:11px;color:var(--muted);
 margin:5px 0 0;line-height:1.7}.panel-body{padding:0 23px 22px}.text-link{color:var(--accent);
 font-size:12px;font-weight:600;white-space:nowrap}.overview-grid{display:grid;
 grid-template-columns:minmax(0,2.15fr) minmax(250px,1fr);gap:20px;margin-bottom:22px}
.map-canvas{margin:0 16px 16px;border:1px solid #e8eef2;border-radius:8px;padding:22px;
 background-color:#fafcfd;background-image:radial-gradient(#dfe8ed 1px,transparent 1px);
 background-size:17px 17px;min-height:267px;display:flex;align-items:center;gap:30px}
.map-root{flex:0 0 95px;text-align:center;position:relative}.map-root-icon{margin:0 auto 9px;
 width:54px;height:54px;display:grid;place-items:center;font-size:25px;color:#087e8b;
 border:1px solid #a8d3d8;background:#eaf8f7;border-radius:16px;box-shadow:0 0 0 7px #f1f9fa}
.map-root strong{font-size:11px}.map-root small{display:block;color:var(--muted);font-size:10px;margin-top:3px}
.map-root:after{content:'';position:absolute;right:-30px;top:28px;width:33px;border-top:1px solid #bad0db}
.map-branches{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:13px;flex:1;
 min-width:0;position:relative;border-left:1px solid #bad0db;padding-left:22px}
.endpoint-node{position:relative;min-width:0;border:1px solid #dce6eb;border-radius:7px;
 background:white;box-shadow:0 2px 4px #17384c04;padding:11px}
.endpoint-node:before{content:'';position:absolute;left:-23px;top:22px;width:22px;border-top:1px solid #bad0db}
.node-path{font-family:var(--mono);font-size:10px;color:#526d7d;overflow-wrap:anywhere;
 border-bottom:1px solid #edf1f5;padding-bottom:7px;margin-bottom:7px}
.candidate-node{display:flex;gap:6px;align-items:center;justify-content:space-between;
 padding:5px 4px;border-radius:4px;font-size:11px}.candidate-node:hover{background:#edf7f7}
.candidate-node .node-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:130px}
.candidate-node strong{font-family:var(--mono);font-size:11px;color:var(--accent)}
.family-dot{width:7px;height:7px;display:inline-block;background:var(--muted);border-radius:50%;flex-shrink:0}
.family-dot.SQLI{background:var(--sqli)}.family-dot.REFLECTED_XSS{background:var(--xss)}
.family-dot.BROKEN_ACCESS_CONTROL{background:var(--bac)}
.map-legend{display:flex;gap:14px;flex-wrap:wrap;padding:0 23px 17px;color:var(--muted);font-size:10px}
.map-legend span{display:flex;gap:5px;align-items:center}.family-panel .donut-layout{justify-content:center}
.family-panel .donut-legend{font-size:11px}.family-panel .donut-svg{width:155px;height:155px}
.family-panel .donut{display:flex;flex-direction:column;align-items:center;gap:16px}
.family-panel .legend{width:100%;font-size:12px}.family-panel .chart-note{margin-top:14px}
.table-scroll{overflow:auto}.candidate-table{width:100%;border-collapse:collapse;white-space:nowrap}
.candidate-table th{text-align:left;background:#f9fbfc;color:#71818e;font-size:10px;font-weight:600;
 padding:11px 18px;border-block:1px solid #eaf0f3}.candidate-table td{padding:14px 18px;
 border-bottom:1px solid #edf1f4;font-size:12px}.candidate-table tr:last-child td{border-bottom:0}
.candidate-table td:first-child{color:#8b9aa6;font-family:var(--mono);font-size:11px;width:52px}
.location-link{display:block;font-family:var(--mono);font-size:12px;font-weight:600;
 max-width:330px;overflow:hidden;text-overflow:ellipsis}.location-sub{font-size:10px;color:var(--muted);
 margin-top:4px}.family-tag{display:inline-flex;align-items:center;gap:6px;font-size:10px;
 border:1px solid var(--line);border-radius:5px;padding:4px 7px;color:#526779}
.score-cell{font-family:var(--mono);font-weight:700}.mini-meter{height:4px;background:#eaf0f4;
 border-radius:4px;margin-top:6px;width:70px}.mini-meter i{display:block;height:100%;background:#248b94;border-radius:4px}
.state{font-size:10px;display:inline-block;border-radius:5px;padding:4px 7px;background:#f0f3f6;color:#617384}
.state.SUPPORTED{background:#fff0eb;color:#a75638}.state.WEAKENED{background:#eaf6f2;color:#267568}
.state.INCONCLUSIVE_ERROR{background:#fff6df;color:#876717}.state.REJECTED{background:#f9eefa;color:#805185}
.selection-note{font-size:11px;color:var(--muted);padding:12px 22px;border-top:1px solid var(--line);
 line-height:1.75;background:#fcfdfe}.journey{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));
 gap:16px;margin:22px 0}.journey-step{display:flex;gap:10px;font-size:11px;line-height:1.7;color:var(--muted)}
.step-number{background:#e6eff2;color:#317181;border-radius:6px;min-width:25px;height:25px;
 display:grid;place-items:center;font-family:var(--mono);font-size:11px}.journey-step b{display:block;color:#354f60;font-size:12px}
.filters{display:none;gap:12px;align-items:end;flex-wrap:wrap;padding:17px 23px;border-top:1px solid var(--line)}
.enhanced .filters{display:flex}.filters label{display:grid;gap:6px;font-size:11px;color:var(--muted)}
.filters label:first-child{flex:1;min-width:180px}.filters input,.filters select{height:39px;background:white;
 border:1px solid #d7e1e7;border-radius:6px;padding:0 12px;color:var(--ink);min-width:0;width:100%}
.filter-count{font-size:11px;color:var(--muted);padding:9px 0}.filter-empty{padding:40px;text-align:center;
 color:var(--muted)}.list-foot{margin-top:23px}.list-foot summary,.technical summary{cursor:pointer;font-size:12px;
 color:#527384;padding:13px 0;font-weight:600}.technical{margin-top:17px;border-top:1px solid var(--line)}
.back-link{display:inline-block;margin-bottom:20px;color:var(--muted);font-size:12px}
.detail-pager{display:flex;justify-content:space-between;gap:20px;margin-top:24px}
.finding{padding:28px;margin:0;border:1px solid var(--line);border-radius:11px;box-shadow:none}
.finding .fhead{padding-bottom:23px;border-bottom:1px solid var(--line);margin-bottom:24px}
.finding .rank{font-size:10px;letter-spacing:2px;color:var(--accent)}.finding .vtype{font-size:24px;margin:7px 0 10px}
.finding .prio{font-size:37px;letter-spacing:-1px}.finding .pcaption{font-family:var(--sans);font-size:11px}
.finding .meterwrap{max-width:260px}.finding .ep{font-size:12px;max-width:700px}
.detail-section{margin-top:27px}.detail-section h2{font-size:16px;margin:0 0 13px;display:flex;gap:10px;align-items:center}
.detail-section h2 span{color:var(--accent);font-family:var(--mono);font-size:11px;font-weight:500}
.plain-intro{font-size:14px;line-height:1.9;color:#4a6273;margin:0 0 15px}
.evidence-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.evidence-item{border:1px solid #e3eaee;background:#fafcfd;border-radius:7px;padding:15px}
.evidence-item b{font-size:12px;display:block}.evidence-item p{font-size:12px;line-height:1.8;color:var(--muted);
 margin:7px 0}.evidence-meta{font-family:var(--mono);font-size:10px;overflow-wrap:anywhere;color:#687c8c}
.missing-note{padding:17px 20px;background:#f4f7f9;border-radius:7px;font-size:12px;color:#617483;line-height:1.8}
.payload-card{border:1px solid var(--line);border-radius:8px;margin:12px 0;overflow:hidden}
.payload-head{background:#f8fafc;padding:13px 17px;display:flex;justify-content:space-between;gap:12px;align-items:center}
.payload-head b{font-size:12px}.payload-body{padding:17px}.payload-values{display:grid;grid-template-columns:1fr 1fr;gap:13px}
.payload-values label{font-size:10px;color:var(--muted);display:block;margin-bottom:6px}
.payload-values pre{margin:0;font-size:12px;padding:12px;background:#132f40;color:#d5eee9;
 border-radius:6px;white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.7}
.payload-body p{font-size:12px;line-height:1.8;color:#526b7c}.payload-body ul{font-size:12px;line-height:1.8;color:#526b7c;padding-left:19px}
.payload-meta{font-size:10px;color:var(--muted);line-height:1.9;overflow-wrap:anywhere}
.delta-table{width:100%;border-collapse:collapse;font-size:11px}.delta-table th,.delta-table td{
 text-align:left;padding:8px;border-bottom:1px solid #edf1f4;overflow-wrap:anywhere}
.delta-table th{color:var(--muted);font-weight:500}.vpanel{padding:20px;background:#f2f8f9;border:1px solid #daebed;border-radius:8px}
.vpanel .vscore{font-size:15px}.vbadge{display:inline-block;border-radius:5px;font-size:11px;
 padding:4px 9px;color:white}.vbadge.high{background:#a85740}.vbadge.low{background:#287867}
.vbadge.muted{background:#627788}.vhead{display:flex;flex-wrap:wrap;gap:16px;align-items:center;margin-bottom:9px}
.fix{padding:23px;background:#f0f8f5;border:1px solid #d9ebe2;border-radius:8px;margin-top:14px}
.fixhead{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.fixchip{font-size:10px;color:#2b7764;
 border:1px solid #c5e1d5;padding:3px 7px;border-radius:4px}.fixlead{font-size:13px;line-height:1.8;margin:12px 0}
.fixgrid{display:grid;grid-template-columns:1fr 1fr;gap:25px}.fixsub{font-size:12px;font-weight:700;
 color:#267360}.fix ul{padding-left:17px;font-size:12px;line-height:1.9;color:#4c6e62}
.fixnote,.fixdisc{font-size:11px;line-height:1.9;color:#537867}.fixdisc{display:block;margin-top:14px}
.ids{overflow-wrap:anywhere;margin-top:24px;font-size:10px;line-height:1.9}
.ko-en{font-size:10px;margin-left:8px;color:var(--muted);font-weight:400;letter-spacing:.3px}
.reading-guide{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:22px}
.reading-guide .panel-body{font-size:13px;line-height:1.9;color:#567080}
.method-chart .chart-grid{margin-top:18px}.notice{box-shadow:none}.notice.small{font-style:normal}
.rec{display:block;overflow-x:auto}.rec td,.rec th{min-width:85px}.why .lab{font-size:12px;color:#506b7b}
footer{display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;font-size:10px;margin-top:27px;
 color:#778b98;border-color:#dfe8ed}footer .warn{color:#778b98}
@media(min-width:1500px){.main-content{padding-inline:46px}.map-canvas{min-height:283px}.endpoint-node{padding:14px}}
.analysis-journey{border:1px solid #cadddf;border-radius:12px;background:linear-gradient(120deg,#edf7f7,#fff);
 padding:25px;margin-bottom:22px;overflow:hidden}.journey-heading{display:flex;justify-content:space-between;
 gap:16px;align-items:center}.journey-heading h2{font-size:20px;letter-spacing:-.7px;margin:7px 0 22px}
.analysis-stages{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:0;margin:0;padding:0;list-style:none}
.analysis-stage{position:relative;padding:18px 23px;border-left:1px solid #cbdfe1;min-width:0}
.analysis-stage:not(:first-child):before{content:'›';position:absolute;left:-9px;top:47%;width:17px;
 text-align:center;color:#547c87;background:#f1f8f8;font-size:23px;border-radius:50%}
.analysis-stage:first-child{border-left:0;padding-left:0}.analysis-stage:last-child{border:0;border-radius:9px;
 background:#103d49;color:white;padding-left:23px}.stage-top{display:flex;align-items:center;gap:9px;
 font-size:11px;color:#557580}.stage-top span{font:11px var(--mono);border:1px solid #bad2d7;border-radius:50%;
 width:25px;height:25px;display:grid;place-items:center}.stage-count{font-size:43px;letter-spacing:-2px;
 font-weight:750;margin:16px 0 10px;line-height:1}.stage-count small{font-size:12px;letter-spacing:0;margin-left:7px}
.analysis-stage h3{font-size:13px;margin:0 0 7px}.analysis-stage p{font-size:11px;line-height:1.6;margin:0;color:#526c79}
.analysis-stage:last-child .stage-top,.analysis-stage:last-child p{color:#c0e0e2}
.journey-note{font-size:11px;color:#526c79;margin:16px 0 0}.comparison-panel{margin-bottom:22px}
.comparison-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;padding:0 23px 23px}
.comparison-card{padding:19px;border:1px solid var(--line);border-radius:9px;min-width:0;display:flex;
 flex-direction:column;background:linear-gradient(180deg,#fafcfd,#fff)}.comparison-top{display:flex;
 justify-content:space-between;gap:8px;font-size:10px;color:var(--muted)}.change-label{color:#086f7a;font-weight:700}
.comparison-card h3{font-size:14px;line-height:1.7;margin:14px 0 6px;overflow-wrap:anywhere;min-height:48px}
.input-number{display:inline-block;font:10px var(--mono);padding:3px 6px;border:1px solid #c1dcdc;
 border-radius:4px;color:#346c72;background:#eff8f7;white-space:nowrap}.comparison-type{font-size:10px;color:var(--muted)}
.confidence-values{display:flex;justify-content:space-between;gap:8px;margin:22px 0 15px;font-size:10px;color:var(--muted)}
.confidence-values span:last-child{text-align:right}.confidence-values b{display:block;font-size:24px;color:#536879;
 margin-top:5px;font-variant-numeric:tabular-nums}.confidence-values span:last-child b{color:#087e8b}
.confidence-track{position:relative;height:6px;background:#e5edf1;border-radius:4px;margin:5px 8px 0}
.confidence-span{position:absolute;height:6px;background:#1796a0;border-radius:4px}
.prior-dot,.final-dot{display:inline-block;box-sizing:border-box;width:12px;height:12px;border-radius:50%;
 border:2px solid #6e8291;background:white}.final-dot{background:#087e8b;border-color:#087e8b;width:18px;height:18px}
.confidence-track i{position:absolute;top:50%;transform:translate(-50%,-50%)}
.confidence-scale{display:flex;justify-content:space-between;margin-top:10px;font-size:9px;color:var(--muted)}
.confidence-legend{display:flex;gap:20px;flex-wrap:wrap;font-size:10px;color:var(--muted);padding:0 23px 18px}
.confidence-legend span{display:flex;gap:7px;align-items:center}.confidence-legend .final-dot{width:12px;height:12px}
.comparison-card p{font-size:11px;line-height:1.8;color:var(--muted);margin:16px 0 18px}
.comparison-card>.text-link{margin-top:auto}.source-caption{background:#edf7f7;border:1px solid #c8e2e3;
 border-radius:9px;padding:17px 22px;margin-bottom:20px}.source-caption p{font-size:11px;color:var(--muted);margin:8px 0 0}
.node-path b{display:block;font-family:var(--sans);font-size:12px;color:var(--ink);margin-bottom:5px}
.candidate-node .node-name{white-space:normal;overflow-wrap:anywhere}.node-name small{display:block;font-size:9px;color:var(--muted);margin-top:3px}
.location-link{font-family:inherit;white-space:normal;line-height:1.7;overflow-wrap:anywhere}
@media(max-width:1100px){.analysis-stage{padding:15px}.analysis-stage:last-child{padding-left:15px}
 .comparison-grid{gap:10px;padding-inline:16px}.comparison-card{padding:15px}.confidence-values b{font-size:21px}}
@media(max-width:850px){.analysis-stages{grid-template-columns:1fr 1fr;gap:12px}.analysis-stage{border:0;padding:12px}
 .analysis-stage:first-child{padding-left:12px}.comparison-grid{grid-template-columns:1fr}.journey-heading{display:block}
 .journey-heading>.text-link{display:inline-block;margin-bottom:15px}.comparison-card h3{margin-top:10px}
 .confidence-values{margin-top:15px}.analysis-journey{padding:18px}.journey-heading h2{font-size:18px;margin-bottom:10px}
 .analysis-stage:before{display:none}.comparison-card h3{min-height:0}}
@media print{.analysis-journey,.comparison-card{break-inside:avoid}.analysis-stage:last-child{background:white;color:var(--ink)}
 .analysis-stage:last-child .stage-top,.analysis-stage:last-child p{color:var(--muted)}}
@media(max-width:1150px){.sidebar{width:190px;padding-inline:14px}.workspace{margin-left:190px}
 .main-content{padding:27px 24px}.topbar{padding-inline:24px}.overview-grid{grid-template-columns:minmax(0,1.9fr) minmax(220px,1fr)}
 .map-canvas{padding:17px;gap:20px}.map-root{flex-basis:70px}.map-root:after{right:-20px;width:23px}
 .map-branches{gap:9px;padding-left:14px}.endpoint-node:before{left:-15px;width:14px}.metric{padding:18px 16px}
 .candidate-table td,.candidate-table th{padding-inline:12px}.map-branches{grid-template-columns:1fr}}
@media(max-width:850px){.sidebar{position:static;width:100%;padding:17px 22px;display:block}.sidebar small,
 .nav-label,.sidebar-bottom{display:none}.sidebar nav{display:flex;gap:7px;margin-top:13px}.sidebar nav a{margin:0;padding:9px 12px}
 .workspace{margin-left:0}.topbar{height:58px}.overview-grid{grid-template-columns:1fr 1fr}.map-branches{grid-template-columns:1fr}
 .map-canvas{gap:22px}.metrics{gap:10px}.metric-label{font-size:11px}.metric-note{font-size:10px}.page-heading{align-items:flex-start}
 .journey{grid-template-columns:1fr 1fr}}
@media(max-width:650px){.main-content{padding:24px 16px}.topbar{padding-inline:17px}.crumb{font-size:10px}
 .snapshot-badge{display:none}.metrics{grid-template-columns:1fr 1fr}.overview-grid,.reading-guide{grid-template-columns:1fr}
 .map-branches{grid-template-columns:1fr 1fr}.map-canvas{gap:22px;padding:18px 12px}.map-root{flex-basis:62px}
 .map-root strong{font-size:10px}.endpoint-node{padding:8px}.candidate-node .node-name{max-width:70px}
 .page-heading{display:block}.page-heading>.button{margin-top:16px}h1.page-title{font-size:25px}
 .target-chip{font-size:10px}.family-panel .donut-layout{flex-direction:row}.panel-head{padding:18px}
 .panel-body{padding-inline:18px}.finding{padding:20px 17px}.evidence-grid,.payload-values,.fixgrid{grid-template-columns:1fr}
 .finding .meterwrap{width:100%;max-width:none;text-align:left}.finding .prio{font-size:32px}
 .fix{padding:17px}.journey{gap:15px}.sidebar nav a{font-size:12px;padding-inline:10px}.nav-icon{font-size:16px}
 .filters{padding-inline:17px}.filters label{flex:1;min-width:125px}.filters label:first-child{flex-basis:100%}
 .sidebar nav{display:grid;grid-template-columns:1fr 1fr 1.2fr;gap:4px}
 .sidebar nav a{font-size:11px;white-space:nowrap;gap:6px;justify-content:center;padding-inline:6px}}
@media(max-width:390px){.map-branches{grid-template-columns:1fr}.sidebar nav a{padding-inline:7px}}
@media(prefers-reduced-motion:no-preference){.button,.candidate-node{transition:background .15s}}
@media print{.sidebar,.topbar,.filters,.back-link,.detail-pager,.skip-link,.page-heading>.button{display:none!important}
 .workspace{margin:0}.main-content{padding:0}.panel,.finding,.metric{box-shadow:none;break-inside:avoid}
 .table-scroll,.rec{overflow:visible}body{background:white}.overview-grid{grid-template-columns:2fr 1fr}
 .metrics{grid-template-columns:repeat(4,1fr)}.report-page{break-after:page}.technical[open]{break-inside:auto}}
"""

STYLE += """
/* Lecture-room palette: dark ink, readable supporting copy, generous controls. */
:root{--sans:"Malgun Gothic","Apple SD Gothic Neo",system-ui,sans-serif;
 --ink:#152e3d;--muted:#465e6e;--accent:#006b75;--line:#cbd9df;--sqli:#966013;--xss:#6253a8}
body{font-size:18px;line-height:1.7}.main-content{padding:30px;max-width:1580px}
h1.page-title{font-size:34px;line-height:1.35}.subtitle{font-size:18px;max-width:920px}
.panel h2,.detail-section h2{font-size:23px}.panel-desc,.plain-intro{font-size:17px}
.button{font-size:16px;min-height:44px;padding:10px 17px}.topbar{height:auto;min-height:76px;gap:12px;padding-block:12px}
.top-actions{flex-wrap:wrap}.sidebar nav a{font-size:16px}.sidebar-bottom,.sidebar small,.nav-label{font-size:13px}
.eyebrow,.target-chip,.crumb,.snapshot-badge,.text-link,.selection-note,.technical summary,.list-foot summary,
.back-link,.source-caption p,.location-sub,.family-tag,.state,.input-number,.comparison-top,.comparison-type,
.confidence-values,.confidence-scale,.confidence-legend,.map-legend,.node-path,.node-name small,
.map-root strong,.map-root small,.stage-top,.stage-top span,.stage-count small,.analysis-stage p,
.journey-note,.journey-step,.step-number,.filters label,.filter-count,.ko-en,.finding .rank,.finding .pcaption,
.evidence-meta,.payload-meta,.fixchip,.fixnote,.fixdisc,.chart-note,footer,footer .warn{font-size:14px;color:var(--muted)}
.text-link,.eyebrow{color:var(--accent)}.sidebar .nav-label,.sidebar small{color:#b8ccd4}
.stage-count{font-size:54px}.analysis-stage h3{font-size:18px}.journey-heading h2{font-size:26px}
.candidate-table td,.location-link{font-size:17px}.candidate-table th,.candidate-table td:first-child{font-size:14px;color:#405766}
.candidate-table td,.candidate-table th{padding:16px}.family-tag,.state{white-space:normal}
.node-path b,.candidate-node,.candidate-node strong{font-size:15px}.candidate-node .node-name{max-width:none}
.family-panel .legend,.family-panel .donut-legend{font-size:16px}.family-panel .donut-svg{width:180px;height:180px}
.comparison-grid{gap:16px}.comparison-card h3{font-size:19px;min-height:65px}.comparison-card p{font-size:16px}
.confidence-values b{font-size:34px}.evidence-item b{font-size:18px}.evidence-item p,.missing-note,
.payload-body,.payload-body p,.payload-body li,.fixlead,.fix ul,.reading-guide .panel-body{font-size:17px}
.payload-values label,.payload-head,.fixsub,.why .lab{font-size:16px}.payload-values pre,.payload-body pre{font-size:16px}
.finding .vtype{font-size:32px}.finding .prio{font-size:52px}.finding .ep{font-size:16px}.finding .meterwrap{max-width:300px}
.vpanel .vscore{font-size:21px}.vbadge{font-size:16px}.rec td,.rec th,.delta-table td,.delta-table th{font-size:15px}
.evidence-summary{margin-bottom:22px}.evidence-counts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:20px;padding:0 24px 24px}
.evidence-count{border-left:4px solid #9aabb4;padding:0 18px}.evidence-count.supported{border-color:#b2652e}.evidence-count.weakened{border-color:#207d65}
.evidence-count>span{font-weight:700;font-size:17px}.evidence-count strong{display:block;font-size:42px;line-height:1.4}.evidence-count small{font-size:16px;margin-left:5px}
.evidence-count p{font-size:14px;color:var(--muted);margin:8px 0 0}.status-track{height:7px;border-radius:5px;background:#e8eef0}.status-track i{display:block;height:100%;background:#728995;border-radius:5px}
.supported .status-track i{background:#b2652e}.weakened .status-track i{background:#207d65}
.presentation-hero{padding:30px 0 20px;border-bottom:2px solid #bdced3}.presentation-hero h1{font-size:clamp(32px,3.5vw,54px);letter-spacing:-1.8px;margin:18px 0}
.presentation-hero p{font-size:20px;margin:8px 0;color:var(--muted)}.presentation-hero b{color:var(--accent)}
.story-route{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;list-style:none;padding:0;margin:26px 0}
.story-route li{font-size:21px;font-weight:700}.story-route b{font:700 18px var(--mono);color:var(--accent);margin-right:12px}
.story-route span{display:block;font-size:15px;font-weight:400;color:var(--muted);margin-left:38px}
.spotlight-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:22px}
.spotlight-card{background:white;border:1px solid #bdd0d5;border-top:5px solid var(--accent);border-radius:14px;padding:28px;min-width:0}
.spotlight-card h2{font-size:24px;line-height:1.6;margin:10px 0}.spotlight-card p{font-size:18px;color:var(--muted)}
.spotlight-score{font-size:76px;font-weight:800;letter-spacing:-3px;line-height:1.2;color:var(--accent);font-variant-numeric:tabular-nums}
.spotlight-score small{font-size:30px;letter-spacing:0}.spotlight-actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:25px}
.presentation-note{font-size:15px;color:var(--muted);margin:22px 0}
.response-comparison{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;margin-top:18px}
.response-card{min-width:0;border:1px solid #b8ccd4;border-top:4px solid #5a7788;border-radius:10px;background:#f9fcfd;padding:22px}
.response-card.probe{border-top-color:#b96529;background:#fffcf6}.response-card h3{font-size:21px;margin:0 0 20px}
.response-card h3 span{font:15px var(--mono);color:var(--muted)}.response-card label,.excerpt-label{font-size:14px;font-weight:700}
.request-value,.response-excerpt{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;font:16px/1.8 var(--mono);padding:16px;background:white;border:1px solid #d4e0e5;border-radius:7px;margin:8px 0 18px}
.request-value{font-size:19px;color:#174956;min-height:68px}.response-excerpt{max-height:300px;overflow:auto;min-height:180px}
.response-excerpt mark{background:#ffe3a3;color:#473007;border-radius:3px;padding:1px 2px}.response-stats{display:flex;justify-content:space-between;gap:12px;font-size:17px}
.response-stats b{font-size:22px}.response-card .technical{font-size:14px;overflow-wrap:anywhere}.response-card code{white-space:normal}
.evidence-takeaway{margin-top:18px;border:1px solid #b3d3d5;border-left:5px solid var(--accent);border-radius:10px;padding:22px 26px;background:#eaf6f5}
.evidence-takeaway h3{font-size:24px;margin:10px 0}.evidence-takeaway p{font-size:18px;margin:10px 0}.evidence-takeaway .evidence-limit{font-size:16px;border-top:1px solid #bed8d9;padding-top:12px;color:#405964}
.projector-toggle{display:none}.enhanced .projector-toggle{display:inline-flex}
.projector-nav{display:none;gap:8px;flex-wrap:wrap}.projector-nav a{padding:8px 12px;border-radius:7px;font-size:17px;font-weight:700}
.projector-nav a:hover,.projector-nav a[aria-current=page]{background:#e5f3f2;color:var(--accent)}
.projector .projector-nav{display:flex}.projector .crumb,.projector .snapshot-badge{display:none}
.projector .topbar{position:sticky;top:0;z-index:20;flex-wrap:wrap;box-shadow:0 2px 12px #152e3d0a}
.projector .sidebar{display:none}.projector .workspace{margin-left:0}.projector .main-content{max-width:1500px}
.projector .subtitle,.projector .plain-intro,.projector .evidence-item p,.projector .comparison-card p,
.projector .evidence-takeaway p,.projector .payload-body p{font-size:20px}
.projector .panel-desc,.projector .analysis-stage p,.projector .comparison-top,.projector .state,.projector .family-tag{font-size:17px}
.projector h1.page-title{font-size:42px}.projector .presentation-hero h1{font-size:56px}.projector .response-excerpt{font-size:18px}
@media(max-width:1150px){.topbar .crumb{display:none}.comparison-grid{grid-template-columns:1fr}.comparison-card h3{min-height:0}
 .overview-grid{grid-template-columns:1fr}.map-branches{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:850px){.sidebar nav{grid-template-columns:repeat(2,minmax(0,1fr));display:grid}
 .response-comparison,.spotlight-grid{grid-template-columns:1fr}
 .evidence-counts{gap:8px;padding-inline:16px}.evidence-count{padding-inline:10px}.main-content{padding:22px 18px}}
@media(max-width:600px){.sidebar nav a{font-size:14px}.story-route{grid-template-columns:1fr;gap:12px}
 .evidence-counts{grid-template-columns:1fr}.evidence-count{display:grid;grid-template-columns:1fr auto;gap:5px 20px}
 .evidence-count strong{font-size:28px}.evidence-count p{grid-column:1/-1}.status-track{grid-column:1/-1}
 .map-canvas{display:block}.map-root{display:none}.map-branches{grid-template-columns:1fr;padding-left:0;border:0}
 .endpoint-node:before{display:none}.candidate-node .node-name{max-width:none}.analysis-stage{padding:10px}
 .stage-count{font-size:40px}.analysis-stage h3{font-size:16px}.stage-top{flex-wrap:wrap}.finding{padding:18px}
 .finding .fhead{flex-wrap:wrap}.finding .meterwrap{max-width:none}.response-card{padding:16px}
 .projector h1.page-title,.projector .presentation-hero h1{font-size:32px}.top-actions{gap:8px}}
@media(prefers-reduced-motion:no-preference){.report-page.active{animation:page-arrive .22s ease-out}
 @keyframes page-arrive{from{opacity:.5;transform:translateY(5px)}to{opacity:1;transform:none}}}
@media print{.projector-nav,.projector-toggle{display:none!important}.response-excerpt{max-height:none;overflow:visible}
 .spotlight-grid,.response-comparison{grid-template-columns:1fr 1fr}.response-card{break-inside:avoid}}
"""

STYLE += """
/* Baseline -> Probe change, read at a glance; then the reason, then the caveat. */
.comparison-lead{margin:20px 0 8px}
.cmp-flow{display:flex;align-items:stretch;gap:16px;flex-wrap:wrap}
.cmp-chip{flex:1;min-width:210px;border:1px solid #bfd0d6;border-radius:13px;background:#fff;
 padding:18px 24px;display:flex;flex-direction:column;gap:5px;box-shadow:0 2px 6px #17384c05}
.cmp-chip .cmp-role{font-size:14px;font-weight:700;color:var(--muted);letter-spacing:.2px}
.cmp-chip b{font-size:38px;font-weight:800;letter-spacing:-1.2px;line-height:1.05;
 font-variant-numeric:tabular-nums;color:#2c4a55}
.cmp-chip small{font-size:15px;color:var(--muted)}
.cmp-chip.probe{border-top:5px solid #5a7788}
.cmp-chip.probe.changed{border-color:#d98a3d;border-top-color:#c05f22;background:#fffaf3}
.cmp-chip.probe.changed b{color:#b0500f}
.cmp-arrow{flex:0 0 auto;align-self:center;text-align:center;color:var(--muted);padding:0 4px}
.cmp-arrow .cmp-arrow-mark{display:block;font-size:36px;line-height:1;color:#9fb2bb}
.cmp-arrow em{font-style:normal;font-size:14px;font-weight:800;letter-spacing:.3px;display:block;margin-top:4px}
.cmp-arrow.hot .cmp-arrow-mark{color:#c05f22}.cmp-arrow.hot em{color:#b0500f}
.cmp-clue{margin-top:16px;border-radius:13px;padding:20px 26px;border:1px solid #e6c78f;
 border-left:7px solid #c8862f;background:#fff8ec}
.cmp-clue.xss{border-color:#c6bfe9;border-left-color:#6253a8;background:#f6f4fd}
.cmp-clue .clue-tag{display:inline-block;font-size:14px;font-weight:800;letter-spacing:.4px;color:#9a5a13}
.cmp-clue.xss .clue-tag{color:#4b3e93}
.cmp-clue code{display:block;margin:11px 0 4px;font:600 21px/1.55 var(--mono);color:#5b2f05;background:#fff;
 border:1px solid #ecd6ad;border-radius:8px;padding:13px 17px;overflow-wrap:anywhere;word-break:break-word}
.cmp-clue p{font-size:17px;color:#4a6273;margin:8px 0 0;line-height:1.8}
.evidence-takeaway .reason-why,.evidence-takeaway .reason-limit{border-radius:11px;padding:15px 20px;margin-top:13px}
.evidence-takeaway .reason-why{background:#ecf6f5;border-left:5px solid var(--accent)}
.evidence-takeaway .reason-limit{background:#f7f3ea;border-left:5px solid #b9922f}
.evidence-takeaway .reason-why b,.evidence-takeaway .reason-limit b{display:block;font-size:15px;
 letter-spacing:.3px;margin-bottom:5px}
.evidence-takeaway .reason-why b{color:#0a6b6f}.evidence-takeaway .reason-limit b{color:#8a6a15}
.evidence-takeaway .reason-why p,.evidence-takeaway .reason-limit p{font-size:18px;line-height:1.85;margin:0;color:#3f5563}
/* A touch more air and size for lecture-room reading of the detail body. */
.detail-section{margin-top:32px}.detail-section h2{font-size:24px;margin-bottom:15px}
.plain-intro{font-size:18px;line-height:1.95}.response-excerpt,.request-value{font-size:17px}
.response-card h3{font-size:22px}.evidence-item p{font-size:17px;line-height:1.85}
@media(max-width:850px){.cmp-flow{gap:10px}.cmp-arrow{width:100%;padding:6px 0}.cmp-arrow .cmp-arrow-mark{transform:rotate(90deg)}
 .cmp-chip b{font-size:32px}.cmp-clue code{font-size:18px}}
.projector .cmp-chip b{font-size:44px}.projector .cmp-clue code{font-size:24px}
.projector .cmp-clue p,.projector .reason-why p,.projector .reason-limit p{font-size:21px}
/* Verification lift, shown as a value the audience can read off the header. */
.verify-delta{display:inline-flex;align-items:baseline;gap:10px;margin:6px 0 12px;padding:7px 15px;
 border-radius:999px;font-size:15px;background:#e8f5ef;border:1px solid #b8ddcd}
.verify-delta.down{background:#f3eef1;border-color:#dcc9d2}
.verify-delta b{font-size:20px;font-weight:800;color:#1c7a58;font-variant-numeric:tabular-nums;letter-spacing:-.3px}
.verify-delta.down b{color:#8a5a6a}
.verify-delta .vd-from{color:var(--muted)}
.verify-delta .vd-label{color:#1c7a58;font-weight:700}.verify-delta.down .vd-label{color:#8a5a6a}
.finding .meter{position:relative;overflow:visible}
.prior-tick{position:absolute;top:-5px;bottom:-5px;width:3px;background:#2f5566;border-radius:2px;transform:translateX(-1px)}
.projector .verify-delta{font-size:18px}.projector .verify-delta b{font-size:24px}
/* Ranked confidence bars: the audience sees the priority order in one glance. */
.priority-ranking{margin:26px 0}
.rank-list{padding:8px 24px 24px;display:flex;flex-direction:column;gap:12px}
.rank-row{display:grid;grid-template-columns:46px minmax(150px,1.3fr) minmax(120px,2.6fr) auto;
 align-items:center;gap:18px;padding:11px 14px;border-radius:11px;border:1px solid transparent}
.rank-row:hover{background:#eef7f6;border-color:#cfe4e1}
.rank-no{font:800 24px/1 var(--mono);color:#526b78;text-align:center}
.rank-name{font-size:17px;font-weight:700;min-width:0;line-height:1.5;overflow-wrap:anywhere}
.rank-name small{display:block;font-size:13px;font-weight:500;color:var(--muted);margin-top:2px}
.rank-name .family-dot{width:11px;height:11px;margin-right:9px}
.rank-bar{height:16px;background:#e9eff2;border-radius:9px;overflow:hidden}
.rank-bar i{display:block;height:100%;border-radius:9px;background:var(--accent)}
.rank-bar i.SQLI{background:var(--sqli)}.rank-bar i.REFLECTED_XSS{background:var(--xss)}
.rank-bar i.BROKEN_ACCESS_CONTROL{background:var(--bac)}
.rank-pct{font:800 27px/1 var(--mono);color:#2c4a55;font-variant-numeric:tabular-nums}
.rank-pct small{font-size:14px;color:var(--muted);margin-left:2px}
.projector .rank-name{font-size:20px}.projector .rank-pct{font-size:32px}.projector .rank-bar{height:20px}
@media(max-width:760px){.rank-row{grid-template-columns:34px 1fr auto;gap:11px}.rank-bar{display:none}
 .rank-pct{font-size:22px}}
@media print{.cmp-chip,.cmp-clue,.rank-row{break-inside:avoid}.cmp-arrow .cmp-arrow-mark{transform:none}}
"""

STYLE += """
/* --- v0.2 visual refinement -----------------------------------------------
   Flatter, editorial surfaces (no template gradients / fuzzy elevation) and
   stronger, colour-coded data cues so the priority story reads at a glance. */
:root{--edge:#d5dfe4;--edge-strong:#aebfc7;--surface:#fff;--surface-2:#f3f7f9;
 --sev-high:#b5473f;--sev-mid:#c08a2a;--sev-low:#5f7280}

/* 1. Strip the soft drop-shadows and card gradients that read as generic. */
.metric,.panel,.endpoint-node,.comparison-card,.cmp-chip,.spotlight-card,
.map-root-icon,.finding,.vpanel{box-shadow:none}
.analysis-journey,.comparison-card,.cmp-chip{background:var(--surface)}
.cmp-clue{background:#fbfcfd}.cmp-clue.xss{background:#fafbff}
.evidence-takeaway{background:#f1f7f7}

/* 2. One consistent, crisp card system: hairline edge, calm radius. */
.panel,.metric,.comparison-card,.endpoint-node,.evidence-item,.payload-card,
.finding,.reading-guide .panel,.vpanel,.fix,.source-caption{
 border-color:var(--edge);border-radius:10px}

/* 3. Metric tiles: a deliberate top rule + a bigger, tabular number. */
.metric{border-top:3px solid var(--edge-strong);padding-top:18px}
.metric.accent{border-top-color:var(--accent)}
.metric-value{font-size:40px;font-variant-numeric:tabular-nums}

/* 4. Discovery -> evidence strip: flat, with an accent spine and a solid
      "focus" endpoint instead of a gradient panel. */
.analysis-journey{border-left:4px solid var(--accent)}
.analysis-stage:last-child{background:#0f3d49}

/* 5. Section headings get a hairline divider -- structure without more text. */
.panel>.panel-head{border-bottom:1px solid var(--line);padding-bottom:15px}
.family-panel>.panel-head,.evidence-summary>.panel-head{border-bottom:0}

/* 6. Candidate table: colour-code each row by family; heavier score meter. */
.candidate-table td:first-child{border-left:4px solid var(--edge-strong)}
.candidate-table tr[data-family="SQLI"] td:first-child{border-left-color:var(--sqli)}
.candidate-table tr[data-family="REFLECTED_XSS"] td:first-child{border-left-color:var(--xss)}
.candidate-table tr[data-family="BROKEN_ACCESS_CONTROL"] td:first-child{border-left-color:var(--bac)}
.candidate-table tbody tr:hover{background:#f5fafb}
.mini-meter{width:104px;height:7px;background:#e6edf1}
.mini-meter i{background:var(--accent)}
.score-cell{color:var(--ink)}

/* 7. Family tag + legend dots: calmer chrome, bigger dots to actually read. */
.family-tag{background:var(--surface-2);border-color:var(--edge)}
.family-dot{width:9px;height:9px}
.map-legend .family-dot,.confidence-legend i{width:10px;height:10px}

/* 8. Comparison cards: a top accent rail, flat body, bolder figures. */
.comparison-card{border-top:3px solid var(--edge-strong)}
.confidence-values b{font-size:32px;font-variant-numeric:tabular-nums}

/* 9. Relationship map: firmer container, quieter branch nodes. */
.map-canvas{border-color:var(--edge);background-color:#fbfdfe}
.endpoint-node{border-color:var(--edge)}

/* 10. Evidence-summary counts: a real bar, not a whisper. */
.status-track{height:9px}
.evidence-count{border-left-width:5px}

/* 11. Primary button / accents: single confident accent, no gloss. */
.button.primary{background:var(--accent);border-color:var(--accent)}
.button.primary:hover{background:#0a5b63}

/* 12. Detail finding header: family accent rail so the type is unmissable. */
.finding{border-left:4px solid var(--accent)}

@media print{
 .analysis-stage:last-child{background:#fff}
 .candidate-table td:first-child{border-left-color:var(--edge-strong)!important}}
"""


STYLE += """
/* --- v0.2 visual layer: type icons, at-a-glance hero, confidence gauges ---- */
:root{--sqli-soft:#f4ecdd;--xss-soft:#efedf8;--bac-soft:#e4f1f0}

/* Type glyphs inherit the family colour wherever they appear. */
.fam-ico{width:17px;height:17px;flex:0 0 auto;vertical-align:-3px}
.family-tag{gap:8px;font-weight:650}
.family-tag.SQLI{color:var(--sqli)}
.family-tag.REFLECTED_XSS{color:var(--xss)}
.family-tag.BROKEN_ACCESS_CONTROL{color:var(--bac)}
.map-legend span.SQLI{color:var(--sqli)}
.map-legend span.REFLECTED_XSS{color:var(--xss)}
.map-legend span.BROKEN_ACCESS_CONTROL{color:var(--bac)}
.map-legend .fam-ico{width:14px;height:14px}
.fam.SQLI{color:var(--sqli)}.fam.REFLECTED_XSS{color:var(--xss)}.fam.BROKEN_ACCESS_CONTROL{color:var(--bac)}

/* "가장 먼저 확인할 곳" — the visual headline of the whole report. */
.risk-headline{margin-bottom:22px}
.risk-grid{display:grid;grid-template-columns:1.6fr 1fr 1fr;gap:14px;padding:6px 23px 24px}
.risk-card{display:flex;align-items:center;gap:16px;min-width:0;padding:18px 20px;
 border:1px solid var(--edge);border-left:5px solid var(--edge-strong);border-radius:12px;
 background:#fff;color:var(--ink)}
.risk-card:hover{background:#f6fafb}
.risk-card.SQLI{border-left-color:var(--sqli)}
.risk-card.REFLECTED_XSS{border-left-color:var(--xss)}
.risk-card.BROKEN_ACCESS_CONTROL{border-left-color:var(--bac)}
.risk-rank{font:800 15px/1 var(--mono);color:#9aa8b2;flex:0 0 auto}
.risk-ico{width:44px;height:44px;border-radius:12px;display:grid;place-items:center;flex:0 0 auto;
 background:var(--surface-2)}
.risk-ico .fam-ico{width:24px;height:24px}
.risk-card.SQLI .risk-ico{color:var(--sqli);background:var(--sqli-soft)}
.risk-card.REFLECTED_XSS .risk-ico{color:var(--xss);background:var(--xss-soft)}
.risk-card.BROKEN_ACCESS_CONTROL .risk-ico{color:var(--bac);background:var(--bac-soft)}
.risk-main{min-width:0;flex:1;display:flex;flex-direction:column;gap:2px}
.risk-fam{font-size:12px;font-weight:800;letter-spacing:.4px;color:var(--muted)}
.risk-loc{font-size:16px;font-weight:700;line-height:1.4;overflow-wrap:anywhere}
.risk-say{font-size:13px;color:var(--muted);margin:7px 0 0;line-height:1.65}
.risk-gauge{position:relative;width:74px;height:74px;flex:0 0 auto}
.risk-gauge svg{width:74px;height:74px;transform:rotate(-90deg)}
.risk-gauge .g-bg{fill:none;stroke:#e7eef1;stroke-width:3.2}
.risk-gauge .g-fg{fill:none;stroke:var(--accent);stroke-width:3.2;stroke-linecap:round}
.risk-card.SQLI .g-fg{stroke:var(--sqli)}
.risk-card.REFLECTED_XSS .g-fg{stroke:var(--xss)}
.risk-card.BROKEN_ACCESS_CONTROL .g-fg{stroke:var(--bac)}
.risk-pct{position:absolute;inset:0;display:grid;place-content:center;text-align:center;line-height:1}
.risk-pct b{font:800 21px/1 var(--mono);color:var(--ink);font-variant-numeric:tabular-nums}
.risk-pct small{font-size:11px;color:var(--muted)}
.risk-card.lead .risk-loc{font-size:19px}
.risk-card.lead .risk-ico{width:52px;height:52px}.risk-card.lead .risk-ico .fam-ico{width:28px;height:28px}
.risk-card.lead .risk-gauge,.risk-card.lead .risk-gauge svg{width:86px;height:86px}
.risk-card.lead .risk-pct b{font-size:25px}
.projector .risk-loc{font-size:18px}.projector .risk-card.lead .risk-loc{font-size:22px}

/* Detail header: a big family glyph makes the type unmistakable. */
.finding .vtype{display:flex;align-items:center;gap:12px}
.finding .vtype .fam{display:inline-grid;place-items:center;width:40px;height:40px;border-radius:11px;
 background:var(--surface-2);flex:0 0 auto}
.finding .vtype .fam-ico{width:24px;height:24px}

@media(max-width:1000px){.risk-grid{grid-template-columns:1fr 1fr}.risk-card.lead{grid-column:1/-1}}
@media(max-width:640px){.risk-grid{grid-template-columns:1fr}.risk-card{padding:15px 16px;gap:12px}
 .risk-card.lead .risk-gauge,.risk-card.lead .risk-gauge svg{width:74px;height:74px}
 .risk-gauge,.risk-gauge svg{width:64px;height:64px}}
@media print{.risk-card{break-inside:avoid}}
"""


STYLE += """
/* The dashboard->DemoShop live "취약점 검증" launcher (demo only). */
.verify-live{background:#b0500f;border-color:#b0500f;white-space:nowrap}
.verify-live:hover{background:#933f08;border-color:#933f08}
.page-heading .verify-live{flex:0 0 auto}
"""


# No report data is interpolated into JavaScript; all data comes from escaped DOM.
SCRIPT = """(() => {
  'use strict';
  const pages = Array.from(document.querySelectorAll('.report-page'));
  const nav = Array.from(document.querySelectorAll('.sidebar nav a, .projector-nav a'));
  function route(focus) {
    const id = location.hash.slice(1);
    const page = pages.find(p => p.id === id) || document.getElementById('overview');
    pages.forEach(p => p.classList.toggle('active', p === page));
    nav.forEach(a => {
      const current = a.hash === '#' + page.id ||
        (page.id.startsWith('candidate-') && a.hash === '#candidates') ||
        (page.id.startsWith('ac-candidate-') && a.hash === '#ac-candidates');
      if (current) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
    const heading = page.querySelector('h1');
    document.querySelector('.skip-link').setAttribute('href', '#' + page.id);
    document.title = (heading ? heading.textContent : '분석 개요') + ' · VulnSpider';
    document.getElementById('current-page').textContent = heading ? heading.textContent : '분석 개요';
    if (focus && heading) { heading.focus({preventScroll:true}); window.scrollTo(0, 0); }
  }
  route(false);
  document.body.classList.add('enhanced');
  window.addEventListener('hashchange', () => route(true));
  document.querySelector('.skip-link').addEventListener('click', event => {
    event.preventDefault();
    const heading = document.querySelector('.report-page.active h1');
    if (heading) heading.focus();
  });
  document.querySelector('[data-print]').addEventListener('click', () => window.print());
  const projector = document.querySelector('[data-projector]');
  projector.addEventListener('click', () => {
    const enabled = document.body.classList.toggle('projector');
    projector.setAttribute('aria-pressed', String(enabled));
    projector.textContent = enabled ? '기본 화면으로' : '화면 크게';
  });
  const search = document.getElementById('candidate-search');
  const family = document.getElementById('family-filter');
  const state = document.getElementById('state-filter');
  const rows = Array.from(document.querySelectorAll('#candidate-list tbody tr'));
  function filter() {
    const query = search.value.trim().toLocaleLowerCase();
    let count = 0;
    rows.forEach(row => {
      const match = row.textContent.toLocaleLowerCase().includes(query) &&
        (!family.value || row.dataset.family === family.value) &&
        (!state.value || row.dataset.state === state.value);
      row.hidden = !match;
      if (match) count++;
    });
    document.getElementById('filter-count').textContent = count + ' / ' + rows.length + '개 표시';
    document.getElementById('filter-empty').hidden = count !== 0;
  }
  search.addEventListener('input', filter);
  family.addEventListener('change', filter);
  state.addEventListener('change', filter);
  document.getElementById('reset-filters').addEventListener('click', () => {
    search.value = ''; family.value = ''; state.value = ''; filter(); search.focus();
  });
  filter();
})();"""
