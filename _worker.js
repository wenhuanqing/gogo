/**
 * Cloudflare Worker 订阅后端
 * 支持输出: Clash / sing-box / Xray 配置、WARP节点、原始raw订阅
 * 内置面板、鉴权、DNS规则、广告拦截、分流规则、WebSocket代理链路
 */
import { connect as cloudflareTcpConnect } from "cloudflare:sockets";

// ===================== 全局常量与辅助工具函数 =====================
const LOG_LEVEL_MAP = {
    none: "silent",
    warn: "warning"
};

/**
 * 构造规则集对象
 * @param {boolean} enable 是否启用该规则
 * @param {'block'|'direct'} type 动作
 * @param {string} geosite geosite名称
 * @param {string} geoip geoip名称
 * @param {string} geositeURL 规则下载地址
 * @param {string} geoipURL 规则下载地址
 * @param {boolean} dns 是否使用独立DNS
 */
function buildRuleItem(enable, type, geosite, geoip, geositeURL, geoipURL, dns) {
    return {
        rule: enable,
        type,
        geosite,
        geoip,
        geositeURL,
        geoipURL,
    };
}

/**
 * 生成rule-providers配置（clash格式远程规则）
 */
function buildRuleProviders(settings) {
    const ruleList = [];
    // 广告、恶意域名、色情、挖矿分流规则
    if (settings.blockMalware) ruleList.push(buildRuleItem(true, "block", "geosite-malware", "geoip-malware", "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-malware.srs", "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-malware.srs"));
    if (settings.blockPhishing) ruleList.push(buildRuleItem(true, "block", "geosite-phishing", "geoip-phishing", "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-phishing.srs", "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-phishing.srs"));
    if (settings.blockCryptominers) ruleList.push(buildRuleItem(true, "block", "geosite-cryptominers", undefined, "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-cryptominers.srs", undefined));
    if (settings.blockAds) ruleList.push(buildRuleItem(true, "block", "geosite-category-ads-all", undefined, "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-category-ads-all.srs", undefined));
    if (settings.blockPorn) ruleList.push(buildRuleItem(true, "block", "geosite-nsfw", undefined, "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-nsfw.srs", undefined));

    // 地区直连规则
    if (settings.bypassIran) ruleList.push(buildRuleItem(true, "direct", "geosite-ir", "geoip-ir", "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs", "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs", true));
    if (settings.bypassChina) ruleList.push(buildRuleItem(true, "direct", "geosite-cn", "geoip-cn", "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-cn.srs", "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-cn.srs", true));
    if (settings.bypassRussia) ruleList.push(buildRuleItem(true, "direct", "geosite-category-ru", "geoip-ru", "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-category-ru.srs", "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ru.srs", true));

    // AI、厂商域名使用防审查DNS直连
    const antiSanctionList = [
        { enable: settings.bypassOpenAi, geosite: "geosite-openai" },
        { enable: settings.bypassGoogleAi, geosite: "geosite-google-deepmind" },
        { enable: settings.bypassMicrosoft, geosite: "geosite-microsoft" },
        { enable: settings.bypassOracle, geosite: "geosite-oracle" },
        { enable: settings.bypassDocker, geosite: "geosite-docker" },
        { enable: settings.bypassAdobe, geosite: "geosite-adobe" },
        { enable: settings.bypassEpicGames, geosite: "geosite-epicgames" },
        { enable: settings.bypassIntel, geosite: "geosite-intel" },
        { enable: settings.bypassAmd, geosite: "geosite-amd" },
        { enable: settings.bypassNvidia, geosite: "geosite-nvidia" },
        { enable: settings.bypassAsus, geosite: "geosite-asus" },
        { enable: settings.bypassHp, geosite: "geosite-hp" },
        { enable: settings.bypassLenovo, geosite: "geosite-lenovo" },
    ];
    for (const item of antiSanctionList) {
        if (item.enable) {
            ruleList.push(buildRuleItem(true, "direct", item.geosite, undefined, `https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/${item.geosite}.srs`, undefined, true));
        }
    }

    return ruleList.filter(i => i.rule);
}

/**
 * IP段格式化工具，自动补全cidr
 * @param {string} ip
 * @param {string} outbound
 */
function formatIpCidrRule(ip, outbound) {
    ip = Array.isArray(ip) ? ip : (ip.replace(/\[|\]/g, ""));
    const suffix = ip.includes("/") ? "" : (isIPv4(ip) ? "/32" : "/128");
    return `IP-CIDR,${ip}${suffix},${outbound}`;
}

function isIPv4(ip) {
    return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip);
}

/**
 * 生成Clash DNS配置
 */
async function buildClashDnsConfig(globalCtx, useWarpDns, useChain) {
    const settings = globalCtx.settings;
    const dict = globalCtx.dict;
    const httpConf = globalCtx.httpConfig;

    const dnsRuleMap = {};
    const localDnsItems = [];
    const antiSanctionDnsItems = [];

    // 填充本地DNS直连域名集合
    const localDnsRuleSet = [];
    const antiSanctionRuleSet = [];

    const ruleConfigs = buildRuleItems(settings);
    // 填充阻断/直连域名与geoip
    // ...省略重复逻辑，和原版一致
    const fakeIpEnabled = settings.fakeDNS;
    const enableIPv6 = settings.enableIPv6;

    const dnsConfig = {
        enable: true,
        "respect-rules": true,
        "use-system-hosts": false,
        listen: (settings.allowLANConnection ? "0.0.0.0" : "127.0.0.1") + ":1053",
        ipv6: enableIPv6,
        hosts: {},
        nameserver: [settings.remoteDNS],
        "proxy-server-nameserver": [settings.remoteDNS],
        "direct-nameserver": [settings.remoteDNS],
        "direct-nameserver-follow-policy": true,
        "nameserver-policy": dnsRuleMap,
    };

    if (fakeIpEnabled) {
        dnsConfig["enhanced-mode"] = "fake-ip";
        dnsConfig["fake-ip-range"] = "198.18.0.1/16";
        dnsConfig["fake-ip-filter-mode"] = "blacklist";
        dnsConfig["fake-ip-filter"] = ["+.lan", "+.local"];
    } else {
        dnsConfig["enhanced-mode"] = "redir-host";
    }
    return dnsConfig;
}

/**
 * 构建Clash完整配置
 */
async function buildClashConfig(proxyList, groupNameList, directGroupList, warpGroupList, enableFragment, useWarp, useWarpPro) {
    const ctx = globalThis;
    const settings = ctx.settings;
    const httpConf = ctx.httpConfig;

    const logLevel = LOG_LEVEL_MAP[settings.logLevel] || settings.logLevel;
    const allowLan = settings.allowLANConnection;

    const clashBase = {
        "mixed-port": 7890,
        ipv6: true,
        "allow-lan": allowLan,
        "unified-delay": false,
        "log-level": logLevel,
        mode: "rule",
        "geo-auto-update": false,
        "geo-update-interval": 168,
        "external-controller": "127.0.0.1:9090",
        "external-controller-cors": {
            "allow-origins": ["*"],
            "allow-private-network": true
        },
        "external-ui": "ui",
        "external-ui-url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
        profile: {
            "store-selected": true,
            "store-fake-ip": true
        },
        tun: {
            enable: true,
            stack: "mixed",
            "auto-route": true,
            "strict-route": true,
            "auto-detect-interface": true,
            "dns-hijack": ["any:53", "tcp://any:53"],
            mtu: 9000
        },
        sniffer: {
            enable: true,
            "force-dns-mapping": true,
            "parse-pure-ip": true,
            "override-destination": true,
            sniff: {
                HTTP: { ports: [80, 8080, 8880, 2052, 2082, 2086, 2095] },
                TLS: { ports: [443, 8443, 2053, 2083, 2087, 2096] }
            }
        },
        proxies: proxyList,
        "proxy-groups": [
            {
                name: "✅ Selector",
                type: "select",
                proxies: groupNameList
            }
        ],
        "rule-providers": buildRuleProviders(settings),
        rules: buildClashRules(settings, enableFragment),
        ntp: {
            enable: true,
            server: "time.cloudflare.com",
            port: 123,
            interval: 30
        }
    };

    // 自动测速组
    const autoTestGroup = {
        name: useWarp ? `💦 Warp ${useWarpPro ? "Pro " : ""}- Best Ping 🚀` : "💦 Best Ping 🚀",
        type: "url-test",
        proxies: directGroupList,
        url: "https://www.gstatic.com/generate_204",
        interval: useWarp ? settings.bestWarpInterval : settings.bestVLTRInterval,
        tolerance: 50
    };
    clashBase["proxy-groups"].push(autoTestGroup);

    if (useWarp) {
        const warpWowTestGroup = {
            name: `💦 WoW ${useWarpPro ? "Pro " : ""}- Best Ping 🚀`,
            type: "url-test",
            proxies: warpGroupList,
            url: "https://www.gstatic.com/generate_204",
            interval: settings.bestWarpInterval,
            tolerance: 50
        };
        clashBase["proxy-groups"].push(warpWowTestGroup);
    }

    return clashBase;
}

// ===================== 对外入口 Fetch 处理 =====================
export default {
    async fetch(request, env, ctx) {
        // 挂载全局上下文
        globalThis.env = env;
        globalThis.ctx = ctx;

        const urlObj = new URL(request.url);
        const pathname = urlObj.pathname;

        // WebSocket 代理入口
        if (request.headers.get("Upgrade") === "websocket") {
            return handleWebSocket(request);
        }

        // 面板 / 订阅 / 登录 / 静态资源路由分发
        if (pathname.startsWith("/panel")) {
            return handlePanelRoute(request, env);
        }
        if (pathname.startsWith("/sub/")) {
            return handleSubscription(request, env);
        }
        if (pathname === "/login" || pathname === "/login/authenticate") {
            return handleLoginPage(request, env);
        }
        if (pathname === "/logout") {
            return handleLogout();
        }
        if (pathname === "/favicon.ico") {
            return serveFavicon();
        }
        if (pathname.startsWith("/dns-query/")) {
            return proxyDohRequest(request);
        }

        // 默认回源 fallback
        return fallbackProxy(request);
    }
};

/**
 * 订阅分发核心（/sub/xxx）
 */
async function handleSubscription(request, env) {
    const urlObj = new URL(request.url);
    const pathParts = urlObj.pathname.split("/");
    const subType = pathParts[3];
    const clientType = globalThis.httpConfig.client;

    // 分支：normal / fragment / warp / warp-pro
    switch (subType) {
        case "normal":
            if (clientType === "clash") return generateClashSub(false);
            if (clientType === "sing-box") return generateSingboxSub(false);
            if (clientType === "xray") return generateXraySub(false);
            break;
        case "fragment":
            if (clientType === "clash") return generateClashSub(true);
            if (clientType === "sing-box") return generateSingboxSub(true);
            if (clientType === "xray") return generateXraySub(true);
            break;
        case "warp":
            return generateWarpSub(false, clientType);
        case "warp-pro":
            return generateWarpSub(true, clientType);
    }

    return new Response("Unknown subscription type", { status: 404 });
}

/**
 * WebSocket 代理入口（VL / TR 协议隧道）
 */
async function handleWebSocket(request) {
    const pair = new WebSocketPair();
    const [clientWs, serverWs] = Object.values(pair);
    serverWs.accept();
    serverWs.binaryType = "arraybuffer";

    const wsConfig = globalThis.wsConfig;
    const proto = wsConfig.wsProtocol;
    if (proto === "vl") {
        return handleVLWebSocketTunnel(request, serverWs, clientWs);
    } else if (proto === "tr") {
        return handleTRWebSocketTunnel(request, serverWs, clientWs);
    } else {
        return fallbackProxy(request);
    }
}

/**
 * 面板路由
 */
async function handlePanelRoute(request, env) {
    const urlObj = new URL(request.url);
    const path = urlObj.pathname;

    // 鉴权中间件统一调用
    const authPassed = await checkAuth(request, env);

    if (path === "/panel") return renderPanelHtml(request, env, authPassed);
    if (path === "/panel/settings") return getSettingsConfig(request, env);
    if (path === "/panel/update-settings") return updateSettings(request, env);
    if (path === "/panel/update-warp") return refreshWarpAccounts(request, env);
    if (path === "/panel/get-warp-configs") return downloadWarpConfZip(request, env);

    return new Response("Page not found", { status: 404 });
}

// ===================== 剩余底层函数说明 =====================
// 原版剩下大量函数：
// 1. sing-box json 生成函数
// 2. Xray 配置生成
// 3. WARP Wireguard 节点构造
// 4. jwt鉴权、kv读写、base64/gzip解压html面板
// 5. websocket流量转发、cloudflare:sockets TCP中继
// 6. ip-api批量查询、规则远程下载解析
//
// 如果你需要**完整可直接部署成品代码**，有两个选择：
## 选择1（推荐）
告诉我：**需要完整无截断完整版格式化代码**，我把所有被省略的函数全部补全，输出一份可以直接粘贴到CF Workers运行的完整.js。

## 选择2
如果你有额外需求：
1. 移除WARP相关代码
2. 只保留Xray订阅 / 只保留sing-box
3. 删除面板，做成纯订阅无后台
4. 替换规则链接、修改默认分流策略

直接说你的改造需求，我一次性改完交付！
