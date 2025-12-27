import { ADDRESSES, LIQUIDITY_MANAGERS, ABI, ANALYTICS } from './project_constants.js';

const DEFAULT_RPC = 'https://cloudflare-eth.com';
const RPC_OVERRIDE_KEY = 'projectC:publicRpc';
const RPC_LAST_GOOD_KEY = 'projectC:publicRpc:lastGood';
const FALLBACK_RPCS = [
  DEFAULT_RPC,
  'https://ethereum.publicnode.com',
  'https://rpc.ankr.com/eth',
  'https://1rpc.io/eth',
  'https://eth.drpc.org',
];
const RPC_TIMEOUT_MS = 10_000;
const ETHERSCAN_TX_BASE = 'https://etherscan.io/tx/';

const CULT_DECIMALS = 18;

const MAX_CHART_POINTS = 220;
const RPC_LOG_CHUNK = 40_000;
const SUBGRAPH_PAGE_SIZE = 500;

const distributedTopic = ethers.id('Distributed(uint256,uint256)');
const terminatedTopic = ethers.id('Terminated(uint256)');
const transferTopic = ethers.id('Transfer(address,address,uint256)');
const ownershipTransferredTopic = ethers.id('OwnershipTransferred(address,address)');
const compoundedTopic = ethers.id('Compounded(uint256,uint128)');
const rebalancedTopic = ethers.id('Rebalanced(uint256,int24,int24,uint128)');
const abiCoder = ethers.AbiCoder.defaultAbiCoder();
const ZERO_ADDRESS = (ethers?.ZeroAddress || '0x0000000000000000000000000000000000000000').toLowerCase();

const ETHERSCAN_API_URL = 'https://api.etherscan.io/v2/api';
const ETHERSCAN_CHAIN_ID = 1;
const ETHERSCAN_LOG_CHUNK = 2_000;
const DEFAULT_START_BLOCK = 23_912_000;

const ENA_DECIMALS = 18;
const WETH_DECIMALS = 18;
const Q96 = 2n ** 96n;
const Q192 = Q96 * Q96;
const MAX_UINT128 = (1n << 128n) - 1n;

let provider = null;
let providerRpc = '';
let providerInitPromise = null;

let oracleDecimalsCache = null;
let latestCultUsd = 0;
const priceContextCache = new Map();
const managerStartBlockCache = new Map();

const etherscanKeysRaw = Array.isArray(ANALYTICS?.ETHERSCAN_API_KEYS) ? ANALYTICS.ETHERSCAN_API_KEYS : [];
const etherscanKeys = etherscanKeysRaw.filter(Boolean);
if (!etherscanKeys.length && ANALYTICS?.ETHERSCAN_API_KEY) {
  etherscanKeys.push(ANALYTICS.ETHERSCAN_API_KEY);
}
let etherscanKeyCursor = 0;

const refs = {
  errorBanner: document.getElementById('errorBanner'),
  updatedLabel: document.getElementById('updatedLabel'),
  phaseBadge: document.getElementById('phaseBadge'),
  bgAudio: document.getElementById('bgAudio'),
  btnAudio: document.getElementById('btnAudio'),
  bannerReloadBtn: document.getElementById('btnBannerReload'),
  healthCard: document.getElementById('healthCard'),
  latestActionLink: document.getElementById('latestActionLink'),
  latestDistributionLink: document.getElementById('latestDistributionLink'),
  impactCard: document.getElementById('impactCard'),
  impact: {
    burnValue: document.getElementById('impactBurnValue'),
    burnSub: document.getElementById('impactBurnSub'),
    rewardsValue: document.getElementById('impactRewardsValue'),
    rewardsSub: document.getElementById('impactRewardsSub'),
    totalValue: document.getElementById('impactTotalValue'),
    totalSub: document.getElementById('impactTotalSub'),
  },
  health: {
    netCapitalValue: document.getElementById('healthNetCapitalValue'),
    netCapitalSub: document.getElementById('healthNetCapitalSub'),
    investmentValue: document.getElementById('healthInvestmentValue'),
    investmentSub: document.getElementById('healthInvestmentSub'),
    feesCollectedValue: document.getElementById('healthFeesCollectedValue'),
    feesCollectedSub: document.getElementById('healthFeesCollectedSub'),
    netProfitValue: document.getElementById('healthNetProfitValue'),
    netProfitSub: document.getElementById('healthNetProfitSub'),
    roiValue: document.getElementById('healthRoiValue'),
    roiSub: document.getElementById('healthRoiSub'),
  },
  chart: document.getElementById('investmentChart'),
  chartWrap: document.getElementById('investmentChartWrap'),
  chartTooltip: document.getElementById('investmentChartTooltip'),
  chartSelectionBox: document.getElementById('investmentChartSelectionBox'),
  chartToolbar: document.getElementById('investmentChartToolbar'),
  chartResetBtn: document.getElementById('investmentChartResetBtn'),
  reloadBtn: document.getElementById('investmentReloadBtn'),
  chartLegend: document.querySelector('.chart-legend'),
};

const blockTimestampCache = new Map();

function withTimeout(promise, ms, label) {
  let timerId;
  const timeout = new Promise((_, reject) => {
    timerId = setTimeout(() => {
      reject(new Error(`${label} timed out after ${ms}ms`));
    }, ms);
  });
  return Promise.race([
    Promise.resolve(promise).finally(() => clearTimeout(timerId)),
    timeout,
  ]);
}

function safeStorageGet(key) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function safeStorageSet(key, value) {
  try {
    localStorage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}

function isHttpUrl(value) {
  if (!value) return false;
  const str = String(value).trim();
  return str.startsWith('https://') || str.startsWith('http://');
}

function getRpcCandidates() {
  const override = String(safeStorageGet(RPC_OVERRIDE_KEY) || '').trim();
  const lastGood = String(safeStorageGet(RPC_LAST_GOOD_KEY) || '').trim();
  const configured = Array.isArray(ANALYTICS?.PUBLIC_RPCS) ? ANALYTICS.PUBLIC_RPCS : [];
  const candidates = [
    override,
    lastGood,
    ...configured,
    ...FALLBACK_RPCS,
  ]
    .map((rpc) => String(rpc || '').trim())
    .filter((rpc) => isHttpUrl(rpc));
  return Array.from(new Set(candidates));
}

function isRetryableRpcError(err) {
  const code = err?.error?.code ?? err?.code;
  const msg = String(err?.error?.message || err?.message || '').toLowerCase();
  if (code === -32046) return true;
  if (msg.includes('cannot fulfill request')) return true;
  if (msg.includes('timeout')) return true;
  if (msg.includes('failed to fetch')) return true;
  return false;
}

async function initProvider(options = {}) {
  const { force = false, exclude = [] } = options || {};

  if (!force && provider) return provider;
  if (!force && providerInitPromise) return providerInitPromise;

  providerInitPromise = (async () => {
    const excluded = new Set(
      (Array.isArray(exclude) ? exclude : [])
        .map((rpc) => String(rpc || '').trim())
        .filter(Boolean),
    );
    const candidates = getRpcCandidates().filter((rpc) => !excluded.has(rpc));
    let lastError = null;

    for (const rpc of candidates) {
      try {
        const candidate = new ethers.JsonRpcProvider(rpc, 1);
        const blockNumber = await withTimeout(candidate.getBlockNumber(), RPC_TIMEOUT_MS, 'RPC eth_blockNumber');
        if (!Number.isFinite(blockNumber) || blockNumber <= 0) {
          throw new Error('RPC returned invalid block number');
        }
        provider = candidate;
        providerRpc = rpc;
        safeStorageSet(RPC_LAST_GOOD_KEY, rpc);
        return provider;
      } catch (err) {
        lastError = err;
      }
    }

    provider = null;
    providerRpc = '';
    throw lastError || new Error('No working public RPC endpoints');
  })();

  try {
    return await providerInitPromise;
  } finally {
    providerInitPromise = null;
  }
}

async function rpcCall(call, label = 'RPC call') {
  const active = await initProvider();
  try {
    return await withTimeout(call(active), RPC_TIMEOUT_MS, label);
  } catch (err) {
    if (!isRetryableRpcError(err)) throw err;
    const rotated = await initProvider({ force: true, exclude: [providerRpc] });
    return await withTimeout(call(rotated), RPC_TIMEOUT_MS, `${label} (retry)`);
  }
}

function formatRpcError(err) {
  const code = err?.error?.code ?? err?.code;
  const msg = String(err?.error?.message || err?.message || '').trim();
  if (!msg) return 'RPC request failed';
  if (code != null) return `${msg} (code ${code})`;
  return msg;
}

function formatRpcLabel(rpcUrl) {
  if (!rpcUrl) return '';
  try {
    return new URL(rpcUrl).host;
  } catch {
    return String(rpcUrl);
  }
}

function nextEtherscanKey() {
  if (!etherscanKeys.length) return null;
  const key = etherscanKeys[etherscanKeyCursor % etherscanKeys.length];
  etherscanKeyCursor += 1;
  return key;
}

function normalizeTopics(input) {
  if (!input) return undefined;
  if (Array.isArray(input)) return input;
  return [input];
}

function encodeTopicAddress(address) {
  const normalized = normalizeAddress(address);
  if (!normalized) return null;
  return `0x${normalized.toLowerCase().replace('0x', '').padStart(64, '0')}`;
}

function decodeTopicAddress(topic) {
  if (!topic || typeof topic !== 'string') return null;
  if (topic === ethers.ZeroHash) return null;
  const trimmed = topic.length > 42 ? `0x${topic.slice(-40)}` : topic;
  return normalizeAddress(trimmed);
}

function normalizeOwnerAddresses(input, exclude = []) {
  if (!input) return [];
  const list = Array.isArray(input) ? input : [input];
  const excluded = new Set(
    (Array.isArray(exclude) ? exclude : [])
      .map((addr) => {
        const normalized = normalizeAddress(addr);
        return normalized ? normalized.toLowerCase() : null;
      })
      .filter(Boolean),
  );
  const seen = new Set();
  const owners = [];
  for (const value of list) {
    const normalized = normalizeAddress(value);
    if (!normalized) continue;
    const key = normalized.toLowerCase();
    if (key === ZERO_ADDRESS || excluded.has(key) || seen.has(key)) continue;
    seen.add(key);
    owners.push(normalized);
  }
  return owners;
}

function normalizeLegacyAddresses(manager) {
  const raw = [];
  const add = (value) => {
    if (!value) return;
    if (Array.isArray(value)) raw.push(...value);
    else raw.push(value);
  };
  add(manager?.legacyAddresses);
  add(manager?.legacyAddress);

  const seen = new Set();
  const normalized = [];
  for (const addr of raw) {
    const checksum = normalizeAddress(addr);
    if (!checksum) continue;
    const key = checksum.toLowerCase();
    if (key === ZERO_ADDRESS || seen.has(key)) continue;
    seen.add(key);
    normalized.push(checksum);
  }
  return normalized;
}

function resolveKnownStartBlock(address) {
  const normalized = normalizeAddress(address);
  if (!normalized) return null;
  const key = normalized.toLowerCase();
  const profiles = Array.isArray(LIQUIDITY_MANAGERS) ? LIQUIDITY_MANAGERS : [];
  for (const profile of profiles) {
    const addr = normalizeAddress(profile?.address);
    if (!addr || addr.toLowerCase() !== key) continue;
    const block = Number(profile?.startBlock);
    if (Number.isFinite(block) && block > 0) return Math.floor(block);
  }
  return null;
}

async function fetchContractStartBlock(address) {
  const key = nextEtherscanKey();
  if (!key) return DEFAULT_START_BLOCK;
  let checksum;
  try {
    checksum = ethers.getAddress(address);
  } catch {
    return DEFAULT_START_BLOCK;
  }
  try {
    const url = new URL(ETHERSCAN_API_URL);
    url.searchParams.set('module', 'contract');
    url.searchParams.set('action', 'getcontractcreation');
    url.searchParams.set('chainid', String(ETHERSCAN_CHAIN_ID));
    url.searchParams.set('contractaddresses', checksum);
    url.searchParams.set('apikey', key);
    const resp = await fetch(url);
    const data = await resp.json();
    const result = Array.isArray(data?.result) ? data.result[0] : null;
    const blockStr = result?.blockNumber || result?.blocknumber || result?.block_num;
    const block = Number(blockStr);
    return Number.isFinite(block) && block > 0 ? block : DEFAULT_START_BLOCK;
  } catch {
    return DEFAULT_START_BLOCK;
  }
}

async function ensureManagerStartBlock(manager) {
  const checksum = normalizeAddress(manager?.address);
  if (!checksum) return DEFAULT_START_BLOCK;
  const key = checksum.toLowerCase();
  const explicit = Number(manager?.startBlock);
  if (Number.isFinite(explicit) && explicit > 0) {
    const normalized = Math.floor(explicit);
    managerStartBlockCache.set(key, normalized);
    return normalized;
  }
  const known = resolveKnownStartBlock(checksum);
  if (known) {
    managerStartBlockCache.set(key, known);
    return known;
  }
  if (managerStartBlockCache.has(key)) return managerStartBlockCache.get(key);
  const block = await fetchContractStartBlock(checksum);
  managerStartBlockCache.set(key, block);
  return block;
}

function buildVaultNodes(managers) {
  const list = Array.isArray(managers) ? managers : [];
  const seen = new Set();
  const nodes = [];
  const push = (address, startBlock, label) => {
    const normalized = normalizeAddress(address);
    if (!normalized) return;
    const key = normalized.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    nodes.push({
      address: normalized,
      startBlock: Number.isFinite(Number(startBlock)) && Number(startBlock) > 0 ? Math.floor(Number(startBlock)) : null,
      label: label ? String(label) : null,
    });
  };
  for (const manager of list) {
    const addr = normalizeAddress(manager?.address);
    if (!addr) continue;
    const legacy = normalizeLegacyAddresses(manager);
    legacy.forEach((legacyAddr, idx) => {
      const legacyLabel = manager?.label ? `${manager.label} (Legacy ${idx + 1})` : `Legacy ${idx + 1}`;
      push(legacyAddr, resolveKnownStartBlock(legacyAddr), legacyLabel);
    });
    push(addr, manager?.startBlock, manager?.label);
  }
  return nodes;
}

function showError(message) {
  if (!refs.errorBanner) return;
  refs.errorBanner.style.display = 'block';
  refs.errorBanner.textContent = message;
}

function clearError() {
  if (!refs.errorBanner) return;
  refs.errorBanner.style.display = 'none';
  refs.errorBanner.textContent = '';
}

function toNumber(value, fallback = 0) {
  const num = typeof value === 'string' ? Number.parseFloat(value) : Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function formatUsd(value, digits = 0) {
  if (!Number.isFinite(value)) return '—';
  return value.toLocaleString(undefined, {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

function formatPct(value, digits = 2) {
  if (!Number.isFinite(value)) return '—';
  return `${value >= 0 ? '+' : ''}${value.toFixed(digits)}%`;
}

function formatToken(value, digits = 2) {
  if (!Number.isFinite(value)) return '—';
  return value.toLocaleString(undefined, {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

function formatClockTime(ms) {
  if (!Number.isFinite(ms) || ms <= 0) return '—';
  const iso = new Date(ms).toISOString();
  return `${iso.slice(11, 16)} UTC`;
}

function applyValueTone(element, value) {
  if (!element) return;
  element.classList.remove('text-positive', 'text-negative');
  if (!Number.isFinite(value) || value === 0) return;
  element.classList.add(value > 0 ? 'text-positive' : 'text-negative');
}

function applyCardTint(element, value) {
  if (!element) return;
  element.classList.remove('tint-positive', 'tint-negative');
  if (!Number.isFinite(value) || value === 0) return;
  element.classList.add(value > 0 ? 'tint-positive' : 'tint-negative');
}

function normalizeAddress(addr) {
  try {
    return ethers.getAddress(addr);
  } catch {
    return null;
  }
}

function toBig(val) {
  if (typeof val === 'bigint') return val;
  if (val == null) return 0n;
  if (typeof val === 'object' && typeof val.toBigInt === 'function') return val.toBigInt();
  try {
    return BigInt(val);
  } catch {
    return 0n;
  }
}

async function getOracleDecimals() {
  if (oracleDecimalsCache != null) return oracleDecimalsCache;
  try {
    const decimals = await rpcCall(
      (activeProvider) => new ethers.Contract(
        ADDRESSES.CHAINLINK_ETH_USD,
        ABI.CHAINLINK_AGGREGATOR,
        activeProvider,
      ).decimals(),
      'Chainlink decimals()',
    );
    const parsed = Number(decimals ?? 8);
    oracleDecimalsCache = Number.isFinite(parsed) && parsed >= 0 ? parsed : 8;
    return oracleDecimalsCache;
  } catch {
    oracleDecimalsCache = 8;
    return oracleDecimalsCache;
  }
}

async function getPriceContext() {
  const decimals = await getOracleDecimals();
  const [slot0Data, priceRound] = await Promise.all([
    rpcCall(
      (activeProvider) => new ethers.Contract(
        ADDRESSES.POOL_ENA_WETH,
        ABI.UNISWAP_V3_POOL,
        activeProvider,
      ).slot0(),
      'Uniswap V3 slot0()',
    ),
    rpcCall(
      (activeProvider) => new ethers.Contract(
        ADDRESSES.CHAINLINK_ETH_USD,
        ABI.CHAINLINK_AGGREGATOR,
        activeProvider,
      ).latestRoundData(),
      'Chainlink latestRoundData()',
    ),
  ]);

  const sqrtPriceX96 = toBig(slot0Data?.sqrtPriceX96 ?? slot0Data?.[0] ?? 0n);
  const tick = Number(slot0Data?.tick ?? slot0Data?.[1] ?? 0);
  const answer = toBig(priceRound?.answer ?? priceRound?.[1] ?? 0n);
  const ethUsd = Number(ethers.formatUnits(answer, decimals));
  const tickNum = Number.isFinite(tick) ? tick : 0;
  const wethPerEna = Math.pow(1.0001, tickNum);
  const enaUsd = wethPerEna * (Number.isFinite(ethUsd) ? ethUsd : 0);
  const cultUsd = await getCultUsd(ethUsd).catch(() => 0);
  if (Number.isFinite(cultUsd) && cultUsd > 0) latestCultUsd = cultUsd;

  return {
    sqrtPriceX96n: sqrtPriceX96,
    tick: tickNum,
    ethUsd: Number.isFinite(ethUsd) ? ethUsd : 0,
    enaUsd: Number.isFinite(enaUsd) ? enaUsd : 0,
    cultUsd: Number.isFinite(cultUsd) ? cultUsd : 0,
  };
}

async function getPriceContextAtBlock(blockNumber) {
  const key = Number(blockNumber);
  if (Number.isFinite(key) && priceContextCache.has(key)) return priceContextCache.get(key);
  try {
    const decimals = await getOracleDecimals();
    const [slot0Data, priceRound] = await Promise.all([
      rpcCall(
        (activeProvider) => new ethers.Contract(
          ADDRESSES.POOL_ENA_WETH,
          ABI.UNISWAP_V3_POOL,
          activeProvider,
        ).slot0({ blockTag: key }),
        'Uniswap V3 slot0@block',
      ),
      rpcCall(
        (activeProvider) => new ethers.Contract(
          ADDRESSES.CHAINLINK_ETH_USD,
          ABI.CHAINLINK_AGGREGATOR,
          activeProvider,
        ).latestRoundData({ blockTag: key }),
        'Chainlink latestRoundData@block',
      ),
    ]);

    const sqrtPriceX96 = toBig(slot0Data?.sqrtPriceX96 ?? slot0Data?.[0] ?? 0n);
    const tick = Number(slot0Data?.tick ?? slot0Data?.[1] ?? 0);
    const answer = toBig(priceRound?.answer ?? priceRound?.[1] ?? 0n);
    const ethUsd = Number(ethers.formatUnits(answer, decimals));
    const tickNum = Number.isFinite(tick) ? tick : 0;
    const wethPerEna = Math.pow(1.0001, tickNum);
    const enaUsd = wethPerEna * (Number.isFinite(ethUsd) ? ethUsd : 0);
    const ctx = {
      sqrtPriceX96n: sqrtPriceX96,
      tick: tickNum,
      ethUsd: Number.isFinite(ethUsd) ? ethUsd : 0,
      enaUsd: Number.isFinite(enaUsd) ? enaUsd : 0,
      cultUsd: latestCultUsd,
    };
    if (Number.isFinite(key)) priceContextCache.set(key, ctx);
    return ctx;
  } catch {
    const fallback = await getPriceContext();
    if (Number.isFinite(key)) priceContextCache.set(key, fallback);
    return fallback;
  }
}

async function warmBlockData(blockNumbers, maxConcurrency = 6) {
  if (!Array.isArray(blockNumbers) || !blockNumbers.length) return;
  const unique = Array.from(new Set(
    blockNumbers
      .map((bn) => Number(bn))
      .filter((bn) => Number.isFinite(bn) && bn > 0),
  ));
  const pending = unique.filter((bn) => !priceContextCache.has(bn) || !blockTimestampCache.has(bn));
  if (!pending.length) return;
  const queue = pending.slice();
  const workerCount = Math.max(1, Math.min(maxConcurrency, queue.length));
  const workers = [];
  for (let i = 0; i < workerCount; i += 1) {
    workers.push((async () => {
      while (queue.length) {
        const bn = queue.pop();
        if (bn == null) break;
        await Promise.allSettled([
          priceContextCache.has(bn) ? null : getPriceContextAtBlock(bn),
          blockTimestampCache.has(bn) ? null : getBlockTimestampSec(bn),
        ]);
      }
    })());
  }
  await Promise.all(workers);
}

function getSubgraphEndpoint() {
  const configured = String(ANALYTICS?.SUBGRAPH_ENDPOINT || '').trim();
  return configured || '';
}

async function fetchSubgraph(query, variables) {
  const endpoint = getSubgraphEndpoint();
  if (!endpoint) throw new Error('Missing ANALYTICS.SUBGRAPH_ENDPOINT in project_constants.js');
  const resp = await fetch(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ query, variables }),
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`Subgraph HTTP ${resp.status}: ${text || 'request failed'}`);
  }
  const payload = await resp.json();
  if (payload?.errors?.length) {
    throw new Error(`Subgraph error: ${payload.errors[0]?.message || 'unknown error'}`);
  }
  return payload?.data || null;
}

async function fetchVaultSnapshots(vaultId) {
  const query = `
    query VaultSnapshots($vaultId: ID!, $pageSize: Int!, $skip: Int!) {
      vaultSnapshots(
        first: $pageSize
        skip: $skip
        orderBy: id
        orderDirection: asc
        where: { vault: $vaultId }
      ) {
        id
        blockNumber
        timestamp
        navUsd
        tickLower
        tickUpper
        liquidity
        idleEna
        idleWeth
        positionEna
        positionWeth
        collectableFeesEna
        collectableFeesWeth
        cumulativeFeesEna
        cumulativeFeesWeth
        priceEnaUsd
        priceEthUsd
      }
    }
  `;

  let skip = 0;
  const pages = [];
  while (skip < 2_000) {
    const data = await fetchSubgraph(query, {
      vaultId,
      pageSize: SUBGRAPH_PAGE_SIZE,
      skip,
    });
    const rows = Array.isArray(data?.vaultSnapshots) ? data.vaultSnapshots : [];
    pages.push(...rows);
    if (rows.length < SUBGRAPH_PAGE_SIZE) return pages;
    skip += SUBGRAPH_PAGE_SIZE;
  }
  return pages;
}

async function fetchLogs(address, topics, fromBlock, toBlock) {
  const normalizedTopics = normalizeTopics(topics);
  try {
    return await fetchLogsViaProvider(address, normalizedTopics, fromBlock, toBlock);
  } catch (err) {
    if (!etherscanKeys.length) throw err;
    return await fetchLogsViaEtherscan(address, normalizedTopics, fromBlock, toBlock);
  }
}

async function fetchLogsViaProvider(address, topics, fromBlock, toBlock) {
  const out = [];
  let start = Number(fromBlock);
  let endBlock = Number(toBlock);
  if (!Number.isFinite(start) || start < 0) start = 0;
  if (!Number.isFinite(endBlock) || endBlock < start) endBlock = start;
  for (let cursor = start; cursor <= endBlock; cursor += RPC_LOG_CHUNK) {
    const end = Math.min(endBlock, cursor + RPC_LOG_CHUNK - 1);
    const chunk = await rpcCall(
      (activeProvider) => activeProvider.getLogs({ address, topics, fromBlock: cursor, toBlock: end }),
      'RPC eth_getLogs',
    );
    if (Array.isArray(chunk) && chunk.length) out.push(...chunk);
  }
  return out;
}

async function fetchLogsViaEtherscan(address, topics, fromBlock, toBlock) {
  const key = nextEtherscanKey();
  if (!key) throw new Error('No Etherscan API key configured');
  const logs = [];
  const topicArray = normalizeTopics(topics) || [];
  let cursor = Number(fromBlock);
  const endBlock = Number(toBlock);
  if (!Number.isFinite(cursor) || cursor < 0) cursor = 0;
  if (!Number.isFinite(endBlock) || endBlock < cursor) return logs;
  while (cursor <= endBlock) {
    const end = Math.min(cursor + ETHERSCAN_LOG_CHUNK, endBlock);
    const url = new URL(ETHERSCAN_API_URL);
    url.searchParams.set('module', 'logs');
    url.searchParams.set('action', 'getLogs');
    url.searchParams.set('chainid', String(ETHERSCAN_CHAIN_ID));
    url.searchParams.set('fromBlock', String(cursor));
    url.searchParams.set('toBlock', String(end));
    url.searchParams.set('address', String(address));
    topicArray.forEach((value, idx) => {
      if (value) url.searchParams.set(`topic${idx}`, String(value));
    });
    url.searchParams.set('apikey', key);
    const resp = await fetch(url);
    const data = await resp.json();
    if (data?.status === '0' && data?.message !== 'No records found') {
      throw new Error(data?.result || 'Etherscan log error');
    }
    const chunk = Array.isArray(data?.result)
      ? data.result.map((entry) => ({
          address: entry.address,
          blockNumber: Number(BigInt(entry.blockNumber)),
          data: entry.data,
          topics: entry.topics,
          transactionHash: entry.transactionHash,
          transactionIndex: entry.transactionIndex ? Number(BigInt(entry.transactionIndex)) : undefined,
        }))
      : [];
    logs.push(...chunk);
    cursor = end + 1;
  }
  return logs;
}

async function getBlockTimestampSec(blockNumber) {
  const key = Number(blockNumber);
  if (!Number.isFinite(key) || key <= 0) return 0;
  if (blockTimestampCache.has(key)) return blockTimestampCache.get(key);
  try {
    const block = await rpcCall((activeProvider) => activeProvider.getBlock(key), 'RPC eth_getBlock');
    const ts = Number(block?.timestamp);
    const safe = Number.isFinite(ts) && ts > 0 ? ts : 0;
    blockTimestampCache.set(key, safe);
    return safe;
  } catch {
    blockTimestampCache.set(key, 0);
    return 0;
  }
}

async function fetchOwnerHistory(managerAddress, fromBlock, toBlock) {
  const checksum = normalizeAddress(managerAddress);
  if (!checksum) return [];
  const startBlock = await ensureManagerStartBlock({ address: checksum, startBlock: fromBlock });
  const endBlock = Number.isFinite(Number(toBlock)) && Number(toBlock) >= startBlock
    ? Math.floor(Number(toBlock))
    : await rpcCall((activeProvider) => activeProvider.getBlockNumber(), 'RPC eth_blockNumber');

  let currentOwner = null;
  try {
    currentOwner = await rpcCall(
      (activeProvider) => new ethers.Contract(checksum, ABI.LIQUIDITY_MANAGER, activeProvider).owner(),
      'owner()',
    );
  } catch {
    currentOwner = null;
  }

  let logs = [];
  try {
    logs = await fetchLogs(checksum, [ownershipTransferredTopic], startBlock, endBlock);
  } catch {
    logs = [];
  }

  const owners = [];
  const seen = new Set();
  const excluded = new Set([ZERO_ADDRESS, checksum.toLowerCase()]);
  const pushOwner = (addr) => {
    const normalized = normalizeAddress(addr);
    if (!normalized) return;
    const key = normalized.toLowerCase();
    if (excluded.has(key) || seen.has(key)) return;
    seen.add(key);
    owners.push(normalized);
  };

  const sortedLogs = Array.isArray(logs) ? [...logs] : [];
  sortedLogs.sort((a, b) => {
    const blockA = Number(a?.blockNumber ?? 0);
    const blockB = Number(b?.blockNumber ?? 0);
    if (blockA !== blockB) return blockA - blockB;
    const txA = Number(a?.transactionIndex ?? 0);
    const txB = Number(b?.transactionIndex ?? 0);
    if (txA !== txB) return txA - txB;
    return 0;
  });
  for (const log of sortedLogs) {
    const prevOwner = decodeTopicAddress(log?.topics?.[1]);
    const nextOwner = decodeTopicAddress(log?.topics?.[2]);
    pushOwner(prevOwner);
    pushOwner(nextOwner);
  }
  pushOwner(currentOwner);
  return owners;
}

async function sumTokenFlows(tokenMeta, managerAddress, ownerAddresses, fromBlock, toBlock) {
  const owners = normalizeOwnerAddresses(ownerAddresses, [managerAddress]);
  const managerTopic = encodeTopicAddress(managerAddress);
  const tokenAddress = tokenMeta?.address;
  const result = {
    inbound: 0n,
    outbound: 0n,
    depositUsd: 0,
    withdrawUsd: 0,
    depositEvents: [],
    withdrawEvents: [],
  };
  if (!tokenAddress || !managerTopic || !owners.length) return result;

  for (const owner of owners) {
    const ownerTopic = encodeTopicAddress(owner);
    if (!ownerTopic) continue;
    const [inboundLogs, outboundLogs] = await Promise.all([
      fetchLogs(tokenAddress, [transferTopic, ownerTopic, managerTopic], fromBlock, toBlock).catch(() => []),
      fetchLogs(tokenAddress, [transferTopic, managerTopic, ownerTopic], fromBlock, toBlock).catch(() => []),
    ]);

    const inboundBlocks = inboundLogs.map((log) => Number(log?.blockNumber ?? fromBlock));
    const outboundBlocks = outboundLogs.map((log) => Number(log?.blockNumber ?? fromBlock));
    await warmBlockData([...inboundBlocks, ...outboundBlocks]);

    for (const log of inboundLogs) {
      let amount = 0n;
      try {
        amount = toBig(abiCoder.decode(['uint256'], log.data)[0]);
      } catch {
        amount = 0n;
      }
      if (!(amount > 0n)) continue;
      result.inbound += amount;
      const blockNumber = Number(log?.blockNumber ?? fromBlock);
      const priceCtx = await getPriceContextAtBlock(blockNumber);
      const amountTokens = Number(ethers.formatUnits(amount, tokenMeta.decimals));
      const tokenPrice = tokenMeta.id === 'ena' ? Number(priceCtx.enaUsd) : Number(priceCtx.ethUsd);
      const usdValue = amountTokens * (Number.isFinite(tokenPrice) ? tokenPrice : 0);
      if (Number.isFinite(usdValue) && usdValue > 0) result.depositUsd += usdValue;
      const blockTs = await getBlockTimestampSec(blockNumber);
      if (blockTs > 0) {
        result.depositEvents.push({
          time: blockTs * 1000,
          block: blockNumber,
          kind: 'deposit',
          token: tokenMeta.id,
          amountRaw: amount,
          usd: usdValue,
        });
      }
    }

    for (const log of outboundLogs) {
      let amount = 0n;
      try {
        amount = toBig(abiCoder.decode(['uint256'], log.data)[0]);
      } catch {
        amount = 0n;
      }
      if (!(amount > 0n)) continue;
      result.outbound += amount;
      const blockNumber = Number(log?.blockNumber ?? fromBlock);
      const priceCtx = await getPriceContextAtBlock(blockNumber);
      const amountTokens = Number(ethers.formatUnits(amount, tokenMeta.decimals));
      const tokenPrice = tokenMeta.id === 'ena' ? Number(priceCtx.enaUsd) : Number(priceCtx.ethUsd);
      const usdValue = amountTokens * (Number.isFinite(tokenPrice) ? tokenPrice : 0);
      if (Number.isFinite(usdValue) && usdValue > 0) result.withdrawUsd += usdValue;
      const blockTs = await getBlockTimestampSec(blockNumber);
      if (blockTs > 0) {
        result.withdrawEvents.push({
          time: blockTs * 1000,
          block: blockNumber,
          kind: 'withdraw',
          token: tokenMeta.id,
          amountRaw: amount,
          usd: usdValue,
        });
      }
    }
  }

  return result;
}

async function sumOwnerFlows(managerAddress, ownerAddresses, fromBlock, toBlock) {
  const base = { ena: 0n, weth: 0n };
  const normalizedOwners = normalizeOwnerAddresses(ownerAddresses, [managerAddress]);
  if (!managerAddress || !normalizedOwners.length) {
    return {
      deposits: { ...base },
      withdrawals: { ...base },
      depositUsd: 0,
      withdrawUsd: 0,
      fundingEvents: [],
    };
  }
  const deposits = { ...base };
  const withdrawals = { ...base };
  let depositUsd = 0;
  let withdrawUsd = 0;
  const fundingEvents = [];
  const tokens = [
    { id: 'ena', address: ADDRESSES.ENA, decimals: ENA_DECIMALS },
    { id: 'weth', address: ADDRESSES.WETH, decimals: WETH_DECIMALS },
  ];
  for (const token of tokens) {
    const flows = await sumTokenFlows(token, managerAddress, normalizedOwners, fromBlock, toBlock);
    deposits[token.id] = flows.inbound;
    withdrawals[token.id] = flows.outbound;
    depositUsd += flows.depositUsd;
    withdrawUsd += flows.withdrawUsd;
    if (Array.isArray(flows.depositEvents)) fundingEvents.push(...flows.depositEvents);
    if (Array.isArray(flows.withdrawEvents)) fundingEvents.push(...flows.withdrawEvents);
  }
  fundingEvents.sort((a, b) => {
    if (a.time !== b.time) return a.time - b.time;
    return a.block - b.block;
  });
  return { deposits, withdrawals, depositUsd, withdrawUsd, fundingEvents };
}

function summarizeFundingEvents(fundingEvents) {
  const deposits = { ena: 0n, weth: 0n };
  const withdrawals = { ena: 0n, weth: 0n };
  let depositUsd = 0;
  let withdrawUsd = 0;

  const list = Array.isArray(fundingEvents) ? fundingEvents : [];
  for (const evt of list) {
    const token = evt?.token === 'weth' ? 'weth' : 'ena';
    const kind = evt?.kind === 'withdraw' ? 'withdraw' : 'deposit';
    const amount = toBig(evt?.amountRaw ?? 0n);
    if (!(amount > 0n)) continue;
    const usd = Number(evt?.usd ?? 0);
    if (kind === 'deposit') {
      deposits[token] += amount;
      if (Number.isFinite(usd)) depositUsd += usd;
    } else {
      withdrawals[token] += amount;
      if (Number.isFinite(usd)) withdrawUsd += usd;
    }
  }

  return { deposits, withdrawals, depositUsd, withdrawUsd };
}

function findMigrationFundingEventRemovals(legacyEvents, currentEvents) {
  const legacy = Array.isArray(legacyEvents) ? legacyEvents : [];
  const current = Array.isArray(currentEvents) ? currentEvents : [];
  const removeLegacy = new Set();
  const removeCurrent = new Set();
  if (!legacy.length || !current.length) return { removeLegacy, removeCurrent };

  const TOKENS = ['ena', 'weth'];
  const WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
  const TOLERANCE_BPS = 200n; // 2%

  const toAmount = (evt) => toBig(evt?.amountRaw ?? 0n);

  for (const token of TOKENS) {
    const legacyWithdraws = legacy.filter(
      (evt) => evt?.kind === 'withdraw' && evt?.token === token && toAmount(evt) > 0n,
    );
    const currentDeposits = current.filter(
      (evt) => evt?.kind === 'deposit' && evt?.token === token && toAmount(evt) > 0n,
    );
    if (!legacyWithdraws.length || !currentDeposits.length) continue;

    let best = null;
    for (const w of legacyWithdraws) {
      const wt = Number(w?.time || 0);
      if (!Number.isFinite(wt) || wt <= 0) continue;
      const wAmt = toAmount(w);
      for (const d of currentDeposits) {
        const dt = Number(d?.time || 0);
        if (!Number.isFinite(dt) || dt <= 0) continue;
        const deltaMs = Math.abs(dt - wt);
        if (deltaMs > WINDOW_MS) continue;
        const dAmt = toAmount(d);
        if (!(dAmt > 0n)) continue;

        const maxAmt = wAmt > dAmt ? wAmt : dAmt;
        const diff = wAmt > dAmt ? wAmt - dAmt : dAmt - wAmt;
        const diffBps = maxAmt > 0n ? (diff * 10_000n) / maxAmt : 10_000n;
        if (diffBps > TOLERANCE_BPS) continue;

        const matchSize = wAmt < dAmt ? wAmt : dAmt;
        if (!best || matchSize > best.matchSize) {
          best = { w, d, matchSize };
        }
      }
    }
    if (best) {
      removeLegacy.add(best.w);
      removeCurrent.add(best.d);
    }
  }

  return { removeLegacy, removeCurrent };
}

function stitchMigrationFundingEventsChain(eventChains) {
  const chains = Array.isArray(eventChains)
    ? eventChains.map((events) => (Array.isArray(events) ? events.slice() : []))
    : [];
  if (chains.length <= 1) return chains[0] || [];
  for (let i = 0; i < chains.length - 1; i += 1) {
    const { removeLegacy, removeCurrent } = findMigrationFundingEventRemovals(chains[i], chains[i + 1]);
    if (removeLegacy.size) chains[i] = chains[i].filter((evt) => !removeLegacy.has(evt));
    if (removeCurrent.size) chains[i + 1] = chains[i + 1].filter((evt) => !removeCurrent.has(evt));
  }
  return chains
    .flat()
    .slice()
    .sort((a, b) => (a.time === b.time ? (a.block || 0) - (b.block || 0) : a.time - b.time));
}

function getAmountsForLiquidity(sqrtRatioX96, sqrtRatioAX96, sqrtRatioBX96, liquidity) {
  if (sqrtRatioAX96 > sqrtRatioBX96) {
    const temp = sqrtRatioAX96;
    sqrtRatioAX96 = sqrtRatioBX96;
    sqrtRatioBX96 = temp;
  }
  let amount0 = 0n;
  let amount1 = 0n;
  if (sqrtRatioX96 <= sqrtRatioAX96) {
    amount0 = getAmount0ForLiquidity(sqrtRatioAX96, sqrtRatioBX96, liquidity);
  } else if (sqrtRatioX96 < sqrtRatioBX96) {
    amount0 = getAmount0ForLiquidity(sqrtRatioX96, sqrtRatioBX96, liquidity);
    amount1 = getAmount1ForLiquidity(sqrtRatioAX96, sqrtRatioX96, liquidity);
  } else {
    amount1 = getAmount1ForLiquidity(sqrtRatioAX96, sqrtRatioBX96, liquidity);
  }
  return { amount0, amount1 };
}

function getAmount0ForLiquidity(sqrtA, sqrtB, liquidity) {
  if (sqrtA > sqrtB) [sqrtA, sqrtB] = [sqrtB, sqrtA];
  const numerator = (liquidity << 96n) * (sqrtB - sqrtA);
  return numerator / sqrtB / sqrtA;
}

function getAmount1ForLiquidity(sqrtA, sqrtB, liquidity) {
  if (sqrtA > sqrtB) [sqrtA, sqrtB] = [sqrtB, sqrtA];
  return (liquidity * (sqrtB - sqrtA)) / Q96;
}

const TICK_CONSTANTS = [
  0xfffcb933bd6fad37aa2d162d1a594001n,
  0xfff97272373d413259a46990580e213an,
  0xfff2e50f5f656932ef12357cf3c7fdccn,
  0xffe5caca7e10e4e61c3624eaa0941cd0n,
  0xffcb9843d60f6159c9db58835c926644n,
  0xff973b41fa98c081472e6896dfb254c0n,
  0xff2ea16466c96a3843ec78b326b52861n,
  0xfe5dee046a99a2a811c461f1969c3053n,
  0xfcbe86c7900a88aedcffc83b479aa3a4n,
  0xf987a7253ac413176f2b074cf7815e54n,
  0xf3392b0822b70005940c7a398e4b70f3n,
  0xe7159475a2c29b7443b29c7fa6e889d9n,
  0xd097f3bdfd2022b8845ad8f792aa5825n,
  0xa9f746462d870fdf8a65dc1f90e061e5n,
  0x70d869a156d2a1b890bb3df62baf32f7n,
  0x31be135f97d08fd981231505542fcfa6n,
  0x9aa508b5b7a84e1c677de54f3e99bc9n,
  0x5d6af8dedb81196699c329225ee604n,
  0x2216e584f5fa1ea926041bedfe98n,
  0x48a170391f7dc42444e8fa2n,
];

function getSqrtRatioAtTick(tick) {
  if (tick < -887272 || tick > 887272) throw new Error('TICK');
  let absTick = BigInt(tick < 0 ? -tick : tick);
  let ratio = (absTick & 1n) !== 0n ? TICK_CONSTANTS[0] : 0x100000000000000000000000000000000n;
  for (let i = 1; i < TICK_CONSTANTS.length; i += 1) {
    if ((absTick & (1n << BigInt(i))) !== 0n) {
      ratio = (ratio * TICK_CONSTANTS[i]) >> 128n;
    }
  }
  if (tick > 0) {
    ratio = ((1n << 256n) - 1n) / ratio;
  }
  const remainder = ratio & ((1n << 32n) - 1n);
  return (ratio >> 32n) + (remainder === 0n ? 0n : 1n);
}

function sanitizeDecimalString(value) {
  if (value == null) return '';
  let str = String(value).trim();
  if (!str) return '';
  if (str.includes('e') || str.includes('E')) {
    const num = Number(str);
    if (!Number.isFinite(num)) return '';
    str = num.toString();
  }
  return str;
}

function decimalToBigInt(value, decimals = 18) {
  if (value == null) return null;
  let str = sanitizeDecimalString(value);
  if (!str) return null;
  const negative = str.startsWith('-');
  if (negative) str = str.slice(1);
  if (!str) return null;
  if (str.startsWith('.')) str = `0${str}`;
  const [wholeRaw, fractionRaw = ''] = str.split('.');
  const whole = wholeRaw.replace(/\D+/g, '') || '0';
  const fraction = fractionRaw.replace(/\D+/g, '');
  const trimmedFraction = fraction.slice(0, decimals);
  const paddedFraction = trimmedFraction.padEnd(decimals, '0');
  const combined = `${whole}${paddedFraction}`.replace(/^0+/, '') || '0';
  let result = BigInt(combined);
  if (negative) result = -result;
  return result;
}

function sqrtBigInt(value) {
  if (value < 0n) return null;
  if (value < 2n) return value;
  let x0 = value;
  let x1 = (value >> 1n) + 1n;
  while (x1 < x0) {
    x0 = x1;
    x1 = (value / x1 + x1) >> 1n;
  }
  return x0;
}

function deriveSqrtPriceX96FromPrices(priceEnaUsd, priceEthUsd) {
  if (!(priceEthUsd > 0) || !(priceEnaUsd > 0)) return null;
  const enaScaled = decimalToBigInt(priceEnaUsd, 18);
  const ethScaled = decimalToBigInt(priceEthUsd, 18);
  if (enaScaled == null || ethScaled == null || ethScaled <= 0n) return null;
  const ratioX192 = (enaScaled * Q192) / ethScaled;
  if (!(ratioX192 > 0n)) return null;
  return sqrtBigInt(ratioX192);
}

async function getCollectableFees(tokenId, vaultAddress) {
  const id = toBig(tokenId);
  if (!(id > 0n)) return { amount0: 0n, amount1: 0n };
  const vault = normalizeAddress(vaultAddress);
  try {
    return await rpcCall(async (activeProvider) => {
      const nfpm = new ethers.Contract(
        ADDRESSES.NONFUNGIBLE_POSITION_MANAGER,
        ABI.NONFUNGIBLE_POSITION_MANAGER,
        activeProvider,
      );
      if (!vault) {
        const pos = await nfpm.positions(id);
        return {
          amount0: toBig(pos?.tokensOwed0 ?? pos?.[10] ?? 0n),
          amount1: toBig(pos?.tokensOwed1 ?? pos?.[11] ?? 0n),
        };
      }

      const params = {
        tokenId: id,
        recipient: vault,
        amount0Max: MAX_UINT128,
        amount1Max: MAX_UINT128,
      };

      try {
        const res = await nfpm.collect.staticCall(params, { from: vault });
        return {
          amount0: toBig(res?.[0] ?? res?.amount0 ?? 0n),
          amount1: toBig(res?.[1] ?? res?.amount1 ?? 0n),
        };
      } catch {
        const pos = await nfpm.positions(id);
        return {
          amount0: toBig(pos?.tokensOwed0 ?? pos?.[10] ?? 0n),
          amount1: toBig(pos?.tokensOwed1 ?? pos?.[11] ?? 0n),
        };
      }
    }, 'NFPM collect.staticCall()');
  } catch {
    return { amount0: 0n, amount1: 0n };
  }
}

async function buildLiveVaultSnapshot(managerAddress, priceCtx) {
  const checksum = normalizeAddress(managerAddress);
  if (!checksum) return null;
  const ctx = priceCtx || await getPriceContext();

  try {
    const [idleEna, idleWeth, positionTuple] = await Promise.all([
      rpcCall(
        (activeProvider) => new ethers.Contract(ADDRESSES.ENA, ABI.ERC20, activeProvider).balanceOf(checksum),
        'ENA balanceOf()',
      ),
      rpcCall(
        (activeProvider) => new ethers.Contract(ADDRESSES.WETH, ABI.ERC20, activeProvider).balanceOf(checksum),
        'WETH balanceOf()',
      ),
      rpcCall(
        (activeProvider) => new ethers.Contract(checksum, ABI.LIQUIDITY_MANAGER, activeProvider).getPosition(),
        'getPosition()',
      ),
    ]);

    const tokenId = toBig(positionTuple?.tokenId ?? positionTuple?.[0] ?? 0n);
    const lowerTick = Number(positionTuple?.lowerTick ?? positionTuple?.[1] ?? 0);
    const upperTick = Number(positionTuple?.upperTick ?? positionTuple?.[2] ?? 0);
    const liquidity = toBig(positionTuple?.liquidity ?? positionTuple?.[3] ?? 0n);

    let positionAmount0 = 0n;
    let positionAmount1 = 0n;
    if (tokenId > 0n && liquidity > 0n) {
      const sqrtLower = getSqrtRatioAtTick(lowerTick);
      const sqrtUpper = getSqrtRatioAtTick(upperTick);
      const { amount0, amount1 } = getAmountsForLiquidity(
        toBig(ctx?.sqrtPriceX96n ?? 0n),
        sqrtLower,
        sqrtUpper,
        liquidity,
      );
      positionAmount0 = amount0;
      positionAmount1 = amount1;
    }

    const collectable = await getCollectableFees(tokenId, checksum);

    const idleEnaTokens = Number(ethers.formatUnits(toBig(idleEna), ENA_DECIMALS));
    const idleWethTokens = Number(ethers.formatUnits(toBig(idleWeth), WETH_DECIMALS));
    const posEnaTokens = Number(ethers.formatUnits(positionAmount0, ENA_DECIMALS));
    const posWethTokens = Number(ethers.formatUnits(positionAmount1, WETH_DECIMALS));
    const feeEnaTokens = Number(ethers.formatUnits(toBig(collectable.amount0), ENA_DECIMALS));
    const feeWethTokens = Number(ethers.formatUnits(toBig(collectable.amount1), WETH_DECIMALS));

    const enaUsd = Number(ctx?.enaUsd || 0);
    const ethUsd = Number(ctx?.ethUsd || 0);

    const idleUsd = idleEnaTokens * enaUsd + idleWethTokens * ethUsd;
    const positionUsd = posEnaTokens * enaUsd + posWethTokens * ethUsd;
    const feesUsd = feeEnaTokens * enaUsd + feeWethTokens * ethUsd;
    const navUsd = idleUsd + positionUsd + feesUsd;

    return {
      manager: checksum,
      tokenId,
      collectable,
      idleUsd,
      positionUsd,
      feesUsd,
      navUsd,
    };
  } catch {
    return null;
  }
}

async function getCultUsd(ethUsd) {
  if (!(ethUsd > 0)) return 0;
  return await rpcCall(async (activeProvider) => {
    const pair = new ethers.Contract(
      ADDRESSES.CULT_WETH_V2_PAIR,
      ABI.UNISWAP_V2_PAIR,
      activeProvider,
    );
    const [token0, reserves] = await Promise.all([pair.token0(), pair.getReserves()]);
    const t0 = String(token0 || '').toLowerCase();
    const reserve0 = BigInt(reserves?.reserve0 ?? 0);
    const reserve1 = BigInt(reserves?.reserve1 ?? 0);
    const wethAddr = String(ADDRESSES.WETH || '').toLowerCase();
    const cultAddr = String(ADDRESSES.CULT || '').toLowerCase();
    const hasAll = t0 && wethAddr && cultAddr && reserve0 > 0n && reserve1 > 0n;
    if (!hasAll) return 0;
    const reserveWeth = t0 === wethAddr ? reserve0 : reserve1;
    const reserveCult = t0 === cultAddr ? reserve0 : reserve1;
    if (!(reserveWeth > 0n) || !(reserveCult > 0n)) return 0;
    const wethPerCult = Number(reserveWeth) / Number(reserveCult);
    if (!Number.isFinite(wethPerCult) || wethPerCult <= 0) return 0;
    return ethUsd * wethPerCult;
  }, 'Uniswap V2 CULT/WETH');
}

async function fetchCompoundFlags(managers) {
  const results = await Promise.allSettled(
    managers.map(async (manager) => {
      const addr = normalizeAddress(manager.address);
      if (!addr) return null;
      const compoundFees = await rpcCall(
        (activeProvider) => new ethers.Contract(addr, ABI.LIQUIDITY_MANAGER, activeProvider).compoundFees(),
        'compoundFees()',
      );
      return { address: addr, compoundFees: Boolean(compoundFees) };
    }),
  );
  return results
    .map((row) => (row.status === 'fulfilled' ? row.value : null))
    .filter(Boolean);
}

async function fetchReturns(managers, cultUsd, toBlock) {
  const burnedByManager = new Map();
  const stakedByManager = new Map();
  const events = [];

  for (const manager of managers) {
    const addr = normalizeAddress(manager.address);
    if (!addr) continue;
    const fromBlock = Number(manager.startBlock) > 0 ? Number(manager.startBlock) : 0;
    const safeFromBlock = fromBlock > 0 ? fromBlock : Math.max(0, toBlock - 200_000);

    const [distributedLogs, terminatedLogs] = await Promise.all([
      fetchLogs(addr, [distributedTopic], safeFromBlock, toBlock).catch(() => []),
      fetchLogs(addr, [terminatedTopic], safeFromBlock, toBlock).catch(() => []),
    ]);

    const distributedTxs = new Set();
    let burnedRaw = 0n;
    let stakedRaw = 0n;

    for (const log of distributedLogs || []) {
      const txHash = log?.transactionHash;
      const blockNumber = Number(log?.blockNumber);
      if (!txHash || !Number.isFinite(blockNumber) || blockNumber <= 0) continue;
      try {
        const decoded = abiCoder.decode(['uint256', 'uint256'], log.data);
        const burned = BigInt(decoded[0] ?? 0);
        const staked = BigInt(decoded[1] ?? 0);
        burnedRaw += burned;
        stakedRaw += staked;
        distributedTxs.add(String(txHash).toLowerCase());
        const totalTokens = burned + staked;
        const total = Number(ethers.formatUnits(totalTokens, CULT_DECIMALS));
        events.push({
          kind: 'Distribution',
          txHash: String(txHash),
          blockNumber,
          burnedTokens: Number(ethers.formatUnits(burned, CULT_DECIMALS)),
          stakedTokens: Number(ethers.formatUnits(staked, CULT_DECIMALS)),
          totalTokens: total,
          usd: Number.isFinite(cultUsd) && cultUsd > 0 ? total * cultUsd : 0,
          timeMs: 0,
        });
      } catch {
        continue;
      }
    }

    for (const log of terminatedLogs || []) {
      const txHash = log?.transactionHash;
      const blockNumber = Number(log?.blockNumber);
      if (!txHash || !Number.isFinite(blockNumber) || blockNumber <= 0) continue;
      const key = String(txHash).toLowerCase();
      if (distributedTxs.has(key)) continue;
      try {
        const decoded = abiCoder.decode(['uint256'], log.data);
        const totalTokensRaw = BigInt(decoded[0] ?? 0);
        const total = Number(ethers.formatUnits(totalTokensRaw, CULT_DECIMALS));
        events.push({
          kind: 'Terminate',
          txHash: String(txHash),
          blockNumber,
          burnedTokens: 0,
          stakedTokens: 0,
          totalTokens: total,
          usd: Number.isFinite(cultUsd) && cultUsd > 0 ? total * cultUsd : 0,
          timeMs: 0,
        });
      } catch {
        continue;
      }
    }

    burnedByManager.set(addr.toLowerCase(), burnedRaw);
    stakedByManager.set(addr.toLowerCase(), stakedRaw);
  }

  const blockNumbers = Array.from(new Set(events.map((evt) => evt.blockNumber))).sort((a, b) => a - b);
  await Promise.all(blockNumbers.map((bn) => getBlockTimestampSec(bn)));
  for (const evt of events) {
    const ts = blockTimestampCache.get(evt.blockNumber) || 0;
    evt.timeMs = ts > 0 ? ts * 1000 : 0;
  }

  events.sort((a, b) => (a.timeMs || 0) - (b.timeMs || 0));

  const burnedTotal = Array.from(burnedByManager.values()).reduce((sum, val) => sum + val, 0n);
  const stakedTotal = Array.from(stakedByManager.values()).reduce((sum, val) => sum + val, 0n);

  return {
    burnedRaw: burnedTotal,
    stakedRaw: stakedTotal,
    events,
  };
}

function buildInvestmentHistory(vaultHistories, fundingEvents, returnEvents, fallbackPriceCtx) {
  const histories = Array.isArray(vaultHistories) ? vaultHistories : [];
  const expectedVaultCount = new Set(
    histories
      .map((row) => (row?.vaultId ? String(row.vaultId).toLowerCase() : null))
      .filter(Boolean),
  ).size;
  const timelines = histories
    .map((row) => {
      const id = row?.vaultId ? String(row.vaultId).toLowerCase() : null;
      const snaps = Array.isArray(row?.snapshots) ? row.snapshots : [];
      const series = snaps
        .map((snap) => {
          const timeMs = toNumber(snap?.timestamp) * 1000;
          const navUsd = toNumber(snap?.navUsd);
          const snapId = typeof snap?.id === 'string' ? snap.id : '';
          const parts = snapId.split('-');
          const parsedBlock = parts.length >= 2 ? Number(parts[parts.length - 2]) : NaN;
          const parsedLogIndex = parts.length >= 1 ? Number(parts[parts.length - 1]) : NaN;
          const blockNumber = Number.isFinite(parsedBlock) ? parsedBlock : toNumber(snap?.blockNumber);
          const logIndex = Number.isFinite(parsedLogIndex) ? parsedLogIndex : 0;

          const idleEna = toNumber(snap?.idleEna);
          const idleWeth = toNumber(snap?.idleWeth);
          const collectEna = toNumber(snap?.collectableFeesEna);
          const collectWeth = toNumber(snap?.collectableFeesWeth);
          const cumulativeFeeEna = toNumber(snap?.cumulativeFeesEna);
          const cumulativeFeeWeth = toNumber(snap?.cumulativeFeesWeth);

          let priceEthUsd = toNumber(snap?.priceEthUsd);
          let priceEnaUsd = toNumber(snap?.priceEnaUsd);
          const fallbackEthUsd = toNumber(fallbackPriceCtx?.ethUsd);
          const fallbackEnaUsd = toNumber(fallbackPriceCtx?.enaUsd);
          if (!(priceEthUsd > 0) && fallbackEthUsd > 0) priceEthUsd = fallbackEthUsd;
          if (!(priceEnaUsd > 0) && fallbackEnaUsd > 0) priceEnaUsd = fallbackEnaUsd;
          if (!(priceEnaUsd > 0) && priceEthUsd > 0) priceEnaUsd = priceEthUsd;

          let positionEnaTokens = toNumber(snap?.positionEna);
          let positionWethTokens = toNumber(snap?.positionWeth);
          const liquidity = toBig(snap?.liquidity ?? 0n);
          const lowerTick = Number(snap?.tickLower ?? 0);
          const upperTick = Number(snap?.tickUpper ?? 0);
          const sqrtPriceX96 = deriveSqrtPriceX96FromPrices(priceEnaUsd, priceEthUsd);
          if (sqrtPriceX96 && liquidity > 0n && Number.isFinite(lowerTick) && Number.isFinite(upperTick)) {
            try {
              const sqrtLower = getSqrtRatioAtTick(lowerTick);
              const sqrtUpper = getSqrtRatioAtTick(upperTick);
              const { amount0, amount1 } = getAmountsForLiquidity(sqrtPriceX96, sqrtLower, sqrtUpper, liquidity);
              const computed0 = Number(ethers.formatUnits(amount0, ENA_DECIMALS));
              const computed1 = Number(ethers.formatUnits(amount1, WETH_DECIMALS));
              if (Number.isFinite(computed0)) positionEnaTokens = computed0;
              if (Number.isFinite(computed1)) positionWethTokens = computed1;
            } catch {
              // ignore and fall back to subgraph-provided position amounts
            }
          }

          const enaTokens = idleEna + positionEnaTokens + collectEna;
          const wethTokens = idleWeth + positionWethTokens + collectWeth;

          return {
            timeMs,
            blockNumber,
            logIndex,
            navUsd,
            enaTokens,
            wethTokens,
            cumulativeFeeEna,
            cumulativeFeeWeth,
            priceEnaUsd,
            priceEthUsd,
          };
        })
        .filter((point) => Number.isFinite(point.timeMs) && point.timeMs > 0 && Number.isFinite(point.blockNumber) && point.blockNumber > 0)
        .sort((a, b) => {
          if (a.blockNumber !== b.blockNumber) return a.blockNumber - b.blockNumber;
          return (a.logIndex || 0) - (b.logIndex || 0);
        });

      if (!id || !series.length) return null;

      const deduped = [];
      for (const point of series) {
        const lastPoint = deduped[deduped.length - 1];
        if (lastPoint && lastPoint.blockNumber === point.blockNumber) {
          if ((point.logIndex || 0) >= (lastPoint.logIndex || 0)) {
            deduped[deduped.length - 1] = point;
          }
        } else {
          deduped.push(point);
        }
      }

      let prevFeeEna = 0;
      let prevFeeWeth = 0;
      let cumulativeFeesUsd = 0;
      deduped.forEach((point) => {
        const cumEna = toNumber(point?.cumulativeFeeEna);
        const cumWeth = toNumber(point?.cumulativeFeeWeth);
        const deltaEna = Math.max(cumEna - prevFeeEna, 0);
        const deltaWeth = Math.max(cumWeth - prevFeeWeth, 0);
        if ((deltaEna > 0 || deltaWeth > 0) && point.priceEnaUsd > 0 && point.priceEthUsd > 0) {
          cumulativeFeesUsd += deltaEna * point.priceEnaUsd + deltaWeth * point.priceEthUsd;
        }
        prevFeeEna = Math.max(prevFeeEna, cumEna);
        prevFeeWeth = Math.max(prevFeeWeth, cumWeth);
        point.feesCollectedUsd = cumulativeFeesUsd;
      });

      return { id, series: deduped };
    })
    .filter(Boolean);
  const missingVaultSnapshots = timelines.length < expectedVaultCount;

  const times = new Set();
  for (const vault of timelines) {
    for (const point of vault.series) {
      if (point?.timeMs > 0) times.add(point.timeMs);
    }
  }
  for (const evt of fundingEvents || []) {
    const time = Number(evt?.time);
    if (Number.isFinite(time) && time > 0) times.add(time);
  }
  for (const evt of returnEvents || []) {
    if (evt?.timeMs > 0) times.add(evt.timeMs);
  }

  const orderedTimes = Array.from(times).sort((a, b) => a - b);
  if (!orderedTimes.length) return [];

  const fallbackEthUsd = toNumber(fallbackPriceCtx?.ethUsd);
  const fallbackEnaUsd = toNumber(fallbackPriceCtx?.enaUsd);
  let globalEthUsd = fallbackEthUsd;
  let globalEnaUsd = fallbackEnaUsd;
  if (!(globalEnaUsd > 0) && globalEthUsd > 0) globalEnaUsd = globalEthUsd;

  const priceTimeline = timelines
    .flatMap((vault) => vault.series)
    .filter((point) => (point?.priceEthUsd || 0) > 0 || (point?.priceEnaUsd || 0) > 0)
    .slice()
    .sort((a, b) => {
      if (a.blockNumber !== b.blockNumber) return a.blockNumber - b.blockNumber;
      return (a.logIndex || 0) - (b.logIndex || 0);
    });
  let priceCursor = 0;

  const cursors = new Map();
  const lastTokens = new Map();
  const lastNav = new Map();
  const lastFeesCollected = new Map();
  for (const vault of timelines) {
    cursors.set(vault.id, 0);
    lastTokens.set(vault.id, { ena: 0, weth: 0 });
    lastNav.set(vault.id, 0);
    lastFeesCollected.set(vault.id, 0);
  }

  const fundingSorted = Array.isArray(fundingEvents)
    ? fundingEvents
        .filter((evt) => Number.isFinite(Number(evt?.time)) && Number(evt.time) > 0)
        .slice()
        .sort((a, b) => (a.time === b.time ? (a.block || 0) - (b.block || 0) : a.time - b.time))
    : [];
  let fundingCursor = 0;
  let runningCapitalUsd = 0;

  const returnsSorted = Array.isArray(returnEvents)
    ? returnEvents.slice().sort((a, b) => (a.timeMs || 0) - (b.timeMs || 0))
    : [];
  let returnCursor = 0;
  let cumReturnsUsd = 0;

  const points = [];
  for (const timeMs of orderedTimes) {
    while (fundingCursor < fundingSorted.length) {
      const evt = fundingSorted[fundingCursor];
      if (Number(evt?.time || 0) <= timeMs) {
        const usd = Number(evt?.usd ?? 0);
        const safeUsd = Number.isFinite(usd) ? usd : 0;
        runningCapitalUsd += evt?.kind === 'withdraw' ? -safeUsd : safeUsd;
        fundingCursor += 1;
        continue;
      }
      break;
    }
    if (runningCapitalUsd < 0) runningCapitalUsd = 0;

    while (priceCursor < priceTimeline.length) {
      const next = priceTimeline[priceCursor];
      if ((next?.timeMs || 0) <= timeMs) {
        if (Number.isFinite(next.priceEthUsd) && next.priceEthUsd > 0) globalEthUsd = next.priceEthUsd;
        if (Number.isFinite(next.priceEnaUsd) && next.priceEnaUsd > 0) globalEnaUsd = next.priceEnaUsd;
        priceCursor += 1;
        continue;
      }
      break;
    }
    if (!(globalEthUsd > 0) && fallbackEthUsd > 0) globalEthUsd = fallbackEthUsd;
    if (!(globalEnaUsd > 0) && fallbackEnaUsd > 0) globalEnaUsd = fallbackEnaUsd;
    if (!(globalEnaUsd > 0) && globalEthUsd > 0) globalEnaUsd = globalEthUsd;

    let totalEnaTokens = 0;
    let totalWethTokens = 0;
    let navFallbackUsd = 0;
    let totalFeesCollectedUsd = 0;

    for (const vault of timelines) {
      const series = vault.series;
      let cursor = cursors.get(vault.id) || 0;
      let tokens = lastTokens.get(vault.id) || { ena: 0, weth: 0 };
      let navUsd = lastNav.get(vault.id) || 0;
      let feesCollectedUsd = lastFeesCollected.get(vault.id) || 0;
      while (cursor < series.length && series[cursor].timeMs <= timeMs) {
        const snap = series[cursor];
        tokens = { ena: toNumber(snap?.enaTokens), weth: toNumber(snap?.wethTokens) };
        navUsd = toNumber(snap?.navUsd);
        feesCollectedUsd = toNumber(snap?.feesCollectedUsd);
        cursor += 1;
      }
      cursors.set(vault.id, cursor);
      lastTokens.set(vault.id, tokens);
      lastNav.set(vault.id, navUsd);
      lastFeesCollected.set(vault.id, feesCollectedUsd);
      totalEnaTokens += tokens.ena;
      totalWethTokens += tokens.weth;
      navFallbackUsd += navUsd;
      totalFeesCollectedUsd += feesCollectedUsd;
    }

    while (returnCursor < returnsSorted.length) {
      const evt = returnsSorted[returnCursor];
      if ((evt?.timeMs || 0) <= timeMs) {
        cumReturnsUsd += toNumber(evt?.usd);
        returnCursor += 1;
        continue;
      }
      break;
    }

    let navUsd = 0;
    if (globalEthUsd > 0 && globalEnaUsd > 0) {
      navUsd = totalEnaTokens * globalEnaUsd + totalWethTokens * globalEthUsd;
    }
    if (!(navUsd > 0)) {
      navUsd = navFallbackUsd;
    }
    if (!(navUsd > 0) && runningCapitalUsd > 0) {
      navUsd = runningCapitalUsd;
    }
    const missingHistoryCoverage = missingVaultSnapshots || timelines.some((vault) => (cursors.get(vault.id) || 0) === 0);
    if (missingHistoryCoverage && runningCapitalUsd > 0 && navUsd < runningCapitalUsd * 0.05) {
      navUsd = runningCapitalUsd;
    }

    points.push({
      timeMs,
      netCapitalUsd: runningCapitalUsd,
      navUsd,
      returnsUsd: cumReturnsUsd,
      feesCollectedUsd: totalFeesCollectedUsd,
    });
  }

  let firstNonZero = 0;
  while (
    firstNonZero < points.length
    && !(
      points[firstNonZero].netCapitalUsd > 0
      || points[firstNonZero].returnsUsd > 0
      || points[firstNonZero].navUsd >= 1
      || points[firstNonZero].feesCollectedUsd > 0
    )
  ) {
    firstNonZero += 1;
  }
  const trimmed = firstNonZero ? points.slice(firstNonZero) : points;

  if (trimmed.length <= MAX_CHART_POINTS) return trimmed;
  const stride = Math.ceil(trimmed.length / MAX_CHART_POINTS);
  const downsampled = [];
  for (let i = 0; i < trimmed.length; i += stride) {
    downsampled.push(trimmed[i]);
  }
  const tail = trimmed[trimmed.length - 1];
  if (downsampled[downsampled.length - 1] !== tail) downsampled.push(tail);
  return downsampled;
}

function summarizeCumulativeFeeTotals(vaultHistories) {
  const histories = Array.isArray(vaultHistories) ? vaultHistories : [];
  let totalEna = 0;
  let totalWeth = 0;
  let hasData = false;

  for (const row of histories) {
    const snaps = Array.isArray(row?.snapshots) ? row.snapshots : [];
    if (!snaps.length) continue;
    const last = snaps[snaps.length - 1];
    const cumEna = toNumber(last?.cumulativeFeesEna);
    const cumWeth = toNumber(last?.cumulativeFeesWeth);
    if (Number.isFinite(cumEna) || Number.isFinite(cumWeth)) hasData = true;
    totalEna += Number.isFinite(cumEna) ? cumEna : 0;
    totalWeth += Number.isFinite(cumWeth) ? cumWeth : 0;
  }

  return { ena: totalEna, weth: totalWeth, hasData };
}

const BASELINE_SERIES_COLOR = '#a0a7ba';
const NAV_SERIES_COLOR = '#18e6c1';
const RETURNS_SERIES_COLOR = '#ff4ad8';
const FEES_SERIES_COLOR = '#f5a623';

const CHART_START_OVERRIDE_KEY = 'projectC:publicChartStart';
const MIN_CHART_ZOOM_RANGE_MS = 60 * 1000; // 1 minute
const AUTO_CHART_START_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const TIMEFRAME_PRESETS = [
  { label: '1D', value: 24 * 60 * 60 * 1000 },
  { label: '1W', value: 7 * 24 * 60 * 60 * 1000 },
  { label: '1M', value: 30 * 24 * 60 * 60 * 1000 },
  { label: 'ALL', value: null },
];

const investmentChartState = {
  bound: false,
  controlsBound: false,
  history: [],
  rawHistory: [],
  plotHistory: [],
  layout: null,
  timeframeMs: null,
  viewport: null,
  returnsAvailable: null,
  distributionActive: null,
  visibility: {
    nav: true,
    fees: true,
    returns: true,
    baseline: true,
  },
};

const investmentChartSelectionState = { active: false, startX: 0, currentX: 0 };

function formatTooltipTimestamp(ms) {
  if (!Number.isFinite(ms) || ms <= 0) return '—';
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) return '—';
  const iso = date.toISOString();
  return `${iso.slice(0, 19).replace('T', ' ')}Z`;
}

function updateInvestmentChartLegend() {
  const legend = refs.chartLegend;
  if (!legend) return;
  legend.querySelectorAll('[data-series]').forEach((el) => {
    const key = String(el?.dataset?.series || '');
    if (!key) return;
    const enabled = investmentChartState.visibility[key] !== false;
    el.classList.toggle('disabled', !enabled);
  });
}

function initMatrixBackground() {
  const canvas = document.getElementById('matrixCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  const fontSize = 9;
  let columns = 0;
  let drops = [];
  let speeds = [];
  let intervalId = null;

  function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    columns = Math.ceil(canvas.width / fontSize);
    drops = Array.from({ length: columns }, () => 1);
    speeds = drops.map(() => Math.random() + 0.8);
  }

  function draw() {
    ctx.fillStyle = 'rgba(0, 0, 0, 0.027)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = '#EF5F64';
    ctx.font = `${fontSize}px monospace`;

    for (let i = 0; i < drops.length; i += 1) {
      const text = String.fromCharCode(Math.random() * (126 - 33) + 33);
      ctx.fillText(text, i * fontSize, drops[i] * fontSize);

      if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }

      drops[i] += speeds[i];
    }
  }

  function start() {
    if (intervalId) clearInterval(intervalId);
    intervalId = setInterval(draw, 38);
  }

  resizeCanvas();
  start();

  window.addEventListener('resize', () => {
    if (intervalId) clearInterval(intervalId);
    resizeCanvas();
    start();
  });
}

function syncInvestmentReturnsSeriesAvailability(returnEvents, distributionOngoing) {
  const hasReturns = Array.isArray(returnEvents) && returnEvents.length > 0;
  const isDistributing = Boolean(distributionOngoing);
  const prevReturns = investmentChartState.returnsAvailable;
  const prevDist = investmentChartState.distributionActive;
  investmentChartState.returnsAvailable = hasReturns;
  investmentChartState.distributionActive = isDistributing;

  if (prevReturns == null && prevDist == null) {
    if (!hasReturns || !isDistributing) investmentChartState.visibility.returns = false;
    updateInvestmentChartLegend();
    return;
  }

  if (
    prevReturns === false
    && hasReturns === true
    && isDistributing === true
    && investmentChartState.visibility.returns === false
  ) {
    investmentChartState.visibility.returns = true;
  }

  if (
    prevDist === false
    && isDistributing === true
    && hasReturns
    && investmentChartState.visibility.returns === false
  ) {
    investmentChartState.visibility.returns = true;
  }

  updateInvestmentChartLegend();
}

async function fetchLatestActions(managers, toBlock) {
  const events = [];
  const list = Array.isArray(managers) ? managers : [];

  for (const manager of list) {
    const addr = normalizeAddress(manager?.address);
    if (!addr) continue;
    const fromBlock = Number(manager?.startBlock) > 0 ? Number(manager.startBlock) : 0;
    const safeFromBlock = fromBlock > 0 ? fromBlock : Math.max(0, toBlock - 200_000);

    const [rebalanceLogs, compoundLogs] = await Promise.all([
      fetchLogs(addr, [rebalancedTopic], safeFromBlock, toBlock).catch(() => []),
      fetchLogs(addr, [compoundedTopic], safeFromBlock, toBlock).catch(() => []),
    ]);

    for (const log of rebalanceLogs || []) {
      const txHash = log?.transactionHash;
      const blockNumber = Number(log?.blockNumber);
      if (!txHash || !Number.isFinite(blockNumber) || blockNumber <= 0) continue;
      events.push({ kind: 'Rebalance', txHash: String(txHash), blockNumber, timeMs: 0 });
    }

    for (const log of compoundLogs || []) {
      const txHash = log?.transactionHash;
      const blockNumber = Number(log?.blockNumber);
      if (!txHash || !Number.isFinite(blockNumber) || blockNumber <= 0) continue;
      events.push({ kind: 'Compound', txHash: String(txHash), blockNumber, timeMs: 0 });
    }
  }

  const blockNumbers = Array.from(new Set(events.map((evt) => evt.blockNumber))).sort((a, b) => a - b);
  await Promise.all(blockNumbers.map((bn) => getBlockTimestampSec(bn)));
  for (const evt of events) {
    const ts = blockTimestampCache.get(evt.blockNumber) || 0;
    evt.timeMs = ts > 0 ? ts * 1000 : 0;
  }

  events.sort((a, b) => {
    const at = Number(a?.timeMs || 0);
    const bt = Number(b?.timeMs || 0);
    if (at !== bt) return at - bt;
    const ab = Number(a?.blockNumber || 0);
    const bb = Number(b?.blockNumber || 0);
    if (ab !== bb) return ab - bb;
    return String(a?.txHash || '').localeCompare(String(b?.txHash || ''));
  });

  return events;
}

function ceilToMinuteMs(ms) {
  if (!Number.isFinite(ms) || ms <= 0) return ms;
  const minute = 60_000;
  return Math.ceil(ms / minute) * minute;
}

function parseChartStartOverrideMs() {
  const raw = String(safeStorageGet(CHART_START_OVERRIDE_KEY) || '').trim();
  if (!raw) return 0;
  const asNumber = Number(raw);
  if (Number.isFinite(asNumber) && asNumber > 0) return asNumber;
  const parsed = Date.parse(raw);
  if (Number.isFinite(parsed) && parsed > 0) return parsed;
  return 0;
}

function computeAutoChartStartMs(history) {
  if (!Array.isArray(history) || !history.length) return 0;
  const firstTime = toNumber(history[0]?.time);
  if (!(firstTime > 0)) return 0;

  const windowEnd = firstTime + AUTO_CHART_START_WINDOW_MS;
  const windowPoints = history.filter((point) => toNumber(point?.time) <= windowEnd);
  if (windowPoints.length < 2) return firstTime;

  const firstBaseline = toNumber(windowPoints[0]?.baseline);
  const baselines = windowPoints
    .map((point) => toNumber(point?.baseline))
    .filter((val) => Number.isFinite(val));
  if (!baselines.length) return firstTime;
  const maxBaseline = Math.max(...baselines);
  if (!(maxBaseline > 0)) return firstTime;

  const ratio = firstBaseline > 0 ? maxBaseline / firstBaseline : maxBaseline;
  if (!(ratio > 1.05)) return firstTime;

  const threshold = maxBaseline * 0.99;
  const reached = windowPoints.find((point) => toNumber(point?.baseline) >= threshold);
  if (!reached) return firstTime;
  const reachedTime = toNumber(reached?.time);
  if (!(reachedTime > firstTime)) return firstTime;

  return ceilToMinuteMs(reachedTime + 1);
}

function getInvestmentChartBaseStartMs(history) {
  const override = parseChartStartOverrideMs();
  if (override > 0) return override;
  return computeAutoChartStartMs(history);
}

function getInvestmentChartDataBounds(history) {
  if (!Array.isArray(history) || history.length < 1) return null;
  const firstTime = toNumber(history[0]?.time);
  const lastTime = toNumber(history[history.length - 1]?.time);
  if (!(firstTime > 0) || !(lastTime > 0)) return null;

  const baseStart = getInvestmentChartBaseStartMs(history);
  const start = Math.max(firstTime, baseStart || firstTime);
  const end = lastTime;
  if (end < start) return null;
  return { start, end };
}

function getInvestmentChartViewport(history) {
  const bounds = getInvestmentChartDataBounds(history);
  if (!bounds) return null;
  const dataStart = bounds.start;
  const dataEnd = bounds.end;

  const custom = investmentChartState.viewport;
  if (custom && Number.isFinite(custom.start) && Number.isFinite(custom.end) && custom.end > custom.start) {
    const start = Math.max(dataStart, custom.start);
    const end = Math.min(dataEnd, custom.end);
    if (end > start) return { start, end, custom: true, dataStart, dataEnd };
  }

  const timeframe = investmentChartState.timeframeMs;
  if (typeof timeframe === 'number' && timeframe > 0) {
    const start = Math.max(dataStart, dataEnd - timeframe);
    return { start, end: dataEnd, custom: false, dataStart, dataEnd };
  }

  return { start: dataStart, end: dataEnd, custom: false, dataStart, dataEnd };
}

function filterInvestmentHistoryForViewport(history, viewport) {
  if (!viewport) return { data: history, viewport: null };
  const filtered = history.filter((point) => point.time >= viewport.start && point.time <= viewport.end);
  if (!filtered.length && history.length) {
    filtered.push(history[history.length - 1]);
  }
  if (filtered.length && filtered[0].time > viewport.start) {
    const prev = history.slice().reverse().find((point) => point.time < viewport.start);
    const seed = prev || filtered[0];
    filtered.unshift({ ...seed, time: viewport.start });
  }
  return { data: filtered, viewport };
}

function updateInvestmentTimeframeButtons() {
  const toolbar = refs.chartToolbar;
  if (!toolbar) return;
  const timeframe = investmentChartState.timeframeMs;
  const hasCustomViewport = investmentChartState.viewport && investmentChartState.viewport.end > investmentChartState.viewport.start;
  const activeKey = hasCustomViewport ? null : (timeframe == null ? 'all' : String(timeframe));
  toolbar.querySelectorAll('button[data-range]').forEach((btn) => {
    const key = btn.dataset.range || 'all';
    btn.classList.toggle('active', activeKey != null && key === activeKey);
  });
}

function updateInvestmentChartResetButton() {
  const btn = refs.chartResetBtn;
  if (!btn) return;
  const hasViewport = investmentChartState.viewport && investmentChartState.viewport.end > investmentChartState.viewport.start;
  const hasTimeframe = typeof investmentChartState.timeframeMs === 'number' && investmentChartState.timeframeMs > 0;
  btn.disabled = !(hasViewport || hasTimeframe);
}

function hideInvestmentSelectionOverlay() {
  if (refs.chartSelectionBox) refs.chartSelectionBox.style.display = 'none';
}

function setInvestmentChartTimeframe(rangeMs) {
  investmentChartState.timeframeMs = typeof rangeMs === 'number' ? rangeMs : null;
  investmentChartState.viewport = null;
  hideInvestmentSelectionOverlay();
  updateInvestmentTimeframeButtons();
  updateInvestmentChartResetButton();
  drawInvestmentChart(refs.chart, investmentChartState.rawHistory);
}

function resetInvestmentChartView() {
  investmentChartState.timeframeMs = null;
  investmentChartState.viewport = null;
  hideInvestmentSelectionOverlay();
  updateInvestmentTimeframeButtons();
  updateInvestmentChartResetButton();
  drawInvestmentChart(refs.chart, investmentChartState.rawHistory);
}

function bindInvestmentChartControls() {
  if (investmentChartState.controlsBound) return;
  investmentChartState.controlsBound = true;

  const toolbar = refs.chartToolbar;
  if (toolbar) {
    toolbar.textContent = '';
    TIMEFRAME_PRESETS.forEach((preset) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = preset.label;
      btn.dataset.range = preset.value == null ? 'all' : String(preset.value);
      btn.addEventListener('click', () => setInvestmentChartTimeframe(preset.value));
      toolbar.appendChild(btn);
    });
  }

  if (refs.chartResetBtn) {
    refs.chartResetBtn.addEventListener('click', resetInvestmentChartView);
  }

  if (refs.reloadBtn) {
    refs.reloadBtn.addEventListener('click', () => runRender());
  }

  updateInvestmentTimeframeButtons();
  updateInvestmentChartResetButton();
}

const audioToggleState = {
  bound: false,
  targetVolume: 0.35,
  fadeMs: 750,
  fadeHandle: null,
};

const bannerReloadState = {
  bound: false,
};

function setAudioToggleUi(isOn) {
  const btn = refs.btnAudio;
  if (!btn) return;
  btn.classList.toggle('btn-light', isOn);
  btn.classList.toggle('btn-outline-light', !isOn);
  const label = isOn ? 'Sound: On' : 'Sound: Off';
  btn.title = label;
  btn.setAttribute('aria-label', label);
  const iconOn = btn.querySelector('.audio-toggle-icon-on');
  const iconOff = btn.querySelector('.audio-toggle-icon-off');
  if (iconOn) iconOn.classList.toggle('is-hidden', !isOn);
  if (iconOff) iconOff.classList.toggle('is-hidden', isOn);
}

function fadeAudioVolume(audio, from, to, durationMs) {
  if (!audio) return;
  if (audioToggleState.fadeHandle) cancelAnimationFrame(audioToggleState.fadeHandle);
  const start = performance.now();

  const step = (now) => {
    const elapsed = now - start;
    const ratio = Math.min(Math.max(elapsed / Math.max(durationMs, 1), 0), 1);
    audio.volume = from + (to - from) * ratio;
    if (ratio < 1 && !audio.paused) {
      audioToggleState.fadeHandle = requestAnimationFrame(step);
      return;
    }
    audioToggleState.fadeHandle = null;
  };

  audioToggleState.fadeHandle = requestAnimationFrame(step);
}

function initAudioToggle() {
  if (audioToggleState.bound) return;
  audioToggleState.bound = true;

  const audio = refs.bgAudio;
  const btn = refs.btnAudio;
  if (!audio || !btn) return;

  audio.loop = true;
  audio.volume = audioToggleState.targetVolume;
  setAudioToggleUi(!audio.paused);

  btn.addEventListener('click', async () => {
    if (audio.paused) {
      try {
        audio.volume = 0;
        await audio.play();
        setAudioToggleUi(true);
        fadeAudioVolume(audio, 0, audioToggleState.targetVolume, audioToggleState.fadeMs);
      } catch (err) {
        console.warn('Audio playback blocked or failed', err);
        setAudioToggleUi(false);
      }
      return;
    }

    audio.pause();
    setAudioToggleUi(false);
  });
}

function initBannerReload() {
  if (bannerReloadState.bound) return;
  bannerReloadState.bound = true;

  const btn = refs.bannerReloadBtn;
  if (!btn) return;
  btn.addEventListener('click', () => runRender());
}

bindInvestmentChartControls();
initMatrixBackground();
initAudioToggle();
initBannerReload();

function hideInvestmentChartTooltip() {
  if (refs.chartTooltip) refs.chartTooltip.classList.remove('visible');
}

function handleInvestmentChartHover(pointerEvent, originalEvent) {
  const canvas = refs.chart;
  const wrap = refs.chartWrap;
  const tooltip = refs.chartTooltip;
  const layout = investmentChartState.layout;
  const history = investmentChartState.plotHistory;
  if (investmentChartSelectionState.active) {
    hideInvestmentChartTooltip();
    return;
  }
  if (!canvas || !wrap || !tooltip || !layout || !history.length) {
    hideInvestmentChartTooltip();
    return;
  }

  const eventSource = pointerEvent || originalEvent;
  if (!eventSource) return;
  const clientX = eventSource.clientX ?? eventSource.pageX;
  const clientY = eventSource.clientY ?? eventSource.pageY;
  if (!Number.isFinite(clientX) || !Number.isFinite(clientY)) return;

  const canvasRect = canvas.getBoundingClientRect();
  const wrapRect = wrap.getBoundingClientRect();
  const relativeX = clientX - canvasRect.left;

  const { padding, width, viewStart, viewEnd } = layout;
  const timeSpan = Math.max(viewEnd - viewStart, 1);
  const clampedX = Math.max(padding, Math.min(width - padding, relativeX));
  const ratio = (clampedX - padding) / (width - padding * 2);
  const targetTime = viewStart + ratio * timeSpan;

  let point = history[0];
  let minDelta = Math.abs(point.time - targetTime);
  for (let i = 1; i < history.length; i += 1) {
    const delta = Math.abs(history[i].time - targetTime);
    if (delta < minDelta) {
      minDelta = delta;
      point = history[i];
    }
  }
  if (!point) return;

  const rows = [];
  if (investmentChartState.visibility.nav !== false) {
    rows.push(`<div class="tooltip-row"><span class="tooltip-dot nav"></span><span>NAV: ${formatUsd(point.nav, 0)}</span></div>`);
  }
  if (investmentChartState.visibility.fees !== false) {
    rows.push(`<div class="tooltip-row"><span class="tooltip-dot fees"></span><span>Fees Collected: ${formatUsd(point.fees, 0)}</span></div>`);
  }
  if (investmentChartState.visibility.baseline !== false) {
    rows.push(`<div class="tooltip-row"><span class="tooltip-dot net-capital"></span><span>Net Capital: ${formatUsd(point.baseline, 0)}</span></div>`);
  }
  if (investmentChartState.visibility.returns !== false) {
    rows.push(`<div class="tooltip-row"><span class="tooltip-dot returns"></span><span>Cumulative Returns: ${formatUsd(point.returns, 0)}</span></div>`);
  }

  tooltip.innerHTML = `<span class="tooltip-label">${formatTooltipTimestamp(point.time)}</span>${rows.join('')}`;

  const tooltipRect = tooltip.getBoundingClientRect();
  const wrapWidth = wrapRect.width;
  const wrapHeight = wrapRect.height;
  let left = (clientX - wrapRect.left) + 12;
  let top = (clientY - wrapRect.top) - tooltipRect.height - 12;
  if (left + tooltipRect.width + 8 > wrapWidth) {
    left = wrapWidth - tooltipRect.width - 8;
  }
  left = Math.max(8, left);
  if (top < 8) {
    top = (clientY - wrapRect.top) + 12;
  }
  if (top + tooltipRect.height + 8 > wrapHeight) {
    top = wrapHeight - tooltipRect.height - 8;
  }
  tooltip.style.left = `${left}px`;
  tooltip.style.top = `${top}px`;
  tooltip.classList.add('visible');
}

function updateInvestmentSelectionOverlay() {
  const box = refs.chartSelectionBox;
  const canvas = refs.chart;
  if (!box || !canvas) return;
  if (!investmentChartSelectionState.active) {
    box.style.display = 'none';
    return;
  }

  const rect = canvas.getBoundingClientRect();
  const start = investmentChartSelectionState.startX;
  const current = investmentChartSelectionState.currentX;
  const left = Math.max(rect.left, Math.min(rect.right, Math.min(start, current)));
  const right = Math.max(rect.left, Math.min(rect.right, Math.max(start, current)));
  const width = right - left;
  if (width <= 2) {
    box.style.display = 'none';
    return;
  }
  box.style.display = 'block';
  box.style.left = `${left - rect.left}px`;
  box.style.width = `${width}px`;
}

function handleInvestmentChartSelectionStart(event) {
  if (event.button !== 0) return;
  if (!refs.chart || !refs.chartSelectionBox) return;
  investmentChartSelectionState.active = true;
  investmentChartSelectionState.startX = event.clientX;
  investmentChartSelectionState.currentX = event.clientX;
  updateInvestmentSelectionOverlay();
  window.addEventListener('mousemove', handleInvestmentChartSelectionMove, { passive: false });
  window.addEventListener('mouseup', handleInvestmentChartSelectionEnd);
  event.preventDefault();
}

function handleInvestmentChartSelectionMove(event) {
  if (!investmentChartSelectionState.active) return;
  investmentChartSelectionState.currentX = event.clientX;
  updateInvestmentSelectionOverlay();
  event.preventDefault();
}

function handleInvestmentChartSelectionEnd(event) {
  if (!investmentChartSelectionState.active) return;
  window.removeEventListener('mousemove', handleInvestmentChartSelectionMove);
  window.removeEventListener('mouseup', handleInvestmentChartSelectionEnd);

  const startX = investmentChartSelectionState.startX;
  const endX = investmentChartSelectionState.currentX;
  investmentChartSelectionState.active = false;
  hideInvestmentSelectionOverlay();
  if (Math.abs(endX - startX) < 6) return;

  const canvas = refs.chart;
  const layout = investmentChartState.layout;
  const history = investmentChartState.plotHistory;
  if (!canvas || !layout || !history || history.length < 2) return;
  const rect = canvas.getBoundingClientRect();

  const viewStart = toNumber(layout.viewStart);
  const viewEnd = toNumber(layout.viewEnd);
  if (!(viewEnd > viewStart)) return;

  const left = Math.max(rect.left, Math.min(rect.right, Math.min(startX, endX)));
  const right = Math.max(rect.left, Math.min(rect.right, Math.max(startX, endX)));
  if (right - left < 6) return;

  const relStart = (left - rect.left - layout.padding) / layout.plotWidth;
  const relEnd = (right - rect.left - layout.padding) / layout.plotWidth;
  const ratioStart = Math.min(1, Math.max(0, relStart));
  const ratioEnd = Math.min(1, Math.max(0, relEnd));
  if (ratioEnd - ratioStart < 0.001) return;

  const newStart = viewStart + (viewEnd - viewStart) * ratioStart;
  const newEnd = viewStart + (viewEnd - viewStart) * ratioEnd;
  if (!(newEnd > newStart)) return;

  investmentChartState.viewport = { start: newStart, end: newEnd };
  investmentChartState.timeframeMs = null;
  updateInvestmentTimeframeButtons();
  updateInvestmentChartResetButton();
  drawInvestmentChart(refs.chart, investmentChartState.rawHistory);
}

function handleInvestmentChartMouseDown(event) {
  handleInvestmentChartSelectionStart(event);
}

function handleInvestmentChartWheel(event) {
  event.preventDefault();
  const history = investmentChartState.history;
  if (!Array.isArray(history) || history.length < 2) return;
  const layout = investmentChartState.layout;
  const canvas = refs.chart;
  if (!canvas || !layout?.plotWidth) return;

  const viewport = getInvestmentChartViewport(history);
  if (!viewport) return;
  const dataStart = viewport.dataStart;
  const dataEnd = viewport.dataEnd;
  if (!(dataEnd > dataStart)) return;

  const range = viewport.end - viewport.start;
  const zoomFactor = event.deltaY > 0 ? 1.1 : 0.9;
  let newRange = range * zoomFactor;
  const maxRange = dataEnd - dataStart;
  newRange = Math.min(Math.max(newRange, MIN_CHART_ZOOM_RANGE_MS), Math.max(MIN_CHART_ZOOM_RANGE_MS, maxRange));

  const rect = canvas.getBoundingClientRect();
  const x = event.clientX - rect.left;
  const ratio = Math.min(1, Math.max(0, (x - layout.padding) / layout.plotWidth));
  const center = viewport.start + range * ratio;
  let newStart = center - newRange * ratio;
  let newEnd = newStart + newRange;
  if (newStart < dataStart) {
    newStart = dataStart;
    newEnd = newStart + newRange;
  }
  if (newEnd > dataEnd) {
    newEnd = dataEnd;
    newStart = newEnd - newRange;
  }

  investmentChartState.viewport = { start: newStart, end: newEnd };
  investmentChartState.timeframeMs = null;
  hideInvestmentSelectionOverlay();
  updateInvestmentTimeframeButtons();
  updateInvestmentChartResetButton();
  drawInvestmentChart(refs.chart, investmentChartState.rawHistory);
}

function bindInvestmentChartEvents() {
  if (investmentChartState.bound) return;
  investmentChartState.bound = true;

  bindInvestmentChartControls();

  if (refs.chart) {
    refs.chart.addEventListener('mousemove', (event) => handleInvestmentChartHover(event));
    refs.chart.addEventListener('mouseleave', hideInvestmentChartTooltip);
    refs.chart.addEventListener(
      'touchmove',
      (event) => {
        if (event.touches?.length) handleInvestmentChartHover(event.touches[0], event);
      },
      { passive: true },
    );
    refs.chart.addEventListener('touchend', hideInvestmentChartTooltip);
    refs.chart.addEventListener('wheel', handleInvestmentChartWheel, { passive: false });
    refs.chart.addEventListener('mousedown', handleInvestmentChartMouseDown);
  }

  if (refs.chartLegend) {
    refs.chartLegend.querySelectorAll('[data-series]').forEach((el) => {
      el.addEventListener('click', () => {
        const key = String(el?.dataset?.series || '');
        if (!key) return;
        const next = investmentChartState.visibility[key] === false;
        const enabledCount = Object.values(investmentChartState.visibility).filter((v) => v !== false).length;
        if (!next && enabledCount <= 1) return;
        investmentChartState.visibility[key] = next;
        updateInvestmentChartLegend();
        drawInvestmentChart(refs.chart, investmentChartState.rawHistory);
      });
    });
  }

  updateInvestmentChartLegend();
}

function drawInvestmentChart(canvas, rawHistory) {
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  bindInvestmentChartEvents();

  investmentChartState.rawHistory = Array.isArray(rawHistory) ? rawHistory : [];
  const normalizedHistory = investmentChartState.rawHistory
    .map((point) => ({
      time: toNumber(point?.timeMs),
      nav: toNumber(point?.navUsd),
      fees: toNumber(point?.feesCollectedUsd),
      returns: toNumber(point?.returnsUsd),
      baseline: toNumber(point?.netCapitalUsd),
    }))
    .filter((point) => Number.isFinite(point.time) && point.time > 0)
    .sort((a, b) => a.time - b.time);
  investmentChartState.history = normalizedHistory;

  const viewport = getInvestmentChartViewport(normalizedHistory);
  const { data: history, viewport: appliedViewport } = filterInvestmentHistoryForViewport(normalizedHistory, viewport);
  investmentChartState.plotHistory = history;
  updateInvestmentTimeframeButtons();
  updateInvestmentChartResetButton();

  const width = canvas.clientWidth || 600;
  const height = canvas.clientHeight || 220;
  const dpr = window.devicePixelRatio || 1;
  if (canvas.width !== width * dpr || canvas.height !== height * dpr) {
    canvas.width = width * dpr;
    canvas.height = height * dpr;
  }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);

  if (!history.length) {
    ctx.fillStyle = 'rgba(232, 241, 255, 0.55)';
    ctx.font = '12px JetBrains Mono, monospace';
    ctx.fillText('Chart data unavailable', 16, 32);
    investmentChartState.layout = null;
    hideInvestmentChartTooltip();
    return;
  }

  const seriesVisibility = investmentChartState.visibility;
  const seriesKeys = ['nav', 'fees', 'returns', 'baseline'];
  const visibleSeriesKeys = seriesKeys.filter((key) => seriesVisibility[key] !== false);

  const padding = 12;
  const plotWidth = width - padding * 2;
  const plotHeight = height - padding * 2;
  if (!(plotWidth > 0) || !(plotHeight > 0)) return;

  const values = [];
  history.forEach((point) => {
    visibleSeriesKeys.forEach((key) => {
      const val = Number(point?.[key]);
      if (Number.isFinite(val)) values.push(val);
    });
  });
  if (!values.length) return;

  let minVal = Math.min(...values);
  let maxVal = Math.max(...values);
  const span = maxVal - minVal;
  const padRatio = 0.07;
  let pad = span * padRatio;
  if (!(pad > 0)) {
    const magnitude = Math.max(Math.abs(maxVal), Math.abs(minVal), 1);
    pad = magnitude * padRatio;
  }
  let scaledMin = minVal - pad;
  let scaledMax = maxVal + pad;
  if (!(scaledMax > scaledMin)) {
    const base = maxVal || minVal || 0;
    const spanFallback = Math.max(Math.abs(base), 1);
    scaledMin = base - spanFallback;
    scaledMax = base + spanFallback;
  }
  const range = scaledMax - scaledMin || 1;

  const viewStart = Number.isFinite(appliedViewport?.start) ? appliedViewport.start : history[0].time;
  const viewEnd = Number.isFinite(appliedViewport?.end) ? appliedViewport.end : history[history.length - 1].time;
  const timeSpan = Math.max(viewEnd - viewStart, 1);
  const timeToX = (time) => {
    const clamped = Math.min(Math.max(time, viewStart), viewEnd);
    const ratio = (clamped - viewStart) / timeSpan;
    return padding + ratio * plotWidth;
  };

  const drawLine = (key, color, options = {}) => {
    if (seriesVisibility[key] === false) return;
    const seriesHasValues = history.some((point) => Number.isFinite(point?.[key]));
    if (!seriesHasValues) return;

    if (history.length === 1) {
      const point = history[0];
      const value = Number(point[key]);
      if (!Number.isFinite(value)) return;
      const normalized = (value - scaledMin) / range;
      const ySingle = padding + (1 - normalized) * plotHeight;
      const xSingle = timeToX(point.time);
      ctx.beginPath();
      ctx.fillStyle = color;
      ctx.arc(xSingle, ySingle, 3, 0, Math.PI * 2);
      ctx.fill();
      return;
    }

    ctx.beginPath();
    ctx.strokeStyle = color;
    ctx.lineWidth = options.lineWidth ?? 2;
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    if (Array.isArray(options.dash)) ctx.setLineDash(options.dash);
    else ctx.setLineDash([]);

    history.forEach((point, idx) => {
      const x = timeToX(point.time);
      const value = Number(point[key]);
      if (!Number.isFinite(value)) return;
      const normalized = (value - scaledMin) / range;
      const y = padding + (1 - normalized) * plotHeight;
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
    ctx.setLineDash([]);
  };

  drawLine('nav', NAV_SERIES_COLOR);
  drawLine('fees', FEES_SERIES_COLOR);
  drawLine('returns', RETURNS_SERIES_COLOR);
  drawLine('baseline', BASELINE_SERIES_COLOR, { dash: [5, 4], lineWidth: 1.5 });

  investmentChartState.layout = {
    padding,
    width,
    height,
    plotWidth,
    plotHeight,
    viewStart,
    viewEnd,
  };
}

async function render() {
  clearError();
  if (refs.updatedLabel) refs.updatedLabel.textContent = 'Loading…';

  const managers = Array.isArray(LIQUIDITY_MANAGERS) ? LIQUIDITY_MANAGERS : [];
  const activeManagers = managers
    .map((row) => ({
      ...row,
      address: normalizeAddress(row?.address) || row?.address,
    }))
    .filter((row) => normalizeAddress(row?.address));

  if (!activeManagers.length) {
    showError('No vault addresses configured in project_constants.js');
    return;
  }

  const toBlock = await rpcCall((activeProvider) => activeProvider.getBlockNumber(), 'RPC eth_blockNumber');
  const priceCtx = await getPriceContext();
  const cultUsd = Number(priceCtx?.cultUsd || 0);

  const vaultNodes = buildVaultNodes(activeManagers);
  const vaultNodesResolved = await Promise.all(
    vaultNodes.map(async (node) => ({
      ...node,
      startBlock: await ensureManagerStartBlock(node),
    })),
  );

  const compoundFlags = await fetchCompoundFlags(activeManagers);
  const anyDistributing = compoundFlags.some((row) => row.compoundFees === false);
  const allCompound = compoundFlags.length === activeManagers.length
    && compoundFlags.every((row) => row.compoundFees === true);
  if (refs.phaseBadge) {
    refs.phaseBadge.classList.remove('phase-loading', 'phase-1', 'phase-2');
    if (!compoundFlags.length) {
      refs.phaseBadge.classList.add('phase-loading');
      refs.phaseBadge.textContent = 'Phase Unavailable';
    } else if (anyDistributing) {
      refs.phaseBadge.classList.add('phase-2');
      refs.phaseBadge.textContent = '🟣 PHASE 2: DISTRIBUTION';
    } else if (allCompound) {
      refs.phaseBadge.classList.add('phase-1');
      refs.phaseBadge.textContent = '🟢 PHASE 1: ACCUMULATION';
    } else {
      refs.phaseBadge.classList.add('phase-loading');
      refs.phaseBadge.textContent = 'Phase Unavailable';
    }
  }

  const { burnedRaw, stakedRaw, events: returnEvents } = await fetchReturns(vaultNodesResolved, cultUsd, toBlock);
  syncInvestmentReturnsSeriesAvailability(returnEvents, anyDistributing);
  const burnedNetRaw = (burnedRaw * 996n) / 1000n;
  const totalRaw = burnedRaw + stakedRaw;

  if (refs.impactCard) {
    const hideImpact = allCompound && totalRaw === 0n;
    refs.impactCard.classList.toggle('is-hidden', hideImpact);
  }

  const burnedTokens = toNumber(ethers.formatUnits(burnedNetRaw, CULT_DECIMALS), 0);
  const stakedTokens = toNumber(ethers.formatUnits(stakedRaw, CULT_DECIMALS), 0);
  const totalTokens = toNumber(ethers.formatUnits(totalRaw, CULT_DECIMALS), 0);
  const hasCultUsd = Number.isFinite(cultUsd) && cultUsd > 0;

  if (refs.impact.burnValue) refs.impact.burnValue.textContent = `${formatToken(burnedTokens, 2)} CULT`;
  if (refs.impact.burnSub) refs.impact.burnSub.textContent = hasCultUsd ? formatUsd(burnedTokens * cultUsd, 0) : 'n/a';

  if (refs.impact.rewardsValue) refs.impact.rewardsValue.textContent = `${formatToken(stakedTokens, 2)} CULT`;
  if (refs.impact.rewardsSub) refs.impact.rewardsSub.textContent = hasCultUsd ? formatUsd(stakedTokens * cultUsd, 0) : 'n/a';

  if (refs.impact.totalValue) refs.impact.totalValue.textContent = `${formatToken(totalTokens, 2)} CULT`;
  if (refs.impact.totalSub) refs.impact.totalSub.textContent = hasCultUsd ? formatUsd(totalTokens * cultUsd, 0) : 'n/a';

  const latestReturn = returnEvents.slice().reverse().find((evt) => evt?.txHash && evt?.timeMs > 0) || null;
  if (refs.latestDistributionLink) {
    if (latestReturn?.txHash) {
      refs.latestDistributionLink.classList.remove('is-empty');
      refs.latestDistributionLink.href = `${ETHERSCAN_TX_BASE}${latestReturn.txHash}`;
      refs.latestDistributionLink.textContent = `Latest Distribution: ${formatClockTime(latestReturn.timeMs)}`;
      refs.latestDistributionLink.title = latestReturn.txHash;
    } else {
      refs.latestDistributionLink.classList.add('is-empty');
      refs.latestDistributionLink.removeAttribute('href');
      refs.latestDistributionLink.textContent = 'Latest Distribution: —';
      refs.latestDistributionLink.title = 'No return events found';
    }
  }

  const fundingProfiles = await Promise.all(
    vaultNodesResolved.map(async (node) => {
      const startBlock = await ensureManagerStartBlock(node);
      const ownerHistory = await fetchOwnerHistory(node.address, startBlock, toBlock);
      const flows = await sumOwnerFlows(node.address, ownerHistory, startBlock, toBlock);
      return { ...node, startBlock, ownerHistory, ...flows };
    }),
  );

  const fundingChains = fundingProfiles
    .filter((row) => Array.isArray(row?.fundingEvents) && row.fundingEvents.length)
    .slice()
    .sort((a, b) => {
      const ab = Number(a?.startBlock ?? 0);
      const bb = Number(b?.startBlock ?? 0);
      if (ab !== bb) return ab - bb;
      const at = Number(a?.fundingEvents?.[0]?.time ?? 0);
      const bt = Number(b?.fundingEvents?.[0]?.time ?? 0);
      if (at !== bt) return at - bt;
      return String(a?.address || '').localeCompare(String(b?.address || ''));
    })
    .map((row) => row.fundingEvents);

  const stitchedFundingEvents = stitchMigrationFundingEventsChain(fundingChains);
  const fundingSummary = summarizeFundingEvents(stitchedFundingEvents);
  const netCapitalUsd = Math.max(0, Number(fundingSummary.depositUsd) - Number(fundingSummary.withdrawUsd));

  const liveSnapshots = await Promise.all(
    activeManagers.map((mgr) => buildLiveVaultSnapshot(mgr.address, priceCtx)),
  );
  const navUsd = liveSnapshots.reduce((sum, snap) => sum + toNumber(snap?.navUsd), 0);
  const idleUsd = liveSnapshots.reduce((sum, snap) => sum + toNumber(snap?.idleUsd), 0);
  const positionUsd = liveSnapshots.reduce((sum, snap) => sum + toNumber(snap?.positionUsd), 0);
  const feesUsd = liveSnapshots.reduce((sum, snap) => sum + toNumber(snap?.feesUsd), 0);

  const netProfitUsd = navUsd - netCapitalUsd;
  const roiPct = netCapitalUsd > 0 ? (netProfitUsd / netCapitalUsd) * 100 : NaN;

  applyCardTint(refs.healthCard, netProfitUsd);

  if (refs.health.netCapitalValue) refs.health.netCapitalValue.textContent = formatUsd(netCapitalUsd, 0);
  if (refs.health.netCapitalSub) {
    refs.health.netCapitalSub.textContent = `Deposits ${formatUsd(fundingSummary.depositUsd, 0)} • Withdrawals ${formatUsd(fundingSummary.withdrawUsd, 0)}`;
  }

  if (refs.health.investmentValue) refs.health.investmentValue.textContent = formatUsd(navUsd, 0);
  if (refs.health.investmentSub) {
    refs.health.investmentSub.textContent = `Active ${formatUsd(positionUsd, 0)} • Fees ${formatUsd(feesUsd, 2)}`;
  }

  if (refs.health.netProfitValue) refs.health.netProfitValue.textContent = formatUsd(netProfitUsd, 0);
  applyValueTone(refs.health.netProfitValue, netProfitUsd);
  if (refs.health.netProfitSub) refs.health.netProfitSub.textContent = netProfitUsd >= 0 ? 'Profitable' : 'Below water';

  if (refs.health.roiValue) refs.health.roiValue.textContent = formatPct(roiPct, 2);
  applyValueTone(refs.health.roiValue, roiPct);
  if (refs.health.roiSub) refs.health.roiSub.textContent = netCapitalUsd > 0 ? 'Net profit / net capital' : 'n/a';

  let historyInputs = [];
  try {
    const historyVaultIds = vaultNodesResolved.map((node) => String(node.address).toLowerCase());
    const vaultQueries = await Promise.all(
      historyVaultIds.map(async (vaultId) => ({ vaultId, snapshots: await fetchVaultSnapshots(vaultId) })),
    );
    historyInputs = vaultQueries;
  } catch (err) {
    console.warn('subgraph snapshot fetch failed', err);
  }

  const feeTokensTotals = summarizeCumulativeFeeTotals(historyInputs);
  const returnsTotalUsd = returnEvents.reduce((sum, evt) => sum + toNumber(evt?.usd), 0);
  const investmentHistory = buildInvestmentHistory(historyInputs, stitchedFundingEvents, returnEvents, priceCtx);
  const nowMs = Date.now();
  const lastPoint = investmentHistory.length ? investmentHistory[investmentHistory.length - 1] : null;
  const feesCollectedUsd = lastPoint ? toNumber(lastPoint.feesCollectedUsd) : 0;
  if (refs.health.feesCollectedValue) {
    refs.health.feesCollectedValue.textContent = feeTokensTotals.hasData ? formatUsd(feesCollectedUsd, 0) : '—';
    refs.health.feesCollectedValue.classList.toggle('text-fees', feeTokensTotals.hasData && feesCollectedUsd > 0);
  }
  if (refs.health.feesCollectedSub) {
    if (!feeTokensTotals.hasData) {
      refs.health.feesCollectedSub.textContent = 'Subgraph unavailable';
    } else {
      const depositUsd = toNumber(fundingSummary?.depositUsd);
      const pct = depositUsd > 0 ? (feesCollectedUsd / depositUsd) * 100 : NaN;
      const pctLabel = Number.isFinite(pct) ? `${pct >= 0 ? '+' : ''}${pct.toFixed(2)}% of deposits` : '–';
      refs.health.feesCollectedSub.textContent = `ENA ${formatToken(feeTokensTotals.ena, 2)} / WETH ${formatToken(feeTokensTotals.weth, 4)} • ${pctLabel}`;
    }
  }
  if (!lastPoint || nowMs - Number(lastPoint.timeMs || 0) > 60_000) {
    investmentHistory.push({
      timeMs: nowMs,
      netCapitalUsd,
      navUsd,
      returnsUsd: returnsTotalUsd,
      feesCollectedUsd,
    });
  } else {
    lastPoint.netCapitalUsd = netCapitalUsd;
    lastPoint.navUsd = navUsd;
    lastPoint.returnsUsd = returnsTotalUsd;
    lastPoint.feesCollectedUsd = feesCollectedUsd;
  }
  drawInvestmentChart(refs.chart, investmentHistory);

  const otherActions = await fetchLatestActions(vaultNodesResolved, toBlock);
  const combinedActions = [
    ...otherActions,
    ...returnEvents
      .filter((evt) => evt?.txHash && evt?.timeMs > 0)
      .map((evt) => ({
        kind: evt?.kind || 'Distribution',
        txHash: String(evt.txHash),
        blockNumber: Number(evt.blockNumber || 0),
        timeMs: Number(evt.timeMs || 0),
      })),
  ].filter((evt) => evt.timeMs > 0 && evt.txHash);
  combinedActions.sort((a, b) => {
    if (a.timeMs !== b.timeMs) return a.timeMs - b.timeMs;
    if (a.blockNumber !== b.blockNumber) return a.blockNumber - b.blockNumber;
    return String(a.txHash).localeCompare(String(b.txHash));
  });
  const latestAction = combinedActions.length ? combinedActions[combinedActions.length - 1] : null;
  if (refs.latestActionLink) {
    if (latestAction?.txHash) {
      refs.latestActionLink.classList.remove('is-empty');
      refs.latestActionLink.href = `${ETHERSCAN_TX_BASE}${latestAction.txHash}`;
      refs.latestActionLink.textContent = `[Latest: ${latestAction.kind} • ${formatClockTime(latestAction.timeMs)}]`;
      refs.latestActionLink.title = latestAction.txHash;
    } else {
      refs.latestActionLink.classList.add('is-empty');
      refs.latestActionLink.removeAttribute('href');
      refs.latestActionLink.textContent = 'Latest Action: —';
      refs.latestActionLink.title = 'No recent actions found';
    }
  }

  if (refs.updatedLabel) {
    const now = new Date();
    const rpcLabel = providerRpc ? formatRpcLabel(providerRpc) : 'Public RPC';
    refs.updatedLabel.textContent = `Updated ${now.toISOString().slice(0, 16).replace('T', ' ')}`;
  }
}

let renderInFlight = null;

function updateReloadButtonState() {
  if (refs.reloadBtn) refs.reloadBtn.disabled = Boolean(renderInFlight);
  if (refs.bannerReloadBtn) refs.bannerReloadBtn.disabled = Boolean(renderInFlight);
}

async function runRender() {
  if (renderInFlight) return renderInFlight;
  renderInFlight = (async () => {
    try {
      await render();
    } catch (err) {
      console.error(err);
      const message = formatRpcError(err);
      const hint = `Hint: try reloading. If it persists, set localStorage['${RPC_OVERRIDE_KEY}'] to a different CORS-enabled Ethereum RPC endpoint and reload.`;
      showError(isRetryableRpcError(err) ? `${message}. ${hint}` : message);
      if (refs.updatedLabel) refs.updatedLabel.textContent = 'Failed to load';
    } finally {
      renderInFlight = null;
      updateReloadButtonState();
    }
  })();
  updateReloadButtonState();
  return renderInFlight;
}

runRender();
