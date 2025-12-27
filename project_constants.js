// --- PUBLIC REPORTING CONSTANTS ---
// Read-Only Configuration for DAO Transparency

export const ADDRESSES = Object.freeze({
  ENA: '0x57e114B691Db790C35207b2e685D4A43181e6061',
  WETH: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
  CULT: '0xf0f9D895aCa5c8678f706FB8216fa22957685A13',
  POOL_ENA_WETH: '0xc3Db44ADC1fCdFd5671f555236eae49f4A8EEa18',
  CULT_WETH_V2_PAIR: '0x5281e311734869c64ca60ef047fd87759397efe6',
  NONFUNGIBLE_POSITION_MANAGER: '0xC36442b4a4522E871399CD717aBDD847Ab11FE88',
  CHAINLINK_ETH_USD: '0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419',
});

// Only C1/C2 (Community Vaults) - No Personal Vaults
export const LIQUIDITY_MANAGERS = Object.freeze([
  {
    key: 'c1',
    label: 'Vault C1', // Generic Label
    address: '0x57fb5558B540c4A052B097157D0b5253b63d0f9B', // Your C1 Address
    legacyAddresses: [] // Add legacy if/when needed
  },
  {
    key: 'c2',
    label: 'Vault C2',
    address: '0x5f0b768E49BeBac6408E327b6e69Eab199464438', // Your C2 Address (Fill in)
    legacyAddresses: []
  },
]);

export const ANALYTICS = Object.freeze({
  // Public keys for read-only access are standard for dApps
  ETHERSCAN_API_KEYS: [
    '5GRQEWFD7DE5N7SC6H1IUYJKKDPJEJ81HG',
    'R9UDM5TUN9HYNVGWTJ6UKTQ8S8F9E42HF7',
    'CVAYS18SABJB7NJMK14UIUEPVPCF6EKZ86'
  ],
  // Hardcode the C-Project Subgraph here so it works out of the box for everyone
  SUBGRAPH_ENDPOINT: 'https://api.studio.thegraph.com/query/1718278/wearecultdao-01/version/latest', 
  TRADE_CACHE_MS: 60_000,
  TRADE_FETCH_OFFSET: 1000,
  TRADE_MAX_PAGES: 4,
});

export const TOKEN_META = Object.freeze({
  ENA: { symbol: 'ENA', decimals: 18 },
  WETH: { symbol: 'WETH', decimals: 18 },
});

export const NETWORK = Object.freeze({
  chainId: 1,
  name: 'Ethereum Mainnet',
});

// MINIMAL READ-ONLY ABIs
export const ABI = Object.freeze({
  ERC20: [
    'function decimals() view returns (uint8)',
    'function balanceOf(address owner) view returns (uint256)',
    'event Transfer(address indexed from, address indexed to, uint256 value)'
  ],
  WETH: [
    'function balanceOf(address src) view returns (uint256)',
    'event Transfer(address indexed src, address indexed dst, uint256 wad)'
  ],
  NONFUNGIBLE_POSITION_MANAGER: [
    'function positions(uint256 tokenId) view returns (uint96 nonce, address operator, address token0, address token1, uint24 fee, int24 tickLower, int24 tickUpper, uint128 liquidity, uint256 feeGrowthInside0LastX128, uint256 feeGrowthInside1LastX128, uint128 tokensOwed0, uint128 tokensOwed1)',
    // Needed for staticCall to check fees:
    'function collect(tuple(uint256 tokenId, address recipient, uint128 amount0Max, uint128 amount1Max) params) payable returns (uint256 amount0, uint256 amount1)', 
  ],
  UNISWAP_V3_POOL: [
    'function slot0() view returns (uint160 sqrtPriceX96, int24 tick, uint16 observationIndex, uint16 observationCardinality, uint16 observationCardinalityNext, uint8 feeProtocol, bool unlocked)',
    'function liquidity() view returns (uint128)',
    'function tickSpacing() view returns (int24)',
    'event Swap(address indexed sender, address indexed recipient, int256 amount0, int256 amount1, uint160 sqrtPriceX96, uint128 liquidity, int24 tick)'
  ],
  UNISWAP_V2_PAIR: [
    'function getReserves() view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)',
    'function token0() view returns (address)',
  ],
  CHAINLINK_AGGREGATOR: [
    'function latestRoundData() view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)',
    'function decimals() view returns (uint8)',
  ],
  LIQUIDITY_MANAGER: [
    // Views Only - No Admin Functions exposed
    'function getPosition() view returns (uint256 tokenId, int24 lowerTick, int24 upperTick, uint128 liquidity)',
    'function automation() view returns (address)',
    'function compoundFees() view returns (bool)', // Needed for Phase Badge
    'function owner() view returns (address)',
    // Events for History Tracking
    'event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)',
    'event Distributed(uint256 cultBurned, uint256 cultStaked)',
    'event Terminated(uint256 totalCultDistributed)',
    'event Rebalanced(uint256 tokenId, int24 lowerTick, int24 upperTick, uint128 liquidityAdded)',
    'event Compounded(uint256 tokenId, uint128 liquidityAdded)',
    'event Deposited(uint256 amountENA, uint256 amountWETH)',
    'event Withdrawn(uint256 shareBps, uint256 amountENA, uint256 amountWETH)',
    'event AutomationUpdated(address indexed automation)',
  ],
});