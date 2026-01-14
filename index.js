import axios from 'axios';
import cfonts from 'cfonts';
import gradient from 'gradient-string';
import chalk from 'chalk';
import fs from 'fs/promises';
import readline from 'readline';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';
import ProgressBar from 'progress';
import ora from 'ora';
import WebSocket from 'ws';
import { ethers } from 'ethers';

const logger = {
  info: (msg, options = {}) => {
    const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
    const emoji = options.emoji || 'ℹ️  ';
    const context = options.context ? `[${options.context}] ` : '';
    const level = chalk.green('INFO');
    const formattedMsg = `[ ${chalk.gray(timestamp)} ] ${emoji}${level} ${chalk.white(context.padEnd(20))}${chalk.white(msg)}`;
    console.log(formattedMsg);
  },
  warn: (msg, options = {}) => {
    const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
    const emoji = options.emoji || '⚠️ ';
    const context = options.context ? `[${options.context}] ` : '';
    const level = chalk.yellow('WARN');
    const formattedMsg = `[ ${chalk.gray(timestamp)} ] ${emoji}${level} ${chalk.white(context.padEnd(20))}${chalk.white(msg)}`;
    console.log(formattedMsg);
  },
  error: (msg, options = {}) => {
    const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
    const emoji = options.emoji || '❌ ';
    const context = options.context ? `[${options.context}] ` : '';
    const level = chalk.red('ERROR');
    const formattedMsg = `[ ${chalk.gray(timestamp)} ] ${emoji}${level} ${chalk.white(context.padEnd(20))}${chalk.white(msg)}`;
    console.log(formattedMsg);
  },
  debug: (msg, options = {}) => {
    const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
    const emoji = options.emoji || '🔍  ';
    const context = options.context ? `[${options.context}] ` : '';
    const level = chalk.blue('DEBUG');
    const formattedMsg = `[ ${chalk.gray(timestamp)} ] ${emoji}${level} ${chalk.white(context.padEnd(20))}${chalk.white(msg)}`;
    console.log(formattedMsg);
  }
};

function delay(seconds) {
  return new Promise(resolve => setTimeout(resolve, seconds * 1000));
}

async function countdown(seconds, message) {
  return new Promise((resolve) => {
    let remaining = seconds;
    process.stdout.write(`${message} ${remaining}s remaining...`);
    const interval = setInterval(() => {
      remaining--;
      process.stdout.clearLine();
      process.stdout.cursorTo(0);
      process.stdout.write(`${message} ${remaining}s remaining...`);
      if (remaining <= 0) {
        clearInterval(interval);
        process.stdout.clearLine();
        process.stdout.cursorTo(0);
        resolve();
      }
    }, 1000);
  });
}

function stripAnsi(str) {
  return str.replace(/\x1B\[[0-9;]*m/g, '');
}

function centerText(text, width) {
  const cleanText = stripAnsi(text);
  const textLength = cleanText.length;
  const totalPadding = Math.max(0, width - textLength);
  const leftPadding = Math.floor(totalPadding / 2);
  const rightPadding = totalPadding - leftPadding;
  return `${' '.repeat(leftPadding)}${text}${' '.repeat(rightPadding)}`;
}

function printHeader(title) {
  const width = 80;
  console.log(gradient.morning(`┬${'─'.repeat(width - 2)}┬`));
  console.log(gradient.morning(`│ ${title.padEnd(width - 4)} │`));
  console.log(gradient.morning(`┴${'─'.repeat(width - 2)}┴`));
}

function printInfo(label, value, context) {
  logger.info(`${label.padEnd(15)}: ${chalk.cyan(value)}`, { emoji: '📍 ', context });
}

function printProfileInfo(address, totalPoints, winRate, context) {
  printHeader(`Profile Info ${context}`);
  printInfo('Address', address || 'N/A', context);
  printInfo('Total Points', totalPoints.toString(), context);
  printInfo('Win Rate', winRate.toString() + '%', context);
  console.log('\n');
}

const userAgents = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/102.0'
];

function getRandomUserAgent() {
  return userAgents[Math.floor(Math.random() * userAgents.length)];
}

function getPrivyConfig(proxy, additionalHeaders = {}) {
  const headers = {
    'accept': 'application/json',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'en-US,en;q=0.9,id;q=0.8',
    'cache-control': 'no-cache',
    'content-type': 'application/json',
    'origin': 'https://hub.aixcrypto.ai',
    'pragma': 'no-cache',
    'priority': 'u=1, i',
    'privy-app-id': 'cmk3zw8d704bxl70chtewm6hd',
    'privy-ca-id': '119aa643-ca62-45b4-b305-e0fab44f33ae',
    'privy-client': 'react-auth:3.10.1',
    'referer': 'https://hub.aixcrypto.ai/',
    'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': getRandomUserAgent(),
    ...additionalHeaders
  };
  const config = {
    headers,
    timeout: 60000
  };
  if (proxy) {
    config.httpsAgent = newAgent(proxy);
    config.proxy = false;
  }
  return config;
}

function getAixConfig(proxy, privyToken, additionalHeaders = {}) {
  const headers = {
    'accept': '*/*',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'en-US,en;q=0.9,id;q=0.8',
    'cache-control': 'no-cache',
    'content-type': 'application/json',
    'cookie': `privy-token=${privyToken}`,
    'origin': 'https://hub.aixcrypto.ai',
    'pragma': 'no-cache',
    'priority': 'u=1, i',
    'referer': 'https://hub.aixcrypto.ai/',
    'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': getRandomUserAgent(),
    ...additionalHeaders
  };
  const config = {
    headers,
    timeout: 60000
  };
  if (proxy) {
    config.httpsAgent = newAgent(proxy);
    config.proxy = false;
  }
  return config;
}

function newAgent(proxy) {
  if (proxy.startsWith('http://') || proxy.startsWith('https://')) {
    return new HttpsProxyAgent(proxy);
  } else if (proxy.startsWith('socks4://') || proxy.startsWith('socks5://')) {
    return new SocksProxyAgent(proxy);
  } else {
    logger.warn(`Unsupported proxy: ${proxy}`);
    return null;
  }
}

async function requestWithRetry(method, url, payload = null, config = {}, retries = 3, backoff = 2000, context) {
  for (let i = 0; i < retries; i++) {
    try {
      let response;
      if (method.toLowerCase() === 'get') {
        response = await axios.get(url, config);
      } else if (method.toLowerCase() === 'post') {
        response = await axios.post(url, payload, config);
      } else {
        throw new Error(`Method ${method} not supported`);
      }
      return response;
    } catch (error) {
      if (error.response && error.response.status >= 500 && i < retries - 1) {
        logger.warn(`Retrying ${method.toUpperCase()} ${url} (${i + 1}/${retries}) due to server error`, { emoji: '🔄', context });
        await delay(backoff / 1000);
        backoff *= 1.5;
        continue;
      }
      if (i < retries - 1) {
        logger.warn(`Retrying ${method.toUpperCase()} ${url} (${i + 1}/${retries})`, { emoji: '🔄', context });
        await delay(backoff / 1000);
        backoff *= 1.5;
        continue;
      }
      throw error;
    }
  }
}

async function readPrivateKeys() {
  try {
    const data = await fs.readFile('pk.txt', 'utf-8');
    const pks = data.split('\n').map(line => line.trim()).filter(line => line.length > 0);
    logger.info(`Loaded ${pks.length} private key${pks.length === 1 ? '' : 's'}`, { emoji: '🔑 ' });
    return pks;
  } catch (error) {
    logger.error(`Failed to read pk.txt: ${error.message}`, { emoji: '❌ ' });
    return [];
  }
}

async function readProxies() {
  try {
    const data = await fs.readFile('proxy.txt', 'utf-8');
    const proxies = data.split('\n').map(line => line.trim()).filter(line => line.length > 0);
    if (proxies.length === 0) {
      logger.warn('No proxies found. Proceeding without proxy.', { emoji: '⚠️ ' });
    } else {
      logger.info(`Loaded ${proxies.length} prox${proxies.length === 1 ? 'y' : 'ies'}`, { emoji: '🌐 ' });
    }
    return proxies;
  } catch (error) {
    logger.warn('proxy.txt not found.', { emoji: '⚠️ ' });
    return [];
  }
}

async function read2CaptchaKey() {
  try {
    const data = await fs.readFile('2captcha.txt', 'utf-8');
    const key = data.trim();
    if (key) {
      logger.info('Loaded 2Captcha API key', { emoji: '🔑 ' });
      return key;
    } else {
      throw new Error('Empty 2captcha.txt');
    }
  } catch (error) {
    logger.error(`Failed to read 2captcha.txt: ${error.message}`, { emoji: '❌ ' });
    return null;
  }
}

async function solveCaptcha(apiKey, context) {
  const siteKey = '0x4AAAAAAAM8ceq5KhP1uJBt';
  const siteUrl = 'https://hub.aixcrypto.ai/';
  const spinner = ora({ text: 'Solving Cloudflare captcha...', spinner: 'dots' }).start();
  try {
    const submitUrl = `http://2captcha.com/in.php?key=${apiKey}&method=turnstile&sitekey=${siteKey}&pageurl=${siteUrl}`;
    const submitResponse = await axios.get(submitUrl);
    if (submitResponse.data.startsWith('OK|')) {
      const captchaId = submitResponse.data.split('|')[1];
      let result;
      for (let i = 0; i < 60; i++) { 
        await delay(5);
        const checkUrl = `http://2captcha.com/res.php?key=${apiKey}&action=get&id=${captchaId}`;
        const checkResponse = await axios.get(checkUrl);
        if (checkResponse.data.startsWith('OK|')) {
          result = checkResponse.data.split('|')[1];
          break;
        } else if (checkResponse.data !== 'CAPCHA_NOT_READY') {
          throw new Error(checkResponse.data);
        }
      }
      if (result) {
        spinner.succeed(chalk.bold.greenBright(` Captcha solved`));
        return result;
      } else {
        throw new Error('Captcha not ready after timeout');
      }
    } else {
      throw new Error(submitResponse.data);
    }
  } catch (error) {
    spinner.fail(chalk.bold.redBright(` Failed to solve captcha: ${error.message}`));
    return null;
  }
}

async function performPrivyLogin(privateKey, proxy, captchaToken, context) {
  const wallet = new ethers.Wallet(privateKey);
  const address = wallet.address;
  const urlInit = 'https://auth.privy.io/api/v1/siwe/init';
  const payloadInit = { address, token: captchaToken };
  const config = getPrivyConfig(proxy);
  const spinner = ora({ text: 'Initializing Privy SIWE...', spinner: 'dots' }).start();
  try {
    const responseInit = await requestWithRetry('post', urlInit, payloadInit, config, 3, 2000, context);
    spinner.stop();
    const { nonce } = responseInit.data;

    const issuedAt = new Date().toISOString();
    const message = `hub.aixcrypto.ai wants you to sign in with your Ethereum account:\n${address}\n\nBy signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.\n\nURI: https://hub.aixcrypto.ai\nVersion: 1\nChain ID: 24101\nNonce: ${nonce}\nIssued At: ${issuedAt}\nResources:\n- https://privy.io`;

    const signature = await wallet.signMessage(message);

    const urlAuth = 'https://auth.privy.io/api/v1/siwe/authenticate';
    const payloadAuth = {
      message,
      signature,
      chainId: 'eip155:24101',
      walletClientType: 'metamask',
      connectorType: 'injected',
      mode: 'login-or-sign-up'
    };
    const responseAuth = await requestWithRetry('post', urlAuth, payloadAuth, config, 3, 2000, context);
    if (responseAuth.data.token) {
      return responseAuth.data.token;
    } else {
      throw new Error('Failed to get Privy token');
    }
  } catch (error) {
    spinner.fail(chalk.bold.redBright(` Failed to login to Privy: ${error.message}`));
    return null;
  }
}

async function performAixLogin(privateKey, proxy, privyToken, context) {
  const wallet = new ethers.Wallet(privateKey);
  const address = wallet.address.toLowerCase();
  const urlChallenge = `https://hub.aixcrypto.ai/api/users/auth/challenge?address=${address}`;
  const spinner = ora({ text: 'Fetching AIxC auth challenge...', spinner: 'dots' }).start();
  try {
    const config = getAixConfig(proxy, privyToken);
    const responseChallenge = await requestWithRetry('get', urlChallenge, null, config, 3, 2000, context);
    spinner.stop();
    const { message } = responseChallenge.data;

    const signature = await wallet.signMessage(message);

    const urlLogin = 'https://hub.aixcrypto.ai/api/login';
    const payload = { address, signature, message };
    const responseLogin = await requestWithRetry('post', urlLogin, payload, config, 3, 2000, context);
    if (responseLogin.data.sessionId) {
      return { address, sessionId: responseLogin.data.sessionId, username: responseLogin.data.username || 'N/A' };
    } else {
      throw new Error('Failed to login to AIxC');
    }
  } catch (error) {
    spinner.fail(chalk.bold.redBright(` Failed to login to AIxC: ${error.message}`));
    return null;
  }
}

async function performLogin(privateKey, proxy, captchaApiKey, context) {
  const captchaToken = await solveCaptcha(captchaApiKey, context);
  if (!captchaToken) return null;

  const privyToken = await performPrivyLogin(privateKey, proxy, captchaToken, context);
  if (!privyToken) return null;

  const loginInfo = await performAixLogin(privateKey, proxy, privyToken, context);
  if (loginInfo) {
    loginInfo.privyToken = privyToken;
  }
  return loginInfo;
}

async function fetchGameLimits(address, proxy, privyToken, context) {
  const url = `https://hub.aixcrypto.ai/api/game/current-round?address=${address}`;
  const spinner = ora({ text: 'Fetching game limits...', spinner: 'dots' }).start();
  try {
    const config = getAixConfig(proxy, privyToken);
    const response = await requestWithRetry('get', url, null, config, 3, 2000, context);
    spinner.stop();
    return {
      dailyBetLimit: response.data.dailyBetLimit,
      dailyBetCount: response.data.dailyBetCount,
      dailyBetRemaining: response.data.dailyBetRemaining
    };
  } catch (error) {
    spinner.fail(chalk.bold.redBright(` Failed to fetch game limits: ${error.message}`));
    return { dailyBetLimit: 0, dailyBetCount: 0, dailyBetRemaining: 0 };
  }
}

async function playGame(address, sessionId, proxy, privyToken, context, maxPlays) {
  const ws = new WebSocket('wss://hub.aixcrypto.ai/ws');
  let connected = false;
  let currentRoundId = null;
  let betsPlaced = 0;

  return new Promise((resolve, reject) => {
    ws.on('open', () => {
      ws.send(JSON.stringify({ type: 'register', payload: { address } }));
      connected = true;
      logger.info('WebSocket connected', { emoji: '🔗 ', context });
    });

    ws.on('message', async (data) => {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'round_start' && betsPlaced < maxPlays) {
        currentRoundId = msg.data.roundId;
        const prediction = Math.random() < 0.5 ? 'UP' : 'DOWN';
        const urlBet = 'https://hub.aixcrypto.ai/api/game/bet';
        const payload = { prediction, sessionId };
        const config = getAixConfig(proxy, privyToken);
        try {
          const response = await requestWithRetry('post', urlBet, payload, config, 3, 2000, context);
          if (response.data.success) {
            betsPlaced++;
            logger.info(`Bet placed: ${prediction} (Bet ${betsPlaced}/${maxPlays})`, { emoji: '🎲 ', context });
          }
        } catch (error) {
          logger.error(`Failed to place bet: ${error.message}`, { emoji: '❌ ', context });
        }
      } else if (msg.type === 'user_settlement' && msg.data.userAddress === address.toLowerCase()) {
        const result = msg.data.result;
        logger.info(`Game result: ${result} (Credits Reward: ${msg.data.creditsReward})`, { emoji: result === 'WIN' ? '🏆 ' : '😞 ', context });
        if (betsPlaced >= maxPlays) {
          ws.close();
        }
      } else if (msg.type === 'round_settle') {
      }
    });

    ws.on('close', () => {
      if (connected) {
        logger.debug('WebSocket closed', { emoji: '🔌 ', context });
      }
      if (betsPlaced < maxPlays) {
        reject(new Error('WebSocket closed prematurely'));
      } else {
        resolve(betsPlaced);
      }
    });

    ws.on('error', (error) => {
      reject(error);
    });
  });
}

async function fetchTasks(address, proxy, privyToken, context) {
  const url = `https://hub.aixcrypto.ai/api/tasks/daily?address=${address}`;
  const spinner = ora({ text: 'Fetching tasks...', spinner: 'dots' }).start();
  try {
    const config = getAixConfig(proxy, privyToken);
    const response = await requestWithRetry('get', url, null, config, 3, 2000, context);
    spinner.succeed(chalk.bold.greenBright(` Tasks fetched`));
    return response.data.tasks;
  } catch (error) {
    spinner.fail(chalk.bold.redBright(` Failed to fetch tasks: ${error.message}`));
    return [];
  }
}

async function completeDiscordPost(sessionId, proxy, privyToken, context) {
  const url = 'https://hub.aixcrypto.ai/api/tasks/discord-post';
  const payload = { sessionId };
  const spinner = ora({ text: 'Completing Discord post task...', spinner: 'dots' }).start();
  try {
    const config = getAixConfig(proxy, privyToken);
    const response = await requestWithRetry('post', url, payload, config, 3, 2000, context);
    if (response.data.success) {
      spinner.succeed(chalk.bold.greenBright(` Discord post task completed`));
      return true;
    } else {
      throw new Error('Failed to complete Discord post');
    }
  } catch (error) {
    spinner.fail(chalk.bold.redBright(` Failed to complete Discord post: ${error.message}`));
    return false;
  }
}

async function claimTask(taskId, title, sessionId, proxy, privyToken, context) {
  const url = 'https://hub.aixcrypto.ai/api/tasks/claim';
  const payload = { taskId, sessionId };
  const spinner = ora({ text: `Claiming task "${title}" (ID: ${taskId})...`, spinner: 'dots' }).start();
  try {
    const config = getAixConfig(proxy, privyToken);
    const response = await requestWithRetry('post', url, payload, config, 3, 2000, context);
    if (response.data.success) {
      spinner.succeed(chalk.bold.greenBright(` Task "${title}" (ID: ${taskId}) claimed, Reward: ${response.data.reward}`));
      return true;
    } else {
      throw new Error('Failed to claim task');
    }
  } catch (error) {
    spinner.fail(chalk.bold.redBright(` Failed to claim task "${title}" (ID: ${taskId}): ${error.message}`));
    return false;
  }
}

async function fetchUserInfo(address, proxy, privyToken, context) {
  const url = `https://hub.aixcrypto.ai/api/user/${address}`;
  const spinner = ora({ text: 'Fetching user info...', spinner: 'dots' }).start();
  try {
    const config = getAixConfig(proxy, privyToken);
    const response = await requestWithRetry('get', url, null, config, 3, 2000, context);
    spinner.stop();
    return {
      address: response.data.address,
      totalPoints: response.data.credits,
      winRate: response.data.winRate
    };
  } catch (error) {
    spinner.fail(chalk.bold.redBright(` Failed to fetch user info: ${error.message}`));
    return { address: 'N/A', totalPoints: 0, winRate: 0 };
  }
}

async function getPublicIP(proxy, context) {
  try {
    const config = getAixConfig(proxy, '');
    const response = await requestWithRetry('get', 'https://api.ipify.org?format=json', null, config, 3, 2000, context);
    return response.data.ip || 'Unknown';
  } catch (error) {
    logger.error(`Failed to get IP: ${error.message}`, { emoji: '❌ ', context });
    return 'Error retrieving IP';
  }
}

let globalUseProxy = false;
let globalProxies = [];

async function initializeConfig() {
  const useProxyAns = await askQuestion(chalk.cyanBright('🔌 Do You Want to Use Proxy? (y/n): '));
  if (useProxyAns.trim().toLowerCase() === 'y') {
    globalUseProxy = true;
    globalProxies = await readProxies();
    if (globalProxies.length === 0) {
      globalUseProxy = false;
      logger.warn('No proxies available, proceeding without proxy.', { emoji: '⚠️ ' });
    }
  } else {
    logger.info('Proceeding without proxy.', { emoji: 'ℹ️ ' });
  }
}

async function askQuestion(query) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  return new Promise(resolve => rl.question(query, ans => {
    rl.close();
    resolve(ans);
  }));
}

async function processAccount(privateKey, index, total, proxy, captchaApiKey) {
  const context = `Account ${index + 1}/${total}`;
  logger.info(chalk.bold.magentaBright(`Starting account processing`), { emoji: '🚀 ', context });

  const loginInfo = await performLogin(privateKey, proxy, captchaApiKey, context);
  if (!loginInfo) {
    logger.error('Login failed, skipping account', { emoji: '❌ ', context });
    return;
  }
  const { address, sessionId, username, privyToken } = loginInfo;

  printHeader(`Account Info ${context}`);
  printInfo('Username', username, context);
  const ip = await getPublicIP(proxy, context);
  printInfo('IP', ip, context);
  console.log('\n');

  try {
    logger.info('Starting auto play games...', { emoji: '🎮 ', context });
    const gameLimits = await fetchGameLimits(address, proxy, privyToken, context);
    const availablePlays = gameLimits.dailyBetRemaining;
    if (availablePlays === 0) {
      logger.info(chalk.bold.yellowBright('No plays available today'), { emoji: '⚠️ ', context });
    } else {
      printInfo('Available Plays', availablePlays, context);
      console.log();
      const bar = new ProgressBar('Processing games [:bar] :percent :etas', {
        complete: '█',
        incomplete: '░',
        width: 30,
        total: availablePlays
      });

      const playsCompleted = await playGame(address, sessionId, proxy, privyToken, context, availablePlays);

      for (let i = 0; i < playsCompleted; i++) {
        bar.tick();
      }
      console.log();
      logger.info(`Processed ${playsCompleted} games`, { emoji: '📊 ', context });
    }

    await delay(5);

    logger.info('Starting tasks and check-in...', { emoji: '📋 ', context });
    let tasks = await fetchTasks(address, proxy, privyToken, context);
    for (const task of tasks) {
      if (['@AIxC_Official', '@AIxCFoundation'].includes(task.title)) continue;
      if (task.title === 'Post in Discord' && task.isCompleted === 0) {
        await completeDiscordPost(sessionId, proxy, privyToken, context);
        tasks = await fetchTasks(address, proxy, privyToken, context);
      }
      if (task.isCompleted === 1 && task.isClaimed === 0) {
        await claimTask(task.id, task.title, sessionId, proxy, privyToken, context);
      }
    }

    const finalUserInfo = await fetchUserInfo(address, proxy, privyToken, context);
    printProfileInfo(finalUserInfo.address, finalUserInfo.totalPoints, finalUserInfo.winRate, context);

    logger.info(chalk.bold.greenBright(`Completed account processing`), { emoji: '🎉 ', context });
    console.log(chalk.cyanBright('________________________________________________________________________________'));
  } catch (error) {
    logger.error(`Error processing account: ${error.message}`, { emoji: '❌ ', context });
  }
}

async function runCycle(captchaApiKey) {
  const privateKeys = await readPrivateKeys();
  if (privateKeys.length === 0) {
    logger.error('No private keys found in pk.txt. Exiting cycle.', { emoji: '❌ ' });
    return;
  }

  for (let i = 0; i < privateKeys.length; i++) {
    const proxy = globalUseProxy ? globalProxies[i % globalProxies.length] : null;
    try {
      await processAccount(privateKeys[i], i, privateKeys.length, proxy, captchaApiKey);
    } catch (error) {
      logger.error(`Error processing account: ${error.message}`, { emoji: '❌ ', context: `Account ${i + 1}/${privateKeys.length}` });
    }
    if (i < privateKeys.length - 1) {
      console.log('\n\n');
    }
    await delay(5);
  }
}

async function run() {
  const terminalWidth = process.stdout.columns || 80;
  cfonts.say('NT EXHAUST', {
    font: 'block',
    align: 'center',
    colors: ['cyan', 'magenta'],
    background: 'transparent',
    letterSpacing: 1,
    lineHeight: 1,
    space: true
  });
  console.log(gradient.retro(centerText('=== Telegram Channel 🚀 : NT Exhaust (@NTExhaust) ===', terminalWidth)));
  console.log(gradient.retro(centerText('✪ AIxC AUTO DAILY BOT ✪', terminalWidth)));
  console.log('\n');
  await initializeConfig();

  const captchaApiKey = await read2CaptchaKey();
  if (!captchaApiKey) {
    logger.error('No 2Captcha key found. Exiting.', { emoji: '❌ ' });
    return;
  }

  while (true) {
    await runCycle(captchaApiKey);
    console.log();
    logger.info(chalk.bold.yellowBright('Cycle completed. Waiting 24 hours...'), { emoji: '🔄 ' });
    await delay(86400);
  }
}

run().catch(error => logger.error(`Fatal error: ${error.message}`, { emoji: '❌' }));