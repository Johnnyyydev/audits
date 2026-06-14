<div align="center">

# 🔐 Johnnyyydev — Smart Contract Security Research

[![X (Twitter)](https://img.shields.io/badge/X-@johnnyyydev-000000?style=for-the-badge&logo=x)](https://x.com/johnnyyydev)
[![GitHub](https://img.shields.io/badge/GitHub-Johnnyyydev-181717?style=for-the-badge&logo=github)](https://github.com/Johnnyyydev)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Johnny_Luis-0077B5?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/johnny-luis-59bb58410/)

![Audits](https://img.shields.io/badge/Audits_Completed-2-brightgreen?style=flat-square)
![Critical Bugs](https://img.shields.io/badge/Critical_Bugs-2-red?style=flat-square)
![High Bugs](https://img.shields.io/badge/High_Bugs-1-orange?style=flat-square)
![Total Issues](https://img.shields.io/badge/Total_Issues-8-blue?style=flat-square)
![PoC Coverage](https://img.shields.io/badge/PoC_Coverage-100%25-success?style=flat-square)

*Independent smart contract security researcher focused on DeFi protocols and cross-chain bridges.*

</div>

---

## 📌 About

I am an independent smart contract security researcher specializing in finding vulnerabilities in DeFi protocols, cross-chain bridges, and EVM-based token contracts. My reports include **full Proof-of-Concept exploits** for every confirmed vulnerability.

**Specialization:**
- 🌉 Cross-chain bridge security
- 💰 DeFi protocol analysis & economic exploit modeling
- 🔍 Reentrancy, flash loan & MEV attack vectors
- 🛡️ ERC20 / BEP20 token security
- 💥 Complex vulnerability patterns with PoC

**Tooling:** Foundry · Slither · Mythril · Manual Review · Hardhat

---

## 📊 Audit Portfolio

| # | Protocol | Type | Date | Severity | Findings | Report |
|---|----------|------|------|----------|----------|---------|
| 1 | **anyBTC Bridge** | Cross-chain Bridge | 2026-06-05 | 🔴 Critical | 2C / 1M / 1L | [View Report](./anybtc-bridge-security-review.md) |
| 2 | **GrootCoin** | BEP20 Token | 2026-06-07 | 🟠 High | 1H / 1M / 1L | [View Report](./grootcoin-security-review.md) |

> **Legend:** C = Critical &nbsp;|&nbsp; H = High &nbsp;|&nbsp; M = Medium &nbsp;|&nbsp; L = Low

---

## 🔥 Key Findings Highlight

### [C-01] anyBTC Bridge — Replay Attack via Transaction Hash Reuse
> **Severity:** Critical &nbsp;|&nbsp; **Protocol:** anyBTC Bridge

The `Swapin()` function lacked transaction hash tracking, allowing any authorized minter to mint tokens **multiple times** for a single Bitcoin deposit. A single BTC deposit could be replayed indefinitely to drain protocol funds.

```solidity
// Legitimate mint
token.Swapin(txhash, user1, amount);
// REPLAY — same txhash, should fail but DOESN'T
token.Swapin(txhash, user2, amount); // ✅ passes — critical bug
```

### [C-02] anyBTC Bridge — Wrong Address Type for Cross-Chain Destinations
> **Severity:** Critical &nbsp;|&nbsp; **Protocol:** anyBTC Bridge

The `Swapout()` function accepted Ethereum `address` type for Bitcoin destinations. Since Bitcoin uses base58 encoding, valid BTC addresses cannot be represented as EVM addresses — resulting in **permanent loss of user funds**.

### [H-01] GrootCoin — Denial of Service via Gas Limit Manipulation
> **Severity:** High &nbsp;|&nbsp; **Protocol:** GrootCoin (BSC)

The contract owner could call `setGasLim(1)` to freeze **all token transfers**, buys, and sells by setting `gaslimit` below the BSC minimum gas price. No timelock or access restrictions existed on this function.

```solidity
vm.prank(owner);
token.setGasLim(1); // Freeze entire token economy

vm.txGasPrice(3 gwei);
vm.expectRevert(); // All transfers revert
token.transfer(user2, 100);
```

---

## 🛠️ Methodology

```
1. Manual code review (primary — line by line)
2. Static analysis    (Slither, Mythril)
3. Dynamic testing    (Foundry fork tests + PoC)
4. Economic modeling  (attack impact & profit analysis)
5. Report writing     (severity, PoC, mitigation)
```

---

## 💬 Work With Me

Looking for a security review of your protocol?

- 📧 Open an issue in this repo
- 🐦 DM on X: [@johnnyyydev](https://x.com/johnnyyydev)
- 🔗 LinkedIn: [Johnny Luis](https://www.linkedin.com/in/johnny-luis-59bb58410/)

> *Available for private audits, bug bounty collaboration, and security consulting.*

---

<div align="center">

*Security is not a feature — it's a foundation.*

</div>
