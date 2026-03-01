# EIP-8141 Frame Transaction Uygulamasi: Kapsamli Rapor ve Egitim Metni

> **Yazar:** alimsahin0007@gmail.com
> **Tarih Araligi:** 26 Subat - 1 Mart 2026 (19 commit, ~2600 satir kod)
> **Amac:** Bu belge, EIP-8141 Frame Transaction uygulamasinin her adimini, her kararini ve her kod degisikligini ayrintili olarak aciklar. Bu metni takip eden birisi, sifirdan ayni sistemi insa edebilecek seviyeye gelir.

---

## BOLUM 1: EIP-8141 NEDIR? (Kavramsal Temel)

### 1.1 Problem: ECDSA Bagimliligi

Ethereum'da her islem (transaction), gonderenin kimligini `secp256k1` ECDSA imzasiyla kanitlar. Bu yaklasim:

- **Tek bir kriptografik semaya kilitler:** Passkey (P256), multisig, kuantum-direncli imzalar kullanilamaz.
- **Hesap soyutlamasini (Account Abstraction) zorlastitir:** ERC-4337 gibi cozumler protokol-ustu katman olarak calisir, protokol seviyesinde degil.
- **Gas sponsorlugunu dogal olarak desteklemez:** Bir baskasinin gas odemesini yapamaz.

### 1.2 Cozum: Frame Transaction (Tip 0x06)

EIP-8141, yeni bir islem tipi (`0x06`) tanimlar. Bu islem tipinde:

1. **ECDSA imzasi yoktur.** Bunun yerine `sender` adresi dogrudan islemin icinde belirtilir.
2. **Dogrulama on-chain'de yapilir.** VERIFY frame'leri icinde herhangi bir kriptografik sema kullanilabilir.
3. **Islem, sirali "frame"lerden olusur.** Her frame farkli bir modda calisir.

### 1.3 Uc Frame Modu

| Mod | Deger | Arayan (msg.sender) | Amac |
|-----|-------|---------------------|------|
| **DEFAULT** | 0 | `ENTRY_POINT` (0x...aa) | Genel amacli calistirma |
| **VERIFY** | 1 | `ENTRY_POINT` | Dogrulama. APPROVE opcode'unu cagirmali |
| **SENDER** | 2 | `tx.sender` | Gonderenin kimligiyle calistirma |

### 1.4 Dort Yeni EVM Opcode

| Opcode | Byte | Stack I/O | Gas | Aciklama |
|--------|------|-----------|-----|----------|
| **APPROVE** | `0xAA` | 3 giris, 0 cikis | 100 | Kapsam bazli onay: 0=sender, 1=odeme, 2=ikisi |
| **TXPARAMLOAD** | `0xB0` | 2 giris, 1 cikis | 3 | Islem parametrelerini stack'e yukler |
| **TXPARAMSIZE** | `0xB1` | 2 giris, 1 cikis | 3 | Frame calldata boyutunu dondurur |
| **TXPARAMCOPY** | `0xB2` | 5 giris, 0 cikis | 3 + bellek | Frame calldata'yi bellege kopyalar |

### 1.5 Islem Formati (RLP Encoding)

```
0x06 || rlp([chain_id, nonce, sender, frames, max_priority_fee_per_gas,
             max_fee_per_gas, max_fee_per_blob_gas, blob_versioned_hashes])
```

Her frame: `[mode, target, gas_limit, data]`

**Kritik tasarim karari:** `signature_hash()` hesaplanirken VERIFY frame'lerinin `data` alani sifirlanir. Boylece imza, kendisini iceren veriyi kapsamaz (dairesel bagimlilik onlenir).

---

## BOLUM 2: MIMARI YAPI VE REPO YAPISI

### 2.1 Uc Katmanli Mimari

```
+---------------------------------------------------+
|  E2E Test Suites (Python)                         |
|  passkey_examples_test.py                         |
|  ecdsa_examples_test.py                           |
|  dilithium_examples_test.py                       |
+---------------------------------------------------+
          |  RPC (eth_sendRawTransaction)
          v
+---------------------------------------------------+
|  Foundry/Anvil Fork (Rust)                        |
|  executor.rs  --> Tespit ve yonlendirme           |
|  eip8141.rs   --> Frame calistirma motoru         |
|  eip8141.rs   --> TxEip8141 tipi (primitives)     |
+---------------------------------------------------+
          |  EVM calistirma
          v
+---------------------------------------------------+
|  revm-eip8141 Fork (Rust)                         |
|  frame_tx.rs  --> Opcode uygulamalari             |
|  opcode.rs    --> Opcode numaralari               |
|  instructions.rs --> Aktivasyon mekanizmasi       |
+---------------------------------------------------+
```

### 2.2 Dosya Yapisi

```
eip8141-implementation/
├── revm-eip8141/                      # revm v34.0.0 fork'u (submodule)
│   └── crates/interpreter/src/
│       └── instructions/frame_tx.rs   # 4 opcode uygulamasi + FrameTxContext
├── foundry/                           # Foundry/Anvil fork'u (submodule)
│   ├── crates/primitives/src/
│   │   └── transaction/eip8141.rs     # TxEip8141 tipi, RLP, validasyon
│   └── crates/anvil/src/eth/backend/
│       ├── eip8141.rs                 # Frame calistirma motoru
│       └── executor.rs               # Tespit + dispatch
├── ethdilithium/                      # ZKNox post-kuantum dogrulayici
├── e2e/
│   ├── tests/                         # 3 test suite
│   ├── utils/                         # Paylasilan yardimci araclar
│   └── contracts/                     # MinimalERC20 sozlesmesi
├── CLAUDE.md                          # Proje dokumantasyonu
└── README.md                          # Teknik aciklama
```

---

## BOLUM 3: KRONOLOJIK GELISTIRME SURECI

Bu bolum, her commit'i kronolojik sirada, ne yapildigini, neden yapildigini ve nasil yapildigini aciklar.

### Faz 1: Temellerin Atilmasi (26-27 Subat 2026)

#### Commit 1 - Ilk Commit (`565c5d05`)
**Tarih:** 26 Subat 19:45

Tek satirlik `README.md` ile repo olusturuldu. Git tarihcesinin baslangic noktasi.

#### Commit 2 - Iskelet Yapi (`43a1171a`)
**Tarih:** 26 Subat 20:52

Projenin temel iskeleti olusturuldu:

**Submodule yapilandirmasi:**
- `revm-eip8141`: revm fork'u (opcode uygulamalari icin)
- `reth-eip8141`: reth fork'u (Ethereum dugum istemcisi icin)

**Solidity dogrulayici sozlesmeleri:**
- `ECDSAVerifier.sol`: `ecrecover` precompile ile ECDSA dogrulamasi
- `MultisigVerifier.sol`: N-of-M esik imza dogrulamasi
- `WebAuthnVerifier.sol`: P256VERIFY precompile ile passkey dogrulamasi

Her dogrulayici, EIP-8141 opcode'larini kullanir:
```solidity
// Imza hash'ini al
bytes32 sigHash = bytes32(verbatim_2i_1o(hex"b0", 0x08, 0x00)); // TXPARAMLOAD
// Dogrulama basariliysa onayla
verbatim_3i_0o(hex"aa", scope, 0, 0); // APPROVE
```

**TypeScript islem kodlayicisi (`showcase/lib/eip8141.ts`):**
- Frame transaction RLP kodlama/cozme
- `computeSignatureHash()`: VERIFY data'yi sifirlayarak hash hesaplama
- `buildEcdsaFrameTx()`: 2-frame islem olusturma (VERIFY + SENDER)
- `buildSponsoredFrameTx()`: 3-frame sponsorlu islem

**Devnet altyapisi:**
- `genesis.json`: Chain ID 8141, tum fork'lar aktif
- `run-devnet.sh`: reth dev modunda baslatma
- `docker-compose.yml`: Konteyner tabanli calistirma

**Ogrenilen ders:** Ilk iskelet genis kapsamliydi: istemci, opcode'lar, sozlesmeler, web uygulamasi ve devnet ayni anda planlanmisti.

#### Commit 3 - Yul Dogrulayicilar (`c63948d5`)
**Tarih:** 27 Subat 00:38

**Kritik kesif:** Solidity'nin `verbatim` builtini sadece bagimsiz Yul modunda calisir, inline assembly'de degil. Bu nedenle:

1. Ozel opcode'lar icin Yul uygulamalari olusturuldu
2. Solidity dosyalari okunabilir referans olarak sadelesstirildi

**Yul uygulamalari:**
- `ECDSAVerifier.yul` (90 satir): Constructor ile owner adresini bytecode sonuna gomuyor
- `MultisigVerifier.yul` (156 satir): N-of-M esik dogrulama, storage mapping ile
- `WebAuthnVerifier.yul` (108 satir): SHA-256 precompile + P256VERIFY precompile zinciri

**Onemli tasarim degisikligi:** VERIFY frame verileri artik `msg.data` (calldata) uzerinden okunuyor, TXPARAM opcode'lari yerine. Bu, EIP-8141'in cerceve verilerini calldata olarak ilettigini yansitir.

#### Commit 4 - Devnet ve Showcase (`a0ba8849`)
**Tarih:** 27 Subat 00:50

- Dockerfile (multi-stage Rust build)
- Next.js 15 showcase web uygulamasi (explorer + playground + landing page)
- Devnet yapilandirmasi iyilestirildi

#### Commit 5 - Kod Incelemesi Duzeltmeleri (`fe42c580`)
**Tarih:** 27 Subat 01:17

7 bulguya yanit verildi:

**Kritik guvenlik duzeltmesi - WebAuthn replay korunmasi:**
```yul
// sig_hash'in clientDataJSON icindeki challenge ile eslestigini dogrula
let embeddedChallenge := mload(add(clientDataJSON, 0x44))
if iszero(eq(embeddedChallenge, sigHash)) { revert(0, 0) }
```
Bu olmadan, gecerli bir passkey imzasi farkli islemler icin tekrar kullanilabilirdi.

### Faz 2: Mimari Pivot (27-28 Subat 2026)

#### Commit 6-7: Dokumantasyon ve Submodule Guncellemeleri
**Tarih:** 27 Subat 02:22 - 07:30

Build komutlari, mimari aciklamalar eklendi. Eski inceleme raporu silindi.

#### Commit 8 - BUYUK PIVOT: reth'ten Anvil'e (`4aad1aeb`)
**Tarih:** 28 Subat 01:22

**Bu, projenin en onemli mimari kararidir.**

**Silinen (24 dosya, -1716 satir):**
- Tum Solidity/Yul sozlesmeleri
- Showcase web uygulamasi
- Docker/devnet altyapisi
- reth-eip8141 submodule'u

**Eklenen:**
- `foundry` submodule'u (Foundry/Anvil fork'u)
- `devnet/anvil_demo.py`: Ilk kendi kendine yeten E2E demo
- `devnet/passkey_demo.py`: P256 passkey demosi
- `devnet/simple_p256_verifier.yul`: P256 dogrulayici Yul kaynagi

**Neden reth'ten Anvil'e gecildi?**
- reth tam bir Ethereum dugum istemcisidir (konsensus, ag, havuz gerektirir)
- Anvil yerel bir gelistirme dugumudur; frame calistirma motoruna odaklanmayi saglar
- Daha hizli gelistirme dongusu
- Daha kolay E2E test

**anvil_demo.py nasil calisir:**
```python
# 1. APPROVE sozlesmesini deploy et (7-byte runtime)
approve_runtime = bytes([0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xAA])
# PUSH1 0, PUSH1 0, PUSH1 0, APPROVE -> kosulsuz onay

# 2. SSTORE hedef sozlesmesini deploy et
target_runtime = bytes([0x60, 42, 0x60, 0x00, 0x55, 0x00])
# PUSH1 42, PUSH1 0, SSTORE, STOP -> slot0 = 42

# 3. Frame TX olustur
frames = [
    [FRAME_MODE_VERIFY, approve_addr, 100_000, b""],
    [FRAME_MODE_SENDER, target_addr, 100_000, b""],
]

# 4. RLP kodlama
raw_tx = bytes([0x06]) + rlp.encode([
    chain_id, nonce, sender, frames,
    max_priority_fee, max_fee, max_blob_fee, blob_hashes
])

# 5. Gonder ve dogrula
tx_hash = w3.eth.send_raw_transaction(raw_tx)
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
assert receipt["type"] == 0x06
assert w3.eth.get_storage_at(target, 0) == 42
```

#### Commit 9 - 9 Kod Incelemesi Bulgusu (`c98bdc24`)
**Tarih:** 28 Subat 02:18

Frame calistirma motorundaki kritik hatalar duzeltildi:

**1. Nonce artirimi ve gas ucreti tahsili (P0):**
Oncesi: Nonce dogrulaniyordu ama hic arttirilmiyordu. Gas ucreti hic tahsil edilmiyordu.
Sonrasi: `nonce + 1` ayarlaniyor, `max_cost` dusuruluyor, execution sonrasi gas iadesi yapiliyor.

**2. VERIFY frame read-only semantigi (P1):**
```rust
// Checkpoint al
let verify_cp = evm.ctx.journaled_state.checkpoint();
// Frame'i calistir
let result = execute_frame(...);
// Onay flag'ini kaydet (journal disinda)
let saved_approved = evm.ctx.chain.sender_approved;
// State degisikliklerini geri al
evm.ctx.journaled_state.checkpoint_revert(verify_cp);
// Onay flag'ini geri yukle
evm.ctx.chain.sender_approved = saved_approved;
```

**3. APPROVE kontrolu (P0):**
```rust
// VERIFY frame basariyla bitti ama APPROVE cagirmadiysa -> revert
if !evm.ctx.chain.sender_approved {
    failure = Some("VERIFY frame did not call APPROVE");
}
```

**4. revm opcode tablosuna placeholder'lar eklendi (P1):**
```rust
// Varsayilan tablo: NotActivated hatasi verir
table[APPROVE as usize] = Instruction::new(control::not_activated, 0);
table[TXPARAMLOAD as usize] = Instruction::new(control::not_activated, 0);
// Gercek handler'lar with_eip8141_opcodes() ile enjekte edilir
```

#### Commit 10 - Handler::execution() Duzeltmesi (`7c4c400`)
**Tarih:** 28 Subat 03:09

**En onemli teknik degisiklik.** Frame calistirma mekanizmasi tamamen yeniden yazildi.

**Onceki yaklasim:**
```rust
// HER frame icin ayri commit yapiyordu!
system_call_with_caller_commit(caller, target, data, gas_limit);
// Bu, journal checkpoint'lerini bozuyordu
```

**Yeni yaklasim:**
```rust
// Handler::execution() journal'a dokunmadan calistirir
let frame_result = MainnetHandler::default().execution(&mut evm, &init_gas);
// Checkpoint/revert duzgun calisir
// Tek atomik commit en sonda
let state = evm.finalize();
evm.commit(state);
```

**Neden onemli?**
- `system_call_with_caller_commit` her frame'den sonra `finalize() + commit()` cagirarak journal state'ini yok ediyordu
- VERIFY frame'lerinin state degisikliklerini geri almak icin journal checkpoint'leri gereklidir
- Yeni yaklasim, TUM frame'lerin tek bir journal icinde calismasini saglar
- Basarisizlik durumunda TUM frame state degisiklikleri geri alinir

**Accounting checkpoint deseni:**
```rust
// Frame dongusu oncesi checkpoint
let accounting_checkpoint = evm.ctx.journaled_state.checkpoint();

for frame in frames {
    // Frame calistir...
    if failure {
        break; // Dongudan cik
    }
}

// Tek cikis noktasi
if failure.is_some() {
    // TUM frame degisikliklerini geri al
    evm.ctx.journaled_state.checkpoint_revert(accounting_checkpoint);
} else {
    evm.ctx.journaled_state.checkpoint_commit();
}
```

#### Commit 11-13: Dokumantasyon ve Yapilandirma
**Tarih:** 28 Subat 03:30 - 03:38

CLAUDE.md yapilandirildi, README teknik dokumanla yeniden yazildi, revm submodule branch'i `eip8141-anvil` olarak ayarlandi.

### Faz 3: E2E Test Suite'leri ve Guvenlik Sertlestirme (28 Subat - 1 Mart)

#### Commit 14 - P256 ve ECDSA Test Suite'leri (`6ef67241`)
**Tarih:** 28 Subat 05:14

Demo script'leri yapilandirilmis test suite'lerine donusturuldu. Her suite 4 ornek akisi test eder:

**Ornek 1: Basit Islem (VERIFY + SENDER)**
```python
frames = [
    encode_frame(FRAME_MODE_VERIFY, verifier_addr, 200_000, b""),  # Dogrulama
    encode_frame(FRAME_MODE_SENDER, target_addr, 100_000, b""),    # Is
]
# Dogrulamalar:
# - status == 1
# - storage slot 0 == 42
# - sender bakiyesi = onceki - (gasUsed * effectiveGasPrice)
# - Tekrar gonderme reddedilir (nonce kontrolu)
```

**Ornek 1a: Akilli Hesap ile ETH Transferi**
```python
# Wallet sozlesmesi: cagirildiginda 1 wei transfer eder
wallet_runtime = build_transfer_wallet_runtime(recipient, amount_wei=1)
# SENDER frame hedefi bos = sender'in kendi kodu calisir
frames = [
    encode_frame(FRAME_MODE_VERIFY, verifier_addr, 200_000, b""),
    encode_frame(FRAME_MODE_SENDER, b"", 100_000, b""),  # Bos hedef = self-call
]
```

**Ornek 1b: Deploy + Calistirma (DEFAULT -> VERIFY -> SENDER)**
```python
# DEFAULT frame ile factory deploy eder
# VERIFY frame ile dogrulama yapilir
# SENDER frame ile yeni deploy edilen child cagrilir
frames = [
    encode_frame(FRAME_MODE_DEFAULT, factory_addr, 250_000, b""),
    encode_frame(FRAME_MODE_VERIFY, verifier_addr, 200_000, b""),
    encode_frame(FRAME_MODE_SENDER, child_addr, 120_000, b""),
]
```

**Ornek 2: Sponsorlu Coklu-Frame Islem**
```python
frames = [
    # Frame 0: Passkey VERIFY - scope 0x0 (sadece calistirma onay)
    encode_frame(FRAME_MODE_VERIFY, verifier_scope0, 220_000, b""),
    # Frame 1: Sponsor VERIFY - scope 0x1 (gas odeme onayi)
    encode_frame(FRAME_MODE_VERIFY, sponsor_verify, 250_000, sponsor_policy_data),
    # Frame 2: Ucret odemesi - sender ERC20 token transfer
    encode_frame(FRAME_MODE_SENDER, token, 200_000, fee_calldata),
    # Frame 3: Kullanici islemi - sender ERC20 token transfer
    encode_frame(FRAME_MODE_SENDER, token, 200_000, transfer_calldata),
    # Frame 4: Sponsor post-op (DEFAULT)
    encode_frame(FRAME_MODE_DEFAULT, postop_target, 100_000, b""),
]
```

#### Commit 15 - Tam Entegrasyon (`950a2c0b`)
**Tarih:** 28 Subat 06:28

- VERIFY frame'leri artik herhangi bir sirada olabilir (once olmak zorunda degil)
- Bos hedef (`b""`) SENDER frame'de sender adresine cozumlenir
- `set_balance()` ile sponsor kontratina ETH yukleme
- Sponsor-odeyen-gas modeli dogrulamasi:
```python
# Sender bakiyesi degismemeli (sponsor oduyor)
expect(sender_after == sender_before)
# Sponsor bakiyesi gas kadar azalmali
assert_sender_cost(w3, receipt, sponsor_before, sponsor_after, "example2-payer")
```

#### Commit 16 - Dilithium Post-Kuantum E2E Suite (`55dacf7`)
**Tarih:** 1 Mart 01:38

**CRYSTALS-Dilithium (ML-DSA-44) entegrasyonu** -- kuantum-direncli imza semasi.

```
+------------------+     +---------------------+     +------------------+
| DilithiumApprover|---->| ZKNOX_ethdilithium |---->| PKContract       |
| (EVM bytecode)   |     | (Solidity verifier) |     | (SSTORE2 ile PK) |
+------------------+     +---------------------+     +------------------+
     |                          |
     | TXPARAMLOAD(0x08, 0)     | STATICCALL
     | -> sigHash               | verify(pk, hash, sig)
     |                          |
     | APPROVE(scope, 0, 0)     | returns selector
```

**DilithiumApprover bytecode olusturma:**
```python
def build_dilithium_approver_runtime(verifier_addr, pk_addr, approve_scope):
    code = bytearray()
    # 1. TXPARAMLOAD(0x08, 0) -> sigHash
    code += bytes([0x60, 0x00, 0x60, 0x08, 0xB0])  # PUSH 0, PUSH 0x08, TXPARAMLOAD
    code += bytes([0x60, 0x24, 0x52])                # MSTORE mem[0x24]

    # 2. ABI-encoded verify() cagirisi olustur
    code += bytes([0x7F]) + selector_word   # PUSH32 selector
    code += bytes([0x60, 0x00, 0x52])       # MSTORE mem[0x00]
    # ... pk adresi, offset'ler, sig data ...

    # 3. STATICCALL verifier
    code += bytes([0x73]) + verifier_addr   # PUSH20 verifier
    code += bytes([0x5A, 0xFA])             # GAS, STATICCALL

    # 4. APPROVE
    code += bytes([0x60, approve_scope, 0x60, 0x00, 0x60, 0x00, 0xAA])
```

**Imza boyutu karsilastirmasi:**
| Sema | Imza Boyutu | Gas Maliyeti | Kuantum Direncli |
|------|-------------|--------------|:----------------:|
| ECDSA | 96 byte | ~10k | Hayir |
| P256 | 64 byte | ~50k | Hayir |
| Dilithium | 2420 byte | ~5M | Evet |

#### Commit 17 - Gercek ERC20 Token Entegrasyonu (`fb3db328`)
**Tarih:** 1 Mart 02:26

Mock SSTORE sozlesmeleri **gercek ERC20 token** ve **zincir-ustu sponsor politikasi dogrulayicisi** ile degistirildi.

**MinimalERC20.sol:**
```solidity
contract MinimalERC20 {
    mapping(address => uint256) public balanceOf;
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
```

**Sponsor Politikasi Dogrulayicisi (erc20_helpers.py):**

Bu, projedeki en karmasik EVM bytecode parcasidir. ~200 byte bytecode, 8 kontrol yapar:

```python
def build_sponsor_policy_verifier_runtime():
    asm = _Asm()

    # 1. Policy calldata uzunlugu == 64 byte mi?
    asm.op(0x36)  # CALLDATASIZE
    asm.push(0x40)
    asm.op(0x14, 0x15)  # EQ, ISZERO -> revert

    # 2. Mevcut frame indeksi == 1 mi?
    _emit_txparamload(asm, 0x10, 0)  # current_frame_index
    asm.push(0x01)
    asm.op(0x14, 0x15)  # EQ, ISZERO -> revert

    # 3. Frame sayisi > 2 mi?
    _emit_txparamload(asm, 0x09, 0)  # frame_count
    asm.push(0x02)
    asm.op(0x11, 0x15)  # GT, ISZERO -> revert

    # 4. Frame[2].mode == SENDER mi?
    _emit_txparamload(asm, 0x14, 2)  # frames[2].mode
    asm.push(0x02)
    asm.op(0x14, 0x15)  # EQ, ISZERO -> revert

    # 5. Frame[2].target == policy.token mi?
    _emit_txparamload(asm, 0x11, 2)  # frames[2].target
    # ... token adresi ile karsilastir

    # 6. Frame[2].data == transfer(sponsor, feeAmount) mi?
    _emit_txparamcopy(asm, 0x12, 2, 0x0100, 0x00, 0x44)
    # ... selector, alici ve miktar kontrolleri

    # 7. balanceOf(sender) >= feeAmount mi?
    # ... STATICCALL ile token.balanceOf(sender)

    # 8. Tum kontroller gecti -> APPROVE(0x1)
    asm.push(0x01)    # scope = 1 (gas odeme onayi)
    asm.push(0x00)
    asm.push(0x00)
    asm.op(0xAA, 0x00)  # APPROVE, STOP
```

**Bu mekanizma nasil calisir:**
1. Sponsor, gas odemeyi kabul eder (APPROVE scope 1)
2. AMA sadece belirli kosullar saglanirsa:
   - Sender'in sonraki frame'de sponsor'a ERC20 token transfer etmesi gerekir
   - Transfer miktari politikadaki ucret miktarina esit olmali
   - Sender'in yeterli token bakiyesi olmali
3. Her iki taraf da atomik olarak guvence altindadir

#### Commit 18 - devnet/ -> e2e/ Yeniden Yapilandirma (`dc20ae18`)
**Tarih:** 1 Mart 02:46

- `devnet/` dizini `e2e/{tests,utils,contracts}` olarak yapilandirildi
- 15 tekrarlanan fonksiyon + 9 sabit `eip8141_utils.py` paylasilan modulune cikarildi
- ~150 satir tekrarlanan kod/test dosyasi eliminasyonu

#### Commit 19 - Guvenlik Sertlestirme (`3f31a629`)
**Tarih:** 1 Mart 04:28

**Submodule guvenlik duzeltmeleri:**
- APPROVE sadece VERIFY frame icinden cagrilabilir
- Gas tahsili DoS duzeltmesi
- Odeyici odeme gucu zamanlama duzeltmesi

**P256 dogrulayici calldatasize korumasi:**
```python
# Onceki: Calldata kontrolu yok, yetersiz veri ile cokebilir
# Sonraki:
"36604010604557"  # if calldatasize() < 64: jump to revert
```

**mk_init_code PUSH2 destegi:**
```python
# Onceki: Sadece 255 byte'a kadar runtime destegi (PUSH1)
# Sonraki: 65535 byte'a kadar (PUSH2) - sponsor verifier icin gerekli
if size <= 0xFF:
    constructor = bytes([0x60, size, ...])    # PUSH1
elif size <= 0xFFFF:
    constructor = bytes([0x61, hi, lo, ...])  # PUSH2
```

**Yanlis anahtar negatif testleri:**
```python
# Yanlis anahtarla imzalanmis islem reddedilmeli
wrong_key = ec.generate_private_key(ec.SECP256R1())
try:
    _, wk_receipt, _ = send_signed_frame_tx(w3, ..., wrong_key, ...)
    wrong_key_rejected = int(wk_receipt["status"]) == 0
except Exception as e:
    err_msg = str(e).lower()
    expect("revert" in err_msg or "approve" in err_msg or ...)
    wrong_key_rejected = True
expect(wrong_key_rejected, "yanlis anahtarla islem reddedilmeli")
```

**Pytest entegrasyonu:**
```python
# conftest.py
@pytest.fixture(scope="session")
def w3():
    provider = Web3(Web3.HTTPProvider("http://localhost:8545"))
    if not provider.is_connected():
        pytest.skip("anvil'e baglanamadi")
    return provider
```

---

## BOLUM 4: OPCODE UYGULAMALARI (DETAYLI)

### 4.1 FrameTxContext: Paylasilan Durum

Tum opcode'lar, EVM'in `chain` parametresi olarak gecirilen `FrameTxContext` uzerinden iletisim kurar:

```rust
pub struct FrameTxContext {
    pub active: bool,                    // Opcode'lar aktif mi?
    pub sender_approved: bool,           // APPROVE(0x0 veya 0x2) cagrildi mi?
    pub payer_approved: bool,            // APPROVE(0x1 veya 0x2) cagrildi mi?
    pub sender: Address,                 // Acik sender adresi
    pub payer: Address,                  // Gas odeyen (sponsor veya sender)
    pub sig_hash: B256,                  // Onceden hesaplanmis imza hash'i
    pub frame_count: usize,              // Toplam frame sayisi
    pub current_frame_index: usize,      // Simdiki frame indeksi
    pub frames: Vec<FrameInfo>,          // Tum frame meta verileri
    pub approve_called_current_frame: bool, // Bu frame'de APPROVE cagrildi mi?
    // ... diger alanlar
}
```

### 4.2 APPROVE (0xAA) - Onay Opcode'u

```
Stack: [offset, length, scope] -> []
```

APPROVE, RETURN gibi davranir (calistirmayi sonlandirir) ama ek olarak islem kapsamli onay durumunu gunceller.

**Kapsam semantigi:**

| Kapsam | Anlam | payer degeri |
|--------|-------|-------------|
| 0x0 | Sadece calistirma onayi | Degismez |
| 0x1 | Sadece odeme onayi | Mevcut frame hedefi (sponsor deseni) |
| 0x2 | Birlesik onay (ikisi) | Sender |

**Guvenlik kontrolleri:**
```rust
// Sadece VERIFY frame icinden cagrilabilir
if ftx.frames[idx].mode != 1 {
    halt(InvalidFEOpcode);
}
// Cifte onay engellenir
if ftx.sender_approved { halt(Revert); }
// Scope 0x1 icin once sender onaylanmali
if !ftx.sender_approved { halt(Revert); }
```

### 4.3 TXPARAMLOAD (0xB0) - Parametre Yukleme

```
Stack: [param_id, index] -> [value]
```

| param_id | Deger |
|----------|-------|
| 0x00 | tx_type (0x06) |
| 0x01 | nonce |
| 0x02 | sender (32 byte'a dolgulu) |
| 0x08 | signature_hash (en cok kullanilan!) |
| 0x09 | frame_count |
| 0x10 | current_frame_index |
| 0x11 | frames[index].target |
| 0x14 | frames[index].mode |
| 0x15 | frames[index].status (sadece gecmis frame'ler) |

**Guvenlik:** VERIFY frame data'si opak'tir (0 dondurur). Frame durumu sadece gecmis frame'ler icin okunabilir.

### 4.4 TXPARAMSIZE (0xB1) ve TXPARAMCOPY (0xB2)

```
TXPARAMSIZE: [param_id, index] -> [size]
TXPARAMCOPY: [param_id, index, dest_offset, src_offset, length] -> []
```

Dinamik uzunluklu veriler (frame calldata) icin kullanilir. TXPARAMCOPY sadece param 0x12 (frame data) icin calisir.

### 4.5 Iki Katmanli Guvenlik Mekanizmasi

```
Katman 1: Varsayilan tablo -> not_activated (OpcodeNotFound)
          with_eip8141_opcodes() ile gercek handler'lar enjekte edilir

Katman 2: Her handler icinde -> if !active { halt(OpcodeNotFound) }
          Sadece frame TX baglaminda calisir
```

---

## BOLUM 5: FRAME CALISTIRMA MOTORU (Rust - eip8141.rs)

### 5.1 Calistirma Akisi

```
1. FrameTxContext olustur (signature_hash onceden hesapla)
2. Ozel EVM olustur (FrameTxContext + opcode'lar)
3. Nonce dogrula
4. Accounting checkpoint al

5. Her frame icin:
   +-- VERIFY: checkpoint -> calistir -> onay flag'lerini kaydet
   |           -> state'i geri al -> APPROVE kontrolu
   +-- DEFAULT/SENDER: calistir -> log'lari topla

6. Basarisizlik varsa:
   -> Accounting checkpoint'e geri don

7. effective_gas_price * gas_used hesapla
8. Onaylanmis odeyiciden tahsil et + nonce arttir
9. Tek finalize() + commit()
```

### 5.2 Executor Entegrasyonu (executor.rs)

```rust
// Islem tipi tespiti
let is_eip8141 = matches!(
    transaction.pending_transaction.transaction.as_ref(),
    FoundryTxEnvelope::Eip8141(_)
);

if is_eip8141 {
    // Ozel yol: ayri EVM, FrameTxContext, opcode'lar
    let frame_tx = extract_frame_tx(&transaction);
    let outcome = execute_eip8141_frame_tx(db, env, &frame_tx, inspector);
    // EIP-8141 ozel makbuzu olustur (payer + frame_statuses)
} else {
    // Normal yol: standart EVM
    evm.transact_commit(env.tx);
}
```

---

## BOLUM 6: GAS SPONSORLUGU NASIL CALISIR?

### 6.1 Kendisi Odeyen Model (Ornek 1)

```
Frame 0: VERIFY -> APPROVE(scope=2)  // Birlesik onay
Frame 1: SENDER -> hedef sozlesmeyi cagir

Gas odemesi: sender (scope 2 = sender odeyen)
```

### 6.2 Sponsor Odeyen Model (Ornek 2)

```
Frame 0: VERIFY(passkey)  -> APPROVE(scope=0)  // Sadece calistirma
Frame 1: VERIFY(sponsor)  -> APPROVE(scope=1)  // Gas odeme onayi
  |                                              // payer = frame[1].target
  |-- Politika kontrolleri:
  |   - Frame[2] SENDER modunda mi?
  |   - Frame[2] token sozlesmesini mi cagiriyor?
  |   - Transfer miktari ucret miktarina esit mi?
  |   - Sender'in yeterli token bakiyesi var mi?
  |
Frame 2: SENDER -> token.transfer(sponsor, ucret)
Frame 3: SENDER -> token.transfer(alici, miktar)
Frame 4: DEFAULT -> sponsor post-op islemi

Gas odemesi: sponsor kontrati (scope 1 ile onaylandi)
Sender ETH bakiyesi: DEGISMEZ
Sponsor ETH bakiyesi: gasUsed * effectiveGasPrice kadar azalir
```

**Bu guvensizlik-siz (trustless) bir degis tokustur:**
- Sponsor ETH gas odur
- Sender ERC20 token odur
- Her iki taraf da atomik olarak guvence altindadir (islem ya tamamen basarili ya da tamamen geri alinir)

---

## BOLUM 7: KENDI BASINIZA UYGULAMAK ICIN ADIM ADIM REHBER

### Adim 1: Ortam Kurulumu

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Python gereksinimler
pip install web3 rlp cryptography eth-keys

# Repo klonlama
git clone --recurse-submodules https://github.com/aalimsahin/eip8141-implementation.git
cd eip8141-implementation
```

### Adim 2: revm Fork'u - Opcode'lari Ekleyin

**2a. Opcode numaralarini tanimlayin** (`crates/bytecode/src/opcode.rs`):
```rust
0xAA => APPROVE      => stack_io(3, 0), terminating;
0xB0 => TXPARAMLOAD  => stack_io(2, 1);
0xB1 => TXPARAMSIZE  => stack_io(2, 1);
0xB2 => TXPARAMCOPY  => stack_io(5, 0);
```

**2b. FrameTxContext olusturun** (`crates/interpreter/src/instructions/frame_tx.rs`):
```rust
pub struct FrameTxContext {
    pub active: bool,
    pub sender_approved: bool,
    pub payer_approved: bool,
    pub sender: Address,
    pub payer: Address,
    pub sig_hash: B256,
    pub frames: Vec<FrameInfo>,
    // ...
}

pub trait FrameTxHost {
    fn frame_tx_context(&self) -> &FrameTxContext;
    fn frame_tx_context_mut(&mut self) -> &mut FrameTxContext;
}
```

**2c. Opcode handler'larini yazin** (ayni dosya):
- `approve()`: Kapsam kontrolu, onay flag'lerini guncelle, RETURN gibi sonlandir
- `txparamload()`: Parametre tablosundan deger oku
- `txparamsize()`: Dinamik alan boyutunu dondur
- `txparamcopy()`: Veriyi EVM bellegine kopyala

**2d. Aktivasyon mekanizmasini ekleyin** (`crates/handler/src/instructions.rs`):
```rust
pub fn with_eip8141_opcodes(mut self) -> Self {
    self.insert_instruction(0xAA, Instruction::new(frame_tx::approve, 100));
    self.insert_instruction(0xB0, Instruction::new(frame_tx::txparamload, 3));
    self.insert_instruction(0xB1, Instruction::new(frame_tx::txparamsize, 3));
    self.insert_instruction(0xB2, Instruction::new(frame_tx::txparamcopy, 3));
    self
}
```

### Adim 3: Foundry Fork'u - Islem Tipi ve Motor

**3a. TxEip8141 tipini tanimlayin** (`crates/primitives/src/transaction/eip8141.rs`):
- RLP Encodable/Decodable uygulama
- `signature_hash()`: VERIFY data'yi sifirlayarak hash
- `validate()`: Yapisal dogrulama
- EIP-2718 zarf desteği

**3b. Frame calistirma motorunu yazin** (`crates/anvil/src/eth/backend/eip8141.rs`):
- `build_frame_tx_context()`: TX -> FrameTxContext donusumu
- `execute_eip8141_frame_tx()`: Frame dongusu, checkpoint/revert, gas hesaplama

**3c. Executor'da tespiti ekleyin** (`executor.rs`):
```rust
if is_eip8141 {
    execute_eip8141_frame_tx(db, env, &frame_tx, inspector)
} else {
    evm.transact_commit(env.tx)
}
```

### Adim 4: Dogrulayici Sozlesmeleri

**P256 Verifier (Yul):**
1. TXPARAMLOAD(0x08, 0) ile sig_hash al
2. Calldata'dan r||s oku
3. P256VERIFY precompile (0x0100) cagir
4. Basariliysa APPROVE(scope, 0, 0)

**ECDSA Verifier (bytecode):**
1. TXPARAMLOAD(0x08, 0) ile sig_hash al
2. Calldata'dan r, s, v oku
3. ecrecover precompile (0x01) cagir
4. Kurtarilan adresi yetkili imzaci ile karsilastir
5. Eslesiyrosa APPROVE(scope, 0, 0)

### Adim 5: E2E Testleri

```python
# 1. Sozlesmeleri deploy et
verifier = deploy_contract(w3, funder, verifier_init_code)
target = deploy_contract(w3, funder, mk_init_code(sstore_runtime(42)))

# 2. Frame'leri olustur
frames = [
    encode_frame(FRAME_MODE_VERIFY, verifier_bytes, 200_000, b""),
    encode_frame(FRAME_MODE_SENDER, target_bytes, 100_000, b""),
]

# 3. Imzala
sig_hash = compute_signature_hash(chain_id, nonce, sender_bytes, frames)
r, s = sign_p256(private_key, sig_hash)
frames[0][3] = r + s  # Imzayi VERIFY frame data'ya yerlestir

# 4. RLP kodla ve gonder
raw_tx = bytes([0x06]) + build_tx_rlp(chain_id, nonce, sender_bytes, frames)
tx_hash = w3.eth.send_raw_transaction(raw_tx)

# 5. Dogrula
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
assert receipt["status"] == 1
assert w3.eth.get_storage_at(target, 0) == 42
```

### Adim 6: Derleme ve Calistirma

```bash
# Anvil'i derle
cd foundry && cargo build -p anvil

# Birim testleri calistir (39 test)
cargo test -p foundry-primitives

# Anvil'i baslat
cargo run -p anvil -- --chain-id 8141

# E2E testleri calistir (ayri terminalde)
cd .. && python3 e2e/tests/passkey_examples_test.py
```

---

## BOLUM 8: ONEMLI DERSLER VE TASARIM KARARLARI

### 8.1 Neden reth'ten Anvil'e Gecildi?

reth tam bir Ethereum dugum istemcisidir: konsensus, P2P ag, islem havuzu, state sync vb. gerektirir. EIP-8141 calismasini dogrudan frame calistirma motoruna odaklamak icin Anvil tercih edildi. Bu, gelistirme dongusunu gunlerden saatlere indirdi.

### 8.2 Neden Solidity Yerine Yul/Bytecode?

Solidity'nin `verbatim` builtini sadece bagimsiz Yul dosyalarinda calisir. Custom opcode'lar icin ham EVM bytecode olusturmak gerekir. Python'da bytecode assembler'lar yazarak bu sorun cozuldu.

### 8.3 VERIFY Frame Neden Read-Only?

VERIFY frame'leri dogrulama yapar ama state degistirmemelidir. Bu, checkpoint/revert mekanizmasiyla saglanir. Onay flag'leri journal disinda (chain context'te) tutulur, boylece state geri alindiktan sonra bile korunur.

### 8.4 Neden Handler::execution() Kullanildi?

`system_call_with_caller_commit()` her frame'den sonra state'i commit ediyordu ve journal checkpoint'lerini yok ediyordu. `Handler::execution()` dogrudan cagrilarak journal kontrolu elde tutuldu.

### 8.5 signature_hash() Neden VERIFY Data'yi Sifirlar?

VERIFY frame'in data alani imzayi/kaniti icerir. Imza, kendisini iceren veriyi kapsayamaz (dairesel bagimlilik). Bu nedenle hash hesaplanirken VERIFY data sifirlanir.

### 8.6 Sponsor Politikasi Neden On-Chain?

Sponsor, gas odemeyi sadece belirli kosullar altinda kabul eder. Bu kosullar TXPARAM opcode'lari ile diger frame'leri inceleyerek on-chain'de dogrulanir. Bu, guvensizlik-siz (trustless) bir gas sponsorlugu saglar.

---

## BOLUM 9: ISTATISTIKLER VE OZET

### Kod Istatistikleri

| Katman | Dosya Sayisi | Toplam Satir |
|--------|-------------|-------------|
| revm opcode'lari | 5 | ~580 |
| Foundry primitives | 1 | ~920 |
| Frame calistirma motoru | 2 | ~600 |
| E2E test suite'leri | 3 | ~1590 |
| Paylasilan yardimcilar | 2 | ~540 |
| Dogrulayici sozlesmeleri | 4 | ~160 |
| **Toplam** | **17** | **~4390** |

### Commit Kronolojisi

| # | Tarih | Tip | Ozet |
|---|-------|-----|------|
| 1 | 26/02 19:45 | init | Ilk commit |
| 2 | 26/02 20:52 | feat | Iskelet: submodule'ler, sozlesmeler, TS kodlayici |
| 3 | 27/02 00:38 | feat | Yul dogrulayicilar (verbatim kesfinden sonra) |
| 4 | 27/02 00:50 | feat | Devnet + showcase web uygulamasi |
| 5 | 27/02 01:17 | fix | 7 kod incelemesi bulgusunu duzelt |
| 6 | 27/02 02:22 | docs | CLAUDE.md mimari aciklamalari |
| 7 | 27/02 07:30 | chore | Submodule guncellemeleri |
| 8 | 28/02 01:22 | **refactor** | **BUYUK PIVOT: reth -> Anvil** |
| 9 | 28/02 02:18 | fix | 9 inceleme: nonce, gas, APPROVE, read-only |
| 10 | 28/02 03:09 | **fix** | **Handler::execution() mekanizmasi** |
| 11-13 | 28/02 03:30-38 | docs | README, CLAUDE.md, submodule branch |
| 14 | 28/02 05:14 | test | P256 + ECDSA test suite'leri |
| 15 | 28/02 06:28 | feat | Tam entegrasyon: receipts, null targets |
| 16 | 01/03 01:38 | feat | Dilithium post-kuantum test suite |
| 17 | 01/03 02:26 | feat | Gercek ERC20 + sponsor politikasi |
| 18 | 01/03 02:46 | refactor | devnet/ -> e2e/ yapilandirma |
| 19 | 01/03 04:28 | fix | Guvenlik sertlestirme + pytest |

### Desteklenen Kriptografik Semalar

| Sema | Dogrulayici | Precompile | Guvenlik |
|------|------------|-----------|----------|
| ECDSA (secp256k1) | Bytecode | ecrecover (0x01) | Klasik |
| P256 (secp256r1/Passkey) | Yul bytecode | P256VERIFY (0x0100) | WebAuthn |
| CRYSTALS-Dilithium (ML-DSA-44) | Solidity | ZKNOX verifier | Kuantum-direncli |

**Sonuc:** EIP-8141, Ethereum'un ECDSA bagimliligini kaldirarak, herhangi bir kriptografik semayi protokol seviyesinde destekleyen, gas sponsorlugu iceren esnek bir islem cercevesi sunar. Bu uygulama, kavramin tum yonlerini calisan kodla kanitlar.
