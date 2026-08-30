#include <mcl/bls12_381.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace mcl::bn;
using Clock = std::chrono::steady_clock;

static constexpr size_t KEY_BYTES = 16;
static constexpr size_t NONCE_BYTES = 12;
static constexpr size_t TAG_BYTES = 16;

struct Header {
    G1 off2;                 // abstract off_{2,e}
    G2 off4;                 // abstract off_{4,e}
    std::vector<G2> gamma;   // A_0,...,A_{t+1}
};

struct OfflineState {
    uint64_t epoch{};
    Header hdr;
    GT theta;
};

struct Credential {
    Fr x;
    G1 sk;
};

struct SetupState {
    Fr r;
    G1 g1;
    G1 g3;
    G2 g2;
    G2 G2r;
    G1 G3r;
    GT mu;
    std::array<unsigned char, 32> kid{};
};

struct Ciphertext {
    std::string sensor_id;
    uint64_t epoch{};
    uint64_t seq{};
    Header hdr;
    std::array<unsigned char, KEY_BYTES> wrapped_key{};
    std::array<unsigned char, NONCE_BYTES> nonce{};
    std::vector<unsigned char> aead_ct; // ciphertext || tag
    std::vector<unsigned char> aad_app;
};

struct OfflineTiming {
    double poly_ms{};
    double group_ms{};
};

static double ms_since(const Clock::time_point& a, const Clock::time_point& b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

static void require(bool ok, const std::string& msg) {
    if (!ok) throw std::runtime_error(msg);
}

static Fr random_nonzero_fr() {
    Fr x;
    do { x.setByCSPRNG(); } while (x.isZero());
    return x;
}

static void append_u64(std::vector<unsigned char>& out, uint64_t v) {
    for (int i = 7; i >= 0; --i) out.push_back(static_cast<unsigned char>((v >> (8*i)) & 0xff));
}

template<class T>
static void append_serialized(std::vector<unsigned char>& out, const T& x) {
    std::array<unsigned char, 2048> buf{};
    const size_t n = x.serialize(buf.data(), buf.size());
    require(n > 0, "serialization failure");
    append_u64(out, static_cast<uint64_t>(n));
    out.insert(out.end(), buf.begin(), buf.begin() + n);
}

static std::vector<unsigned char> encode_header(const Header& h) {
    std::vector<unsigned char> out;
    append_serialized(out, h.off2);
    append_serialized(out, h.off4);
    append_u64(out, h.gamma.size());
    for (const auto& A : h.gamma) append_serialized(out, A);
    return out;
}

static std::vector<unsigned char> encode_ctx(
    const std::string& sensor_id,
    uint64_t epoch,
    uint64_t seq,
    const Header& hdr,
    const std::array<unsigned char, NONCE_BYTES>& nonce,
    const std::vector<unsigned char>& aad)
{
    std::vector<unsigned char> out;
    const std::string domain = "LBED-CTX-v1";
    out.insert(out.end(), domain.begin(), domain.end());
    append_u64(out, sensor_id.size());
    out.insert(out.end(), sensor_id.begin(), sensor_id.end());
    append_u64(out, epoch);
    append_u64(out, seq);
    auto hb = encode_header(hdr);
    append_u64(out, hb.size());
    out.insert(out.end(), hb.begin(), hb.end());
    out.insert(out.end(), nonce.begin(), nonce.end());
    append_u64(out, aad.size());
    out.insert(out.end(), aad.begin(), aad.end());
    return out;
}

static std::vector<unsigned char> serialize_gt(const GT& x) {
    std::vector<unsigned char> out(2048);
    size_t n = x.serialize(out.data(), out.size());
    require(n > 0, "GT serialization failure");
    out.resize(n);
    return out;
}

static G2 H2(const GT& x) {
    auto b = serialize_gt(x);
    const std::string prefix = "LBED-H2-v1:";
    std::vector<unsigned char> msg(prefix.begin(), prefix.end());
    msg.insert(msg.end(), b.begin(), b.end());
    G2 P;
    hashAndMapToG2(P, msg.data(), msg.size());
    return P;
}

static std::array<unsigned char, 32> hmac_sha256(
    const unsigned char* key, size_t key_len,
    const unsigned char* data, size_t data_len)
{
    std::array<unsigned char, 32> out{};
    unsigned int out_len = 0;
    unsigned char* p = HMAC(EVP_sha256(), key, static_cast<int>(key_len),
                            data, data_len, out.data(), &out_len);
    require(p != nullptr && out_len == out.size(), "HMAC-SHA256 failure");
    return out;
}

// Benchmark instantiation of F_{k_id}(ID || ctr) -> Fr.
// The manuscript remains abstract; this is an implementation choice only.
static Fr derive_coordinate(const std::array<unsigned char, 32>& kid,
                            const std::string& id,
                            uint64_t ctr)
{
    std::vector<unsigned char> in;
    const std::string domain = "LBED-ID-PRF-v1:";
    in.insert(in.end(), domain.begin(), domain.end());
    in.insert(in.end(), id.begin(), id.end());
    append_u64(in, ctr);
    auto h = hmac_sha256(kid.data(), kid.size(), in.data(), in.size());
    Fr x;
    x.setLittleEndianMod(h.data(), h.size());
    return x;
}

static std::array<unsigned char, KEY_BYTES> kdf128(
    const GT& theta,
    const std::vector<unsigned char>& ctx)
{
    // One-block HKDF-style extract/expand using HMAC-SHA256.
    // This is only the concrete benchmark instantiation of the abstract KDF.
    auto gt = serialize_gt(theta);
    std::vector<unsigned char> ikm;
    const std::string dom = "LBED-KDF-v1:";
    ikm.insert(ikm.end(), dom.begin(), dom.end());
    ikm.insert(ikm.end(), gt.begin(), gt.end());
    ikm.insert(ikm.end(), ctx.begin(), ctx.end());

    std::array<unsigned char, 32> zero_salt{};
    auto prk = hmac_sha256(zero_salt.data(), zero_salt.size(), ikm.data(), ikm.size());

    const std::string info = "LBED-WRAP-128";
    std::vector<unsigned char> exp(info.begin(), info.end());
    exp.push_back(0x01);
    auto okm = hmac_sha256(prk.data(), prk.size(), exp.data(), exp.size());

    std::array<unsigned char, KEY_BYTES> out{};
    std::copy_n(okm.begin(), KEY_BYTES, out.begin());
    return out;
}

static std::vector<unsigned char> aes128gcm_encrypt(
    const std::array<unsigned char, KEY_BYTES>& key,
    const std::array<unsigned char, NONCE_BYTES>& nonce,
    const std::vector<unsigned char>& pt,
    const std::vector<unsigned char>& aad)
{
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    require(c != nullptr, "EVP_CIPHER_CTX_new failed");
    std::vector<unsigned char> out(pt.size() + TAG_BYTES);
    int len = 0, total = 0;
    require(EVP_EncryptInit_ex(c, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1, "GCM init");
    require(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_BYTES, nullptr) == 1, "GCM ivlen");
    require(EVP_EncryptInit_ex(c, nullptr, nullptr, key.data(), nonce.data()) == 1, "GCM key/iv");
    if (!aad.empty()) require(EVP_EncryptUpdate(c, nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1, "GCM aad");
    if (!pt.empty()) {
        require(EVP_EncryptUpdate(c, out.data(), &len, pt.data(), static_cast<int>(pt.size())) == 1, "GCM enc");
        total = len;
    }
    require(EVP_EncryptFinal_ex(c, out.data() + total, &len) == 1, "GCM final");
    total += len;
    std::array<unsigned char, TAG_BYTES> tag{};
    require(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG_BYTES, tag.data()) == 1, "GCM tag");
    EVP_CIPHER_CTX_free(c);
    out.resize(total);
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

static bool aes128gcm_decrypt(
    const std::array<unsigned char, KEY_BYTES>& key,
    const std::array<unsigned char, NONCE_BYTES>& nonce,
    const std::vector<unsigned char>& ct_tag,
    const std::vector<unsigned char>& aad,
    std::vector<unsigned char>& pt)
{
    if (ct_tag.size() < TAG_BYTES) return false;
    const size_t ct_len = ct_tag.size() - TAG_BYTES;
    const unsigned char* tag = ct_tag.data() + ct_len;

    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return false;
    pt.assign(ct_len, 0);
    int len = 0, total = 0;
    bool ok = true;
    ok &= EVP_DecryptInit_ex(c, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1;
    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_BYTES, nullptr) == 1;
    ok &= EVP_DecryptInit_ex(c, nullptr, nullptr, key.data(), nonce.data()) == 1;
    if (ok && !aad.empty()) ok &= EVP_DecryptUpdate(c, nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1;
    if (ok && ct_len) {
        ok &= EVP_DecryptUpdate(c, pt.data(), &len, ct_tag.data(), static_cast<int>(ct_len)) == 1;
        total = len;
    }
    if (ok) ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG_BYTES, const_cast<unsigned char*>(tag)) == 1;
    if (ok) ok &= EVP_DecryptFinal_ex(c, pt.data() + total, &len) == 1;
    total += len;
    EVP_CIPHER_CTX_free(c);
    if (!ok) { pt.clear(); return false; }
    pt.resize(total);
    return true;
}

static SetupState setup() {
    SetupState s;
    s.r = random_nonzero_fr();

    const std::string m1 = "LBED-BENCH-G1";
    const std::string m2 = "LBED-BENCH-G2";
    const std::string m3 = "LBED-BENCH-G3";
    hashAndMapToG1(s.g1, m1.data(), m1.size());
    hashAndMapToG2(s.g2, m2.data(), m2.size());
    hashAndMapToG1(s.g3, m3.data(), m3.size());

    G2::mul(s.G2r, s.g2, s.r);
    G1::mul(s.G3r, s.g3, s.r);
    pairing(s.mu, s.g1, s.g2);
    require(RAND_bytes(s.kid.data(), static_cast<int>(s.kid.size())) == 1, "RAND_bytes kid");
    return s;
}

static Credential keygen(const SetupState& s, const Fr& x) {
    Fr den, inv;
    Fr::add(den, s.r, x);
    require(!den.isZero(), "invalid r+x");
    Fr::inv(inv, den);
    Credential c;
    c.x = x;
    G1::mul(c.sk, s.g1, inv);
    return c;
}

static std::vector<Fr> vanishing_poly(const std::vector<Fr>& xs) {
    std::vector<Fr> z(1);
    z[0] = 1;
    for (const auto& x : xs) {
        std::vector<Fr> n(z.size() + 1);
        for (auto& v : n) v.clear();
        for (size_t k = 0; k < z.size(); ++k) {
            Fr xzk;
            Fr::mul(xzk, x, z[k]);
            Fr::sub(n[k], n[k], xzk);      // -x*z_k
            Fr::add(n[k+1], n[k+1], z[k]); // +z_k X
        }
        z.swap(n);
    }
    return z;
}

static OfflineState offline_enc(
    const SetupState& s,
    const Credential& sensor,
    const std::vector<Fr>& recipients,
    uint64_t epoch,
    OfflineTiming* timing = nullptr)
{
    const auto tp0 = Clock::now();
    const auto z = vanishing_poly(recipients);
    const size_t t = recipients.size();

    Fr rho0 = random_nonzero_fr();
    Fr rho1 = random_nonzero_fr();
    // match manuscript: not both zero; choosing both nonzero is a valid subset for benchmarking
    std::vector<Fr> b(t + 2);
    for (auto& v : b) v.clear();
    for (size_t k = 0; k <= t + 1; ++k) {
        Fr term0, term1;
        term0.clear(); term1.clear();
        if (k <= t) Fr::mul(term0, rho0, z[k]);
        if (k >= 1 && k-1 <= t) Fr::mul(term1, rho1, z[k-1]);
        Fr::add(b[k], term0, term1);
    }
    const auto tp1 = Clock::now();

    Fr n1 = random_nonzero_fr();
    Fr n2 = random_nonzero_fr();
    Fr beta = random_nonzero_fr();

    // off1 = (G2r + x_s*g2) * n1 in additive notation
    G2 xsg2, sum2, off1;
    G2::mul(xsg2, s.g2, sensor.x);
    G2::add(sum2, s.G2r, xsg2);
    G2::mul(off1, sum2, n1);

    // off2 = (g3 + x_s^{-1} G3r) * n1
    Fr inv_xs;
    Fr::inv(inv_xs, sensor.x);
    G1 g3rinv, sum1, off2;
    G1::mul(g3rinv, s.G3r, inv_xs);
    G1::add(sum1, s.g3, g3rinv);
    G1::mul(off2, sum1, n1);

    GT off3;
    GT::pow(off3, s.mu, n1);

    GT mu_n2;
    GT::pow(mu_n2, s.mu, n2);
    G2 hmu = H2(mu_n2);
    G2 g2beta, off4;
    G2::mul(g2beta, s.g2, beta);
    G2::add(off4, hmu, g2beta);

    Fr beta_over_xs;
    Fr::mul(beta_over_xs, beta, inv_xs);
    G1 g3term, off5;
    G1::mul(g3term, s.g3, beta_over_xs);
    G1::add(off5, sensor.sk, g3term);

    GT pair56, off6, theta;
    pairing(pair56, off5, off1);
    GT::inv(off6, pair56);
    GT::mul(theta, off3, off6);

    Header hdr;
    hdr.off2 = off2;
    hdr.off4 = off4;
    hdr.gamma.resize(t + 2);

    // A0 = G2r*n2 + g2*(n2*b0)
    G2 a0a, a0b;
    G2::mul(a0a, s.G2r, n2);
    Fr n2b0;
    Fr::mul(n2b0, n2, b[0]);
    G2::mul(a0b, s.g2, n2b0);
    G2::add(hdr.gamma[0], a0a, a0b);

    // A1 = g2 * n2*(1+b1)
    Fr one, onepb1, n2a1;
    one = 1;
    Fr::add(onepb1, one, b[1]);
    Fr::mul(n2a1, n2, onepb1);
    G2::mul(hdr.gamma[1], s.g2, n2a1);

    for (size_t k = 2; k <= t + 1; ++k) {
        Fr n2bk;
        Fr::mul(n2bk, n2, b[k]);
        G2::mul(hdr.gamma[k], s.g2, n2bk);
    }

    const auto tp2 = Clock::now();
    if (timing) {
        timing->poly_ms = ms_since(tp0, tp1);
        timing->group_ms = ms_since(tp1, tp2);
    }
    return OfflineState{epoch, std::move(hdr), theta};
}

static Ciphertext online_enc(
    const OfflineState& st,
    const std::string& sensor_id,
    uint64_t seq,
    const std::vector<unsigned char>& payload,
    const std::vector<unsigned char>& aad)
{
    Ciphertext c;
    c.sensor_id = sensor_id;
    c.epoch = st.epoch;
    c.seq = seq;
    c.hdr = st.hdr;
    c.aad_app = aad;

    std::array<unsigned char, KEY_BYTES> kd{};
    require(RAND_bytes(kd.data(), kd.size()) == 1, "RAND_bytes kd");
    require(RAND_bytes(c.nonce.data(), c.nonce.size()) == 1, "RAND_bytes nonce");

    const auto ctx = encode_ctx(sensor_id, c.epoch, seq, c.hdr, c.nonce, aad);
    const auto mask = kdf128(st.theta, ctx);
    for (size_t i = 0; i < KEY_BYTES; ++i) c.wrapped_key[i] = kd[i] ^ mask[i];
    c.aead_ct = aes128gcm_encrypt(kd, c.nonce, payload, ctx);
    return c;
}

static bool decrypt(
    const Ciphertext& c,
    const Credential& user,
    std::vector<unsigned char>& payload_out)
{
    const size_t t = c.hdr.gamma.size() - 2;

    // Y_R = product A_k^{x_R^k}; additive notation => sum [x_R^k] A_k
    G2 Y;
    Y.clear();
    Fr xpow;
    xpow = 1;
    for (size_t k = 0; k <= t + 1; ++k) {
        G2 term;
        if (k == 0) {
            term = c.hdr.gamma[0];
        } else {
            Fr next;
            Fr::mul(next, xpow, user.x);
            xpow = next;
            G2::mul(term, c.hdr.gamma[k], xpow);
        }
        G2 tmp;
        G2::add(tmp, Y, term);
        Y = tmp;
    }

    GT KR;
    pairing(KR, user.sk, Y);

    G2 hkr = H2(KR);
    G2 neg_hkr, BR;
    G2::neg(neg_hkr, hkr);
    G2::add(BR, c.hdr.off4, neg_hkr);

    GT SR, thetaR;
    pairing(SR, c.hdr.off2, BR);
    GT::inv(thetaR, SR);

    const auto ctx = encode_ctx(c.sensor_id, c.epoch, c.seq, c.hdr, c.nonce, c.aad_app);
    const auto mask = kdf128(thetaR, ctx);
    std::array<unsigned char, KEY_BYTES> kd{};
    for (size_t i = 0; i < KEY_BYTES; ++i) kd[i] = c.wrapped_key[i] ^ mask[i];
    return aes128gcm_decrypt(kd, c.nonce, c.aead_ct, ctx, payload_out);
}

static Fr register_coord(const SetupState& s, const std::string& id,
                         std::set<std::string>& used, uint64_t& ctr)
{
    for (;;) {
        Fr x = derive_coordinate(s.kid, id, ctr);
        Fr rx;
        Fr::add(rx, s.r, x);
        const std::string repr = x.getStr(16);
        if (!x.isZero() && !rx.isZero() && !used.count(repr)) {
            used.insert(repr);
            return x;
        }
        ++ctr;
    }
}

static std::vector<size_t> parse_t_list(const std::string& s) {
    std::vector<size_t> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) out.push_back(static_cast<size_t>(std::stoul(item)));
    return out;
}

int main(int argc, char** argv) {
    size_t reps = 20;
    size_t warmup = 3;
    size_t payload_bytes = 1024;
    std::vector<size_t> tvals{10,25,50,100,200,400,800,1000};

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--reps" && i+1 < argc) reps = std::stoul(argv[++i]);
        else if (a == "--warmup" && i+1 < argc) warmup = std::stoul(argv[++i]);
        else if (a == "--payload" && i+1 < argc) payload_bytes = std::stoul(argv[++i]);
        else if (a == "--t" && i+1 < argc) tvals = parse_t_list(argv[++i]);
        else if (a == "--help") {
            std::cout << "Usage: lbed_bench [--reps N] [--warmup N] [--payload bytes] [--t 10,50,100]\n";
            return 0;
        }
    }

    initPairing(BLS12_381);
    // Practical Type-3 benchmark instantiation only.
    // mcl's pairing is e: G1 x G2 -> GT.
    verifyOrderG1(true);
    verifyOrderG2(true);
    const char* dst = "LBED_BENCH_BLS12381G2_XMD:SHA-256_SSWU_RO_V1";
    require(setDstG2(dst, std::strlen(dst)), "setDstG2 failed");

    std::vector<unsigned char> payload(payload_bytes, 0x42);
    std::vector<unsigned char> aad = {'L','B','E','D','-','A','A','D'};

    const auto setup_start = Clock::now();
    SetupState s = setup();
    const auto setup_end = Clock::now();

    std::set<std::string> used;
    uint64_t ctr = 0;
    Fr xs = register_coord(s, "sensor-001", used, ctr);
    auto sensor = keygen(s, xs);

    std::cout << "# LBED Type-3 benchmark harness\n";
    std::cout << "# curve=BLS12-381 library=mcl mode=single-threaded\n";
    std::cout << "# setup_ms=" << std::fixed << std::setprecision(6) << ms_since(setup_start, setup_end) << "\n";
    std::cout << "# columns: t,rep,offline_ms,poly_ms,group_ms,online_ms,decrypt_ms,correct\n";
    std::cout << "t,rep,offline_ms,poly_ms,group_ms,online_ms,decrypt_ms,correct\n";

    for (size_t t : tvals) {
        std::vector<Fr> xs_rec;
        std::vector<Credential> creds;
        xs_rec.reserve(t); creds.reserve(t);
        for (size_t i = 0; i < t; ++i) {
            uint64_t ctri = 0;
            auto x = register_coord(s, "user-" + std::to_string(t) + "-" + std::to_string(i), used, ctri);
            xs_rec.push_back(x);
            creds.push_back(keygen(s, x));
        }

        // correctness smoke test + warm-up
        for (size_t w = 0; w < warmup; ++w) {
            auto st = offline_enc(s, sensor, xs_rec, 1, nullptr);
            auto ct = online_enc(st, "sensor-001", w+1, payload, aad);
            std::vector<unsigned char> dec;
            require(decrypt(ct, creds[0], dec) && dec == payload, "authorized correctness failure");
        }

        // one nonrecipient negative test outside measured loop
        {
            uint64_t ctrn = 0;
            auto xn = register_coord(s, "nonrecipient-" + std::to_string(t), used, ctrn);
            auto non = keygen(s, xn);
            auto st = offline_enc(s, sensor, xs_rec, 2, nullptr);
            auto ct = online_enc(st, "sensor-001", 9999, payload, aad);
            std::vector<unsigned char> dec;
            require(!decrypt(ct, non, dec), "nonrecipient unexpectedly decrypted");
        }

        for (size_t rep = 0; rep < reps; ++rep) {
            OfflineTiming ot;
            auto a0 = Clock::now();
            auto st = offline_enc(s, sensor, xs_rec, 100 + rep, &ot);
            auto a1 = Clock::now();

            auto b0 = Clock::now();
            auto ct = online_enc(st, "sensor-001", rep + 1, payload, aad);
            auto b1 = Clock::now();

            std::vector<unsigned char> dec;
            auto c0 = Clock::now();
            bool ok = decrypt(ct, creds[0], dec);
            auto c1 = Clock::now();
            ok = ok && dec == payload;

            std::cout << t << "," << rep << ","
                      << ms_since(a0,a1) << ","
                      << ot.poly_ms << ","
                      << ot.group_ms << ","
                      << ms_since(b0,b1) << ","
                      << ms_since(c0,c1) << ","
                      << (ok ? 1 : 0) << "\n";
        }
    }
    return 0;
}
