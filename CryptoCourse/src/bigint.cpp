// bigint.cpp
#include "bigint.h"
#include <stdexcept>
#include <cstdlib>
#include <cstring>
#include <algorithm>

namespace NTL {

using std::vector;
using std::string;

// ---------------- 内部工具 ----------------
static int cmpMag(const vector<uint32_t>& a, const vector<uint32_t>& b) {
    if (a.size() != b.size()) return a.size() < b.size() ? -1 : 1;
    for (size_t i = a.size(); i-- > 0; ) {
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return 0;
}

static vector<uint32_t> addMag(const vector<uint32_t>& a, const vector<uint32_t>& b) {
    vector<uint32_t> r(std::max(a.size(), b.size()) + 1, 0);
    uint64_t carry = 0;
    size_t n = std::max(a.size(), b.size());
    for (size_t i = 0; i < n; i++) {
        uint64_t x = (uint64_t)(i < a.size() ? a[i] : 0) + (i < b.size() ? b[i] : 0) + carry;
        r[i] = (uint32_t)x;
        carry = x >> 32;
    }
    r[n] = (uint32_t)carry;
    while (r.size() > 1 && r.back() == 0) r.pop_back();
    return r;
}

// 假定 a >= b
static vector<uint32_t> subMag(const vector<uint32_t>& a, const vector<uint32_t>& b) {
    vector<uint32_t> r(a.size(), 0);
    int64_t borrow = 0;
    for (size_t i = 0; i < a.size(); i++) {
        int64_t x = (int64_t)a[i] - (i < b.size() ? (int64_t)b[i] : 0) - borrow;
        if (x < 0) { x += (1LL << 32); borrow = 1; }
        else borrow = 0;
        r[i] = (uint32_t)x;
    }
    while (r.size() > 1 && r.back() == 0) r.pop_back();
    return r;
}

static vector<uint32_t> mulMag(const vector<uint32_t>& a, const vector<uint32_t>& b) {
    if (a.empty() || b.empty()) return vector<uint32_t>(1, 0);
    vector<uint64_t> t(a.size() + b.size(), 0);
    for (size_t i = 0; i < a.size(); i++) {
        uint64_t carry = 0;
        for (size_t j = 0; j < b.size(); j++) {
            uint64_t prod = (uint64_t)a[i] * b[j] + t[i + j] + carry;
            t[i + j] = (uint32_t)prod;
            carry = prod >> 32;
        }
        t[i + b.size()] += carry;
    }
    vector<uint32_t> r(t.size(), 0);
    uint64_t carry = 0;
    for (size_t i = 0; i < t.size(); i++) {
        uint64_t cur = t[i] + carry;
        r[i] = (uint32_t)cur;
        carry = cur >> 32;
    }
    while (r.size() > 1 && r.back() == 0) r.pop_back();
    return r;
}

// Knuth 算法 D：u / v -> (q, r)。使用 unsigned __int128 避免比较溢出。
static void divmodMag(const vector<uint32_t>& uIn, const vector<uint32_t>& vIn,
                      vector<uint32_t>& qOut, vector<uint32_t>& rOut) {
    if (vIn.empty() || (vIn.size() == 1 && vIn[0] == 0)) throw std::runtime_error("division by zero");
    vector<uint32_t> u = uIn; while (!u.empty() && u.back() == 0) u.pop_back();
    vector<uint32_t> v = vIn; while (!v.empty() && v.back() == 0) v.pop_back();
    if (cmpMag(u, v) < 0) { qOut.assign(1, 0); rOut = u.empty() ? vector<uint32_t>(1, 0) : u; return; }

    size_t n = v.size();
    size_t m = u.size();

    // 归一化：将 v 的最高位置为 1
    uint32_t shift = 0;
    uint32_t vtop = v[n - 1];
    while (!(vtop & 0x80000000u)) { vtop <<= 1; shift++; }

    auto shiftLeft = [&](vector<uint32_t>& a) {
        if (shift == 0) return;
        uint32_t carry = 0;
        for (size_t i = 0; i < a.size(); i++) {
            uint32_t cur = a[i];
            a[i] = (cur << shift) | carry;
            carry = cur >> (32 - shift);
        }
        if (carry) a.push_back(carry);
    };

    vector<uint32_t> vn = v; shiftLeft(vn);
    vector<uint32_t> un(m + 1, 0);
    for (size_t i = 0; i < m; i++) un[i] = u[i];
    shiftLeft(un);

    n = vn.size();
    size_t m2 = un.size();
    qOut.assign(m2 - n + 1, 0);

    const unsigned __int128 B = (unsigned __int128)1 << 32; // 基 2^32

    for (size_t j = m2 - n; j-- > 0; ) {
        unsigned __int128 num = ((unsigned __int128)un[j + n] << 32) | un[j + n - 1];
        unsigned __int128 qhat = num / vn[n - 1];
        if (qhat >= B) qhat = B - 1;   // 估算商（Knuth 证明不会偏小，最多偏大 2）
        uint64_t qhat64 = (uint64_t)qhat;

        // 乘减：un[j..j+n] -= qhat * vn
        int64_t borrow = 0; uint64_t carry = 0;
        for (size_t i = 0; i < n; i++) {
            uint64_t p = qhat64 * (uint64_t)vn[i] + carry;
            int64_t sub = (int64_t)un[j + i] - (int64_t)(uint32_t)p - borrow;
            if (sub < 0) { sub += (1LL << 32); borrow = 1; }
            else borrow = 0;
            un[j + i] = (uint32_t)sub;
            carry = p >> 32;
        }
        int64_t toprem = (int64_t)un[j + n] - borrow - (int64_t)carry;
        un[j + n] = (uint32_t)toprem;
        qOut[j] = (uint32_t)qhat64;

        // 若借位为负（qhat 偏大），回退一个 vn，必要时再回退一次
        while (toprem < 0) {
            qhat64--;
            uint64_t c = 0;
            for (size_t i = 0; i < n; i++) {
                uint64_t sum = (uint64_t)un[j + i] + (uint64_t)vn[i] + c;
                un[j + i] = (uint32_t)sum;
                c = sum >> 32;
            }
            toprem = toprem + (int64_t)c;
            un[j + n] = (uint32_t)toprem;
            qOut[j] = (uint32_t)qhat64;
        }
    }

    vector<uint32_t> rn(un.begin(), un.begin() + n);
    if (shift) {
        uint32_t mask = (uint32_t)(1u << shift) - 1u;
        uint32_t carry = 0;
        for (size_t i = rn.size(); i-- > 0; ) {
            uint32_t cur = rn[i];
            rn[i] = (cur >> shift) | (carry << (32 - shift));
            carry = cur & mask;
        }
    }
    while (rn.size() > 1 && rn.back() == 0) rn.pop_back();
    rOut = rn.empty() ? vector<uint32_t>(1, 0) : rn;
    while (qOut.size() > 1 && qOut.back() == 0) qOut.pop_back();

    // 兜底修正（理论上不应触发）：保证 0 <= r < v
    while (cmpMag(rOut, vIn) >= 0) {
        rOut = subMag(rOut, vIn);
        vector<uint32_t> one(1, 1);
        qOut = addMag(qOut, one);
        if (rOut.empty()) { rOut.assign(1, 0); break; }
    }
}

// ---------------- ZZ 实现 ----------------
ZZ::ZZ() : sign_(0) { mag_.assign(1, 0); }

ZZ::ZZ(long a) { set(a); }

void ZZ::set(long v) {
    if (v == 0) { sign_ = 0; mag_.assign(1, 0); return; }
    sign_ = v < 0 ? -1 : 1;
    unsigned long long u = (unsigned long long)(v < 0 ? -(v + 1) : v);
    if (v < 0) u = (unsigned long long)(-(v + 1)) + 1u;
    mag_.clear();
    while (u) { mag_.push_back((uint32_t)(u & 0xffffffffu)); u >>= 32; }
}

ZZ::ZZ(const string& s) {
    sign_ = 0; mag_.assign(1, 0);
    if (s.empty()) return;
    size_t pos = 0; bool neg = false;
    if (s[0] == '+' || s[0] == '-') { neg = (s[0] == '-'); pos = 1; }
    if (s.compare(pos, 2, "0x") == 0 || s.compare(pos, 2, "0X") == 0) {
        string body = s.substr(pos + 2);
        if (body.empty()) return;
        ZZ base(1); ZZ cur(0);
        for (size_t i = body.size(); i-- > 0; ) {
            char c = body[i]; int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else throw std::runtime_error("bad hex in ZZ");
            cur = cur + ZZ(d) * base;
            base = base * ZZ(16);
        }
        *this = cur;
        if (neg && !IsZero()) sign_ = -1;
        return;
    }
    string body = s.substr(pos);
    if (body.empty()) return;
    ZZ base(1); ZZ cur(0);
    for (size_t i = body.size(); i-- > 0; ) {
        if (body[i] < '0' || body[i] > '9') throw std::runtime_error("bad decimal in ZZ");
        cur = cur + ZZ(body[i] - '0') * base;
        base = base * ZZ(10);
    }
    *this = cur;
    if (neg && !IsZero()) sign_ = -1;
}

void ZZ::trim() {
    while (mag_.size() > 1 && mag_.back() == 0) mag_.pop_back();
    if (mag_.size() == 1 && mag_[0] == 0) sign_ = 0;
}

bool ZZ::IsZero() const { return sign_ == 0; }
long ZZ::sign() const { return sign_; }

ZZ& ZZ::operator=(const ZZ& o) { mag_ = o.mag_; sign_ = o.sign_; return *this; }
ZZ& ZZ::operator+=(const ZZ& b) { *this = *this + b; return *this; }
ZZ& ZZ::operator-=(const ZZ& b) { *this = *this - b; return *this; }
ZZ& ZZ::operator*=(const ZZ& b) { *this = *this * b; return *this; }
ZZ& ZZ::operator<<=(long n) { *this = *this << n; return *this; }
ZZ& ZZ::operator>>=(long n) { *this = *this >> n; return *this; }

ZZ operator|(const ZZ& a, const ZZ& b) {
    ZZ r; r.sign_ = 1;
    size_t n = std::max(a.mag_.size(), b.mag_.size());
    r.mag_.assign(n, 0);
    for (size_t i = 0; i < n; i++) {
        uint32_t x = (i < a.mag_.size() ? a.mag_[i] : 0);
        uint32_t y = (i < b.mag_.size() ? b.mag_[i] : 0);
        r.mag_[i] = x | y;
    }
    r.trim();
    return r;
}

ZZ operator+(const ZZ& a, const ZZ& b) {
    if (a.sign_ == 0) return b;
    if (b.sign_ == 0) return a;
    ZZ r;
    if (a.sign_ == b.sign_) {
        r.mag_ = addMag(a.mag_, b.mag_);
        r.sign_ = a.sign_;
    } else {
        int c = cmpMag(a.mag_, b.mag_);
        if (c == 0) { r.mag_.assign(1, 0); r.sign_ = 0; return r; }
        if (c > 0) { r.mag_ = subMag(a.mag_, b.mag_); r.sign_ = a.sign_; }
        else { r.mag_ = subMag(b.mag_, a.mag_); r.sign_ = b.sign_; }
    }
    r.trim(); return r;
}
ZZ operator-(const ZZ& a) { ZZ r = a; if (r.sign_ != 0) r.sign_ = -r.sign_; return r; }
ZZ operator-(const ZZ& a, const ZZ& b) { return a + (-b); }

ZZ operator*(const ZZ& a, const ZZ& b) {
    if (a.sign_ == 0 || b.sign_ == 0) return ZZ();
    ZZ r;
    r.mag_ = mulMag(a.mag_, b.mag_);
    r.sign_ = (a.sign_ == b.sign_) ? 1 : -1;
    r.trim(); return r;
}

ZZ operator/(const ZZ& a, const ZZ& b) {
    vector<uint32_t> q, r;
    divmodMag(a.mag_, b.mag_, q, r);
    ZZ res;
    res.mag_ = q.empty() ? vector<uint32_t>(1, 0) : q;
    res.sign_ = (cmpMag(res.mag_, vector<uint32_t>(1, 0)) == 0) ? 0
                : ((a.sign_ == b.sign_) ? 1 : -1);
    res.trim(); return res;
}

ZZ operator%(const ZZ& a, const ZZ& b) {
    vector<uint32_t> q, r;
    divmodMag(a.mag_, b.mag_, q, r);
    ZZ res;
    res.mag_ = r.empty() ? vector<uint32_t>(1, 0) : r;
    res.sign_ = (cmpMag(res.mag_, vector<uint32_t>(1, 0)) == 0) ? 0 : a.sign_;
    res.trim(); return res;
}

ZZ operator<<(const ZZ& a, long n) {
    if (n == 0) return a;
    if (n < 0) return a >> (-n);
    ZZ r = a;
    long words = n / 32; long bits = n % 32;
    if (words) {
        vector<uint32_t> nm(r.mag_.size() + words, 0);
        for (size_t i = 0; i < r.mag_.size(); i++) nm[i + words] = r.mag_[i];
        r.mag_ = nm;
    }
    if (bits) {
        uint32_t carry = 0;
        for (size_t i = 0; i < r.mag_.size(); i++) {
            uint64_t cur = ((uint64_t)r.mag_[i] << bits) | carry;
            r.mag_[i] = (uint32_t)cur;
            carry = (uint32_t)(cur >> 32);
        }
        if (carry) r.mag_.push_back(carry);
    }
    r.trim(); return r;
}

ZZ operator>>(const ZZ& a, long n) {
    if (n == 0) return a;
    if (n < 0) return a << (-n);
    ZZ r = a;
    if (r.sign_ == 0) return r;
    long words = n / 32; long bits = n % 32;
    if (words >= (long)r.mag_.size()) return ZZ();
    if (words) r.mag_.erase(r.mag_.begin(), r.mag_.begin() + words);
    if (bits) {
        uint32_t mask = (uint32_t)(1u << bits) - 1u;
        uint32_t carry = 0;
        for (size_t i = r.mag_.size(); i-- > 0; ) {
            uint32_t cur = r.mag_[i];
            r.mag_[i] = (cur >> bits) | (carry << (32 - bits));
            carry = cur & mask;
        }
    }
    r.trim(); return r;
}

bool operator==(const ZZ& a, const ZZ& b) {
    if (a.sign_ != b.sign_) return false;
    return cmpMag(a.mag_, b.mag_) == 0;
}
bool operator!=(const ZZ& a, const ZZ& b) { return !(a == b); }
bool operator<(const ZZ& a, const ZZ& b) {
    if (a.sign_ != b.sign_) return a.sign_ < b.sign_;
    if (a.sign_ == 0) return false;
    int c = cmpMag(a.mag_, b.mag_);
    return a.sign_ > 0 ? c < 0 : c > 0;
}
bool operator>(const ZZ& a, const ZZ& b) { return b < a; }
bool operator<=(const ZZ& a, const ZZ& b) { return !(b < a); }
bool operator>=(const ZZ& a, const ZZ& b) { return !(a < b); }

long ZZ::NumBits() const {
    if (sign_ == 0) return 0;
    uint32_t top = mag_.back();
    long hb = 0;
    while (top) { top >>= 1; hb++; }
    return (long)(mag_.size() - 1) * 32 + hb;
}

long ZZ::NumBytes() const { return (NumBits() + 7) / 8; }

string ZZ::to_string() const {
    if (sign_ == 0) return "0";
    ZZ t = *this; t.sign_ = 1;
    string s; ZZ ten(10);
    while (!t.IsZero()) {
        ZZ rem = t % ten;
        long dig = rem.mag_.empty() ? 0 : (rem.mag_[0] % 10);
        s.push_back(char('0' + dig));
        t = t / ten;
    }
    if (sign_ < 0) s.push_back('-');
    std::reverse(s.begin(), s.end());
    return s;
}

string ZZ::to_hex() const {
    if (sign_ == 0) return "0";
    ZZ t = *this; t.sign_ = 1;
    string s; ZZ sixteen(16);
    while (!t.IsZero()) {
        ZZ rem = t % sixteen;
        long dig = rem.mag_.empty() ? 0 : (rem.mag_[0] % 16);
        s.push_back(dig < 10 ? char('0' + dig) : char('a' + dig - 10));
        t = t / sixteen;
    }
    if (sign_ < 0) s.push_back('-');
    std::reverse(s.begin(), s.end());
    return s;
}

std::ostream& operator<<(std::ostream& os, const ZZ& a) { os << a.to_string(); return os; }
std::istream& operator>>(std::istream& is, ZZ& a) { string s; is >> s; if (!s.empty()) a = ZZ(s); return is; }

ZZ ZZ::fromBytes(const string& bytes) {
    ZZ cur(0); ZZ b256(256);
    for (unsigned char c : bytes) cur = cur * b256 + ZZ((long)c);
    return cur;
}
string ZZ::toBytes() const {
    if (sign_ == 0) return string();
    ZZ t = *this; t.sign_ = 1;
    string s; ZZ b256(256);
    while (!t.IsZero()) {
        ZZ rem = t % b256;
        unsigned char c = (unsigned char)(rem.mag_.empty() ? 0 : (rem.mag_[0] & 0xff));
        s.push_back((char)c);
        t = t / b256;
    }
    std::reverse(s.begin(), s.end());
    return s;
}

// ---------------- 随机 / 数论 ----------------
static uint32_t rand32() {
    uint32_t x = 0;
    for (int i = 0; i < 4; i++) x = (x << 8) | (uint32_t)(std::rand() & 0xff);
    return x;
}

void RandomBits(ZZ& x, long n) {
    if (n <= 0) { x = ZZ(); return; }
    long words = (n + 31) / 32;
    vector<uint32_t> m(words, 0);
    for (long i = 0; i < words; i++) m[i] = rand32();
    long rem = words * 32 - n;
    if (rem > 0) {
        uint32_t mask = (rem >= 32) ? 0u : (~0u >> rem);
        m[words - 1] &= mask;
    }
    x.mag_ = m; x.sign_ = 1; x.trim();
}

ZZ RandomLen_ZZ(long n) {
    ZZ x; RandomBits(x, n);
    if (x.IsZero()) x = ZZ(1);
    return x;
}

ZZ MulMod(const ZZ& a, const ZZ& b, const ZZ& m) {
    ZZ r = (a.sign_ < 0 ? -a : a) * (b.sign_ < 0 ? -b : b);
    r = r % m;
    if (r.sign_ < 0) r = r + m;
    return r;
}

ZZ PowerMod(const ZZ& a, const ZZ& e, const ZZ& m) {
    if (m == ZZ(1)) return ZZ(0);
    ZZ base = a % m; if (base.sign_ < 0) base = base + m;
    ZZ result(1); ZZ exp = e;
    if (exp.sign_ < 0) throw std::runtime_error("PowerMod: negative exponent");
    while (!exp.IsZero()) {
        if ((exp.mag_[0] & 1u)) result = MulMod(result, base, m);
        exp = exp >> 1;
        base = MulMod(base, base, m);
    }
    return result;
}

ZZ GCD(const ZZ& a, const ZZ& b) {
    ZZ x; x.mag_ = a.mag_; x.sign_ = 1;
    ZZ y; y.mag_ = b.mag_; y.sign_ = 1;
    while (!y.IsZero()) { ZZ t = x % y; x = y; y = t; }
    return x;
}

ZZ InvMod(const ZZ& a, const ZZ& m) {
    if (m <= ZZ(1)) throw std::runtime_error("InvMod: modulus <= 1");
    ZZ aa = a % m; if (aa.sign_ < 0) aa = aa + m;
    ZZ r = m, newr = aa;
    ZZ t(0), newt(1);
    while (!newr.IsZero()) {
        ZZ q = r / newr;
        ZZ tmp = newt; newt = t - q * newt; t = tmp;
        tmp = newr; newr = r - q * newr; r = tmp;
    }
    if (r > ZZ(1)) throw std::runtime_error("InvMod: not invertible");
    if (t.sign_ < 0) t = t + m;
    return t;
}

bool ProbPrime(const ZZ& n, long k) {
    if (n <= ZZ(1)) return false;
    if (n == ZZ(2) || n == ZZ(3)) return true;
    if ((n.mag_[0] & 1u) == 0) return false;
    ZZ nm1 = n - ZZ(1);
    ZZ d = nm1; long s = 0;
    while ((d.mag_[0] & 1u) == 0) { d = d >> 1; s++; }
    for (long i = 0; i < k; i++) {
        ZZ a = RandomLen_ZZ(n.NumBits());
        a = a % nm1;
        if (a <= ZZ(1)) a = a + ZZ(2);
        ZZ x = PowerMod(a, d, n);
        if (x == ZZ(1) || x == nm1) continue;
        bool composite = true;
        for (long r = 1; r < s; r++) {
            x = MulMod(x, x, n);
            if (x == nm1) { composite = false; break; }
        }
        if (composite) return false;
    }
    return true;
}

void GenPrime(ZZ& x, long n, long k) {
    if (n < 2) { x = ZZ(2); return; }
    for (;;) {
        RandomBits(x, n);
        x = x | ZZ(1);
        if (x.NumBits() < n) x = x | (ZZ(1) << (n - 1));
        if (ProbPrime(x, k)) return;
    }
}

ZZ RandomPrime(long n, long k) { ZZ x; GenPrime(x, n, k); return x; }

} // namespace NTL
