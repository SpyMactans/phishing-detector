#include <iostream>
#include <string>
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
typedef SOCKET SocketHandle;
#define INVALID_SOCK INVALID_SOCKET
#define CLOSE_SOCKET closesocket
#else
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int SocketHandle;
#define INVALID_SOCK (-1)
#define CLOSE_SOCKET close
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

using namespace std;

struct UrlComponents {
    string original;
    string scheme;
    string host;
    string port;
    string path;
    string query;
    bool hasAt = false;
};

struct Finding {
    string description;
    int weight = 0;
};

struct AnalysisResult {
    UrlComponents url;
    Finding findings[30];
    int findingCount = 0;
    int score = 0;

    void add(const string& desc, int weight) {
        findings[findingCount].description = desc;
        findings[findingCount].weight = weight;
        findingCount++;
        score += weight;
    }
};

char toLowerChar(char c) {
    if (c >= 'A' && c <= 'Z') return c + 32;
    return c;
}

string toLower(const string& s) {
    string out = s;
    for (size_t i = 0; i < out.size(); i++) {
        out[i] = toLowerChar(out[i]);
    }
    return out;
}

int countChar(const string& s, char c) {
    int total = 0;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == c) total++;
    }
    return total;
}

int minInt(int a, int b) {
    return (a < b) ? a : b;
}

int absInt(int a) {
    return (a < 0) ? -a : a;
}

bool endsWith(const string& s, const string& suffix) {
    if (suffix.size() > s.size()) return false;
    return s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool isAllDigits(const string& s) {
    if (s.empty()) return false;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] < '0' || s[i] > '9') return false;
    }
    return true;
}

bool isIPv4(const string& host) {
    string parts[4];
    int partCount = 0;
    string current = "";
    for (size_t i = 0; i <= host.size(); i++) {
        if (i == host.size() || host[i] == '.') {
            if (partCount >= 4) return false;
            parts[partCount] = current;
            partCount++;
            current = "";
        } else {
            current += host[i];
        }
    }
    if (partCount != 4) return false;
    for (int i = 0; i < 4; i++) {
        if (!isAllDigits(parts[i])) return false;
        if (parts[i].size() > 3) return false;
        int value = 0;
        for (size_t j = 0; j < parts[i].size(); j++) {
            value = value * 10 + (parts[i][j] - '0');
        }
        if (value > 255) return false;
    }
    return true;
}

int levenshtein(const string& a, const string& b) {
    if (a.size() > 500 || b.size() > 500) return 9999;
    int n = (int)a.size();
    int m = (int)b.size();
    static int dp[501][501];
    for (int i = 0; i <= n; i++) dp[i][0] = i;
    for (int j = 0; j <= m; j++) dp[0][j] = j;
    for (int i = 1; i <= n; i++) {
        for (int j = 1; j <= m; j++) {
            int cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
            int deletion = dp[i - 1][j] + 1;
            int insertion = dp[i][j - 1] + 1;
            int substitution = dp[i - 1][j - 1] + cost;
            dp[i][j] = minInt(minInt(deletion, insertion), substitution);
        }
    }
    return dp[n][m];
}

UrlComponents parseUrl(const string& rawUrl) {
    UrlComponents u;
    u.original = rawUrl;
    string url = rawUrl;

    size_t schemePos = url.find("://");
    if (schemePos != string::npos) {
        u.scheme = toLower(url.substr(0, schemePos));
        url = url.substr(schemePos + 3);
    }

    size_t authorityEnd = url.find_first_of("/?#");
    string authority = (authorityEnd == string::npos) ? url : url.substr(0, authorityEnd);
    size_t lastAt = authority.find_last_of('@');
    if (lastAt != string::npos) {
        u.hasAt = true;
        url = url.substr(lastAt + 1);
    }

    string hostPort = url;
    size_t pathPos = url.find_first_of("/?#");
    if (pathPos != string::npos) {
        hostPort = url.substr(0, pathPos);
        string rest = url.substr(pathPos);
        size_t queryPos = rest.find('?');
        if (queryPos != string::npos) {
            u.path = rest.substr(0, queryPos);
            u.query = rest.substr(queryPos + 1);
        } else {
            u.path = rest;
        }
    }

    size_t colonPos = hostPort.find(':');
    if (colonPos != string::npos) {
        u.host = toLower(hostPort.substr(0, colonPos));
        u.port = hostPort.substr(colonPos + 1);
    } else {
        u.host = toLower(hostPort);
    }

    return u;
}

const int KEYWORD_COUNT = 19;
string suspiciousKeywords[KEYWORD_COUNT] = {
    "login", "signin", "verify", "account", "secure", "update", "confirm",
    "banking", "password", "billing", "webscr", "suspend", "unlock",
    "invoice", "wallet", "recover", "support", "helpdesk", "security-alert"
};

const int SHORTENER_COUNT = 11;
string urlShorteners[SHORTENER_COUNT] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly"
};

const int TLD_COUNT = 14;
string suspiciousTlds[TLD_COUNT] = {
    ".zip", ".mov", ".xyz", ".top", ".click", ".work", ".gq", ".tk",
    ".ml", ".cf", ".loan", ".men", ".review", ".country"
};

const int POPULAR_COUNT = 15;
string popularDomains[POPULAR_COUNT] = {
    "google.com", "facebook.com", "apple.com", "microsoft.com",
    "amazon.com", "paypal.com", "netflix.com", "instagram.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "irs.gov",
    "dropbox.com", "linkedin.com", "github.com"
};

AnalysisResult analyzeUrl(const string& rawUrl) {
    AnalysisResult result;
    result.url = parseUrl(rawUrl);
    UrlComponents u = result.url;

    if (rawUrl.size() > 90) {
        result.add("URL is unusually long (" + to_string(rawUrl.size()) +
            " characters) - length is often used to bury the real domain.", 10);
    }

    if (u.scheme.empty()) {
        result.add("No scheme (http/https) was specified.", 5);
    } else if (u.scheme != "https") {
        result.add("Does not use HTTPS (scheme: " + u.scheme + ").", 10);
    }

    if (isIPv4(u.host)) {
        result.add("Host is a raw IP address rather than a domain name.", 25);
    }

    if (u.hasAt) {
        result.add("URL contains '@' - browsers ignore everything before it, a classic way to disguise the real destination behind a trusted-looking prefix.", 25);
    }

    int dotCount = countChar(u.host, '.');
    if (dotCount >= 4) {
        result.add("Host has an unusually high number of subdomains (" + to_string(dotCount) + " dots).", 15);
    } else if (dotCount == 3) {
        result.add("Host has several subdomains, which can help bury the real domain.", 8);
    }

    int hyphenCount = countChar(u.host, '-');
    if (hyphenCount >= 2) {
        result.add("Host contains multiple hyphens (" + to_string(hyphenCount) + "), a pattern common in fake brand domains.", 12);
    } else if (hyphenCount == 1) {
        result.add("Host contains a hyphen, sometimes used to imitate a real brand domain.", 5);
    }

    for (int i = 0; i < SHORTENER_COUNT; i++) {
        if (u.host == urlShorteners[i]) {
            result.add("Host is a known URL shortener (" + urlShorteners[i] + "), which can hide the true destination.", 15);
            break;
        }
    }

    for (int i = 0; i < TLD_COUNT; i++) {
        if (endsWith(u.host, suspiciousTlds[i])) {
            result.add("Domain uses a TLD (" + suspiciousTlds[i] + ") that is frequently abused in phishing.", 12);
            break;
        }
    }

    string haystack = toLower(u.host + u.path + u.query);
    string matchedKeywords = "";
    int keywordHits = 0;
    for (int i = 0; i < KEYWORD_COUNT; i++) {
        if (haystack.find(suspiciousKeywords[i]) != string::npos) {
            if (keywordHits > 0) matchedKeywords += ", ";
            matchedKeywords += suspiciousKeywords[i];
            keywordHits++;
        }
    }
    if (keywordHits > 0) {
        string message = "Contains " + to_string(keywordHits) + " credential/urgency keyword(s) (" + matchedKeywords + ") commonly used in phishing lures.";
        result.add(message, minInt(20, keywordHits * 6));
    }

    if (u.path.find("//") != string::npos) {
        result.add("Path contains '//' after the domain, sometimes used to redirect elsewhere.", 8);
    }

    if (!u.port.empty() && u.port != "80" && u.port != "443") {
        result.add("URL specifies a non-standard port (" + u.port + ").", 8);
    }

    int percentCount = countChar(rawUrl, '%');
    if (percentCount >= 3) {
        result.add("URL contains heavy percent-encoding (" + to_string(percentCount) + " '%' characters), which can be used to obscure content.", 10);
    }

    string bareHost = u.host;
    if (bareHost.substr(0, 4) == "www.") bareHost = bareHost.substr(4);

    for (int i = 0; i < POPULAR_COUNT; i++) {
        string popular = popularDomains[i];
        if (bareHost == popular) continue;

        bool isLegitSubdomain = false;
        if (bareHost.size() > popular.size() && endsWith(bareHost, popular)) {
            if (bareHost[bareHost.size() - popular.size() - 1] == '.') {
                isLegitSubdomain = true;
            }
        }
        if (isLegitSubdomain) continue;

        int distance = levenshtein(bareHost, popular);
        int lengthDiff = absInt((int)bareHost.size() - (int)popular.size());

        if (distance > 0 && distance <= 2 && lengthDiff <= 3) {
            result.add("Host '" + u.host + "' is suspiciously similar to the popular domain '" + popular + "' (edit distance " + to_string(distance) + ") - possible typosquatting.", 30);
            break;
        }
    }

    if (u.host.empty()) {
        result.add("Could not identify a valid host in this URL.", 20);
    }

    return result;
}

string classify(int score) {
    if (score >= 50) return "LIKELY PHISHING";
    if (score >= 20) return "SUSPICIOUS";
    return "LIKELY SAFE";
}

void printResult(const AnalysisResult& result) {
    cout << "\n============================================================\n";
    cout << "URL:        " << result.url.original << "\n";
    cout << "Host:       " << (result.url.host.empty() ? "(none)" : result.url.host) << "\n";
    cout << "Risk score: " << result.score << "\n";
    cout << "Verdict:    " << classify(result.score) << "\n";

    if (result.findingCount == 0) {
        cout << "No suspicious patterns detected.\n";
    } else {
        cout << "Findings:\n";
        for (int i = 0; i < result.findingCount; i++) {
            cout << "  - [+";
            if (result.findings[i].weight < 10) cout << " ";
            cout << result.findings[i].weight << "] " << result.findings[i].description << "\n";
        }
    }
    cout << "============================================================\n";
}

void printBanner() {
    cout << "Phishing URL Detector (offline heuristics)\n";
    cout << "Type a URL to analyze it, or 'quit' to exit.\n";
    cout << "Note: local heuristics only, not a live blocklist - treat results\n";
    cout << "as a helpful signal rather than a final verdict.\n";
}

const char* ML_HOST = "127.0.0.1";
const int ML_PORT = 5050;
const int ML_TIMEOUT_SECONDS = 5;

struct MlResult {
    bool available = false;
    string error;
    string prediction;
    string band;
    double confidence = 0;
    double phishingProbability = 0;
    string signals[5];
    int signalCount = 0;
};

string jsonEscape(const string& s) {
    const char* hex = "0123456789abcdef";
    string out;
    for (size_t i = 0; i < s.size(); i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c < 0x20) {
            out += "\\u00";
            out += hex[c >> 4];
            out += hex[c & 15];
        } else out += (char)c;
    }
    return out;
}

size_t jsonValueStart(const string& json, const string& key) {
    string needle = "\"" + key + "\"";
    size_t k = json.find(needle);
    if (k == string::npos) return string::npos;
    size_t colon = json.find(':', k + needle.size());
    if (colon == string::npos) return string::npos;
    size_t pos = colon + 1;
    while (pos < json.size() && json[pos] == ' ') pos++;
    return pos;
}

string jsonString(const string& json, const string& key) {
    size_t pos = jsonValueStart(json, key);
    if (pos == string::npos || pos >= json.size() || json[pos] != '"') return "";
    size_t end = json.find('"', pos + 1);
    if (end == string::npos) return "";
    return json.substr(pos + 1, end - pos - 1);
}

double jsonNumber(const string& json, const string& key, double fallback) {
    size_t pos = jsonValueStart(json, key);
    if (pos == string::npos) return fallback;
    try {
        return stod(json.substr(pos));
    } catch (...) {
        return fallback;
    }
}

int jsonStringArray(const string& json, const string& key, string* out, int maxItems) {
    size_t pos = jsonValueStart(json, key);
    if (pos == string::npos || pos >= json.size() || json[pos] != '[') return 0;
    size_t close = json.find(']', pos);
    if (close == string::npos) return 0;
    int count = 0;
    pos++;
    while (count < maxItems) {
        size_t q1 = json.find('"', pos);
        if (q1 == string::npos || q1 > close) break;
        size_t q2 = json.find('"', q1 + 1);
        if (q2 == string::npos || q2 > close) break;
        out[count++] = json.substr(q1 + 1, q2 - q1 - 1);
        pos = q2 + 1;
    }
    return count;
}

bool sendAll(SocketHandle sock, const string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        int n = (int)send(sock, data.c_str() + sent, (int)(data.size() - sent), MSG_NOSIGNAL);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

void setSocketTimeouts(SocketHandle sock, int seconds) {
#ifdef _WIN32
    DWORD ms = (DWORD)(seconds * 1000);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&ms, sizeof(ms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&ms, sizeof(ms));
#else
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

bool exchangeWithService(SocketHandle sock, const string& request, string& response, string& error) {
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)ML_PORT);
    inet_pton(AF_INET, ML_HOST, &addr.sin_addr);

    setSocketTimeouts(sock, ML_TIMEOUT_SECONDS);
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        error = "could not connect to " + string(ML_HOST) + ":" + to_string(ML_PORT) + " - is server.py running?";
        return false;
    }
    if (!sendAll(sock, request)) {
        error = "could not send the request";
        return false;
    }
    char buffer[4096];
    while (true) {
        int n = (int)recv(sock, buffer, sizeof(buffer), 0);
        if (n < 0) {
            error = "timed out waiting for the ML service";
            return false;
        }
        if (n == 0) break;
        response.append(buffer, (size_t)n);
        if (response.size() > 65536) break;
    }
    return true;
}

bool httpPostJson(const string& path, const string& body, string& responseBody, string& error) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        error = "WSAStartup failed";
        return false;
    }
#endif
    SocketHandle sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCK) {
        error = "could not create a socket";
        return false;
    }

    string request = "POST " + path + " HTTP/1.0\r\n"
        "Host: " + string(ML_HOST) + ":" + to_string(ML_PORT) + "\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + to_string(body.size()) + "\r\n"
        "\r\n" + body;

    string response;
    bool ok = exchangeWithService(sock, request, response, error);
    CLOSE_SOCKET(sock);
    if (!ok) return false;

    size_t headerEnd = response.find("\r\n\r\n");
    if (headerEnd == string::npos) {
        error = "malformed reply from the ML service";
        return false;
    }
    if (response.compare(0, 12, "HTTP/1.0 200") != 0 && response.compare(0, 12, "HTTP/1.1 200") != 0) {
        error = "ML service replied: " + response.substr(0, response.find("\r\n"));
        return false;
    }
    responseBody = response.substr(headerEnd + 4);
    return true;
}

MlResult askMlService(const string& url) {
    MlResult r;
    string body = "{\"url\": \"" + jsonEscape(url) + "\"}";
    string reply;
    if (!httpPostJson("/predict", body, reply, r.error)) return r;

    r.prediction = jsonString(reply, "prediction");
    r.band = jsonString(reply, "band");
    r.confidence = jsonNumber(reply, "probability", -1);
    r.phishingProbability = jsonNumber(reply, "phishing_probability", -1);
    if (r.prediction.empty() || r.band.empty() || r.confidence < 0) {
        r.error = "unexpected reply from the ML service";
        return r;
    }
    r.signalCount = jsonStringArray(reply, "top_signals", r.signals, 3);
    r.available = true;
    return r;
}

int heuristicLevel(int score) {
    if (score >= 50) return 2;
    if (score >= 20) return 1;
    return 0;
}

int mlLevel(const string& band) {
    if (band == "phish") return 2;
    if (band == "unsure") return 1;
    return 0;
}

const char* RISK_TABLE[3][3] = {
    {"LOW",    "MEDIUM", "MEDIUM"},
    {"LOW",    "MEDIUM", "HIGH"},
    {"MEDIUM", "HIGH",   "HIGH"}
};

const char* RISK_BASIS[3][3] = {
    {"Heuristics and the AI model both see little risk.",
     "No heuristic red flags, but the AI model is not confident either way.",
     "The AI model sees risk that the rules did not catch - review manually."},
    {"The AI model clears the moderate heuristic signals.",
     "Heuristic signals are moderate and the AI model is not confident.",
     "Heuristics and the AI model both lean towards phishing."},
    {"Strong heuristic signals, but the AI model disagrees - review manually.",
     "Strong heuristic signals and the AI model does not contradict them.",
     "Heuristics and the AI model both indicate phishing."}
};

string toUpper(const string& s) {
    string out = s;
    for (size_t i = 0; i < out.size(); i++) {
        if (out[i] >= 'a' && out[i] <= 'z') out[i] = out[i] - 32;
    }
    return out;
}

void printHybridResult(const AnalysisResult& result, const MlResult& ml) {
    int h = heuristicLevel(result.score);

    cout << "\n============================================================\n";
    cout << "URL:        " << result.url.original << "\n\n";
    cout << "Heuristic Score:   " << result.score << "\n";
    cout << "Heuristic Verdict: " << classify(result.score) << "\n\n";

    if (ml.available) {
        int percent = (int)(ml.confidence * 100 + 0.5);
        if (percent > 99) percent = 99;
        int m = mlLevel(ml.band);
        cout << "AI Prediction: " << toUpper(ml.prediction) << "\n";
        cout << "AI Confidence: " << percent << "%\n\n";
        cout << "Final Risk: " << RISK_TABLE[h][m] << "\n";
        cout << "Basis: " << RISK_BASIS[h][m] << "\n\n";
    } else {
        const char* heuristicOnly[3] = {"LOW", "MEDIUM", "HIGH"};
        cout << "AI Prediction: UNAVAILABLE (" << ml.error << ")\n\n";
        cout << "Final Risk: " << heuristicOnly[h] << " (heuristics only)\n\n";
    }

    if (result.findingCount == 0) {
        cout << "Findings:\n  - No suspicious patterns detected by the heuristics.\n";
    } else {
        cout << "Findings:\n";
        for (int i = 0; i < result.findingCount; i++) {
            cout << "  - [+";
            if (result.findings[i].weight < 10) cout << " ";
            cout << result.findings[i].weight << "] " << result.findings[i].description << "\n";
        }
    }

    if (ml.available && ml.signalCount > 0) {
        cout << "\nAI model signals that raised the phishing score:\n";
        for (int i = 0; i < ml.signalCount; i++) {
            cout << "  - " << ml.signals[i] << "\n";
        }
    }

    cout << "\nThis is a risk assessment, not a verdict. Verify before acting on it.\n";
    cout << "============================================================\n";
}

void analyzeAndPrint(const string& url, bool useMl) {
    AnalysisResult heuristic = analyzeUrl(url);
    if (!useMl) {
        printResult(heuristic);
        return;
    }
    printHybridResult(heuristic, askMlService(url));
}

int main(int argc, char* argv[]) {
    bool useMl = true;
    bool haveUrls = false;
    for (int i = 1; i < argc; i++) {
        if (string(argv[i]) == "--no-ml") useMl = false;
        else haveUrls = true;
    }

    if (haveUrls) {
        for (int i = 1; i < argc; i++) {
            if (string(argv[i]) == "--no-ml") continue;
            analyzeAndPrint(argv[i], useMl);
        }
        return 0;
    }

    printBanner();
    if (useMl) cout << "AI service: " << ML_HOST << ":" << ML_PORT << " (start it with: python server.py)\n";
    string line;
    while (true) {
        cout << "\n> ";
        if (!getline(cin, line)) break;
        if (line.empty()) continue;
        string lower = toLower(line);
        if (lower == "quit" || lower == "exit") break;
        analyzeAndPrint(line, useMl);
    }
    cout << "Goodbye.\n";
    return 0;
}
