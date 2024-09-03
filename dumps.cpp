#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <map>
#include <list>
#include <utility>
#include <iterator>

using namespace std;

struct Record {
    uint32_t freq;
    uint32_t group;
    uint32_t cc;
    vector<uint8_t> key;
};

struct Stat {
    Record rec;
    int cnt;
    int cnt_suc;
};

bool record_is_equal(const Record &a, const Record &b)
{
    return a.freq == b.freq && a.group == b.group && a.cc == b.cc && a.key == b.key;
}

void compute_tabular_method_tables_reverse(uint32_t* pTbl, uint32_t kNumTables)
{
    uint32_t i = 0;
    uint32_t PP = 0x04C11DB7;

    // initialize tbl0, the first 256 elements of pTbl,
    // using naive CRC to compute pTbl[i] = CRC(i)
    for (; i < 256; ++i) {
        uint32_t R = i << 24;
        for (int j = 0; j < 8; ++j)
            R = R & (1L<<31) ? (R << 1) ^ PP : R << 1;
        pTbl[i] = R;
    }

    // initialize remaining tables by taking the previous
    // table's entry for i and churning through 8 more zero bits
    for (; i < kNumTables * 256; ++i) {
        const uint32_t R = pTbl[i - 256];
        pTbl[i] = (R << 8) ^ pTbl[(uint8_t)(R>>24)];
    }
}

vector<uint8_t> trans(const string str)
{
    vector<uint8_t> res(str.length()/2);
    char tmp[3] = {0, 0, 0};
    for (int i=0;i<str.length()/2;i++) {
        tmp[0] = str[2*i];
        tmp[1] = str[2*i+1];
        res[i] = strtol(tmp, NULL, 16) & 0xff;
    }
    return res;
}

uint32_t g_tbl_R[256*12];

static uint32_t crc32_12_bytes(const uint8_t *M)
{
    uint32_t R = 0;
    R ^= M[0]|(M[1]<<8)|(M[2]<<16)|(M[3]<<24);
    R = g_tbl_R[ 0 * 256 + M[11]] ^
    g_tbl_R[ 1 * 256 + M[10]] ^
    g_tbl_R[ 2 * 256 + M[9]] ^
    g_tbl_R[ 3 * 256 + M[8]] ^
    g_tbl_R[ 4 * 256 + M[7]] ^
    g_tbl_R[ 5 * 256 + M[6]] ^
    g_tbl_R[ 6 * 256 + M[5]] ^
    g_tbl_R[ 7 * 256 + M[4]] ^
    g_tbl_R[ 8 * 256 + M[3]] ^
    g_tbl_R[ 9 * 256 + M[2]] ^
    g_tbl_R[10 * 256 + M[1]] ^
    g_tbl_R[11 * 256 + M[0]];
    return R;
}

uint8_t md680_alg1_tbl[256];

static void md680_alg1_init(uint8_t *in, uint8_t len)
{
    for (int i=0;i<256;i++)
        md680_alg1_tbl[i] = i;
    
    uint8_t k8 = 0;
    for (int i=0;i<256;i++) {
        k8 = (md680_alg1_tbl[i] + k8 +in[i%len]) & 0xff;
        uint8_t t9 = md680_alg1_tbl[i];
        md680_alg1_tbl[i] = md680_alg1_tbl[k8];
        md680_alg1_tbl[k8] = t9;
    }
}


static void md680_make_key(vector<uint8_t> &key, vector<uint8_t> &iv)
{
    uint8_t md680_kiv[16];
    
    for (int i=0;i<6;i++)
        md680_kiv[2*i+1] = iv[i];
    
    
    for (int i=0;i<6;i++)
        md680_kiv[2*i+0] = key[i];
    
    uint32_t crc = crc32_12_bytes(md680_kiv);
    //        uint32_t crc = crc32_12_bytes_reverse(md680_kiv);
    md680_kiv[12] = crc & 0xff;
    md680_kiv[13] = (crc >> 8) & 0xff;
    md680_kiv[14] = (crc >> 16) & 0xff;
    md680_kiv[15] = (crc >> 24) & 0xff;
    
    md680_alg1_init(md680_kiv, sizeof(md680_kiv));
}

static void md680_decrypt_alg1(uint8_t *buf, uint8_t len)
{
        uint8_t *tbl;
        uint8_t j = 0;
        uint8_t k = 0;

        tbl = md680_alg1_tbl;
        for (int i=0;i<len;i++) {
                j += 1;
                k = k + tbl[j];
                uint8_t a = tbl[j];
                tbl[j] = tbl[k];
                tbl[k] = a;
                uint8_t b = (tbl[k] + tbl[j]) & 0xff;
                buf[i] ^= tbl[b];
        }
}

uint32_t target = 0xcc8cc000;


int main(int argc, char **argv) {
    int c;
    
    int print_dumps = false;
    
    FILE * records_file;
    FILE * output_file;
    FILE * best_dumps_file;
    
    fstream records_in;
    fstream dump_in;
    fstream keys_in;
    
    bool output_dumps = false;
    bool output_records = false;
    bool output_best_dumps = false;
    
    bool keys_in_exist = false;
    bool dumps_in_exist = false;
    
    int error = 0;
    int freq = -1;
    
    while ((c = getopt(argc, argv, "v:hk:d:K:o:e:f:b:")) != -1) {
        switch (c) {
            case 'v':
                print_dumps = stoi(optarg);
                break;
            case 'k':
                keys_in = fstream(optarg, keys_in.in);
                if (fopen(optarg, "r") != NULL)
                    keys_in_exist = true;
                else
                    printf("file %s doesn't exist\n", optarg);
                break;
            case 'd':
                dump_in = fstream(optarg, dump_in.in);
                if (fopen(optarg, "r") != NULL)
                    dumps_in_exist = true;
                else
                    printf("file %s doesn't exist\n", optarg);
                break;
            case 'K':
                records_file = fopen(optarg, "a");
                records_in = fstream(optarg, records_in.in);
                output_records = true;
                break;
            case 'o':
                output_file = fopen(optarg, "a");
                output_dumps = true;
                break;
            case 'e':
                error = stoi(optarg);
                break;
            case 'f':
                freq = stoi(optarg);
                break;
            case 'b':
                best_dumps_file = fopen(optarg, "a");
                output_best_dumps = true;
                break;
            case 'h':
                printf("Usage: dumps -d dumps_in -o dumps_out -k dictionary -K keys_out -v verbouse -e error -f frequency -b best_dumps_out\n");
                return 0;
                break;
            default:
                break;
        }
    }
    
    if (!keys_in_exist || !dumps_in_exist) {
        printf("Usage: dumps -d dumps_in -o dumps_out -k dictionary -K keys_out -v verbouse -e error -f frequency -b best_dumps_out\n");
        return 0;
    }
    
    vector<Record> records;
    string line;
    
    if (output_records) {
        while (getline(records_in, line)) {
            if (line.empty()) {
                continue;
            }
            
            Record rec;
            
            int found = line.find_first_of(" ");
            rec.freq = stoi(line.substr(0, found));
            
            if (line.substr(found+1, line.find_first_of(" ",found+1)-found-1) != "44")
                continue;
            
            found = line.find_first_of(" ",found+1);
            
            found = line.find_first_of(" ",found+1);
            
            rec.group = stoi(line.substr(found+1, line.find_first_of(" ",found+1)-found-1));
            found = line.find_first_of(" ",found+1);
            
            rec.cc = stoi(line.substr(found+1, line.find_first_of(" ",found+1)-found-1));
            found = line.find_first_of(" ",found+1);
            
            rec.key = trans(line.substr(found+1));
            
            if (freq == -1 || freq == rec.freq)
                records.push_back(rec);
        }
    }
    
    compute_tabular_method_tables_reverse(g_tbl_R, 12);
    vector<vector<uint8_t> > keys;
    
    
    while (getline(keys_in, line)) {
        keys.push_back(trans(line));
    }
    
    
    vector<Stat> stats;
    
    map<pair<uint32_t, vector<uint8_t>>, list<vector<uint8_t>>> dumps_by_freq_and_iv;
    
    int cnt = 0;
    
    while (getline(dump_in, line)) {
        cnt++;
        if (line.empty()) {
            break;
        }
        
        Record rec;
        vector<uint8_t> iv;
    
        try {
            unsigned long found = line.find_first_of(" ");
            rec.freq = stoi(line.substr(0, found));
            
            iv = trans(line.substr(found+1, line.find_first_of(" ",found+1)-found-1));
            found = line.find_first_of(" ",found+1);
            
            rec.group = stoi(line.substr(found+1, line.find_first_of(" ",found+1)-found-1));
            found = line.find_first_of(" ",found+1);
            
            rec.cc = stoi(line.substr(found));
        } catch(exception) {
            cout<<"error in line "<<cnt<<" :"+line+"\n";
            return 0;
        }
            
        getline(dump_in, line);
        ++cnt;
        uint8_t dump[27];
        vector<uint8_t> tmp = trans(line);
        for (int i=0;i<27;++i)
            dump[i] = tmp[i];
        
        if (freq != -1 and freq != rec.freq)
            continue;
        
        if (output_best_dumps) {
            dumps_by_freq_and_iv[make_pair(rec.freq, iv)].push_back(tmp);
        }
        
        int type;
        
        if ((dump[5] & 0x88) == 0x08 && (dump[6] & 0x88) == 0x80 &&
            (dump[7] & 0x88) == 0x08 && (dump[8] & 0x88) == 0x80 &&
            (dump[15] & 0x88) == 0x80 &&
            (dump[16] & 0x88) == 0x08 && (dump[17] & 0x88) == 0x80 &&
            (dump[24] & 0x88) == 0x80 &&
            (dump[25] & 0x88) == 0x08 && (dump[26] & 0x88) == 0x80) {
            target = 0xc888c400;
//            printf("good1\n");
            type = 1;
        }

        if ((dump[5] & 0x88) == 0x80 && (dump[6] & 0x88) == 0x80 &&
            (dump[7] & 0x88) == 0x00 && (dump[8] & 0x88) == 0x08 &&
            (dump[15] & 0x88) == 0x80 &&
            (dump[16] & 0x88) == 0x00 && (dump[17] & 0x88) == 0x08 &&
            (dump[24] & 0x88) == 0x80 &&
            (dump[25] & 0x88) == 0x00 && (dump[26] & 0x88) == 0x08) {
            target = 0xcc8cc000;
//            printf("good2\n");
            type = 2;
        }
        
        uint8_t to_decrypt[16];
        memcpy(to_decrypt, dump, 5);
        memcpy(to_decrypt+5, dump+9, 5);
        memcpy(to_decrypt+10, dump+18, 5);
        to_decrypt[15] = (dump[14] &0xf0) | (dump[23] >> 4);
        
        bool successful_decrypt = false;
        
        int min_diff = 100;
        uint8_t min_diff_decrypt[16];
        vector<uint8_t> best_key;
        
        for (auto key:keys) {
            uint8_t to_decrypt_cp[16];
            memcpy(to_decrypt_cp, to_decrypt, 16);
            
            md680_make_key(key, iv);
            md680_decrypt_alg1(to_decrypt_cp, 16);
            
            int diff = 0;
            
            for (int i=0;i<3;i++) {
                uint32_t v = ((to_decrypt_cp[i*5+0] & 0xcc) << 24) |
                    ((to_decrypt_cp[i*5+1] & 0xcc) << 16) |
                    ((to_decrypt_cp[i*5+2] & 0xcc) <<  8) |
                    ((to_decrypt_cp[i*5+3] & 0x88))       |
                    ((to_decrypt_cp[i*5+4] & 0x88) >>  1);
                
                diff +=  __builtin_popcountl(v^target);
            }
            
            if (print_dumps == 1 and diff < min_diff) {
                min_diff = diff;
                memcpy(min_diff_decrypt, to_decrypt_cp, 16);
                best_key = key;
            }
            
            if (diff <= error) {
                successful_decrypt = true;
                
                rec.key = key;
                
                bool flag = true;
                for (auto record:records) {
                    if (record_is_equal(rec, record)) {
                        flag = false;
                        break;
                    }
                }
                
                if (flag && output_records) {
                    records.push_back(rec);
                    fprintf(records_file, "%d 44 000 %04d %02d ", rec.freq, rec.group, rec.cc);
                    for (auto x:key)
                        fprintf(records_file, "%02X", x);
                    fprintf(records_file, "\n");
                }
            }
        }
        
        
        
        if (print_dumps == 1) {
            printf("%d ", type);
            for (int i=0;i<6;++i) {
                printf("%02X", best_key[i]);
            }
            printf(" ");
            for (int i=0;i<16;++i) {
                printf("%02X", min_diff_decrypt[i]);
            }
            printf(" %d\n", min_diff);
        }
        
        
        bool flag = true;
        for (auto &stat:stats) {
            stat.rec.key = rec.key;
            if (record_is_equal(stat.rec, rec)) {
                flag = false;
                if (successful_decrypt)
                    ++stat.cnt_suc;
                ++stat.cnt;
                break;
            }
        }
        
        if (flag) {
            Stat stat;
            stat.rec = rec;
            stat.cnt = 1;
            stat.cnt_suc = successful_decrypt;
            stats.push_back(stat);
        }
        
        if (!successful_decrypt && output_dumps) {
            fprintf(output_file, "%d ", rec.freq);
            
            for (auto x:iv)
                fprintf(output_file, "%02X", x);
            
            fprintf(output_file, " %d %d\n", rec.group, rec.cc);
            
            for (auto x:dump)
                fprintf(output_file, "%02X", x);
            fprintf(output_file, "\n");
        }
    }
    
    for (auto stat : stats) {
        printf("%d %d %d %d/%d %0.2f %% \n", stat.rec.freq, stat.rec.group, stat.rec.cc, stat.cnt_suc, stat.cnt, 1.0*stat.cnt_suc/stat.cnt*100);
    }
    
    if (output_best_dumps) {
        for (auto x : dumps_by_freq_and_iv) {
            int mx = 0;
            vector<uint8_t> best_dump(27);
            for (auto dump : x.second) {
                int cnt = 0;
                for (auto dump2 : x.second) {
                    bool flag = true;
                    for (int i=0;i<=4;++i)
                        if (dump[i] != dump2[i])
                            flag = false;
                    for (int i=9;i<=14;++i)
                        if (dump[i] != dump2[i])
                            flag = false;
                    for (int i=18;i<=22;++i)
                        if (dump[i] != dump2[i])
                            flag = false;
                    cnt += flag;
                }
                
                if (cnt>mx) {
                    mx = cnt;
                    best_dump = dump;
                }
            }
            
            fprintf(best_dumps_file, "%d ", x.first.first);
            
            for (auto el : x.first.second)
                fprintf(best_dumps_file, "%02X", el);
            fprintf(best_dumps_file, " ");
            
            for (auto el : best_dump)
                fprintf(best_dumps_file, "%02X", el);
            fprintf(best_dumps_file, " %d\n", mx-1);
        }
    }
    
    
    return 0;
}
