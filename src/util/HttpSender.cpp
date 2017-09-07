// Copyright (c) 2016, Tencent Inc.
// All rights reserved.
//
// Author: Wu Cheng <chengwu@tencent.com>
// Created: 03/08/2016
// Description:
#include "util/HttpSender.h"

#include <string>
#include <iostream>
#include <fstream>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <cstring>
#include <stdint.h>
#include "json/json.h"
#include "CosParams.h"
#include "request/CosResult.h"
#include "CosSysConfig.h"
#include "CosDefines.h"
#include "util/StringUtil.h"
#ifdef __USE_L5
#include "util/l5_endpoint_provider.h"
#endif

using std::string;
using std::size_t;

namespace qcloud_cos {
/*
review: 函数接口设计上可能存在缺陷
void * 可以转换为其他任何类型的指针，使用void指针本质上屏蔽了C++的类型检查。
函数的形参buffer其类型实际应为 char *, stream类型应为string & 为宜。
如果传入参数实际上非为 char *, string，其行为未定义。
此外建议使用C++ style的强制类型转换(static_cast, dynamic_cast, const_cast)，而不是C style的强制类型转换，代码存在两者混用情况。
*/   
size_t HttpSender::CurlWriter(void *buffer, size_t size, size_t count, void *stream) {
    string *pstream = static_cast<string *>(stream);
    (*pstream).append((char *)buffer, size * count);
    return size * count;
}

/*
 * 生成一个easy curl对象，并设置一些公共值
 */
CURL *HttpSender::CurlEasyHandler(const string &url, string *rsp, bool is_post) {
    CURL *easy_curl = curl_easy_init();

    uint64_t conn_timeout = CosSysConfig::getTimeoutInms();
    uint64_t global_timeout = CosSysConfig::getGlobalTimeoutInms();
    curl_easy_setopt(easy_curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(easy_curl, CURLOPT_NOSIGNAL, 1);
    // TODO(rabbitliu) 是否需要保护，如最少30s
    curl_easy_setopt(easy_curl, CURLOPT_TIMEOUT_MS, global_timeout);
    curl_easy_setopt(easy_curl, CURLOPT_CONNECTTIMEOUT_MS, conn_timeout);
    curl_easy_setopt(easy_curl, CURLOPT_SSL_VERIFYHOST, 0);
    curl_easy_setopt(easy_curl, CURLOPT_SSL_VERIFYPEER, 1);

    if (CosSysConfig::getKeepAlive()) {
        curl_easy_setopt(easy_curl, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(easy_curl, CURLOPT_TCP_KEEPIDLE, 20L);
        curl_easy_setopt(easy_curl, CURLOPT_TCP_KEEPINTVL, 5L);
    }

    if (is_post) {
        curl_easy_setopt(easy_curl, CURLOPT_POST, 1);
    }

    curl_easy_setopt(easy_curl, CURLOPT_WRITEFUNCTION, CurlWriter);
    curl_easy_setopt(easy_curl, CURLOPT_WRITEDATA, rsp);

    return easy_curl;
}

struct curl_slist* HttpSender::SetCurlHeaders(CURL *curl_handler, const std::map<string, string> &user_headers) {
    struct curl_slist *header_lists = NULL;
    header_lists = curl_slist_append(header_lists, "Accept: */*");
    //header_lists = curl_slist_append(header_lists, "Host: web.file.myqcloud.com");
    header_lists = curl_slist_append(header_lists, "Connection: Keep-Alive");
    header_lists = curl_slist_append(header_lists, "User-Agent: cos-cpp-sdk-v4.2");

    /*
    review: 尽可能延后变量定义式出现的时间 & 以及避免不成熟的劣化。
    it， header_key, header_value, fullstr 在循环内定义为宜，一般变量宜定义在能确定其初值所在之处。
    此外，尽量使用 const 引用，而不是只用对象，编译器并不能保证一定会对其优化，此即，避免不成熟的劣化。
    for(auto it = user_headers.begin(); it != user_headers.end(), ++it)
    {
        const string & header_key = it->first;
        const string & header_value = it->second;
        string full_str = header_key + ":" + header_value;
        header_lists = curl_slist_append(header_lists, full_str.c_str());
    }
    */
    std::map<string, string>::const_iterator it = user_headers.begin();
    string header_key, header_value, full_str;
    for (; it != user_headers.end(); ++it) {
        header_key = it->first;
        header_value = it->second;
        full_str = header_key + ": " + header_value;
        header_lists = curl_slist_append(header_lists, full_str.c_str());
    }
    curl_easy_setopt(curl_handler, CURLOPT_HTTPHEADER, header_lists);
    return header_lists;
}

string HttpSender::SendGetRequest(const string url,
                                  const std::map<string, string> &user_headers,
                                  const std::map<string, string> &user_params) 
{
    /*
    review: 尽可能延后变量定义式出现的时间 & 以及避免不成熟的劣化。
    同上，下面还有很多代码都存在相同的问题，不再重复。
    */
    string user_params_str = "";
    string param_key = "";
    string param_value = "";
    std::map<string, string>::const_iterator it = user_params.begin();
    for (; it != user_params.end(); ++it) {
        if (!user_params_str.empty()) {
            user_params_str += '&';
        }
        param_key = it->first;
        param_value = it->second;
        user_params_str += param_key + "=" + param_value;
    }

    string full_url(url);
    if (full_url.find('?') ==string::npos) {
        full_url += "?" + user_params_str;
    } else {
        full_url += "&" + user_params_str;
    }

    SDK_LOG_DBG("full url : %s", full_url.c_str());

    string response = "";
    CURL* get_curl = CurlEasyHandler(full_url, &response, false);
    curl_slist* header_lists = SetCurlHeaders(get_curl, user_headers);

    int64_t start = GetTimeStampInUs();
    CURLcode ret_code = curl_easy_perform(get_curl);
    int64_t time_cost_in_us = GetTimeStampInUs() - start;

    curl_slist_free_all(header_lists);
    curl_easy_cleanup(get_curl);


    if (ret_code != CURLE_OK) {
        SDK_LOG_ERR("SendGetRequest error! full_url: %s, time_cost: %lu",full_url.c_str(), time_cost_in_us );
        
    /*
    review：关于宏使用的隐忧。
    宏作为编译器的预处理命令，虽然方便，但并不具有可扩展性。
    一般而言，只有在极少数情况下使用宏是合理的，典型如头文件保护符。
    此处用作编译开关，虽然方便，但应该可以用其他更为合理的方法来替代。
    */
#ifdef __USE_L5
        int64_t l5_modid = CosSysConfig::getL5Modid();
        int64_t l5_cmdid = CosSysConfig::getL5Cmdid();
        L5EndpointProvider::UpdateRouterResult(full_url, l5_modid,
                                               l5_cmdid,
                                               time_cost_in_us, -1);
#endif
        return CosResult(NETWORK_ERROR_CODE,NETWORK_ERROR_DESC).toJsonString();
    }
#ifdef __USE_L5
    int64_t l5_modid = CosSysConfig::getL5Modid();
    int64_t l5_cmdid = CosSysConfig::getL5Cmdid();
    L5EndpointProvider::UpdateRouterResult(full_url, l5_modid, l5_cmdid,
                                           time_cost_in_us, 0);
#endif
    return response;
}

int HttpSender::SendGetRequest(string* pRsp, const string& url,
                const std::map<string, string> &user_headers,
                const std::map<string, string> &user_params) {
    string user_params_str = "";
    string param_key = "";
    string param_value = "";
    std::map<string, string>::const_iterator it = user_params.begin();
    for (; it != user_params.end(); ++it) {
        if (!user_params_str.empty()) {
            user_params_str += '&';
        }
        param_key = it->first;
        param_value = it->second;
        user_params_str += param_key + "=" + param_value;
    }
    string full_url(url);
    if (!user_params_str.empty())
    {
        if (full_url.find('?') ==string::npos) {
            full_url += "?" + user_params_str;
        } else {
            full_url += "&" + user_params_str;
        }
    }

    CURL* get_curl = CurlEasyHandler(full_url, pRsp, false);
    curl_slist* header_lists = SetCurlHeaders(get_curl, user_headers);
    CURLcode ret_code = curl_easy_perform(get_curl);

    SDK_LOG_DBG("ret_code=%d, full_url = %s",ret_code, full_url.c_str());

    long http_code = -1;
    if (ret_code == CURLE_OK) {
        ret_code = curl_easy_getinfo(get_curl, CURLINFO_RESPONSE_CODE , &http_code);
    } else {
        SDK_LOG_ERR("down error, ret_code=%d, full_url=%s, pRsp= %s",ret_code, full_url.c_str(), pRsp->c_str());
    }

    curl_slist_free_all(header_lists);
    curl_easy_cleanup(get_curl);

    return http_code;
}

string HttpSender::SendJsonPostRequest(const string url,
                                       const std::map<string, string> &user_headers,
                                       const std::map<string, string> &user_params) {
    string response = "";
    CURL* json_post_curl = CurlEasyHandler(url, &response, true);

    std::map<string, string> user_headers_cp = user_headers;
    user_headers_cp["Content-Type"] = "application/json";
    curl_slist* header_lists = SetCurlHeaders(json_post_curl, user_headers_cp);

    Json::Value param_json;
    std::map<string, string>::const_iterator it = user_params.begin();
    for (; it != user_params.end(); ++it) {
        param_json[it->first] = it->second;
    }
    Json::FastWriter json_writer;
    string param_str = json_writer.write(param_json);
    curl_easy_setopt(json_post_curl, CURLOPT_POSTFIELDS, param_str.c_str());

    int64_t start = GetTimeStampInUs();
    CURLcode ret_code = curl_easy_perform(json_post_curl);
    int64_t time_cost_in_us = GetTimeStampInUs() - start;

    curl_slist_free_all(header_lists);
    curl_easy_cleanup(json_post_curl);


    if (ret_code != CURLE_OK) {
        SDK_LOG_ERR("SendJsonPostRequest error! url: %s, time_cost:%lu", url.c_str(), time_cost_in_us);
#ifdef __USE_L5
        int64_t l5_modid = CosSysConfig::getL5Modid();
        int64_t l5_cmdid = CosSysConfig::getL5Cmdid();
        L5EndpointProvider::UpdateRouterResult(url, l5_modid,l5_cmdid,
                                               time_cost_in_us, -1);
#endif
        return CosResult(NETWORK_ERROR_CODE,NETWORK_ERROR_DESC).toJsonString();
    }

#ifdef __USE_L5
    int64_t l5_modid = CosSysConfig::getL5Modid();
    int64_t l5_cmdid = CosSysConfig::getL5Cmdid();
    L5EndpointProvider::UpdateRouterResult(url, l5_modid, l5_cmdid,
                                           time_cost_in_us, 0);
#endif
    return response;
}

string HttpSender::SendJsonBodyPostRequest(const string url,const std::string& jsonBody,
                                       const std::map<string, string> &user_headers) {
    string response = "";
    CURL* json_post_curl = CurlEasyHandler(url, &response, true);

    std::map<string, string> user_headers_cp = user_headers;
    user_headers_cp["Content-Type"] = "application/json";
    curl_slist* header_lists = SetCurlHeaders(json_post_curl, user_headers_cp);

    curl_easy_setopt(json_post_curl, CURLOPT_POSTFIELDS, jsonBody.c_str());

    int64_t start = GetTimeStampInUs();
    CURLcode ret_code = curl_easy_perform(json_post_curl);
    int64_t time_cost_in_us = GetTimeStampInUs() - start;

    curl_slist_free_all(header_lists);
    curl_easy_cleanup(json_post_curl);


    if (ret_code != CURLE_OK) {
        SDK_LOG_ERR("SendJsonPostRequest error! url: %s,time_cost:%lu",url.c_str(), time_cost_in_us);
#ifdef __USE_L5
        int64_t l5_modid = CosSysConfig::getL5Modid();
        int64_t l5_cmdid = CosSysConfig::getL5Cmdid();
        L5EndpointProvider::UpdateRouterResult(url, l5_modid,l5_cmdid,
                                               time_cost_in_us, -1);
#endif
        return CosResult(NETWORK_ERROR_CODE,NETWORK_ERROR_DESC).toJsonString();
    }

#ifdef __USE_L5
    int64_t l5_modid = CosSysConfig::getL5Modid();
    int64_t l5_cmdid = CosSysConfig::getL5Cmdid();
    L5EndpointProvider::UpdateRouterResult(url, l5_modid, l5_cmdid,
                                           time_cost_in_us, 0);
#endif
    return response;
}

string HttpSender::SendSingleFilePostRequest(const string &url,
                                             const std::map<string, string> &user_headers,
                                             const std::map<string, string> &user_params,
                                             const unsigned char* fileContent,
                                             const unsigned int fileContent_len) {

    //review: struct多余
    struct curl_httppost *firstitem = NULL;
    struct curl_slist *header_lists = NULL;
    string response = "";
    CURL *file_curl = PrepareMultiFormDataCurl(url,
                                               user_headers,
                                               user_params,
                                               fileContent,
                                               fileContent_len,
                                               firstitem,
                                               header_lists,
                                               &response);
    int64_t start = GetTimeStampInUs();
    CURLcode ret_code = curl_easy_perform(file_curl);
    int64_t time_cost_in_us = GetTimeStampInUs() - start;
    time_cost_in_us = time_cost_in_us;

    //review：异常安全问题，如果前面函数存在异常抛出，以下资源释放函数并不会执行，此时，仍然存在资源泄露问题。
    curl_formfree(firstitem);
    curl_slist_free_all(header_lists);
    curl_easy_cleanup(file_curl);


    if (ret_code != CURLE_OK) {
        SDK_LOG_ERR("sendSingleFilePost error! url: %s",url.c_str());
#ifdef __USE_L5
        int64_t l5_modid = CosSysConfig::getL5Modid();
        int64_t l5_cmdid = CosSysConfig::getL5Cmdid();
        L5EndpointProvider::UpdateRouterResult(url, l5_modid,l5_cmdid,
                                               time_cost_in_us, -1);
#endif
        return CosResult(NETWORK_ERROR_CODE,NETWORK_ERROR_DESC).toJsonString();
    }

#ifdef __USE_L5
    int64_t l5_modid = CosSysConfig::getL5Modid();
    int64_t l5_cmdid = CosSysConfig::getL5Cmdid();
    L5EndpointProvider::UpdateRouterResult(url, l5_modid, l5_cmdid,
                                           time_cost_in_us, 0);
#endif
    return response;
}

/*
review:除非指向NULL合法，否则使用“引用”进行参数传递优先于使用“指针进行参数传递”。
代码中response对象使用string *，但函数中并未进行判空，如果传递的response == NULL，则会引发错误。
而使用“引用”，很大程度上能够避免这个问题，因为引用需要初始化，除非特意为之，一般不会指向NULL。
*/
CURL *HttpSender::PrepareMultiFormDataCurl(const string &url,
                                           const std::map<string, string> &user_headers,
                                           const std::map<string, string> &user_params,
                                           const unsigned char* fileContent,
                                           const unsigned int fileContent_len,
                                           struct curl_httppost* &firstitem,
                                           struct curl_slist* &header_lists,
                                           string *response) {

    struct curl_httppost *lastitem = NULL;
    //review: 尽量延迟变量定义的时间 && 尽量避免不成熟的劣化, 同上。
    string param_key = "";
    string param_value = "";
    std::map<string, string>::const_iterator it = user_params.begin();
    for (; it != user_params.end(); ++it) {
        param_key = it->first;
        param_value = it->second;
        curl_formadd(&firstitem, &lastitem,
                     CURLFORM_COPYNAME, param_key.c_str(),
                     CURLFORM_COPYCONTENTS, param_value.c_str(),
                     CURLFORM_END);
    }

    if (fileContent != NULL && fileContent_len != 0) {
        curl_formadd(&firstitem, &lastitem,
                     CURLFORM_COPYNAME, "filecontent",
                     CURLFORM_BUFFER, "data",
                     CURLFORM_BUFFERPTR, fileContent,
                     CURLFORM_BUFFERLENGTH, (long) fileContent_len,
                     CURLFORM_END);
    }

    CURL* file_curl = CurlEasyHandler(url, response, true);

    header_lists = SetCurlHeaders(file_curl, user_headers);

    curl_easy_setopt(file_curl, CURLOPT_HTTPPOST, firstitem);
    return file_curl;
}

string HttpSender::SendFileParall(const string url,
                                  const std::map<string, string> user_headers,
                                  const std::map<string, string> user_params,
                                  const string localFileName,
                                  unsigned long offset,
                                  const unsigned long sliceSize) {

    string final_response = "";
    bool error_occur = false;

    CURLM *multi_curl = curl_multi_init();

    std::ifstream fileInput(localFileName.c_str(),
                       std::ios::in | std::ios::binary);
    fileInput.seekg(0, std::ios::end);
    unsigned long file_len = fileInput.tellg();
    fileInput.seekg(offset, std::ios::beg);

    const unsigned int max_parall_num = 20;
    unsigned char *sliceContentArr[max_parall_num];
    
    /*
    review: RAII 资源获取就是初始化，以对象管理资源，以及为异常安全而努力是值得的。
    下面的代码并没有遵循上面的原则，直接用new来创建数组，并且使用了指针数组。
    但在后面的逻辑代码中，有可能“直接抛出异常而函数退出”，导致后面的 delete[] sliceContentArr[i]; 并没有执行，此时则发生了资源泄露。
    解决办法是使用智能指针shared_ptr保证资源一定能够释放，或者在这里直接使用vector<vector<unsigned char>> 或者 vector<string>
    */
    for (unsigned int i = 0; i < max_parall_num; ++i) {
        sliceContentArr[i] = new unsigned char[sliceSize];
    }

    // 用于保存easy_handler
    CURL *easyHandlerArr[max_parall_num];
    memset(easyHandlerArr, 0, sizeof(easyHandlerArr));
    // 用于保存first_item
    struct curl_httppost *firstitemArr[max_parall_num];
    memset(firstitemArr, 0, sizeof(firstitemArr));
    // 用于保存curl_slist
    struct curl_slist* header_listsArr[max_parall_num];
    memset(header_listsArr, 0, sizeof(header_listsArr));
    // 用来保存每一个easy_handler的返回值
    string easyResponseArr[max_parall_num];

    // 用来记录每一个分片的头部信息
    std::map<string, string> slice_params = user_params;

    while(offset < file_len) {
        unsigned int easy_handler_count = 0;
        while(easy_handler_count < max_parall_num) {
            string offset_string = StringUtil::Uint64ToString(offset);
            slice_params["offset"] = offset_string;
            fileInput.read((char *)sliceContentArr[easy_handler_count], sliceSize);
            // byte read len
            unsigned long byte_read_len = 0;
            byte_read_len = fileInput.gcount();

            easyHandlerArr[easy_handler_count] = PrepareMultiFormDataCurl(url,
                                                                          user_headers,
                                                                          slice_params,
                                                                          sliceContentArr[easy_handler_count],
                                                                          byte_read_len,
                                                                          firstitemArr[easy_handler_count],
                                                                          header_listsArr[easy_handler_count],
                                                                          &(easyResponseArr[easy_handler_count]));
            curl_multi_add_handle(multi_curl, easyHandlerArr[easy_handler_count]);

            ++easy_handler_count;
            offset += byte_read_len;
            if (offset >= file_len) {
                break;
            }
        }

        int easy_handler_running = 0;
        curl_multi_perform(multi_curl, &easy_handler_running);

        do {
            int numfds = 0;
            CURLMcode res = curl_multi_wait(multi_curl, NULL, 0, MAX_WAIT_MSECS, &numfds);
            if (res != CURLM_OK) {
                std::cerr << "error: curl_multi_wait() returned " << res << std::endl;
            }
            curl_multi_perform(multi_curl, &easy_handler_running);
        } while(easy_handler_running);

        CURLMsg *msg = NULL;
        int msgs_left = 0;
        CURLcode return_code = CURLE_OK;
        int http_status_code;
        while((msg = curl_multi_info_read(multi_curl, &msgs_left))) {
            if (msg->msg == CURLMSG_DONE) {
                CURL *easy_handler_over = msg->easy_handle;
                unsigned int j = 0;
                for(; j < max_parall_num; ++j) {
                    if (easyHandlerArr[j] == easy_handler_over) {
                        break;
                    }
                }
                string slice_response = easyResponseArr[j];
                struct curl_slist *slice_header_slist = header_listsArr[j];
                header_listsArr[j] = NULL;
                struct curl_httppost *slice_firstitem = firstitemArr[j];
                firstitemArr[j] = NULL;

                return_code = msg->data.result;
                if (return_code != CURLE_OK) {
                    std::cerr << "slice CURL error code:" << msg->data.result << std::endl;
                    error_occur = true;
                    break;
                }

                http_status_code = 0;
                curl_easy_getinfo(easy_handler_over, CURLINFO_RESPONSE_CODE, &http_status_code);
                if (http_status_code != 200) {
                    std::cerr << "slice CURL get failed http status code " << http_status_code << std::endl;
                    error_occur = true;
                    break;
                }

                Json::Reader reader;
                Json::Value json_object;
                if (!reader.parse(slice_response.c_str(), json_object)) {
                    std::cerr << "slice CURL return string not json format!" << slice_response << std::endl;
                    error_occur = true;
                    break;
                }

                if (final_response.empty()) {
                    final_response = slice_response;
                }

                int code_member = json_object["code"].asInt();
                if (code_member != 0) {
                    final_response = slice_response;
                }

                Json::Value data_member = json_object["data"];
                if (!data_member["access_url"].isNull()) {
                    final_response = slice_response;
                }

                curl_multi_remove_handle(multi_curl, easy_handler_over);
                curl_formfree(slice_firstitem);
                curl_slist_free_all(slice_header_slist);
                curl_easy_cleanup(easy_handler_over);
            }
        }

    }

    fileInput.close();
    for (unsigned int i = 0; i < max_parall_num; ++i) {
        delete[] sliceContentArr[i];
    }
    curl_multi_cleanup(multi_curl);
    if (error_occur) {
        return CosResult(NETWORK_ERROR_CODE,NETWORK_ERROR_DESC).toJsonString();
    } else {
        return final_response;
    }
}


int64_t HttpSender::GetTimeStampInUs() {
    // 构造时间
    struct timeval tv;     //review: struct 多余。
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}
}
