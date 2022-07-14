#include<stdio.h>
#include<string.h>
#include<jannson.h>

static const char hash_map[][256] = {
         "/usr/sbin/tcpdump",
         "/usr/sbin/iw",
         "/sbin/procd",
         "/sbin/netifd"
 };

#define HASHLENGTH 7
#define FAIL_LIST_LEN 4096
void hash_func(void)
{
        char cmd[1024] = {0,};
        char current_hash[HASHLENGTH+1] = {0,};
        char fail_list[FAIL_LIST_LEN] = {0,};
        char file_name[1024] = {0,};
        char log_cmd[1024] = {0,};
        int ret = 1;

 		    json_t *value;  
        json_error_t error;	
			  json_t *jsonFile = json_load_file("/root/hash.json", 0, &error);
        int hash_size = sizeof(hash_map)/sizeof(hash_map[0]);
        json_t *cp_file = json_deep_copy(jsonFile);
        size_t index = json_array_size(cp_file);
        //printf("array size : %d\n", index);

        for (int i = 0; i < hash_size; i++) {
                sprintf(cmd, "sha256sum %s", hash_map[i]);
                // hash_map[i] --> sha256sum
                FILE *fp = popen(cmd, "r");
                if (fp == NULL) {
                        perror("popen() 실패");
                        ret = 0;
                        goto out;
                }
                fgets(current_hash, HASHLENGTH+1, fp); //hash 7 + eof
                pclose(fp);

                json_array_foreach(cp_file, index, value) {
                        json_t *file_value = json_object_get(value, "file");
                        if(file_value == NULL){
                                printf("get file name fail\n");
                                ret = 0;
                                goto out;
                        }               
                        if(!strcmp(json_string_value(file_value), hash_map[i])){
                                json_t *hash_value = json_object_get(value, "hash");
                                if(hash_value == NULL){
                                        printf("get hash fail\n");
                                        ret = 0;
                                        goto out;
                                }
                                if(!strcmp(json_string_value(hash_value), current_hash)){
                                        json_array_remove(cp_file, index);
                                }
                        }
                }
        }

        index = json_array_size(cp_file);

        //int log_num = 0;

        if(index==0)
                //system("slog 'Hash 검사 성공' 6");
				printf("Hash 검사 성공");
        else {
                json_array_foreach(cp_file_hash, index, value) {
                        json_t *fail_file_value = json_object_get(value, "file");       
                       
                        memset(file_name, 0, sizeof(file_name));
                        strcpy(file_name,json_string_value(fail_file_value));

                        if(!strlen(fail_list))
                                strncpy(fail_list, file_name, strlen(file_name));
                        else{
                                // 사이즈 검사
                                if(strlen(fail_list) + strlen(file_name) > FAIL_LIST_LEN) {
                                        fail_list[strlen(fail_list) - 2] = '\0';
                                        sprintf(log_cmd, "slog 'hash 검사 실패 : %s' 3", fail_list);
                                        //system(log_cmd);
										printf("hash 검사 실패");
                                        //log_num++;

                                        memset(fail_list, 0, FAIL_LIST_LEN);
                                        strncpy(fail_list, file_name, strlen(file_name));
                                } else
                                        strncpy(fail_list + strlen(fail_list), file_name, strlen(file_name));
                        }
                        if(index != (json_array_size(cp_file_hash)-1))
                                strcat(fail_list,", ");
                        else{
                                if(strlen(fail_list) > 0){
                                        sprintf(log_cmd, "slog 'hash 검사 실패 : %s' 3", fail_list);
                                        //system(log_cmd);
										printf("hash 검사 실패");
                                        sleep(1);
                                        //system("reboot");
                                }
                        }
                }
        }
out:
//printf("--- (%s) end\n", __func__);
        json_decref(cp_file);
        //return ret;
}

