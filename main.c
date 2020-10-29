#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_MAX_LEN 512
#define LABEL_MAX_LEN 32
#define OPERAND_MAX_LEN 32
#define OPERATOR_MAX_LEN 32
#define ADDRESS_MAX_LEN 32
#define LISTING_FILE_PRINTING_FORMAT "%-16x%-32s%-32s%-32s\n"
#define OBJECT_CODE_MAX_LEN 61

char* source_path;
char* object_path;
char* intermediate_path = "./inter.txt";
char* listing_path = "./listing.txt";


char line_to_parse[LINE_MAX_LEN];

char label[LABEL_MAX_LEN];
char operator[OPERATOR_MAX_LEN];
char operand[OPERAND_MAX_LEN];

int line_idx = 0;
int location_counter = 0;
int starting_address = 0;
int listing_line_num = 0;
int obj_length = 0;
int can_use_base = 0;
int base_addr = 0;
int current_location_for_relocation = 0;

FILE* input_file;
FILE* output_file;
FILE* intermediate_file;
FILE* listing_file;

typedef struct op_t{
    char *mnemoic;
    int format;
    int op_code;
}op;

typedef struct modification_record_t{
    int starting_location;
    int length_to_modify;
    struct modification_record_t* next;
}modification_record;

op op_set[64] = {
    {"ADD",3,0x18},
    {"ADDF", 3,0x58},
    {"ADDR",2,0x90},
    {"AND",3,0x40},
    {"CLEAR",2,0xB4},
    {"COMP",3,0x28},
    {"COMPR",2,0xA0},
    {"COMPF",3,0x88},
    {"DIV",3,0x24},
    {"DIVF",0x64},
    {"DIVR",2,0x9c},
    {"FIX",1,0xc4},
    {"FLOAT",1,0xc0},
    {"HIO",1,0xf4},
    {"J",3,0x3c},
    {"JEQ",3,0X30},
    {"JGT",3,0X34},
    {"JLT",3,0X38},
    {"JSUB",3,0X48},
    {"LDA",3,0X00},
    {"LDB",3,0X68},
    {"LDCH",3,0X50},
    {"LDF",3,0X70},
    {"LDL",3,0X08},
    {"LDS",3,0X6C},
    {"LDT",3,0X74},
    {"LDX",3,0X04},
    {"LPS",3,0XD0},
    {"MUL",3,0x20},
    {"MULF",3,0x60},
    {"MULR",2,0X98},
    {"NORM",1,0XC8},
    {"OR",3,0X44},
    {"RD",3,0XD8},
    {"RMO",2,0XAC},
    {"RSUB",3,0X4C},
    {"SHIFTL",2,0XA4},
    {"SHITFR",2,0XA8},
    {"SIO",1,0XF0},
    {"SSK",3,0XEC},
    {"STA",3,0X0C},
    {"STB",3,0X78},
    {"STCH",3,0X54},
    {"STF",3,80},
    {"STI",3,0XD4},
    {"STL",3,0X14},
    {"STS",3,0X7C},
    {"STSW",3,0XE8},
    {"STT",3,0X84},
    {"STX",3,0X10},
    {"SUB",3,0X1C},
    {"SUBF",3,0X5C},
    {"SUBR",2,0X94},
    {"SVC",2,0XB0},
    {"TD",3,0XE0},
    {"TIO",1,0XF8},
    {"TIX",3,0X2C},
    {"TIXR",2,0XB8},
    {"WD",3,0XDC},
    {"END",-1,0XFF}
};

typedef struct register_t{
    char name[2];
    int num;
}reg;

reg registers[10] ={
    { "A", 0 },
    { "X", 1 },
    { "L", 2 },
    { "B", 3 },
    { "S", 4 },
    { "T", 5 },
    { "F", 6 },
    { "PC", 8 },
    { "SW", 9 }
};

typedef struct text_record_t{
    int starting_address;
    int current_length; // 현재 text record의 길이
    char object_code[OBJECT_CODE_MAX_LEN]; // OBJECT_CODE_MAX_LEN = 61;
}text_record;

text_record temp_text_record;

typedef struct op_node_t{
    struct op_node_t* next;
    char* mnemonic;
    int op_code;
    int format;
}opnode;


typedef struct label_node_t{
    struct label_node_t* next;
    char* label;
    int address;
}label_node;

int modification_counter_record = 0;

opnode** op_hash_table;
label_node** label_hash_table;
modification_record* modifitaction_record_list;

void init_moification_record_list(int start_loc, int len_to_modifty){
    modifitaction_record_list = (modification_record*)malloc(sizeof(modification_record));
    modifitaction_record_list->starting_location = start_loc;
    modifitaction_record_list->length_to_modify = len_to_modifty;
    modifitaction_record_list->next = NULL;
}

void add_modification_record(int start_loc, int len_to_modifty){
    if(modifitaction_record_list == NULL){
        init_moification_record_list(start_loc, len_to_modifty);
    }else{
        modification_record* end = modifitaction_record_list;
        while (end->next != NULL) {
            end = end->next;
        }
        end->next = (modification_record*)malloc(sizeof(modification_record));
        end->next->length_to_modify = len_to_modifty;
        end->next->starting_location = start_loc;
        end->next->next = NULL;
        return;
    }
}

int hash(char* key, int table_size){
    int sum = 0;
    for(int i = 0 ; i < strlen(key); i++){
        sum += key[i];
    }
    return sum % table_size;
}

opnode* make_op_node(char* mnemonic, int op_code, int format){
    opnode* new_node = (opnode*)malloc(sizeof(opnode));
    char* new_string = (char*)malloc(sizeof(char)*32);
    strcpy(new_string, mnemonic);
    new_node -> mnemonic = new_string;
    new_node->format = format;
    new_node->op_code = op_code;
    new_node->next = NULL;
    return new_node;
}

opnode** make_op_table(int table_size){
    opnode** op_table = (opnode**)malloc(table_size * sizeof(opnode*));
    for(int i = 0; i < table_size; i++){
        op_table[i] = NULL;
    }
    return op_table;
}

opnode* getOp(opnode** optable, int table_size, char* mnemonic){
    int idx = hash(mnemonic, 64);
    if(optable != NULL){
        opnode* starting_node = optable[idx];
        
        while(starting_node != NULL){
            if(strcmp(starting_node->mnemonic, mnemonic) == 0){
                break;
            }
            starting_node = starting_node->next;
        }
        
        return starting_node;
    }
    return NULL;
}

opnode* setOp(opnode** optable, int table_size ,char* mnemonic, int opcode, int format){
    int idx = hash(mnemonic, table_size);
    opnode* new_node = make_op_node(mnemonic, opcode, format);

    if(optable != NULL){
        opnode* starting_node = optable[idx];
        if(starting_node == NULL){
            optable[idx] = new_node;
            return new_node;
        }else{
            while(starting_node->next != NULL){
                starting_node = starting_node -> next;
            }
            starting_node->next = new_node;
            return new_node;
        }
    }
    return NULL;
}

label_node* make_label_node(char* label, int address){
    label_node* new_node = (label_node*)malloc(sizeof(label_node));
    char* new_string = (char*)malloc(sizeof(char)*LABEL_MAX_LEN);
    strcpy(new_string, label);
    new_node->label = new_string;
    new_node->address = address;
    new_node->next = NULL;
    return new_node;
}

label_node** make_label_table(int table_size){
    label_node** label_table = (label_node**)malloc(table_size * sizeof(label_node*));
    for(int i = 0; i < table_size; i++){
        label_table[i] = NULL;
    }
    return label_table;
}

label_node* getLabel(label_node** label_table, int table_size, char* label){
    int idx = hash(label, 64);
    if(label_table != NULL){
        label_node* starting_node = label_table[idx];
        
        
        while(starting_node != NULL){
             if(strcmp(starting_node->label, label) == 0)
                 break;
            starting_node = starting_node->next;
        }
        
        return starting_node;
    }
    return NULL;
}

label_node* setLabel(label_node** label_table, int table_size ,char* label, int address){
    int idx = hash(label, table_size);
    label_node* new_node = make_label_node(label, address);

    if(label_table != NULL){
        label_node* starting_node = label_table[idx];
        if(starting_node == NULL){
            label_table[idx] = new_node;
            return new_node;
        }else{
            while(starting_node->next != NULL){
                starting_node = starting_node -> next;
            }
            starting_node->next = new_node;
            return new_node;
        }
    }
    return NULL;
}

void read_token(char* line_to_parse, char* place_to_store){
    int token_idx = 0;
    while(!(line_to_parse[line_idx] == ' ' || line_to_parse[line_idx] == '\t' || line_to_parse[line_idx] == '\n')){
        place_to_store[token_idx] = line_to_parse[line_idx];
        token_idx++;
        line_idx++;
    }
    place_to_store[token_idx] = '\0';
    return;
}


void read_operand(char* line_to_parse, char* place_to_store){
    int token_idx = 0;
    while(!(line_to_parse[line_idx] == '\n')){
        place_to_store[token_idx] = line_to_parse[line_idx];
        token_idx++;
        line_idx++;
    }
    place_to_store[token_idx] = '\0';
    return;
}


void read_blank(char* line_to_parse){
    while(line_to_parse[line_idx] == ' ' || line_to_parse[line_idx] == '\t')
        line_idx++;
}

void parse_line(char* line_to_parse, char* label, char* operator, char* operand){
    
    line_idx = 0;
    read_token(line_to_parse,label);
    read_blank(line_to_parse);
    read_token(line_to_parse,operator);
    read_blank(line_to_parse);
    read_operand(line_to_parse,operand);
    return;
}

opnode** inst_set_to_hash_table(op* inst_set){
    opnode** new_table = make_op_table(64);
    int i = 0;
    while(inst_set[i].format != -1){
//        printf("%d\n", op_set[i].op_code);
        setOp(new_table, 64 ,op_set[i].mnemoic, op_set[i].op_code, op_set[i].format);
        i++;
    }
    return new_table;
}

int op_str_to_dec(char* op_str){ // BYTE directive의 operand의 길이를 반환 ex) C'EOF' -> 3 반환
    int len = 0;
    if((op_str[0] == 'X' || op_str[0] == 'x') && op_str[1] == '\''){
        return 1;
    }else{
        int idx = 2;
        while(op_str[idx++] != '\''){
            len++;
        }
    }
    return len;
}

void initialize_op_hash_table(){
    op_hash_table = make_op_table(64);
    int i = 0;
    while(op_set[i].format != -1){
        opnode* node= setOp(op_hash_table, 64, op_set[i].mnemoic, op_set[i].op_code, op_set[i].format);
//        printf("%s, %d, %d\n", node->mnemonic, node->op_code, node->format);
        i++;
    }
}

void initialize_label_hash_table(){
    label_hash_table = make_label_table(64);
}

//void write_to_listing_file(int listing_line_num, int location_ctr, char* label, char* operator, char* operand, char* obj){
//    fprintf(listing_file, LISTING_FILE_PRINTING_FORMAT, location_counter,label,operator,operand,obj);
//}

void write_to_intermediate_file(int listing_line_num, int location_ctr, char* label, char* operator, char* operand, char* obj){
    if(strcmp("END", operator) == 0){
        fprintf(intermediate_file, "%48s%-32s%-32s%-32s\n","",operator,operand,"");
    }else{
        fprintf(intermediate_file, LISTING_FILE_PRINTING_FORMAT, location_counter, label,operator,operand);
    }
}

void store_obj_length(int* place_to_store, int length){
    *place_to_store = length;
    return;
}


void do_path1(){
    intermediate_file = fopen(intermediate_path, "w");
    if(intermediate_file == NULL){
        printf("intermeidiate file problem");
        return;
    }
    
    /* read first line */
    fgets(line_to_parse, LINE_MAX_LEN, input_file);
    parse_line(line_to_parse, label, operator, operand);
    
    if(strcmp(operator, "START") == 0){
        listing_line_num += 5;
        int opd = (int)strtol(operand, NULL, 10);
        starting_address = opd;
        location_counter = starting_address;
        setLabel(label_hash_table, 64, label, location_counter);
        write_to_intermediate_file(listing_line_num, location_counter, label, operator, operand, NULL);
        fgets(line_to_parse,LINE_MAX_LEN,input_file);
        parse_line(line_to_parse, label, operator, operand);
    }else{
        location_counter = 0;
    }
    
    while(strcmp(operator, "END") != 0){
        listing_line_num += 5;
        if(line_to_parse[0] == '.' || (strlen(label) + strlen(operator) + strlen(operand) == 0)){
            fgets(line_to_parse,LINE_MAX_LEN,input_file);
            parse_line(line_to_parse, label, operator, operand);
            continue;
        }
        
        if(strlen(label) == 0){
            label[0] = '-';
            label[1] = '\0';
        }
        
        write_to_intermediate_file(listing_line_num, location_counter, label, operator, operand, NULL);
        
        if( strlen(label) != 0 && label[0] != '-'){
            // fprintf(intermediate_file, "%-32s%-32x\n",label,location_counter);
            // searching symbol tab for label
            if(getLabel(label_hash_table, 64, label) == NULL){
                setLabel(label_hash_table, 64, label, location_counter);
            }else{
                fprintf(intermediate_file,"%s%d\n","error : duplicated symbol!! at ",location_counter);
            }
        }
        
        opnode* opnode = NULL;
        
        if(operator[0] == '+')
            opnode = getOp(op_hash_table, 64, operator + 1);
        else
            opnode = getOp(op_hash_table, 64, operator);
        
        if(opnode != NULL){
            if(operator[0] == '+'){
//                printf("op: %s ,size : %d \n", operator, 4);
                location_counter += 4;
            }else{
//                printf("op: %s ,size : %d \n", operator, opnode->format);
                location_counter += opnode->format;
            }
            
        }else if(strcmp(operator, "WORD") == 0){
//            printf("op: %s ,size : %d \n", operator,3);
            location_counter += 3;
        }else if(strcmp(operator, "RESW") == 0){
            int opd = (int)strtol(operand, NULL, 10);
//            printf("op: %s ,size : %d \n", operator, 3*opd);
            location_counter += 3 * opd;
        }else if(strcmp(operator, "RESB") == 0){
            int opd = (int)strtol(operand, NULL, 10);
//            printf("op: %s ,size : %d \n", operator, 1 * opd);
            location_counter += 1 * opd;
        }else if(strcmp(operator, "BYTE") == 0){
//            printf("op: %s ,size : %d \n", operator, 1 * op_str_to_dec(operand));
            location_counter += 1 * op_str_to_dec(operand);
        }else if(strcmp(operator, "BASE") == 0){
        }else{
            fprintf(intermediate_file, "%s%d\n","error : there's no such op in sic/xe at ",location_counter);
        }

        fgets(line_to_parse,LINE_MAX_LEN,input_file);
        parse_line(line_to_parse, label, operator, operand);
    }
    
    write_to_intermediate_file(listing_line_num, 0, label, operator, operand, "");
    store_obj_length(&obj_length, location_counter - starting_address);
}

void make_symtab_with_hash_table(){
    char address[ADDRESS_MAX_LEN] = "";
    char line[LINE_MAX_LEN] = "";
    label_hash_table = NULL;
    label_hash_table = make_label_table(64);
    
    fclose(intermediate_file);
    intermediate_file = fopen(intermediate_path, "r");
    
    do{
        fgets(line, LINE_MAX_LEN, intermediate_file);
        line_idx = 0;
        read_token(line, label);
        read_blank(line);
        read_token(line, address);
        
        if(label[0] != '-' && ((strcmp(label,"END") != 0))){
            int addr = (int)strtol(address, NULL, 16);
            setLabel(label_hash_table, 64, label, addr);
        }
    }while(strcmp(address, "END") != 0);
}

void parse_intermediate_line(char* line_to_parse, int* address, char* label, char* operator, char* operand){
    /* line parsing */
//    printf("line to parse : %s\n",line_to_parse);
    char *ptr = strtok(line_to_parse, " ");
    
    if(strcmp(ptr, "END") != 0){
        printf("address : %s\n",ptr);
        *address = (int)strtol(ptr,NULL,16);
        ptr = strtok(NULL, " ");
        printf("label : %s\n",ptr);
        strcpy(label, ptr);
        ptr = strtok(NULL, " ");
        printf("operator : %s\n",ptr);
        strcpy(operator, ptr);
        ptr = strtok(NULL, " ");
        if(ptr[0] == '\n')
            ptr[0] = '\0';
        printf("operand : %s\n",ptr);
        strcpy(operand, ptr);
//        printf("after parsing : %x %s %s %s\n", *address, label, operator, operand);
    }else{
        strcpy(label, ptr);
    }
    
}

char* generate_header_record(char* program_name, int starting_address, int program_length){
    char* header_record = (char*)malloc(sizeof(char) * 20);
    char prog_len[ADDRESS_MAX_LEN] = "";
    char start_addr[ADDRESS_MAX_LEN] = "";
    
    int pro_len_len = 0;
    int start_addr_len = 0;
    int header_record_idx = 0;
    
    sprintf(prog_len, "%x", program_length);
    
    
    sprintf(start_addr, "%x", starting_address);
    pro_len_len = (int)strlen(prog_len);
    start_addr_len = (int)strlen(start_addr);
    
    header_record[0] = 'H';
    header_record_idx++;
    
    for(int i = 0; i < strlen(program_name); i++){
        header_record[header_record_idx] = program_name[i];
        header_record_idx++;
    }
    
    for(int i = 0; i < 6 - strlen(program_name); i++){
        header_record[header_record_idx] = ' ';
        header_record_idx++;
    }
    
    for(int i = 0; i < 6 - start_addr_len; i++){
        header_record[header_record_idx] = '0';
        header_record_idx++;
    }
    
    for(int i = 0; i < start_addr_len; i++){
        header_record[header_record_idx] = start_addr[i];
        header_record_idx++;
    }
    
    for(int i = 0; i < 6 - pro_len_len; i++){
        header_record[header_record_idx] = '0';
        header_record_idx++;
    }
    
    for(int i = 0; i < pro_len_len; i++){
        header_record[header_record_idx] = prog_len[i];
        header_record_idx++;
    }
    
    header_record[header_record_idx] = '\0';
    
    return header_record;
}


char* get_label(char* operand){
    int start = 0;
    char* true_label = (char*)malloc(sizeof(char) * (LABEL_MAX_LEN + 1));
    
    if(operand[0] == '#' || operand[0] == '@')
        start++;
    
    for(int i = 0 ; i < 10 ; i++){
        if(strcmp(operand, registers[i].name) == 0){
            return NULL;
        }
    }
    
    int true_label_idx = 0;
    for(int i = start ; i < strlen(operand) ; i++, true_label_idx++){
        
        if(operand[i] == ','){
            true_label[true_label_idx] = '\0';
            break;
        }
        
        if(!(
                ( 'a' <= operand[i] && operand[i] <= 'z' )
                || ( 'A' <= operand[i] && operand[i] <= 'Z' )
                || ( operand[i] == '_' )
             )
        )return NULL;
        
        true_label[true_label_idx] = operand[i];
        
    }
    
    return true_label;
}

void parse_register_code(char* operand, char* first, char* second){
    char* ptr = strtok(operand, " ,");
    strcpy(first, ptr);
    ptr = strtok(NULL, " ,\n");
    if(ptr != NULL){
        strcpy(second, ptr);
    }
    return;
}

int get_register_num (char* reg){
    for(int i = 0; i < 10 ; i++){
        if(strcmp(registers[i].name, reg) == 0){
           return registers[i].num;
        }
    }
    
    return -1;
}

void small_to_cap(char* str){
    for(int i = 0; i < strlen(str); i++){
        if( 'a' <= str[i] && str[i] <= 'z' ){
            str[i] += 'A' - 'a';
        }
    }
}

void fill_0(char* str){
    for(int i = 0; i< strlen(str); i++){
        if(str[i] == ' '){
            str[i] = '0';
        }
    }
    return;
}


char* generate_obj_code(int addr, char* operator, char* operand){
    unsigned long obj = 0;
    
    opnode* op_info = NULL;
    
    if(operator[0] == '+')
        op_info = getOp(op_hash_table, 64, operator + 1);
    else
        op_info = getOp(op_hash_table, 64, operator);
    
    if(op_info != NULL){
        char first[3];
        char second[3];
        
        switch (op_info->format) {
            case 1:
                obj = op_info->op_code;
                char* opcode_form_1 = (char*)malloc(sizeof(char)*4 + 1);
                sprintf(opcode_form_1,"%x",obj);
                printf("oject code : %s\n\n", opcode_form_1);
                small_to_cap(opcode_form_1);
                return opcode_form_1;
                // just op
                // size = 1byte;
                
            case 2:
                parse_register_code(operand, first, second);
//                printf("%s %s\n", first, second);
                
                unsigned int first_reg_num = get_register_num(first);
                unsigned int second_reg_num = -1;
                
                if(strlen(second) != 0){
                    second_reg_num = get_register_num(second);
                }
                
                obj = op_info -> op_code;
                obj = obj << 4;
                obj = obj | first_reg_num;
                obj = obj << 4; // move 1byte;
                
                if(second_reg_num == -1)
                    second_reg_num = 0;
    
                obj = obj | second_reg_num;
                char* opcode_form_2 = (char*)malloc(sizeof(char)*8 + 1);
                sprintf(opcode_form_2,"%x",obj);
                small_to_cap(opcode_form_2);
//                printf("object code : %s\n\n", opcode_form_2);
                
                return opcode_form_2;
                // no memory reference
                // size = 2byte;
                break;
                
            case 3:
                obj = op_info->op_code;
                long disp = 0;
                int format = 3;
                int target_addr = 0;
                int i = 1;
                int n = 1;
                int e = 0;
                int x = 0;
                int b = 0;
                int p = 0;
                
                int pc = addr;
                if(operand[strlen(operand) - 1] == 'X')
                    x = 1;
                if(operand[0] == '@')
                    i = 0;
                    // indirect addressing
                if(operand[0] == '#')
                    // immediate addressing
                    n = 0;
                if(operator[0] == '+'){
                    e = 1;
                    format = 4;
                }if(operand[strlen(operand)] == 'X'){
                    x = 1;
                }
                
                pc = pc + format;
        
                char* true_label = get_label(operand);
                label_node* label_info = NULL;
                
                if(true_label != NULL){
                    // label이 있는 operand
                    label_info = getLabel(label_hash_table, 64, true_label);
                    if(label_info == NULL){
                        printf("undefined symbol!\n");
                    }else{
                        if(operator[0] == '+'){
                            disp = label_info->address;
                        }else{
                            target_addr = label_info -> address;
                            disp = target_addr - pc;
                            p = 1;
                            // disp가 -2047에서 2048사이 이면 pc-relative 가능
                            if(!(-2047 <= disp && disp <= 2048)){
                                if(can_use_base){
                                    disp = target_addr - base_addr;
                                    b = 1;
                                    p = 0;
                                    if(!(-2047 <= disp && disp <= 2048)){
                                        printf("can't addressing!!\n");
                                        disp = 0;
                                    }
                                }else{
                                    printf("can't addressing!!\n");
                                    disp = 0;
                                }
                            }
                            
                            if(-2047<=disp && disp <= -1){
                                long filter = 0x00000FFF;
                                disp = disp & filter;
                            }
                            // disp 범위를 넘어가면 base-relative 사용
                            // 만약 base-relative가 지원이 안되면
                            // addressing이 불가하다.
                        }
                    }
                }else {
                    if(operand[0] == '#')
                        disp = (int)strtol(operand + 1, NULL, 10);
                }
                
                obj = 1;
                
                obj = obj * op_info->op_code;
                n = n << 1;
                obj = obj | n;
                obj = obj | i;
                n = n >> 1;
//                printf("---------------%lx-------------------\n", obj);
                
                obj = obj << 1;
                obj = obj | x;
                
                obj = obj << 1;
                obj = obj | b;
                
                obj = obj << 1;
                obj = obj | p;
                
                obj = obj << 1;
                obj = obj | e;
                
                if(format == 3){
                    obj = obj << 12;
                    obj = obj | disp;

                }else{
                    obj = obj << 20;
                    obj = obj | disp;
                }
                
                if(format == 3){
                    char* opcode_form_3 = (char*)malloc(sizeof(char)*12 + 1);
                    sprintf(opcode_form_3,"%06lx",obj);
                    small_to_cap(opcode_form_3);
//                    printf("object code : %s\n\n", opcode_form_3);
                    if(n == 1 && i == 1 && b == 0 && p == 0 && x == 0 && strlen(operand) > 0){
                        add_modification_record(modification_counter_record, 3);
                    }
                    return opcode_form_3;
                    
                }else{
                    char* opcode_form_4 = (char*)malloc(sizeof(char)*16 + 1);
                    sprintf(opcode_form_4,"%08lx",obj);
                    small_to_cap(opcode_form_4);
                    if(n == 1 && i == 1 && b == 0 && p == 0 && x == 0){
                        printf("%d",n);
                        add_modification_record(modification_counter_record, 5);
                    }
//                    printf("object code : %s\n\n", opcode_form_4);
                    return opcode_form_4;
                }
                break;
        }
        
    }else{
        if(strcmp(operator, "BYTE") == 0){
            char* objcet_code_byte_type_x = (char*)malloc(sizeof(char) * 2 + 1);
            char* character_temp_arr = (char*)malloc(sizeof(char) * 256 + 1);
            char* objcet_code_byte_type_c = (char*)malloc(sizeof(char) * 256 * 2 + 1);
            int find_open = 0;
            int idx = 0;
            if(operand[0] == 'X'){
                for(int i = 0 ; i < strlen(operand); i++){
                    if(operand[i] == '\'' && find_open == 0){
                        find_open = 1;
                        continue;
                    }
                    if(operand[i] == '\'' && find_open == 1){
                        find_open = 0;
                        objcet_code_byte_type_x[i] = '\0';
                        break;
                    }
                    if(find_open != 0){
                        objcet_code_byte_type_x[idx] = operand[i];
                        idx++;
                    }
                }
                
                if(strlen(objcet_code_byte_type_x) == 1){
                    objcet_code_byte_type_x[0] = objcet_code_byte_type_x[1];
                    objcet_code_byte_type_x[0] = '0';
                }
                
                return objcet_code_byte_type_x;
                
            }else if (operand[0] == 'C'){
                find_open = 0;
                for(int i = 0 ; i < strlen(operand); i++){
                    if(operand[i] == '\'' && find_open == 0){
                        find_open = 1;
                        continue;
                    }
                    if(operand[i] == '\'' && find_open == 1){
                        find_open = 0;
                        character_temp_arr[i] = '\0';
                        break;
                    }
                    if(find_open != 0){
                        character_temp_arr[idx] = operand[i];
                        idx++;
                    }
                }
                
                int j = 0;
                for(int i = 0 ; i < strlen(character_temp_arr); i++){
                    char temp[3] = {' ',' ','\0'};
                    sprintf(temp, "%02x", character_temp_arr[i]);
                    objcet_code_byte_type_c[j++] = temp[0];
                    objcet_code_byte_type_c[j++] = temp[1];
                }
                
                objcet_code_byte_type_c[j] = '\0';
                small_to_cap(objcet_code_byte_type_c);
//                printf("BYTE-C : %s\n", objcet_code_byte_type_c);
                return objcet_code_byte_type_c;
                
            }else{
                int byte = (int)strtol(operand, NULL, 10);
                sprintf(objcet_code_byte_type_x, "%02x", byte);
                return objcet_code_byte_type_x;
            }
            
        }else if(strcmp(operator, "WORD") == 0){
            char* objcet_code_word = (char*)malloc(sizeof(char) * 7);
            int word = (int)strtol(operand, NULL, 10);
            sprintf(objcet_code_word, "%06x", word);
//            printf("WORD : %s\n", objcet_code_word);
            return objcet_code_word;
        }
    }
    
    return NULL;
}

int is_object_code_fit(char* object_code){
    if(temp_text_record.current_length + strlen(object_code) <= 60)
        return 1;
    else
        return 0;
}

void init_text_record(int starting_addr){
    temp_text_record.starting_address = starting_addr;
    temp_text_record.current_length = 0;
    temp_text_record.object_code[0] = '\0';
}

void write_text_record_into_obj_file(){
    fprintf(output_file,"T");
    fprintf(output_file,"%06x", temp_text_record.starting_address);
    fprintf(output_file,"%02x", temp_text_record.current_length/2);
    fprintf(output_file,"%s\n", temp_text_record.object_code);
    temp_text_record.current_length = 0;
    temp_text_record.object_code[0] = '\0';
    temp_text_record.starting_address = 0;
}

void add_text_record(int address, char* object_code){
    modification_counter_record += strlen(object_code);
    if(is_object_code_fit(object_code)){
        for(int j = 0; j < strlen(object_code); j++,temp_text_record.current_length++){
            temp_text_record.object_code[temp_text_record.current_length] = object_code[j];
        }
        temp_text_record.object_code[temp_text_record.current_length] = '\0';
    }else{
        write_text_record_into_obj_file();
        init_text_record(address);
        for(int j = 0; j < strlen(object_code); j++,temp_text_record.current_length++){
            temp_text_record.object_code[temp_text_record.current_length] = object_code[j];
        }
        temp_text_record.object_code[temp_text_record.current_length] = '\0';
    }
}

void write_end_record(int program_start_addr){
    fprintf(output_file,"E");
    fprintf(output_file,"%06x\n", program_start_addr);
}

void write_modification_record(){
    modification_record* end = modifitaction_record_list;
    while(end != NULL){
//        printf("modification : %d %d\n", end->starting_location, end->length_to_modify);
        fprintf(output_file,"M");
        fprintf(output_file,"%06x",(end->starting_location + 2)/2);
        fprintf(output_file,"%02x\n", end->length_to_modify);
        end = end->next;
    }
}

void do_path2(){
    int program_start_address = 0;
    int address;
    char label[ADDRESS_MAX_LEN] = "";
    char operator[OPERATOR_MAX_LEN] = "";
    char operand[OPERAND_MAX_LEN] = "";
    
    /* make listing file */
    listing_file = fopen(listing_path, "w");

    /* change intermediate_file mode to read mode */
    fclose(intermediate_file);
    intermediate_file = fopen(intermediate_path,"r");
    
    /* read first inpyt line from intermediate file*/
    fgets(line_to_parse, LINE_MAX_LEN, intermediate_file);
    parse_intermediate_line(line_to_parse, &address, label, operator, operand);
    if(strcmp(operator,"START") == 0){
        
        fprintf(listing_file, LISTING_FILE_PRINTING_FORMAT, address, label, operator, operand);
//        fgets(line_to_parse, LINE_MAX_LEN, intermediate_file);
        int starting_addr = (int)strtol(operand, NULL, 16);
        program_start_address = starting_addr;
        char* header_record = generate_header_record(label, starting_addr, obj_length);
        fprintf(output_file, "%s\n", header_record);
        // write head record to object program
        init_text_record(starting_addr);
        printf(">> object code : - \n\n");
        // initialize text record
    }
    
    do{
        fgets(line_to_parse, LINE_MAX_LEN, intermediate_file);
        parse_intermediate_line(line_to_parse, &address, label, operator, operand);
        // read line and parsing line
        
        if(strcmp(operator, "BASE") == 0){
            can_use_base = 1;
            label_node* label = getLabel(label_hash_table, 64, operand);
            base_addr = label->address;
        }
        
        if(strcmp(operator, "NOBASE") == 0)
            can_use_base = 0;
        
        if((strcmp("RESB", operator) == 0
            || strcmp("RESW", operator) == 0)
           &&(temp_text_record.current_length > 0)){
            write_text_record_into_obj_file();
            printf(">> object code : - \n\n");
            continue;
        }
        
        if(strcmp(label,"END") != 0){
            char* obj_code = generate_obj_code(address, operator, operand);
            if(obj_code != NULL){
                // 이곳에 들어오면 무조건 text_record에 들어가야 한다.
                printf(">> object code : %s\n\n", obj_code);
                
                add_text_record(address, obj_code);
            }else{
                printf(">> object code : - \n\n");
            }
        }
        
        
    }while(strcmp(label, "END") != 0);
    
    if(temp_text_record.current_length > 0){
        write_text_record_into_obj_file();
    }
    
    write_modification_record();
    write_end_record(program_start_address);
}

int main (int argc, char* argv[]){
    if(argc < 3){
        printf("you need source.asm and object.asm");
        return 0;
    }else{
        source_path = argv[1];
        object_path = argv[2];
    }

    input_file = fopen(source_path, "r");
    output_file = fopen(object_path, "w");

    if(input_file == NULL || output_file == NULL){
        printf("you need source.asm and object.obj");
        return 0;
    }
    
    initialize_op_hash_table();
    initialize_label_hash_table();
    do_path1();
    do_path2();
    return 0;
}

